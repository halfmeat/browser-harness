"""Reconnect exhaustion cleanup (policy mode). The retry policy itself is unchanged:
exactly 3 attempts, pauses min(2**attempt, 5) between them. Live-found defects:

* a reconnect connection that connected but failed the startup contract was never
  stopped — the next attempt overwrote ``self.cdp`` and the WebSocket plus its
  message/keepalive tasks stayed alive for the daemon's lifetime (3 per outage);
* a 4 s pause ran after the LAST failed attempt, with no attempt after it;
* nothing logged that automatic reconnects had stopped.
"""
import asyncio
import json
import os
import time

import pytest

import browser_harness.daemon as daemon_mod

from .policy_harness import FakeBrowser, make_policy_daemon, meta, model, new_loop, run


@pytest.fixture(autouse=True)
def _loop():
    loop = new_loop()
    try:
        yield loop
    finally:
        loop.close()
        asyncio.set_event_loop(None)


@pytest.fixture
def logs(monkeypatch):
    lines = []
    monkeypatch.setattr(daemon_mod, "log", lines.append)
    return lines


@pytest.fixture
def sleeps(monkeypatch):
    """Record the daemon's backoff pauses (non-zero delays) without waiting them out."""
    real, seen = asyncio.sleep, []

    async def fast(delay, *a, **k):
        if delay:
            seen.append(delay)
        await real(0)
    monkeypatch.setattr(daemon_mod.asyncio, "sleep", fast)
    return seen


def _candidates(monkeypatch, d, fail_at="Browser.setDownloadBehavior", succeed_on=None, order=None):
    """_new_cdp_client hands out a NEW FakeBrowser per attempt (like production). Attempts
    fail at ``fail_at`` (after Target.createBrowserContext, so a failed context exists),
    except attempt number ``succeed_on`` (1-based)."""
    made = []

    async def factory():
        n = len(made) + 1
        b = FakeBrowser(ctx_prefix=f"CTX-C{n}", tid_prefix=f"C{n}T", sid_prefix=f"C{n}S")
        if n != succeed_on:
            b.fail[fail_at] = RuntimeError(f"boom {n}")
        b._message_handler_task = asyncio.get_event_loop().create_future()  # stays connected
        orig_stop = b.stop

        async def disposed(_p, _s, n=n):
            if order is not None:
                order.append(("dispose", n))
        b.hooks["Target.disposeBrowserContext"] = disposed

        async def stop():
            if order is not None:
                order.append(("stop", n, d.cdp is b))
            await orig_stop()
        monkeypatch.setattr(b, "stop", stop)
        if order is not None:
            order.append(("new", n))
        made.append(b)
        return b
    monkeypatch.setattr(d, "_new_cdp_client", factory)
    return made


def test_failed_candidates_are_stopped_before_the_next_attempt(monkeypatch, logs, sleeps):
    d = make_policy_daemon()
    b1, order = d.cdp, []
    made = _candidates(monkeypatch, d, order=order)
    assert run(d._policy_reconnect()) is False
    assert len(made) == 3
    assert [c.stopped for c in made] == [1, 1, 1]
    # each candidate is stopped (and no longer self.cdp) before the next one exists
    assert order == [("new", 1), ("dispose", 1), ("stop", 1, False), ("new", 2), ("dispose", 2),
                     ("stop", 2, False), ("new", 3), ("dispose", 3), ("stop", 3, False)]
    # its failed Hermes context is disposed over that candidate BEFORE it is stopped
    for n, c in enumerate(made, 1):
        assert ("Target.disposeBrowserContext", {"browserContextId": f"CTX-C{n}"}, None) in c.calls
    # the displaced (pre-outage) client is put back and never stopped
    assert d.cdp is b1 and b1.stopped == 0


def test_no_candidate_when_the_new_connection_itself_fails(monkeypatch, logs, sleeps):
    d = make_policy_daemon()
    b1, calls = d.cdp, []

    async def unreachable():
        calls.append(1)
        raise RuntimeError("BU_CDP_URL unreachable after 30s")
    monkeypatch.setattr(d, "_new_cdp_client", unreachable)
    assert run(d._policy_reconnect()) is False
    assert len(calls) == 3 and d.cdp is b1 and b1.stopped == 0
    assert sleeps == [1, 2]


def test_successful_reconnect_keeps_its_client_and_stops_only_failed_ones(monkeypatch, logs, sleeps):
    d = make_policy_daemon()
    b1 = d.cdp
    made = _candidates(monkeypatch, d, succeed_on=2)
    lost = asyncio.get_event_loop().create_future()
    b1._message_handler_task = lost
    d._policy_watch = asyncio.get_event_loop().create_task(d._watch_policy_connection())
    run(asyncio.sleep(0))
    lost.set_result(None)

    async def until_ready():
        for _ in range(500):
            if d.policy.registry.generation == 3 and d.policy.registry.initial_ready:
                return
            await asyncio.sleep(0)
        raise AssertionError("never ready")
    run(until_ready())
    reg = d.policy.registry
    assert len(made) == 2 and made[0].stopped == 1 and made[1].stopped == 0 and b1.stopped == 0
    assert d.cdp is made[1] and reg.browser_context_id == "CTX-C2"
    assert reg.generation == 3  # gen 1 (start), gen 2 (failed attempt), gen 3 (this one)
    assert meta(d, "ping")["policy"]["ready"] is True
    assert not d._policy_watch.done()  # the watcher now watches the successful client
    assert sleeps == [1]
    assert not any("exhausted" in ln for ln in logs)
    d._shutting_down = True
    d._policy_watch.cancel()
    run(asyncio.gather(d._policy_watch, return_exceptions=True))


def test_candidate_stop_failure_is_contained(monkeypatch, logs, sleeps):
    d = make_policy_daemon()
    made = _candidates(monkeypatch, d)
    orig = d._discard_reconnect_candidate

    async def broken_stop():
        raise OSError("socket already gone")
    for_next = {"n": 0}

    async def discard(candidate, *rest):
        for_next["n"] += 1
        candidate.stop = broken_stop
        await orig(candidate, *rest)
    monkeypatch.setattr(d, "_discard_reconnect_candidate", discard)
    assert run(d._policy_reconnect()) is False  # never raises out of the reconnect task
    assert len(made) == 3 and for_next["n"] == 3
    assert sum("stopping the failed reconnect connection: OSError" in ln for ln in logs) == 3


def test_no_pause_after_the_last_attempt_and_inter_attempt_pauses_kept(monkeypatch, logs, sleeps):
    d = make_policy_daemon()
    _candidates(monkeypatch, d)
    assert run(d._policy_reconnect()) is False
    assert sleeps == [1, 2]  # was [1, 2, 4]
    sleeps.clear()
    _candidates(monkeypatch, d)
    assert run(d._policy_reconnect(attempts=5)) is False
    assert sleeps == [1, 2, 4, 5]  # formula/cap unchanged, still no pause after the last


def test_exhaustion_logged_exactly_once_after_the_last_failure(monkeypatch, logs, sleeps):
    d = make_policy_daemon()
    _candidates(monkeypatch, d)
    lost = asyncio.get_event_loop().create_future()
    d.cdp._message_handler_task = lost
    d._policy_watch = asyncio.get_event_loop().create_task(d._watch_policy_connection())
    run(asyncio.sleep(0))
    lost.set_result(None)

    async def until_done():
        for _ in range(500):
            if d._policy_watch.done():
                return
            await asyncio.sleep(0)
        raise AssertionError("watcher did not finish")
    run(until_done())
    policy = [ln for ln in logs if ln.startswith("policy:") and "stopping" not in ln]
    assert policy[-2].startswith("policy: reconnect attempt 3/3 failed")
    assert policy[-1] == ("policy: reconnect exhausted after 3 failed attempts; no further automatic "
                          "attempts (not ready until this daemon is replaced)")
    assert sum("exhausted" in ln for ln in logs) == 1
    reg = d.policy.registry
    assert not reg.connected and not reg.initial_ready and reg.owned_target_ids() == set()
    assert meta(d, "ping")["policy"]["ready"] is False
    assert "error" in model(d, "Target.getTargets", {})


def test_no_exhaustion_log_when_shutdown_ends_the_attempts(monkeypatch, logs, sleeps):
    d = make_policy_daemon()

    async def cancelled_by_shutdown():
        d._ws_url_stop.set()  # serve() teardown: discovery cancelled, the attempt fails
        raise daemon_mod.EndpointDiscoveryCancelled("browser endpoint discovery cancelled")
    monkeypatch.setattr(d, "_new_cdp_client", cancelled_by_shutdown)
    assert run(d._policy_reconnect()) is False
    assert not any("exhausted" in ln for ln in logs)

    d2 = make_policy_daemon()
    calls = []

    async def first_fails_then_shutdown():
        calls.append(1)
        d2._shutting_down = True
        raise RuntimeError("unreachable")
    monkeypatch.setattr(d2, "_new_cdp_client", first_fails_then_shutdown)
    logs.clear()
    assert run(d2._policy_reconnect()) is False
    assert calls == [1] and not any("exhausted" in ln for ln in logs)


def test_real_cdp_connections_are_closed_after_failed_reinstalls(monkeypatch, logs):
    """Real cdp_use client + real WebSocket server that answers every CDP method with an
    error: before the fix all 3 connections (and their message/keepalive tasks) stayed
    open after exhaustion. Real pauses: 1 s + 2 s, and none after attempt 3."""
    from websockets.asyncio.server import serve

    d = make_policy_daemon()
    state = {"open": 0, "total": 0}

    async def handler(ws):
        state["open"] += 1
        state["total"] += 1
        try:
            async for raw in ws:
                m = json.loads(raw)
                await ws.send(json.dumps({"id": m.get("id"), "error": {"code": -32000, "message": "no"}}))
        except Exception:
            pass
        finally:
            state["open"] -= 1

    async def scenario():
        async with serve(handler, "127.0.0.1", 0) as server:
            port = next(iter(server.sockets)).getsockname()[1]
            monkeypatch.setattr(daemon_mod, "get_ws_url", lambda stop=None: f"ws://127.0.0.1:{port}/devtools/browser/x")
            before = asyncio.all_tasks()
            t = time.monotonic()
            ok = await d._policy_reconnect()
            elapsed = time.monotonic() - t
            for _ in range(100):
                if state["open"] == 0:
                    break
                await asyncio.sleep(0.01)
            return ok, elapsed, state["open"], state["total"], _new_tasks(before)
    ok, elapsed, still_open, total, leftovers = run(scenario())
    assert ok is False and total == 3
    assert still_open == 0, f"{still_open} reconnect WebSocket(s) leaked"
    assert leftovers == [], leftovers
    assert 2.9 <= elapsed < 5.5, elapsed  # 1 + 2 s pauses; the old trailing 4 s pause would make it >= 7
    assert sum("exhausted" in ln for ln in logs) == 1


# ── R1: cancellation (shutdown) while a candidate is being installed ─────────────
def _new_tasks(before):
    """Tasks alive now that were not alive at ``before`` (identity, not coroutine names)."""
    return sorted(repr(t.get_coro()) for t in asyncio.all_tasks() - before if t is not asyncio.current_task())


class _AsyncioProxy:
    """``daemon_mod.asyncio`` replacement recording the daemon's own backoff pauses only
    (websockets' keepalive keeps the real asyncio.sleep)."""

    def __init__(self, seen, block=False):
        self._seen, self._block = seen, block

    def __getattr__(self, name):
        return getattr(asyncio, name)

    async def sleep(self, delay, *a, **k):
        if delay:
            self._seen.append(delay)
            if self._block:
                await asyncio.Event().wait()
        await asyncio.sleep(0)


@pytest.fixture
def dsleeps(monkeypatch):
    seen = []
    monkeypatch.setattr(daemon_mod, "asyncio", _AsyncioProxy(seen))
    return seen


def _counting_clients(monkeypatch):
    """Real cdp_use clients (both production classes), instrumented to count stop() and to
    keep references to the connection's message-handler and keepalive tasks."""
    made = []

    def wrap(base):
        class Counting(base):
            async def start(self):
                await super().start()
                self.stops = 0
                self.handler_task = self._message_handler_task
                self.keepalive = self.ws.keepalive_task

            async def stop(self):
                self.stops += 1
                await super().stop()

        def make(url):
            c = Counting(url)
            made.append(c)
            return c
        return make
    monkeypatch.setattr(daemon_mod, "CDPClient", wrap(daemon_mod.CDPClient))
    monkeypatch.setattr(daemon_mod, "_PatientCDPClient", wrap(daemon_mod._PatientCDPClient))
    return made


class _CDPServer:
    """Loopback CDP WebSocket endpoint: ``answers[method]`` -> result, ``hang`` methods are
    never answered (sets ``hung``), everything else gets a CDP error."""

    def __init__(self, monkeypatch, answers=None, hang=()):
        self.mp, self.answers, self.hang = monkeypatch, answers or {}, set(hang)
        self.open = self.total = 0
        self.methods = []
        self.hung = asyncio.Event()

    async def _handler(self, ws):
        self.open += 1
        self.total += 1
        try:
            async for raw in ws:
                m = json.loads(raw)
                self.methods.append((m.get("method"), m.get("params")))
                if m.get("method") in self.hang:
                    self.hung.set()
                    continue
                if m.get("method") in self.answers:
                    reply = {"id": m.get("id"), "result": self.answers[m["method"]]}
                else:
                    reply = {"id": m.get("id"), "error": {"code": -32000, "message": "no"}}
                await ws.send(json.dumps(reply))
        except Exception:
            pass
        finally:
            self.open -= 1

    async def __aenter__(self):
        from websockets.asyncio.server import serve
        self._cm = serve(self._handler, "127.0.0.1", 0)
        server = await self._cm.__aenter__()
        port = next(iter(server.sockets)).getsockname()[1]
        self.mp.setattr(daemon_mod, "get_ws_url", lambda stop=None: f"ws://127.0.0.1:{port}/devtools/browser/x")
        return self

    async def __aexit__(self, *exc):
        return await self._cm.__aexit__(*exc)

    async def closed(self):
        for _ in range(200):
            if self.open == 0:
                return True
            await asyncio.sleep(0.01)
        return False


async def _drop_and_watch(d):
    lost = asyncio.get_running_loop().create_future()
    d.cdp._message_handler_task = lost
    d._policy_watch = asyncio.create_task(d._watch_policy_connection())  # production watcher
    await asyncio.sleep(0)
    lost.set_result(None)


async def _cancel_like_serve(d):
    """serve() teardown: no further reconnects, then cancel the watcher once."""
    d._shutting_down = True
    return await _cancelled(d._policy_watch, 10)


async def _cancelled(task, timeout=5):
    """Cancel task once; True iff it then ENDS CANCELLED (CancelledError propagated out of
    it). Bounded without awaiting the task itself, so a swallowed cancel fails, never hangs."""
    task.cancel()
    done, _ = await asyncio.wait({task}, timeout=timeout)
    return task in done and task.cancelled()


@pytest.mark.parametrize("hang, ctx_created", [("Target.createBrowserContext", False),
                                                ("Browser.setDownloadBehavior", True)])
def test_cancel_during_start_policy_stops_the_real_candidate(monkeypatch, logs, dsleeps, hang, ctx_created):
    """Codex R1: shutdown cancels the watcher while _start_policy() is awaiting on a NEW,
    real connection. CancelledError bypassed ``except Exception`` and the candidate (WS,
    message-handler and keepalive tasks) stayed alive as self.cdp."""
    d = make_policy_daemon()
    b1 = d.cdp
    made = _counting_clients(monkeypatch)

    async def scenario():
        async with _CDPServer(monkeypatch, answers={"Target.createBrowserContext": {"browserContextId": "CTX-CAND"},
                                                    "Target.disposeBrowserContext": {}},
                              hang={hang}) as srv:
            before = asyncio.all_tasks()
            await _drop_and_watch(d)
            await asyncio.wait_for(srv.hung.wait(), 10)  # candidate created, startup blocked
            cand = made[0]
            assert d.cdp is cand and not cand.handler_task.done() and not cand.keepalive.done()
            assert d.policy.registry.connected is ctx_created  # begin_generation ran iff ctx exists
            propagated = await _cancel_like_serve(d)
            closed = await srv.closed()
            return cand, propagated, closed, srv, _new_tasks(before)
    cand, propagated, closed, srv, leftovers = run(scenario())
    assert propagated and d._policy_watch.cancelled()           # CancelledError propagates
    assert cand.stops == 1 and cand.ws is None                   # stopped exactly once
    assert cand.handler_task.done() and cand.keepalive.done()    # its tasks exited
    assert closed and srv.total == 1                             # WS closed; no retry connection
    assert leftovers == [], leftovers                            # no candidate task left anywhere
    assert d.cdp is b1 and b1.stopped == 0                       # previous client back, untouched
    assert len(made) == 1 and dsleeps == []                      # no retry, no retry pause
    assert not any("reconnect attempt" in ln or "exhausted" in ln for ln in logs)  # not a failure
    disposed = [p for m, p in srv.methods if m == "Target.disposeBrowserContext"]
    assert disposed == ([{"browserContextId": "CTX-CAND"}] if ctx_created else [])  # over the candidate
    reg = d.policy.registry
    assert not reg.connected and not reg.initial_ready and reg.owned_target_ids() == set()
    assert meta(d, "ping")["policy"]["ready"] is False


def test_cancel_during_inter_attempt_pause_does_not_stop_twice(monkeypatch, logs):
    d = make_policy_daemon()
    b1 = d.cdp
    made = _candidates(monkeypatch, d)
    seen = []
    monkeypatch.setattr(daemon_mod, "asyncio", _AsyncioProxy(seen, block=True))

    async def scenario():
        t = asyncio.create_task(d._policy_reconnect())
        for _ in range(200):
            if seen:
                break
            await asyncio.sleep(0)
        assert seen == [1] and made[0].stopped == 1  # failed candidate already stopped, now pausing
        assert await _cancelled(t), "CancelledError did not propagate out of the reconnect"
    run(scenario())
    assert len(made) == 1 and made[0].stopped == 1 and d.cdp is b1 and b1.stopped == 0
    assert not any("exhausted" in ln for ln in logs)


def test_cancel_after_adoption_keeps_the_accepted_client(monkeypatch, logs, sleeps):
    """The policy is installed on the new connection (accepted); a cancellation while the OLD
    context is being disposed must not stop the now-operational client."""
    d = make_policy_daemon()
    made = _candidates(monkeypatch, d, succeed_on=1)
    gate = asyncio.Event()
    orig_factory = d._new_cdp_client

    async def factory():
        b = await orig_factory()

        async def block(p, _s):
            if p.get("browserContextId") == "CTX-HERMES":
                await gate.wait()
        b.hooks["Target.disposeBrowserContext"] = block
        return b
    monkeypatch.setattr(d, "_new_cdp_client", factory)

    async def scenario():
        t = asyncio.create_task(d._policy_reconnect())
        for _ in range(500):
            if made and made[0].count("Target.disposeBrowserContext"):
                break
            await asyncio.sleep(0)
        assert await _cancelled(t), "CancelledError did not propagate out of the reconnect"
    run(scenario())
    reg = d.policy.registry
    assert made[0].stopped == 0 and d.cdp is made[0]
    assert reg.generation == 2 and reg.initial_ready and reg.browser_context_id == "CTX-C1"


def test_cancel_while_creating_the_connection_has_nothing_to_stop(monkeypatch, logs, sleeps):
    d = make_policy_daemon()
    b1 = d.cdp

    async def never():
        await asyncio.Event().wait()
    monkeypatch.setattr(d, "_new_cdp_client", never)

    async def scenario():
        t = asyncio.create_task(d._policy_reconnect())
        await asyncio.sleep(0)
        assert await _cancelled(t), "CancelledError did not propagate out of the reconnect"
    run(scenario())
    assert d.cdp is b1 and b1.stopped == 0 and sleeps == []
    assert not any("exhausted" in ln or "reconnect attempt" in ln for ln in logs)


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="needs /proc fd accounting")
def test_repeated_real_failed_candidate_cycles_do_not_accumulate(monkeypatch, logs, dsleeps):
    """Several full exhaustion rounds of real candidates: open WS, new tasks and the process
    fd count return to the baseline after every round (no cumulative growth)."""
    d = make_policy_daemon()
    made = _counting_clients(monkeypatch)
    rounds = []

    async def scenario():
        async with _CDPServer(monkeypatch) as srv:
            before, fds0 = asyncio.all_tasks(), len(os.listdir("/proc/self/fd"))
            for _ in range(4):
                assert await d._policy_reconnect() is False
                await srv.closed()
                rounds.append({"open": srv.open, "total": srv.total, "tasks": _new_tasks(before),
                               "fds": len(os.listdir("/proc/self/fd")) - fds0})
    run(scenario())
    assert [r["total"] for r in rounds] == [3, 6, 9, 12]
    assert all(r["open"] == 0 and r["tasks"] == [] and r["fds"] == 0 for r in rounds), rounds
    assert len(made) == 12 and all(c.stops == 1 and c.ws is None and c.handler_task.done()
                                   and c.keepalive.done() for c in made)
    assert dsleeps == [1, 2] * 4 and sum("exhausted" in ln for ln in logs) == 4
