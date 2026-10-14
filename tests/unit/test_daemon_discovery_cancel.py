"""Reload/shutdown during a browser outage: a policy reconnect waits for the browser in
get_ws_url() on an asyncio.to_thread() worker. Cancelling the awaiting task does not stop that
thread, and asyncio.run() joins the default executor on exit, so the daemon process lingered
for the rest of get_ws_url()'s ~30 s window after acknowledging shutdown. get_ws_url() now takes
an optional ``stop`` event (checked before each attempt, interrupting each retry pause) that
serve() sets on exit; without one (cold start) its behaviour is unchanged."""
import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
import time
import urllib.error
from pathlib import Path

import pytest

import browser_harness.daemon as dm

SRC = str(Path(dm.__file__).resolve().parent.parent)


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Blackhole:
    """Loopback listener that never answers: a request blocks for its whole timeout."""

    def __enter__(self):
        self.s = socket.socket()
        self.s.bind(("127.0.0.1", 0))
        self.s.listen(8)
        self.port = self.s.getsockname()[1]
        return self

    def __exit__(self, *a):
        self.s.close()


# ── behaviour without a stop event is unchanged (fake clock) ──────────────────────────────
class _Clock:
    def __init__(self):
        self.now = 1000.0
        self.log = []

    def time(self):
        return self.now

    def sleep(self, s):
        self.log.append(("pause", s))
        self.now += s


class _UnsetEvent:
    """An event that is never set: wait() must behave exactly like the plain sleep."""

    def __init__(self, clock):
        self.clock = clock

    def is_set(self):
        return False

    def wait(self, s):
        self.clock.sleep(s)
        return False


class _Resp:
    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body


def _run_discovery(monkeypatch, outcomes, use_event):
    """Drive get_ws_url() through ``outcomes`` (exceptions to raise / a ws URL to return) on a
    fake clock; returns (result_or_exception, call log)."""
    clock = _Clock()
    seq = list(outcomes)

    def urlopen(url, timeout=None):
        clock.log.append(("urlopen", url, timeout))
        clock.now += 0.001
        nxt = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(nxt, BaseException):
            raise nxt
        return _Resp(json.dumps({"webSocketDebuggerUrl": nxt}).encode())
    monkeypatch.setattr(dm.time, "time", clock.time)
    monkeypatch.setattr(dm.time, "sleep", clock.sleep)
    monkeypatch.setattr(dm.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(dm, "_ws_from_devtools_active_port", lambda url: "ws://fallback/devtools/browser/x")
    stop = _UnsetEvent(clock) if use_event else None
    try:
        out = dm.get_ws_url(stop) if use_event else dm.get_ws_url()
    except Exception as e:
        out = e
    return out, clock.log


REFUSED = urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))


def _http(code):
    return urllib.error.HTTPError("http://x/json/version", code, "x", {}, None)


@pytest.mark.parametrize("outcomes", [
    [REFUSED, REFUSED, "ws://127.0.0.1:9/devtools/browser/ok"],       # browser comes up during grace
    [_http(500), "ws://127.0.0.1:9/devtools/browser/ok"],
    [_http(403)],                                                      # permission-blocked
    [_http(404)],                                                      # DevToolsActivePort fallback
    [REFUSED],                                                         # never comes up: 30 s deadline
    [TimeoutError("timed out")],
])
def test_no_stop_event_behaviour_is_unchanged(monkeypatch, outcomes):
    monkeypatch.setenv("BU_CDP_URL", "http://127.0.0.1:9/")
    monkeypatch.delenv("BU_CDP_WS", raising=False)
    plain, plain_log = _run_discovery(monkeypatch, outcomes, use_event=False)
    evented, evented_log = _run_discovery(monkeypatch, outcomes, use_event=True)
    assert evented_log == plain_log
    assert type(evented) is type(plain) and str(evented) == str(plain)
    assert all(c[2] == 5 for c in plain_log if c[0] == "urlopen")      # per-request timeout kept
    assert all(c[1] == 1 for c in plain_log if c[0] == "pause")        # 1 s retry pause kept


def test_deadline_is_still_30s_without_stop(monkeypatch):
    monkeypatch.setenv("BU_CDP_URL", "http://127.0.0.1:9")
    monkeypatch.delenv("BU_CDP_WS", raising=False)
    out, log = _run_discovery(monkeypatch, [REFUSED], use_event=False)
    assert isinstance(out, RuntimeError) and "unreachable after 30s" in str(out)
    assert 29 <= sum(c[1] for c in log if c[0] == "pause") <= 31


def test_bu_cdp_ws_short_circuit_unchanged(monkeypatch):
    monkeypatch.setenv("BU_CDP_WS", "ws://h/devtools/browser/x")
    stop = threading.Event()
    stop.set()
    assert dm.get_ws_url() == dm.get_ws_url(stop) == "ws://h/devtools/browser/x"


# ── cooperative cancellation (real sockets, real threads) ─────────────────────────────────
def _discover_in_thread(monkeypatch, url):
    monkeypatch.setenv("BU_CDP_URL", url)
    monkeypatch.delenv("BU_CDP_WS", raising=False)
    stop, box = threading.Event(), {}

    def worker():
        try:
            box["out"] = dm.get_ws_url(stop)
        except BaseException as e:
            box["out"] = e
        box["done"] = time.monotonic()
    t = threading.Thread(target=worker)
    t.start()
    return stop, t, box


def test_stop_during_retry_pause_returns_promptly_refused(monkeypatch):
    stop, t, box = _discover_in_thread(monkeypatch, f"http://127.0.0.1:{_closed_port()}")
    time.sleep(0.5)
    set_at = time.monotonic()
    stop.set()
    t.join(5)
    assert not t.is_alive()
    assert box["done"] - set_at < 0.3
    assert isinstance(box["out"], dm.EndpointDiscoveryCancelled)


def test_stop_during_blackhole_request_is_bounded_by_its_timeout(monkeypatch):
    with _Blackhole() as bh:
        stop, t, box = _discover_in_thread(monkeypatch, f"http://127.0.0.1:{bh.port}")
        time.sleep(0.5)  # inside the first 5 s urlopen
        set_at = time.monotonic()
        stop.set()
        t.join(10)
    assert not t.is_alive()
    assert box["done"] - set_at < 5.5  # at most the in-flight request's own timeout
    assert isinstance(box["out"], dm.EndpointDiscoveryCancelled)


def test_stop_already_set_makes_no_request(monkeypatch):
    calls = []
    monkeypatch.setattr(dm.urllib.request, "urlopen", lambda *a, **k: calls.append(a))
    monkeypatch.setenv("BU_CDP_URL", "http://127.0.0.1:9")
    monkeypatch.delenv("BU_CDP_WS", raising=False)
    stop = threading.Event()
    stop.set()
    with pytest.raises(dm.EndpointDiscoveryCancelled):
        dm.get_ws_url(stop)
    assert calls == []


def test_local_discovery_is_cancellable(monkeypatch, tmp_path):
    """Local-profile branch: each poll iteration also honours ``stop``."""
    monkeypatch.delenv("BU_CDP_URL", raising=False)
    monkeypatch.delenv("BU_CDP_WS", raising=False)
    monkeypatch.setattr(dm, "PROFILES", [tmp_path])
    monkeypatch.setattr(dm, "supported_browser_running", lambda: True)
    monkeypatch.setattr(dm, "remote_debugging_toggle_profiles", lambda: [tmp_path])
    stop, box = threading.Event(), {}

    def worker():
        try:
            box["out"] = dm.get_ws_url(stop)
        except BaseException as e:
            box["out"] = e
    t = threading.Thread(target=worker)
    t.start()
    time.sleep(0.5)
    stop.set()
    t.join(2)
    assert not t.is_alive() and isinstance(box["out"], dm.EndpointDiscoveryCancelled)


# ── wiring: only the reconnect path is cancellable; cold start is unchanged ────────────────
def test_cold_start_calls_get_ws_url_without_stop(monkeypatch):
    seen = []

    def fake(*a, **k):
        seen.append((a, k))
        raise RuntimeError("stop here")
    monkeypatch.setattr(dm, "get_ws_url", fake)
    d = dm.Daemon()
    with pytest.raises(RuntimeError, match="stop here"):
        dm.asyncio.run(d.start())
    assert seen == [((), {})]


def test_reconnect_passes_the_daemon_stop_event(monkeypatch):
    seen = []

    def fake(*a, **k):
        seen.append(a)
        return "ws://127.0.0.1:1/devtools/browser/x"

    class _C:
        def __init__(self, url):
            self.url = url

        async def start(self):
            return None
    monkeypatch.setattr(dm, "get_ws_url", fake)
    monkeypatch.setattr(dm, "CDPClient", _C)
    monkeypatch.setattr(dm, "_PatientCDPClient", _C)
    d = dm.Daemon()
    dm.asyncio.run(d._new_cdp_client())
    assert seen == [(d._ws_url_stop,)] and not d._ws_url_stop.is_set()


# ── end to end: serve() shutdown while a reconnect worker is inside get_ws_url ─────────────
_PROGRAM = textwrap.dedent("""
    import asyncio, threading, time, sys
    import browser_harness.daemon as dm
    d = dm.Daemon()
    marks = {}
    async def main():
        d.stop = asyncio.Event()
        async def reconnect():
            try:
                await d._new_cdp_client()          # production call: to_thread(get_ws_url, stop)
            except BaseException:
                pass
        task = asyncio.create_task(reconnect())
        async def shutdown_soon():
            await asyncio.sleep(1.5)                # worker is now inside get_ws_url
            marks["shutdown"] = time.monotonic()
            d.stop.set()                            # what meta=shutdown does
        asyncio.create_task(shutdown_soon())
        await dm.serve(d)
        task.cancel()                               # like the policy watcher cancel
    asyncio.run(main())                             # joins the default executor here
    marks["exited"] = time.monotonic()
    print("EXIT_AFTER_SHUTDOWN", round(marks["exited"] - marks["shutdown"], 3))
    print("THREADS", sorted(t.name for t in threading.enumerate()))
""")


def _serve_shutdown(tmp_path, cdp_url, timeout):
    env = dict(os.environ, PYTHONPATH=SRC, BU_CDP_URL=cdp_url, BU_NAME="cancel-test",
               BH_RUNTIME_DIR=str(tmp_path / "rt"), BH_HOME=str(tmp_path / "home"),
               BH_AGENT_WORKSPACE=str(tmp_path / "ws"))
    for k in ("BU_CDP_WS", "BH_CDP_POLICY"):
        env.pop(k, None)
    for d in ("rt", "home", "ws"):
        (tmp_path / d).mkdir(mode=0o700)
    t = time.monotonic()
    r = subprocess.run([sys.executable, "-c", _PROGRAM], env=env, cwd=tmp_path, capture_output=True,
                       text=True, timeout=timeout)
    return r, time.monotonic() - t


def _exit_after(r):
    line = next(x for x in r.stdout.splitlines() if x.startswith("EXIT_AFTER_SHUTDOWN"))
    return float(line.split()[1])


def test_serve_shutdown_is_not_held_by_reconnect_worker_refused(tmp_path):
    r, _ = _serve_shutdown(tmp_path, f"http://127.0.0.1:{_closed_port()}", timeout=20)
    assert r.returncode == 0, r.stderr[-800:]
    assert _exit_after(r) < 1.5, r.stdout             # was: the rest of the ~30 s window
    assert "THREADS ['MainThread']" in r.stdout       # no worker thread left behind


def test_serve_shutdown_is_bounded_by_one_request_blackhole(tmp_path):
    with _Blackhole() as bh:
        r, _ = _serve_shutdown(tmp_path, f"http://127.0.0.1:{bh.port}", timeout=25)
    assert r.returncode == 0, r.stderr[-800:]
    assert _exit_after(r) < 5.5, r.stdout             # <= the in-flight request's 5 s timeout
    assert "THREADS ['MainThread']" in r.stdout
