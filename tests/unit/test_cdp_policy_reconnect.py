"""Reconnect / recovery: a lost CDP connection makes the policy not-ready at once;
ready returns only after a FULL policy reinstall on the new connection (new
generation, new Hermes context, download-deny, discovery, owned page/session,
critical Page monitoring). Nothing from the old generation stays owned and no
foreign tab is ever adopted."""
import asyncio

import pytest

import browser_harness.daemon as daemon_mod

from .policy_harness import FakeBrowser, make_policy_daemon, meta, model, new_loop, run

STARTUP = ["Target.createBrowserContext", "Browser.setDownloadBehavior", "Target.setDiscoverTargets",
           "Target.createTarget", "Target.getTargetInfo", "Target.attachToTarget", "Page.enable"]


@pytest.fixture(autouse=True)
def _loop():
    loop = new_loop()
    try:
        yield loop
    finally:
        loop.close()
        asyncio.set_event_loop(None)


@pytest.fixture(autouse=True)
def _fast_backoff(monkeypatch):
    real = asyncio.sleep

    async def fast(_delay, *a, **k):
        await real(0)
    monkeypatch.setattr(daemon_mod.asyncio, "sleep", fast)


def _new_browser(d, monkeypatch, tid_prefix="N", **fail):
    b2 = FakeBrowser(ctx_prefix="CTX-NEW", tid_prefix=tid_prefix, sid_prefix=f"{tid_prefix}S")
    b2.add_target("USER", "page", "https://bank.example/", "DEFAULT")
    b2.fail.update(fail)
    b2._message_handler_task = asyncio.get_event_loop().create_future()  # stays connected
    seen = []

    async def sample(_p, _s):
        a = d.policy.attestation(live_state=True)  # even a "live" claim cannot make it ready
        seen.append((a["ready"], d.policy.registry.infrastructure_ok()))
    for m in STARTUP:
        b2.hooks[m] = sample

    async def factory():
        return b2
    monkeypatch.setattr(d, "_new_cdp_client", factory)
    return b2, seen


def _drop_connection(d):
    """Run the production watcher and kill the first connection."""
    lost = asyncio.get_event_loop().create_future()
    d.cdp._message_handler_task = lost
    d._policy_watch = asyncio.get_event_loop().create_task(d._watch_policy_connection())
    run(asyncio.sleep(0))
    lost.set_result(None)


def _until(pred):
    async def wait():
        for _ in range(500):
            if pred():
                return
            await asyncio.sleep(0)
        raise AssertionError("condition not reached")
    run(wait())


def _stop_watch(d):
    d._shutting_down = True
    d._policy_watch.cancel()
    run(asyncio.gather(d._policy_watch, return_exceptions=True))


def test_full_reinstall_before_ready(monkeypatch):
    d = make_policy_daemon()
    b1 = d.cdp
    b2, seen = _new_browser(d, monkeypatch)
    _drop_connection(d)
    _until(lambda: d.policy.registry.generation == 2 and d.policy.registry.initial_ready)
    reg = d.policy.registry
    assert seen and all(r is False and i is False for r, i in seen)  # never ready mid-reinstall
    assert [m for m in b2.methods() if m in STARTUP][:3] == STARTUP[:3]
    deny = [p for m, p, _s in b2.calls if m == "Browser.setDownloadBehavior"]
    assert deny == [{"behavior": "deny", "browserContextId": "CTX-NEW", "eventsEnabled": True}]
    assert reg.generation == 2 and reg.browser_context_id == "CTX-NEW"
    assert reg.is_revoked("T1") and not reg.session_owned("S1")      # stale registry invalidated
    attached = [p["targetId"] for m, p, _s in b2.calls if m == "Target.attachToTarget"]
    assert attached == ["N1"] and b2.targets["N1"]["browserContextId"] == "CTX-NEW"
    assert (reg.current_target_id, reg.current_session_id) == ("N1", "NS1") == (d.target_id, d.session)
    assert ("Target.disposeBrowserContext", {"browserContextId": "CTX-HERMES"}, None) in b2.calls
    assert b1.count("Target.disposeBrowserContext") == 0
    assert meta(d, "ping")["policy"]["ready"] is True
    _stop_watch(d)


def test_stale_id_collision_is_never_adopted(monkeypatch):
    d = make_policy_daemon()
    b2, _seen = _new_browser(d, monkeypatch, tid_prefix="T")
    _drop_connection(d)
    _until(lambda: d.policy.registry.generation == 3 and d.policy.registry.initial_ready)
    reg = d.policy.registry
    # The new browser hands out the old-generation id "T1" first: that attempt
    # fails closed (revoked forever); the retry succeeds on a fresh id.
    assert not reg.target_owned("T1") and reg.current_target_id == "T2"
    assert reg.generation == 3 and reg.browser_context_id == "CTX-NEW-2"
    disposed = [p["browserContextId"] for m, p, _s in b2.calls if m == "Target.disposeBrowserContext"]
    assert disposed == ["CTX-NEW", "CTX-HERMES"]  # failed attempt's context, then the old one
    assert meta(d, "ping")["policy"]["ready"] is True
    _stop_watch(d)


@pytest.mark.parametrize("failing", ["Browser.setDownloadBehavior", "Page.enable", "Target.setDiscoverTargets"])
def test_failed_reinstall_stays_not_ready_without_foreign_fallback(monkeypatch, failing):
    d = make_policy_daemon()
    b2, _seen = _new_browser(d, monkeypatch, **{failing: RuntimeError("boom")})
    _drop_connection(d)
    _until(lambda: d._policy_watch.done())
    reg = d.policy.registry
    assert not reg.connected and not reg.initial_ready and reg.owned_target_ids() == set()
    assert meta(d, "ping")["policy"]["ready"] is False
    assert all(p.get("targetId") != "USER" for m, p, _s in b2.calls if m == "Target.attachToTarget")
    n = len(b2.calls)
    assert "error" in model(d, "Runtime.evaluate", {"expression": "1"})
    assert "error" in model(d, "Runtime.evaluate", {"expression": "1"}, session_id="S1")
    assert len(b2.calls) == n


def test_disconnect_drops_meta_state_immediately():
    d = make_policy_daemon()
    run(d.cdp.emit("Page.javascriptDialogOpening", {"message": "m"}, "S1"))
    run(d.cdp.emit("Runtime.consoleAPICalled", {"args": []}, "S1"))
    d._policy_connection_lost()
    assert meta(d, "ping")["policy"]["ready"] is False
    assert meta(d, "pending_dialog") == {"dialog": None}
    assert meta(d, "drain_events") == {"events": []}
    assert d.session is None and d.target_id is None
