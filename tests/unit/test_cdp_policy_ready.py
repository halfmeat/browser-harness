"""BLOCKER 3: attestation ``ready`` is derived only from live security invariants
(incl. a trusted live refresh made for that very ping), never a sticky flag."""
import asyncio

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
def d():
    return make_policy_daemon()


def att(d):
    return meta(d, "ping")["policy"]


def test_ready_after_full_startup_with_every_invariant(d):
    a = att(d)
    assert a["ready"] is True
    for k in ("connected", "registry_ready", "hermes_context_ready", "download_deny_installed",
              "monitoring_installed", "management_peer_protection", "current_pair_valid",
              "live_state_verified"):
        assert a[k] is True, k
    assert a["policy_version"] == "v1" and a["connection_generation"] == 1


@pytest.mark.parametrize("failing", ["Page.enable", "Browser.setDownloadBehavior",
                                     "Target.setDiscoverTargets", "Target.createBrowserContext"])
def test_startup_step_failure_is_never_ready(failing):
    b = FakeBrowser()
    b.fail[failing] = RuntimeError("boom")
    d = make_policy_daemon(b, start=False)
    with pytest.raises(Exception):
        run(d._start_policy())
    assert att(d)["ready"] is False
    assert "error" in model(d, "Runtime.evaluate", {"expression": "1"})
    assert b.count("Runtime.evaluate") == 0


def test_detach_current_session_not_ready(d):
    model(d, "Target.detachFromTarget", {"sessionId": "S1"})
    assert att(d)["ready"] is False and att(d)["current_pair_valid"] is False


def test_detached_event_for_current_not_ready(d):
    run(d.cdp.emit("Target.detachedFromTarget", {"sessionId": "S1"}))
    assert att(d)["ready"] is False


def test_close_current_not_ready(d):
    model(d, "Target.closeTarget", {"targetId": "T1"})
    assert att(d)["ready"] is False


def test_destroyed_event_for_current_not_ready(d):
    run(d.cdp.emit("Target.targetDestroyed", {"targetId": "T1"}))
    assert att(d)["ready"] is False


def test_disconnect_not_ready(d):
    d._policy_connection_lost()
    a = att(d)
    assert a["ready"] is False and a["connected"] is False


def test_generation_change_not_ready(d):
    d.policy.registry.begin_generation("CTX-OTHER")
    a = att(d)
    assert a["ready"] is False and a["download_deny_installed"] is False


def test_no_owned_current_pair_not_ready(d):
    d.policy.registry.set_current(None, None)
    assert att(d)["ready"] is False


def test_monitoring_failure_not_ready(d, monkeypatch):
    def broken(*_a):
        raise ValueError("monitor bug")
    monkeypatch.setattr(d.policy, "observe_event", broken)
    run(d.cdp.emit("Page.loadEventFired", {}, "S1"))
    assert att(d)["ready"] is False


def test_silent_forbidden_live_url_not_ready_and_revoked(d):
    d.cdp.set_url("T1", "file:///etc/shadow")
    assert att(d)["ready"] is False
    assert d.policy.registry.is_revoked("T1")


def test_live_check_failure_not_ready_without_revoke(d):
    d.cdp.fail["Target.getTargetInfo"] = RuntimeError("cdp down")
    a = att(d)
    assert a["ready"] is False and a["live_state_verified"] is False
    assert d.policy.registry.target_owned("T1")
    del d.cdp.fail["Target.getTargetInfo"]
    assert att(d)["ready"] is True


def test_live_check_is_full_refresh_without_dialog(d):
    n = len(d.cdp.calls)
    assert att(d)["ready"] is True
    assert d.cdp.methods()[n:] == ["Target.getTargetInfo", "Page.getFrameTree"]


# ── Round 3: ping readiness needs the full frame-tree proof (dialog aside) ───
@pytest.mark.parametrize("tree", [
    {"frame": {"id": "OTHER", "url": "about:blank"}},                  # top frame id differs
    {"frame": {"id": "T1", "url": "file:///etc/passwd"}},             # forbidden frame URL
    {"frame": {"id": "T1", "url": "https://elsewhere.example/"}},       # contradicts TargetInfo
    {"frame": {"id": "T1", "url": "about:blank", "parentId": "X"}},     # not top-level
    {"nope": 1},
])
def test_ping_not_ready_on_contradictory_frame_tree(d, tree):
    d.cdp.frame_overrides["S1"] = tree  # TargetInfo stays safe (about:blank)
    assert att(d)["ready"] is False
    assert d.policy.registry.is_revoked("T1")
    assert att(d)["ready"] is False


def test_ping_not_ready_on_frame_tree_error_without_revoke(d):
    d.cdp.fail["Page.getFrameTree"] = RuntimeError("renderer gone")
    assert att(d)["ready"] is False
    assert d.policy.registry.target_owned("T1")


def test_ping_not_ready_on_frame_tree_timeout(d, monkeypatch):
    monkeypatch.setattr(daemon_mod, "_PING_LIVE_TIMEOUT", 0.05)

    async def hang(_p, _s):
        await asyncio.sleep(1)
    d.cdp.hooks["Page.getFrameTree"] = hang
    assert att(d)["ready"] is False


def _blocked_renderer(d):
    """Page.getFrameTree never answers while a dialog is open (renderer blocked)."""
    async def hang(_p, _s):
        await asyncio.Event().wait()
    d.cdp.hooks["Page.getFrameTree"] = hang


def test_owned_open_alert_uses_degraded_check_and_dialog_stays_handleable(d):
    run(d.cdp.emit("Page.javascriptDialogOpening", {"type": "alert", "message": "hi"}, "S1"))
    _blocked_renderer(d)
    n = len(d.cdp.calls)
    a = run(asyncio.wait_for(d.handle({"meta": "ping"}), 2))["policy"]
    assert a["ready"] is True
    assert d.cdp.methods()[n:] == ["Target.getTargetInfo"]  # no frame-tree call
    assert "result" in model(d, "Page.handleJavaScriptDialog", {"accept": True})
    d.cdp.set_url("T1", "file:///etc/passwd")  # degraded path still enforces the URL
    assert att(d)["ready"] is False and d.policy.registry.is_revoked("T1")


def test_full_frame_check_resumes_after_dialog_closed(d, monkeypatch):
    monkeypatch.setattr(daemon_mod, "_PING_LIVE_TIMEOUT", 0.05)
    run(d.cdp.emit("Page.javascriptDialogOpening", {"type": "alert", "message": "hi"}, "S1"))
    _blocked_renderer(d)
    assert att(d)["ready"] is True
    run(d.cdp.emit("Page.javascriptDialogClosed", {"result": True}, "S1"))
    n = len(d.cdp.calls)
    assert att(d)["ready"] is False  # full check again → frame tree (still hung) → not ready
    assert d.cdp.methods()[n:] == ["Target.getTargetInfo", "Page.getFrameTree"]
    d.cdp.hooks.pop("Page.getFrameTree")
    assert att(d)["ready"] is True


@pytest.mark.parametrize("where", ["foreign", "non_current_owned", "old_generation", "injected_stale"])
def test_foreign_or_stale_dialog_never_enables_degraded_check(d, monkeypatch, where):
    monkeypatch.setattr(daemon_mod, "_PING_LIVE_TIMEOUT", 0.05)
    if where == "foreign":
        run(d.cdp.emit("Page.javascriptDialogOpening", {"message": "x"}, "FOREIGN"))
    elif where == "non_current_owned":
        tid = model(d, "Target.createTarget", {"url": "about:blank"})["result"]["targetId"]
        s2 = model(d, "Target.attachToTarget", {"targetId": tid, "flatten": True})["result"]["sessionId"]
        run(d.cdp.emit("Page.javascriptDialogOpening", {"message": "x"}, s2))
    elif where == "old_generation":
        run(d.cdp.emit("Page.javascriptDialogOpening", {"message": "x"}, "S1"))
        d.dialog_generation -= 1
    else:
        d.dialog, d.dialog_session = {"message": "x"}, "S1"  # never reported by the browser
    d.cdp.frame_overrides["S1"] = {"frame": {"id": "OTHER", "url": "about:blank"}}
    n = len(d.cdp.calls)
    assert att(d)["ready"] is False
    assert "Page.getFrameTree" in d.cdp.methods()[n:]
