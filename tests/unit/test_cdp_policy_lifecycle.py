"""REQUIRED 2: cascading revoke, lifecycle events, and concurrency. Model flows
re-validate their (generation, session, target) token after EVERY await; a
revocation injected at any await point means DENY with no registry commit."""
import asyncio

import pytest

import browser_harness.cdp_policy as cp

from .policy_harness import announce_iframe, make_policy_daemon, meta, model, new_loop, run

EVAL = {"expression": "1+1"}


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


def _second_page(d):
    tid = model(d, "Target.createTarget", {"url": "about:blank"})["result"]["targetId"]
    sid = model(d, "Target.attachToTarget", {"targetId": tid, "flatten": True})["result"]["sessionId"]
    return tid, sid


# ── lifecycle ────────────────────────────────────────────────────────────────
def test_close_current_page_revokes_everything_tied_to_it(d):
    run(d.cdp.emit("Page.javascriptDialogOpening", {"message": "m"}, "S1"))
    model(d, "Target.closeTarget", {"targetId": "T1"})
    reg = d.policy.registry
    assert reg.is_revoked("T1") and not reg.session_owned("S1")
    assert reg.current_session_id is None and d.session is None and d.dialog is None
    assert "error" in model(d, "Runtime.evaluate", EVAL, session_id="S1")


def test_detach_current_session_keeps_target_but_clears_current(d):
    model(d, "Target.detachFromTarget", {"sessionId": "S1"})
    reg = d.policy.registry
    assert reg.target_owned("T1") and not reg.session_owned("S1") and reg.current_session_id is None
    assert "error" in model(d, "Runtime.evaluate", EVAL)
    sid = model(d, "Target.attachToTarget", {"targetId": "T1", "flatten": True})["result"]["sessionId"]
    assert meta(d, "set_session", session_id=sid, target_id="T1") == {"session_id": sid}
    assert "result" in model(d, "Runtime.evaluate", EVAL)


@pytest.mark.parametrize("event", ["Target.targetDestroyed", "Target.targetCrashed"])
def test_destroyed_parent_cascades_to_iframes(d, event):
    tid, sid = _second_page(d)
    announce_iframe(d, "IF1", parent_frame=tid)
    run(d.cdp.emit(event, {"targetId": tid}))
    reg = d.policy.registry
    assert not reg.target_owned(tid) and not reg.target_owned("IF1") and not reg.session_owned(sid)
    assert reg.target_owned("T1")  # unrelated page untouched


def test_forbidden_frame_navigated_event_revokes_with_children(d):
    announce_iframe(d, "IF1", parent_frame="T1")
    run(d.cdp.emit("Page.frameNavigated", {"frame": {"id": "T1", "url": "chrome-error://chromewebdata/"}}, "S1"))
    reg = d.policy.registry
    assert reg.is_revoked("T1") and reg.is_revoked("IF1")


# ── concurrency ──────────────────────────────────────────────────────────────
def _race(d, hook_method, on_hook, req):
    """Run ``req`` through handle(); when it reaches ``hook_method`` run ``on_hook``."""
    async def hook(_p, _s):
        res = on_hook()
        if asyncio.iscoroutine(res):
            await res
    d.cdp.hooks[hook_method] = hook
    return run(d.handle(req))


@pytest.mark.parametrize("at", ["Target.getTargetInfo", "Page.getFrameTree", "Runtime.evaluate"])
def test_session_call_revoked_at_every_await(d, at):
    r = _race(d, at, lambda: d.policy.registry.revoke_target("T1"),
              {"method": "Runtime.evaluate", "params": EVAL})
    assert "error" in r and "result" not in r
    if at != "Runtime.evaluate":
        assert d.cdp.count("Runtime.evaluate") == 0


@pytest.mark.parametrize("at", ["Target.getTargetInfo", "Page.getFrameTree", "Target.attachToTarget"])
def test_attach_revoked_at_every_await(d, at):
    r = _race(d, at, lambda: d.policy.registry.revoke_target("T1"),
              {"method": "Target.attachToTarget", "params": {"targetId": "T1", "flatten": True}})
    assert "error" in r
    assert d.policy.registry.session_for_target("T1") is None
    if at == "Target.attachToTarget":  # browser made a session: trusted cleanup detaches it
        assert d.cdp.methods()[-1] == "Target.detachFromTarget"


@pytest.mark.parametrize("at", ["Target.createTarget", "Target.getTargetInfo"])
def test_create_target_across_connection_loss_is_discarded(d, at):
    r = _race(d, at, d._policy_connection_lost,
              {"method": "Target.createTarget", "params": {"url": "about:blank"}})
    assert "error" in r
    assert d.policy.registry.owned_target_ids() == set()
    assert d.cdp.methods()[-1] == "Target.closeTarget"


@pytest.mark.parametrize("at", ["Target.getTargetInfo", "Page.getFrameTree", "Page.enable"])
def test_set_session_revoked_at_every_await(d, at):
    tid, sid = _second_page(d)
    r = _race(d, at, lambda: d.policy.registry.revoke_target(tid),
              {"meta": "set_session", "session_id": sid, "target_id": tid})
    assert "error" in r
    assert d.policy.registry.current_session_id == "S1"


def test_concurrent_close_vs_evaluate_discards_result(d):
    async def scenario():
        gate = asyncio.Event()

        async def slow_eval(_p, _s):
            await gate.wait()
        d.cdp.hooks["Runtime.evaluate"] = slow_eval
        ev = asyncio.create_task(d.handle({"method": "Runtime.evaluate", "params": EVAL}))
        while d.cdp.count("Runtime.evaluate") == 0:
            await asyncio.sleep(0)
        d.cdp.hooks.pop("Runtime.evaluate")
        closed =await d.handle({"method": "Target.closeTarget", "params": {"targetId": "T1"}})
        d.cdp.sessions["S1"] = "T1"  # browser still answers the in-flight call
        gate.set()
        return closed, await ev
    closed, ev = run(scenario())
    assert "result" in closed
    assert "error" in ev and "discarded" in ev["error"]


def test_concurrent_revoke_vs_attach_never_registers_session(d):
    tid, _sid = _second_page(d)
    model(d, "Target.detachFromTarget", {"sessionId": _sid})
    r = _race(d, "Target.attachToTarget",
              lambda: d.cdp.emit("Target.targetDestroyed", {"targetId": tid}),
              {"method": "Target.attachToTarget", "params": {"targetId": tid, "flatten": True}})
    assert "error" in r and d.policy.registry.session_for_target(tid) is None
    assert d.cdp.methods()[-1] == "Target.detachFromTarget"


def test_stale_generation_close_does_not_mutate_new_generation(d):
    tid, _sid = _second_page(d)
    reg = d.policy.registry

    def new_gen():
        reg.begin_generation("CTX-2")
        reg.add_page("T-NEW", "about:blank")
    r = _race(d, "Target.closeTarget", new_gen,
              {"method": "Target.closeTarget", "params": {"targetId": tid}})
    assert "result" in r
    assert reg.generation == 2 and reg.target_owned("T-NEW") and not reg.is_revoked("T-NEW")
    assert not reg.is_revoked(tid)  # old-gen close result never applied to the new generation


def test_dialog_handling_not_blocked_by_inflight_evaluate(d):
    async def scenario():
        dismissed = asyncio.Event()

        async def alert_blocks(_p, _s):
            await dismissed.wait()

        async def dismiss(_p, _s):
            dismissed.set()
        d.cdp.hooks["Runtime.evaluate"] = alert_blocks
        d.cdp.hooks["Page.handleJavaScriptDialog"] = dismiss
        ev = asyncio.create_task(d.handle({"method": "Runtime.evaluate", "params": {"expression": "alert(1)"}}))
        while d.cdp.count("Runtime.evaluate") == 0:
            await asyncio.sleep(0)
        dlg = await asyncio.wait_for(d.handle({"method": "Page.handleJavaScriptDialog",
                                               "params": {"accept": True}}), 2)
        return dlg, await asyncio.wait_for(ev, 2)
    dlg, ev = run(scenario())
    assert "result" in dlg and "result" in ev


# ── Round 3: close / detach run the same trusted live refresh first ──────────
def _break(d, how, tid="T1", sid="S1"):
    if how == "forbidden":
        d.cdp.set_url(tid, "file:///etc/passwd")  # silent, no event
    elif how == "contradictory":
        d.cdp.frame_overrides[sid] = {"frame": {"id": "OTHER", "url": "about:blank"}}
    elif how == "timeout":
        cp.TRUSTED_TIMEOUT = 0.05

        async def hang(_p, _s):
            await asyncio.sleep(1)
        d.cdp.hooks["Target.getTargetInfo"] = hang


@pytest.fixture
def restore_timeout():
    saved = cp.TRUSTED_TIMEOUT
    yield
    cp.TRUSTED_TIMEOUT = saved


@pytest.mark.parametrize("how", ["forbidden", "contradictory", "timeout"])
@pytest.mark.parametrize("method,params", [
    ("Target.closeTarget", {"targetId": "T1"}),
    ("Target.detachFromTarget", {"sessionId": "S1"}),
])
def test_close_and_detach_denied_before_send_on_bad_live_state(d, restore_timeout, how, method, params):
    _break(d, how)
    n = d.cdp.count(method)
    r = model(d, method, params)
    assert "error" in r, r
    assert d.cdp.count(method) == n  # zero model-origin close/detach
    assert "T1" in d.cdp.targets and "S1" in d.cdp.sessions
    reg = d.policy.registry
    if how == "timeout":
        assert reg.target_owned("T1") and reg.session_owned("S1")  # fail closed, no revoke
    else:
        assert reg.is_revoked("T1") and not reg.session_owned("S1")


def test_detach_of_iframe_session_refreshes_its_root_page(d):
    announce_iframe(d, "IF1", parent_frame="T1")
    s = model(d, "Target.attachToTarget", {"targetId": "IF1", "flatten": True})["result"]["sessionId"]
    d.cdp.set_url("T1", "chrome://settings/")
    n = d.cdp.count("Target.detachFromTarget")
    assert "error" in model(d, "Target.detachFromTarget", {"sessionId": s})
    assert d.cdp.count("Target.detachFromTarget") == n
    assert d.policy.registry.is_revoked("IF1")


def test_valid_close_and_detach_still_work_with_correct_cleanup(d):
    tid = model(d, "Target.createTarget", {"url": "about:blank"})["result"]["targetId"]
    sid = model(d, "Target.attachToTarget", {"targetId": tid, "flatten": True})["result"]["sessionId"]
    sid2 = model(d, "Target.attachToTarget", {"targetId": tid, "flatten": True})["result"]["sessionId"]
    assert "result" in model(d, "Target.detachFromTarget", {"sessionId": sid})
    reg = d.policy.registry
    assert not reg.session_owned(sid) and reg.session_owned(sid2) and reg.target_owned(tid)
    assert reg.current_session_id == "S1"
    i = d.cdp.methods().index("Target.detachFromTarget")
    assert d.cdp.methods()[i - 2:i] == ["Target.getTargetInfo", "Page.getFrameTree"]
    assert "result" in model(d, "Target.closeTarget", {"targetId": tid})
    assert reg.is_revoked(tid) and not reg.session_owned(sid2)
