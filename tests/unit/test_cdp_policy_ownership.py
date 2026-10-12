"""BLOCKER 1: ownership never comes from Target.getTargets or model-named ids;
iframes become owned only via the daemon's TRUSTED discovery flow."""
import asyncio

import pytest

from .policy_harness import (FakeBrowser, announce_iframe, make_policy_daemon, model, new_loop,
                             run, settle, visible_ids)


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
    b = FakeBrowser()
    b.add_target("USER", "page", "https://bank.example/", "DEFAULT")
    b.add_target("ROGUE", "page", "https://x.example/", "CTX-HERMES")  # same ctx, never registered
    return make_policy_daemon(b)


def _attach_calls(d, tid):
    return [p for m, p, _s in d.cdp.calls if m == "Target.attachToTarget" and p.get("targetId") == tid]


def test_get_targets_never_grants_ownership(d):
    d.cdp.add_target("IFX", "iframe", "https://f.example/", "CTX-HERMES", parent_frame="T1")
    before = d.policy.registry.snapshot()
    assert visible_ids(d) == ["T1"]
    settle(d)
    assert d.policy.registry.snapshot() == before
    assert d._policy_discovering == {}


def test_unregistered_same_context_page_hidden_and_unattachable(d):
    assert "ROGUE" not in visible_ids(d)
    n = len(d.cdp.calls)
    r = model(d, "Target.attachToTarget", {"targetId": "ROGUE", "flatten": True})
    assert "error" in r and len(d.cdp.calls) == n  # not even a trusted probe
    assert not d.policy.registry.target_owned("ROGUE")


def test_unproven_iframe_hidden_and_unattachable(d):
    d.cdp.add_target("IFX", "iframe", "https://f.example/", "CTX-HERMES", parent_frame="T1")
    assert "IFX" not in visible_ids(d)
    r = model(d, "Target.attachToTarget", {"targetId": "IFX", "flatten": True})
    assert "error" in r and _attach_calls(d, "IFX") == []


def test_trusted_discovery_registers_proven_iframe(d):
    announce_iframe(d, "IF1", parent_frame="T1")
    reg = d.policy.registry
    assert reg.target_type("IF1") == "iframe" and reg.parent_chain("IF1") == ["IF1", "T1"]
    assert ("Target.getTargetInfo", {"targetId": "IF1"}, None) in d.cdp.calls
    assert visible_ids(d) == ["IF1", "T1"]
    r = model(d, "Target.attachToTarget", {"targetId": "IF1", "flatten": True})
    assert reg.target_for_session(r["result"]["sessionId"]) == "IF1"


def test_nested_iframe_via_owned_child_frame_and_owned_iframe(d):
    d.cdp.child_frames["T1"] = ["F-CHILD"]
    announce_iframe(d, "IF1", parent_frame="F-CHILD")
    announce_iframe(d, "IF2", parent_frame="IF1")
    reg = d.policy.registry
    assert reg.parent_chain("IF1") == ["IF1", "T1"]
    assert reg.parent_chain("IF2") == ["IF2", "IF1", "T1"]


@pytest.mark.parametrize("ctx,parent", [
    ("DEFAULT", "T1"),           # foreign browser context
    ("CTX-HERMES", "USER"),      # parent frame is a foreign page
    ("CTX-HERMES", "ROGUE"),     # parent frame is an unregistered same-context page
    ("CTX-HERMES", "NOWHERE"),   # parent frame in no owned frame tree
])
def test_discovery_rejects_unproven_parent_or_context(d, ctx, parent):
    announce_iframe(d, "IFZ", parent_frame=parent, ctx=ctx)
    assert not d.policy.registry.target_owned("IFZ")
    assert "IFZ" not in visible_ids(d)


def test_discovery_rejects_event_contradicted_by_trusted_info(d):
    info = {"targetId": "IFP", "type": "iframe", "browserContextId": "CTX-HERMES", "parentFrameId": "T1"}
    d.cdp.add_target("IFP", "page", "https://p.example/", "CTX-HERMES")  # trusted truth: a page
    run(d.cdp.emit("Target.targetCreated", {"targetInfo": info}))
    settle(d)
    assert not d.policy.registry.target_owned("IFP")


@pytest.mark.parametrize("method", ["Target.closeTarget", "Target.activateTarget"])
@pytest.mark.parametrize("tid", ["USER", "ROGUE", "IFX", "T1-revoked"])
def test_page_ops_on_unowned_targets_denied_with_zero_send(d, method, tid):
    d.cdp.add_target("IFX", "iframe", "https://f.example/", "CTX-HERMES", parent_frame="T1")
    if tid == "T1-revoked":
        tid = "T1"
        d.policy.registry.revoke_target("T1")
    n = len(d.cdp.calls)
    assert "error" in model(d, method, {"targetId": tid})
    assert len(d.cdp.calls) == n and tid in d.cdp.targets


def test_parent_revoke_cascades_to_child_iframes(d):
    announce_iframe(d, "IF1", parent_frame="T1")
    announce_iframe(d, "IF2", parent_frame="IF1")
    s = model(d, "Target.attachToTarget", {"targetId": "IF2", "flatten": True})["result"]["sessionId"]
    model(d, "Target.closeTarget", {"targetId": "T1"})
    reg = d.policy.registry
    assert not reg.target_owned("IF1") and not reg.target_owned("IF2") and not reg.session_owned(s)
    assert reg.is_revoked("IF1") and reg.is_revoked("IF2")
    announce_iframe(d, "IF1", parent_frame="T1")  # re-announce: revoked forever
    assert not reg.target_owned("IF1")
