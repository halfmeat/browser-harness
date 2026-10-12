"""BLOCKER 2: a TRUSTED refresh of the owned target's live state runs before every
model-facing action; no event is needed for the policy to notice a bad state."""
import asyncio

import pytest

import browser_harness.cdp_policy as cp

from .policy_harness import make_policy_daemon, model, new_loop

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


def _denied_without_send(d, method="Runtime.evaluate", params=EVAL):
    before = d.cdp.count(method)
    r = model(d, method, params)
    assert "error" in r, r
    assert d.cdp.count(method) == before
    return r


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "chrome://settings/", "chrome-error://chromewebdata/",
    "javascript:alert(1)", "data:text/html,x", "about:blank#x", "https://u:p@x.example/",
    "devtools://devtools/bundled/x.html", "view-source:https://x.example/",
])
def test_forbidden_url_without_any_event_denies_next_action(d, url):
    d.cdp.set_url("T1", url)  # silent: no Page.frameNavigated / targetInfoChanged
    _denied_without_send(d)
    assert d.cdp.calls[-1][0] in ("Target.getTargetInfo", "Page.getFrameTree")
    assert d.policy.registry.is_revoked("T1")


def test_revoke_is_permanent_even_after_return_to_safe_url(d):
    d.cdp.set_url("T1", "file:///etc/passwd")
    _denied_without_send(d)
    d.cdp.set_url("T1", "https://ok.example/")
    _denied_without_send(d)
    _denied_without_send(d, "Page.navigate", {"url": "https://ok.example/"})
    assert not d.policy.registry.target_owned("T1")


def test_allowed_live_url_passes_and_is_recorded(d):
    d.cdp.set_url("T1", "https://ok.example/a")
    r = model(d, "Runtime.evaluate", EVAL)
    assert r == {"result": {"ok": "Runtime.evaluate"}}
    assert d.policy.registry.target_url("T1") == "https://ok.example/a"
    i = d.cdp.methods().index("Runtime.evaluate")
    assert d.cdp.methods()[i - 2:i] == ["Target.getTargetInfo", "Page.getFrameTree"]


def test_fragment_split_between_target_and_frame_is_consistent(d):
    d.cdp.set_url("T1", "https://ok.example/p#sec")
    d.cdp.frame_overrides["S1"] = {"frame": {"id": "T1", "url": "https://ok.example/p", "urlFragment": "#sec"}}
    assert "result" in model(d, "Runtime.evaluate", EVAL)


@pytest.mark.parametrize("info", [
    {"targetId": "T1", "type": "page", "browserContextId": "CTX-HERMES"},               # no url
    {"targetId": "T1", "type": "page", "browserContextId": "CTX-HERMES", "url": 7},     # malformed url
    {"targetId": "T1", "type": "other", "browserContextId": "CTX-HERMES", "url": "about:blank"},
    {"targetId": "T1", "type": "page", "browserContextId": "DEFAULT", "url": "about:blank"},
    {"targetId": "T9", "type": "page", "browserContextId": "CTX-HERMES", "url": "about:blank"},
])
def test_malformed_or_contradictory_target_state_denies_and_revokes(d, info):
    d.cdp.targets["T1"] = info
    _denied_without_send(d)
    assert d.policy.registry.is_revoked("T1")


@pytest.mark.parametrize("tree", [
    {"frame": {"id": "OTHER", "url": "about:blank"}},                     # frame identity
    {"frame": {"id": "T1", "url": "about:blank", "parentId": "P"}},        # not top-level
    {"frame": {"id": "T1", "url": "https://elsewhere.example/"}},          # URL contradicts target
    {"frame": "garbage"},
    "garbage",
])
def test_contradictory_frame_tree_denies_and_revokes(d, tree):
    d.cdp.frame_overrides["S1"] = tree
    _denied_without_send(d)
    assert d.policy.registry.is_revoked("T1")


@pytest.mark.parametrize("method", ["Target.getTargetInfo", "Page.getFrameTree"])
def test_trusted_refresh_error_denies(d, method):
    d.cdp.fail[method] = RuntimeError("boom")
    _denied_without_send(d)


def test_trusted_refresh_timeout_denies(d, monkeypatch):
    monkeypatch.setattr(cp, "TRUSTED_TIMEOUT", 0.05)

    async def hang(_p, _s):
        await asyncio.sleep(1)
    d.cdp.hooks["Target.getTargetInfo"] = hang
    _denied_without_send(d)


def test_dialog_handling_refreshes_without_renderer_frame_tree(d):
    n = len(d.cdp.calls)
    r = model(d, "Page.handleJavaScriptDialog", {"accept": True})
    assert "result" in r
    assert d.cdp.methods()[n:] == ["Target.getTargetInfo", "Page.handleJavaScriptDialog"]
    d.cdp.set_url("T1", "file:///x")
    _denied_without_send(d, "Page.handleJavaScriptDialog", {"accept": False})


# ── Round 3 BLOCKER: Target.getTargets exposes only live-verified owned targets ──
def _second_page(d, attach=True):
    tid = model(d, "Target.createTarget", {"url": "about:blank"})["result"]["targetId"]
    sid = None
    if attach:
        sid = model(d, "Target.attachToTarget", {"targetId": tid, "flatten": True})["result"]["sessionId"]
    return tid, sid


def _listing(d):
    r = model(d, "Target.getTargets", {})
    return {t["targetId"]: t for t in r["result"]["targetInfos"]}


@pytest.mark.parametrize("attach", [True, False])  # with session (frame tree) / target-level only
def test_get_targets_hides_and_revokes_silently_forbidden_owned_page(d, attach):
    tid, sid = _second_page(d, attach)
    d.cdp.set_url(tid, "file:///home/user/secret.txt")  # no event
    listing = _listing(d)
    assert list(listing) == ["T1"] and "secret" not in repr(listing)
    reg = d.policy.registry
    assert reg.is_revoked(tid) and not reg.target_owned(tid)
    n = len(d.cdp.calls)
    assert "error" in model(d, "Target.attachToTarget", {"targetId": tid, "flatten": True})
    assert "error" in model(d, "Target.closeTarget", {"targetId": tid})
    if sid:
        assert "error" in model(d, "Runtime.evaluate", EVAL, session_id=sid)
    assert len(d.cdp.calls) == n  # all denied before any send
    d.cdp.set_url(tid, "https://ok.example/")
    assert tid not in _listing(d)  # revoke is permanent


@pytest.mark.parametrize("mode", ["error", "timeout"])
def test_get_targets_hides_entry_when_trusted_refresh_fails(d, monkeypatch, mode):
    tid, _sid = _second_page(d)
    d.cdp.set_url(tid, "https://stale-secret.example/")
    monkeypatch.setattr(cp, "TRUSTED_TIMEOUT", 0.05)

    async def broken(params, _s):
        if params.get("targetId") == tid:
            if mode == "error":
                raise RuntimeError("cdp error")
            await asyncio.sleep(1)
    d.cdp.hooks["Target.getTargetInfo"] = broken
    listing = _listing(d)
    assert list(listing) == ["T1"] and "stale-secret" not in repr(listing)
    # fail closed without revoke (same invariant as every trusted refresh error)
    assert d.policy.registry.target_owned(tid)


def test_get_targets_keeps_safe_owned_pages_with_live_info(d):
    tid, _sid = _second_page(d)
    d.cdp.set_url(tid, "https://ok.example/now")
    listing = _listing(d)
    assert sorted(listing) == ["T1", tid]
    assert listing[tid]["url"] == "https://ok.example/now"
    assert ("Target.getTargetInfo", {"targetId": tid}, None) in d.cdp.calls


def test_get_targets_refresh_never_registers_or_probes_unowned(d):
    d.cdp.add_target("ROGUE", "page", "https://x.example/", "CTX-HERMES")
    d.cdp.add_target("USER", "page", "https://bank.example/", "DEFAULT")
    d.cdp.add_target("IFX", "iframe", "https://f.example/", "CTX-HERMES", parent_frame="T1")
    owned = d.policy.registry.owned_target_ids()
    n = len(d.cdp.calls)
    assert list(_listing(d)) == ["T1"]
    assert d.policy.registry.owned_target_ids() == owned
    probed = {p.get("targetId") for m, p, _s in d.cdp.calls[n:] if m == "Target.getTargetInfo"}
    assert probed == {"T1"}
