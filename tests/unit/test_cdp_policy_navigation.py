"""Live navigation defect: right after Page.navigate, live Chromium briefly reports
Target.getTargetInfo.url == "" while Page.getFrameTree already holds the new URL.

Owner decision: an empty TargetInfo.url is a TRANSIENT UNKNOWN — neither a safe
URL nor proof of a contradiction. The trusted refresh re-reads it with a bounded
async backoff; a non-empty URL gets the unchanged strict checks; a URL still empty
at the end of the budget is a DENY with NO revoke (the page stays owned). The
frame tree alone never authorizes an action."""
import asyncio
import time

import pytest

import browser_harness.cdp_policy as cp
from browser_harness import daemon as daemon_mod

from .policy_harness import make_policy_daemon, meta, model, new_loop, run

EVAL = {"expression": "1+1"}
FINAL = "http://127.0.0.1:8000/page.html?n=1"
OTHER = "http://127.0.0.1:8000/elsewhere.html"


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


def _frame(d, url, sid="S1", tid="T1"):
    """Live frame tree already on the new URL (what Chromium shows mid-navigation)."""
    d.cdp.frame_overrides[sid] = {"frame": {"id": tid, "url": url, "loaderId": "L"}}


def _url_sequence(d, urls, tid="T1"):
    """Successive trusted Target.getTargetInfo reads of ``tid`` return ``urls`` in
    order (the last one repeats). Returns the list of URLs actually served."""
    seq, served = list(urls), []

    async def hook(params, _sid):
        if params.get("targetId") == tid:
            d.cdp.set_url(tid, seq.pop(0) if len(seq) > 1 else seq[0])
            served.append(d.cdp.targets[tid]["url"])
    d.cdp.hooks["Target.getTargetInfo"] = hook
    return served


def _infos(d, since=0):
    return [m for m, _p, _s in d.cdp.calls[since:] if m == "Target.getTargetInfo"]


# ── A: transient empty → safe ────────────────────────────────────────────────
def test_transient_empty_then_safe_passes_without_revoke(d):
    _frame(d, FINAL)
    served = _url_sequence(d, ["", "", FINAL])
    n = len(d.cdp.calls)
    r = model(d, "Runtime.evaluate", EVAL)
    assert r == {"result": {"ok": "Runtime.evaluate"}}
    assert served == ["", "", FINAL]
    reg = d.policy.registry
    assert reg.target_owned("T1") and not reg.is_revoked("T1")
    assert reg.target_url("T1") == FINAL
    # the frame tree is consulted only once TargetInfo.url is known, then the action
    assert d.cdp.methods()[n:] == ["Target.getTargetInfo"] * 3 + ["Page.getFrameTree", "Runtime.evaluate"]


def test_transient_empty_then_safe_navigate_then_evaluate_flow(d):
    """helpers' goto_url → wait_for_load sequence: navigate, then the very next action."""
    assert "result" in model(d, "Page.navigate", {"url": FINAL})
    _frame(d, FINAL)
    _url_sequence(d, ["", FINAL])
    r = model(d, "Runtime.evaluate", {"expression": "document.readyState", "returnByValue": True})
    assert "result" in r and not d.policy.registry.is_revoked("T1")
    assert d.cdp.count("Runtime.evaluate") == 1


# ── B: empty until the budget ends → DENY, NOT revoked ───────────────────────
def test_empty_until_timeout_denies_without_revoke_and_recovers_later(d):
    _frame(d, FINAL)
    d.cdp.set_url("T1", "")
    n = len(d.cdp.calls)
    r = model(d, "Runtime.evaluate", EVAL)
    assert "error" in r and "transient" in r["error"], r
    assert d.cdp.count("Runtime.evaluate") == 0          # zero model-origin send_raw
    assert "Page.getFrameTree" not in d.cdp.methods()[n:]  # frame tree is not an authority
    assert len(_infos(d, n)) == 1 + len(cp.EMPTY_URL_RETRY_DELAYS)
    reg = d.policy.registry
    assert reg.target_owned("T1") and not reg.is_revoked("T1")
    assert reg.session_owned("S1") and reg.current_pair_valid()
    assert reg.target_url("T1") != ""                     # empty URL never recorded
    # TargetInfo.url arrives later → the next action refreshes and proceeds
    d.cdp.set_url("T1", FINAL)
    assert model(d, "Runtime.evaluate", EVAL) == {"result": {"ok": "Runtime.evaluate"}}
    assert d.cdp.count("Runtime.evaluate") == 1


@pytest.mark.parametrize("method, params", [
    ("Page.navigate", {"url": OTHER}),
    ("Page.captureScreenshot", {}),
    ("Input.insertText", {"text": "x"}),
    ("Page.handleJavaScriptDialog", {"accept": True}),   # frames=False path
])
def test_empty_until_timeout_denies_every_session_action(d, method, params):
    _frame(d, FINAL)
    d.cdp.set_url("T1", "")
    r = model(d, method, params)
    assert "error" in r and "transient" in r["error"], r
    assert d.cdp.count(method) == 0
    assert not d.policy.registry.is_revoked("T1")


def test_empty_until_timeout_target_level_ops_deny_without_revoke(d):
    tid = model(d, "Target.createTarget", {"url": "about:blank"})["result"]["targetId"]
    d.cdp.set_url(tid, "")
    for method in ("Target.activateTarget", "Target.closeTarget"):
        r = model(d, method, {"targetId": tid})
        assert "error" in r and "transient" in r["error"], r
        assert d.cdp.count(method) == 0
    r = model(d, "Target.attachToTarget", {"targetId": tid, "flatten": True})
    assert "error" in r and d.cdp.count("Target.attachToTarget") == 1  # only the startup attach
    assert d.policy.registry.target_owned(tid)


def test_empty_url_hides_page_from_get_targets_without_revoke(d):
    d.cdp.set_url("T1", "")
    r = model(d, "Target.getTargets", {})
    assert r["result"]["targetInfos"] == []
    assert not d.policy.registry.is_revoked("T1")
    d.cdp.set_url("T1", "about:blank")
    r = model(d, "Target.getTargets", {})
    assert [t["targetId"] for t in r["result"]["targetInfos"]] == ["T1"]


def test_ping_not_ready_while_empty_then_ready_without_revoke(d):
    d.cdp.set_url("T1", "")
    assert meta(d, "ping")["policy"]["ready"] is False
    assert not d.policy.registry.is_revoked("T1")
    d.cdp.set_url("T1", "about:blank")
    assert meta(d, "ping")["policy"]["ready"] is True


def test_retry_budget_fits_inside_ping_live_timeout():
    assert cp.EMPTY_URL_RETRY_BUDGET < daemon_mod._PING_LIVE_TIMEOUT
    assert sum(cp.EMPTY_URL_RETRY_DELAYS) <= cp.EMPTY_URL_RETRY_BUDGET


# ── C: empty → forbidden → permanent revoke ──────────────────────────────────
@pytest.mark.parametrize("bad", ["file:///etc/passwd", "chrome-error://chromewebdata/", "about:blank#x"])
def test_empty_then_forbidden_revokes(d, bad):
    _frame(d, bad)  # frame tree agrees, so the forbidden-URL rule itself decides
    _url_sequence(d, ["", bad])
    r = model(d, "Runtime.evaluate", EVAL)
    assert r == {"error": "policy: forbidden or malformed active URL"}
    assert d.cdp.count("Runtime.evaluate") == 0
    assert d.policy.registry.is_revoked("T1")
    d.cdp.hooks.clear()
    d.cdp.set_url("T1", FINAL)
    _frame(d, FINAL)
    assert "error" in model(d, "Runtime.evaluate", EVAL)  # permanent
    assert d.cdp.count("Runtime.evaluate") == 0


def test_empty_then_forbidden_revokes_on_dialog_path(d):
    _url_sequence(d, ["", "file:///etc/passwd"])
    r = model(d, "Page.handleJavaScriptDialog", {"accept": True})
    assert r == {"error": "policy: forbidden or malformed active URL"}
    assert d.cdp.count("Page.handleJavaScriptDialog") == 0
    assert d.policy.registry.is_revoked("T1")


# ── D: empty → contradictory → permanent revoke ──────────────────────────────
def test_empty_then_contradictory_url_revokes(d):
    _frame(d, FINAL)
    _url_sequence(d, ["", OTHER])  # safe on its own, but contradicts the frame tree
    r = model(d, "Runtime.evaluate", EVAL)
    assert r == {"error": "policy: contradictory top-level URL"}
    assert d.cdp.count("Runtime.evaluate") == 0
    assert d.policy.registry.is_revoked("T1")


@pytest.mark.parametrize("change", [
    {"browserContextId": "DEFAULT"}, {"type": "other"}, {"targetId": "T9"}, {"url": 7}, {"url": None},
])
def test_empty_then_contradictory_target_state_revokes(d, change):
    _frame(d, FINAL)
    reads = []

    async def hook(params, _sid):
        reads.append(1)
        if len(reads) == 1:
            d.cdp.set_url("T1", "")
        else:
            d.cdp.targets["T1"] = {**d.cdp.targets["T1"], "url": FINAL, **change}
    d.cdp.hooks["Target.getTargetInfo"] = hook
    assert "error" in model(d, "Runtime.evaluate", EVAL)
    assert len(reads) == 2
    assert d.cdp.count("Runtime.evaluate") == 0
    assert d.policy.registry.is_revoked("T1")


def test_empty_url_with_contradictory_identity_revokes_immediately(d):
    """The identity check is NOT relaxed for an empty URL: no retry, revoke."""
    d.cdp.targets["T1"] = {**d.cdp.targets["T1"], "url": "", "browserContextId": "DEFAULT"}
    n = len(d.cdp.calls)
    assert model(d, "Runtime.evaluate", EVAL) == {"error": "policy: contradictory target state"}
    assert len(_infos(d, n)) == 1
    assert d.policy.registry.is_revoked("T1")


# ── E: existing normal case unchanged ────────────────────────────────────────
def test_non_empty_matching_url_single_read_no_retry(d, monkeypatch):
    slept = []
    real_sleep = asyncio.sleep

    async def spy(delay, *a, **k):
        slept.append(delay)
        return await real_sleep(delay, *a, **k)
    monkeypatch.setattr(cp.asyncio, "sleep", spy)
    d.cdp.set_url("T1", FINAL)
    n = len(d.cdp.calls)
    assert model(d, "Runtime.evaluate", EVAL) == {"result": {"ok": "Runtime.evaluate"}}
    assert d.cdp.methods()[n:] == ["Target.getTargetInfo", "Page.getFrameTree", "Runtime.evaluate"]
    assert slept == []


def test_non_empty_contradictory_url_still_revokes_without_retry(d):
    _frame(d, FINAL)
    d.cdp.set_url("T1", OTHER)
    n = len(d.cdp.calls)
    assert model(d, "Runtime.evaluate", EVAL) == {"error": "policy: contradictory top-level URL"}
    assert len(_infos(d, n)) == 1
    assert d.policy.registry.is_revoked("T1")


# ── F: bounded in attempts and time; async (event loop stays live) ──────────
def test_retry_attempts_bounded(d):
    d.cdp.set_url("T1", "")
    n = len(d.cdp.calls)
    model(d, "Runtime.evaluate", EVAL)
    assert len(_infos(d, n)) == 1 + len(cp.EMPTY_URL_RETRY_DELAYS) == 5


def test_retry_time_bounded_by_budget_even_with_long_delays(d, monkeypatch):
    monkeypatch.setattr(cp, "EMPTY_URL_RETRY_DELAYS", (10.0, 10.0, 10.0))
    monkeypatch.setattr(cp, "EMPTY_URL_RETRY_BUDGET", 0.05)
    d.cdp.set_url("T1", "")
    t = time.monotonic()
    r = model(d, "Runtime.evaluate", EVAL)
    assert time.monotonic() - t < 1.0
    assert "error" in r and not d.policy.registry.is_revoked("T1")


def test_retry_read_that_hangs_is_cut_by_budget_not_trusted_timeout(d, monkeypatch):
    monkeypatch.setattr(cp, "EMPTY_URL_RETRY_BUDGET", 0.05)
    d.cdp.set_url("T1", "")
    reads = []

    async def hook(_p, _s):
        reads.append(1)
        if len(reads) > 1:
            await asyncio.sleep(30)  # a retry read that never answers in time
    d.cdp.hooks["Target.getTargetInfo"] = hook
    t = time.monotonic()
    r = model(d, "Runtime.evaluate", EVAL)
    assert time.monotonic() - t < 1.0
    assert "error" in r and d.cdp.count("Runtime.evaluate") == 0
    assert not d.policy.registry.is_revoked("T1")


def test_whole_retry_completes_within_budget_real_clock(d):
    d.cdp.set_url("T1", "")
    t = time.monotonic()
    model(d, "Runtime.evaluate", EVAL)
    assert time.monotonic() - t < cp.EMPTY_URL_RETRY_BUDGET + 0.5


def test_retry_is_async_and_never_uses_time_sleep(d, monkeypatch):
    def forbidden(_s):
        raise AssertionError("time.sleep would block the daemon event loop")
    monkeypatch.setattr(time, "sleep", forbidden)
    d.cdp.set_url("T1", "")
    ticks = []

    async def ticker():
        while True:
            ticks.append(1)
            await asyncio.sleep(0.002)

    async def scenario():
        task = asyncio.create_task(ticker())
        try:
            return await d.handle({"method": "Runtime.evaluate", "params": EVAL})
        finally:
            task.cancel()
    r = run(scenario())
    assert "error" in r and not d.policy.registry.is_revoked("T1")
    assert len(ticks) >= 5  # other loop work progressed during the retry window


# ── ownership change during the retry window ────────────────────────────────
def test_ownership_lost_during_retry_denies_without_resurrecting(d):
    _frame(d, FINAL)
    reads = []

    async def hook(_p, _s):
        reads.append(1)
        if len(reads) == 1:
            d.cdp.set_url("T1", "")
            # the browser reports the target gone while the refresh is sleeping
            asyncio.get_running_loop().call_soon(
                lambda: asyncio.ensure_future(d.cdp.emit("Target.targetDestroyed", {"targetId": "T1"})))
        else:
            d.cdp.set_url("T1", FINAL)
    d.cdp.hooks["Target.getTargetInfo"] = hook
    r = model(d, "Runtime.evaluate", EVAL)
    assert "error" in r and d.cdp.count("Runtime.evaluate") == 0
    assert len(reads) == 1  # no further trusted read for a target no longer owned
    assert not d.policy.registry.target_owned("T1")


def test_empty_url_on_new_target_confirmation_still_rejected(d):
    """createTarget confirmation is unchanged: only an exact about:blank is adopted."""
    async def hook(params, _sid):
        if params.get("targetId") != "T1":
            d.cdp.set_url(params["targetId"], "")
    d.cdp.hooks["Target.getTargetInfo"] = hook
    r = model(d, "Target.createTarget", {"url": "about:blank"})
    assert "error" in r
    assert d.policy.registry.owned_target_ids() == {"T1"}
