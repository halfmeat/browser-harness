"""BH_CDP_POLICY=v1: selector, startup contract, allowlist (policy core)."""
import asyncio

import pytest

import browser_harness.cdp_policy as cp

from .policy_harness import FakeBrowser, make_policy_daemon, meta, model, new_loop, run


@pytest.fixture(autouse=True)
def _loop():
    loop = new_loop()
    try:
        yield loop
    finally:
        loop.close()
        asyncio.set_event_loop(None)


@pytest.mark.parametrize("raw,expected", [(None, None), ("", None), ("v1", "v1")])
def test_selector_accepts_only_unset_empty_or_v1(raw, expected):
    assert cp.resolve_selector(raw) == expected


@pytest.mark.parametrize("raw", ["V1", "v2", "1", "true", " v1", "off"])
def test_selector_rejects_anything_else(raw):
    with pytest.raises(cp.PolicyConfigError):
        cp.resolve_selector(raw)


def test_startup_order_and_ownership():
    d = make_policy_daemon()
    m = d.cdp.methods()
    assert m[:3] == ["Target.createBrowserContext", "Browser.setDownloadBehavior",
                     "Target.setDiscoverTargets"]
    assert m.index("Target.createTarget") < m.index("Target.attachToTarget") < m.index("Page.enable")
    _m, deny, _s = d.cdp.calls[1]
    assert deny == {"behavior": "deny", "browserContextId": "CTX-HERMES", "eventsEnabled": True}
    reg = d.policy.registry
    assert reg.current_target_id == "T1" and reg.current_pair_valid()
    assert meta(d, "ping")["policy"]["ready"] is True


def test_startup_never_attaches_a_preexisting_foreign_page():
    b = FakeBrowser()
    b.add_target("USER", "page", "https://bank.example/", "DEFAULT")
    d = make_policy_daemon(b)
    attached = [p["targetId"] for m, p, _s in b.calls if m == "Target.attachToTarget"]
    assert attached == ["T1"]
    assert not d.policy.registry.target_owned("USER")


def test_unlisted_method_denied_with_zero_send():
    d = make_policy_daemon()
    before = len(d.cdp.calls)
    r = model(d, "Browser.setDownloadBehavior", {"behavior": "allow"})
    assert r["error"].startswith("policy:")
    assert len(d.cdp.calls) == before


def test_unknown_meta_denied():
    d = make_policy_daemon()
    assert "error" in run(d.handle({"meta": "eval_anything"}))


# ── NON-BLOCKING: unexpected errors become a controlled DENY ────────────────
@pytest.mark.parametrize("exc", [KeyError("secret-key"), TypeError("x"), RecursionError(), ValueError()])
def test_validator_exception_is_controlled_deny_with_zero_send(monkeypatch, exc):
    def broken(_params, _reg):
        raise exc
    monkeypatch.setitem(cp._VALIDATORS, "Runtime.evaluate", broken)
    d = make_policy_daemon()
    n = len(d.cdp.calls)
    r = model(d, "Runtime.evaluate", {"expression": "1"})
    assert r == {"error": f"policy: invalid request ({type(exc).__name__})"}
    assert len(d.cdp.calls) == n


def test_unexpected_engine_error_is_controlled_deny_with_zero_model_send(monkeypatch):
    d = make_policy_daemon()

    async def broken(*_a, **_k):
        raise AttributeError("internal detail")
    monkeypatch.setattr(d.policy, "refresh_target", broken)
    r = model(d, "Runtime.evaluate", {"expression": "1"})
    assert r == {"error": "policy: request denied (internal error)"}
    assert d.cdp.count("Runtime.evaluate") == 0


@pytest.mark.parametrize("req", [
    {"method": 5}, {"method": None}, {}, {"method": "Runtime.evaluate", "params": [1]},
    {"method": "Runtime.evaluate", "params": {"expression": "1"}, "session_id": 3},
])
def test_malformed_requests_denied_with_zero_send(req):
    d = make_policy_daemon()
    n = len(d.cdp.calls)
    assert "error" in run(d.handle(req))
    assert len(d.cdp.calls) == n
