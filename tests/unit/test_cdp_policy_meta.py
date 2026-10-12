"""REQUIRED 3: model-safe meta never leaks foreign, revoked or stale state."""
import asyncio
import json

import pytest

from .policy_harness import make_policy_daemon, meta, model, new_loop, run


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


def emit(d, method, params, sid=None):
    run(d.cdp.emit(method, params, sid))


def test_foreign_and_browser_level_events_hidden(d):
    emit(d, "Network.requestWillBeSent", {"request": {"url": "https://bank.example/secret"}}, "FOREIGN")
    emit(d, "Target.targetCreated", {"targetInfo": {"targetId": "USER", "url": "https://bank.example/"}})
    emit(d, "Network.requestWillBeSent", {"request": {"url": "https://ok.example/"}}, "S1")
    out = meta(d, "drain_events")["events"]
    assert [e["session_id"] for e in out] == ["S1"]
    assert "bank.example" not in json.dumps(out)
    assert meta(d, "drain_events")["events"] == []


def test_revoked_session_events_purged_and_not_recorded(d):
    emit(d, "Runtime.consoleAPICalled", {"args": ["before"]}, "S1")
    model(d, "Target.closeTarget", {"targetId": "T1"})
    emit(d, "Runtime.consoleAPICalled", {"args": ["after"]}, "S1")
    assert meta(d, "drain_events")["events"] == []


def test_events_from_previous_generation_never_drained(d):
    # begin_generation() drops sessions without a revoke notification; the
    # drain-time ownership filter is what keeps old-generation events hidden.
    emit(d, "Runtime.consoleAPICalled", {"args": ["old-gen"]}, "S1")
    d.policy.registry.begin_generation("CTX-2")
    assert meta(d, "drain_events")["events"] == []


def test_foreign_dialog_hidden(d):
    emit(d, "Page.javascriptDialogOpening", {"message": "foreign"}, "FOREIGN")
    emit(d, "Page.javascriptDialogOpening", {"message": "browser"})
    assert meta(d, "pending_dialog") == {"dialog": None}
    assert d.dialog is None


def test_foreign_dialog_close_does_not_clear_owned_dialog(d):
    emit(d, "Page.javascriptDialogOpening", {"message": "mine"}, "S1")
    emit(d, "Page.javascriptDialogClosed", {}, "FOREIGN")
    assert meta(d, "pending_dialog")["dialog"] == {"message": "mine"}


def test_revoked_dialog_hidden(d):
    emit(d, "Page.javascriptDialogOpening", {"message": "mine"}, "S1")
    assert meta(d, "pending_dialog")["dialog"] == {"message": "mine"}
    d.cdp.set_url("T1", "file:///etc/passwd")
    assert "error" in model(d, "Runtime.evaluate", {"expression": "1"})
    assert meta(d, "pending_dialog") == {"dialog": None}


def test_stale_current_tab_leaks_nothing(d):
    d.cdp.set_url("T1", "file:///home/user/secret.txt")
    r = meta(d, "current_tab")
    assert set(r) == {"error"} and "secret" not in json.dumps(r)
    model(d, "Target.closeTarget", {"targetId": "T1"})
    n = len(d.cdp.calls)
    r = meta(d, "current_tab")
    assert set(r) == {"error"} and len(d.cdp.calls) == n


def test_current_tab_reports_live_owned_state(d):
    d.cdp.set_url("T1", "https://ok.example/")
    assert meta(d, "current_tab") == {"targetId": "T1", "url": "https://ok.example/", "title": "title-T1"}


def test_stale_session_leaks_nothing(d):
    assert meta(d, "session") == {"session_id": "S1"}
    model(d, "Target.detachFromTarget", {"sessionId": "S1"})
    r = meta(d, "session")
    assert set(r) == {"error"} and "S1" not in json.dumps(r)


@pytest.mark.parametrize("sid,tid", [
    ("FOREIGN", "USER"), ("S1", "USER"), ("FOREIGN", "T1"), (None, "T1"), ("S1", None), (7, "T1"),
])
def test_set_session_rejects_unowned_pairs(d, sid, tid):
    n = len(d.cdp.calls)
    assert "error" in meta(d, "set_session", session_id=sid, target_id=tid)
    assert len(d.cdp.calls) == n and d.policy.registry.current_session_id == "S1"


def test_set_session_rejects_mismatched_owned_pair(d):
    tid = model(d, "Target.createTarget", {"url": "about:blank"})["result"]["targetId"]
    assert "error" in meta(d, "set_session", session_id="S1", target_id=tid)
