"""Live-found availability defect: the policy reconnect path must not run the
blocking get_ws_url() (urllib + time.sleep polling) on the event-loop thread.
While it waits for the browser, the daemon keeps serving IPC: ping answers fast
with ready=false; once the browser is back, reconnect completes."""
import asyncio
import threading
import time

import pytest

import browser_harness.daemon as daemon_mod

from .policy_harness import FakeBrowser, make_policy_daemon, new_loop, run


@pytest.fixture(autouse=True)
def _loop():
    loop = new_loop()
    try:
        yield loop
    finally:
        loop.close()
        asyncio.set_event_loop(None)


def test_reconnect_wait_for_browser_does_not_block_event_loop(monkeypatch):
    d = make_policy_daemon()
    reg = d.policy.registry
    entered, release = threading.Event(), threading.Event()
    inside = {"now": False}

    def blocking_get_ws_url():  # stands in for urllib + time.sleep(1) polling
        inside["now"] = True
        entered.set()
        release.wait(3)  # safety bound: an event-loop-blocking caller stalls here
        inside["now"] = False
        return "ws://127.0.0.1:1/devtools/browser/fake"
    b2 = FakeBrowser(ctx_prefix="CTX-NEW", tid_prefix="N", sid_prefix="NS")
    monkeypatch.setattr(daemon_mod, "get_ws_url", blocking_get_ws_url)
    monkeypatch.setattr(daemon_mod, "CDPClient", lambda url: b2)
    monkeypatch.setattr(daemon_mod, "_PatientCDPClient", lambda url: b2)

    async def scenario():
        loop = asyncio.get_running_loop()
        b2._message_handler_task = loop.create_future()  # new connection stays up
        lost = loop.create_future()
        d.cdp._message_handler_task = lost
        d._policy_watch = loop.create_task(d._watch_policy_connection())  # production watcher
        await asyncio.sleep(0)
        lost.set_result(None)  # browser connection lost
        for _ in range(300):
            if entered.is_set():
                break
            await asyncio.sleep(0.01)
        ticks, end = 0, loop.time() + 0.2
        while loop.time() < end:
            await asyncio.sleep(0.01)
            ticks += 1
        inside_after_ticks = inside["now"]
        t = time.monotonic()
        resp = await asyncio.wait_for(d.handle({"meta": "ping"}), 1.0)
        latency = time.monotonic() - t
        inside_after_ping = inside["now"]
        release.set()
        for _ in range(300):
            if reg.generation == 2 and reg.initial_ready:
                break
            await asyncio.sleep(0.01)
        after = await d.handle({"meta": "ping"})
        d._shutting_down = True
        d._policy_watch.cancel()
        await asyncio.gather(d._policy_watch, return_exceptions=True)
        return ticks, inside_after_ticks, resp, latency, inside_after_ping, after

    try:
        ticks, inside_after_ticks, resp, latency, inside_after_ping, after = run(scenario())
    finally:
        release.set()
    assert entered.is_set(), "reconnect never reached get_ws_url"
    # The loop kept running independent coroutines WHILE get_ws_url was blocked...
    assert inside_after_ticks and ticks >= 10, (inside_after_ticks, ticks)
    # ...and the production handler answered ping during the wait, fast, not ready.
    assert inside_after_ping, "ping was only answered after get_ws_url returned (loop blocked)"
    assert latency < 0.5, latency
    pol = resp["policy"]
    assert pol["ready"] is False and pol["connected"] is False
    # After the browser is back, the reconnect completes the full startup contract.
    assert reg.generation == 2 and reg.browser_context_id == "CTX-NEW" and d.cdp is b2
    assert ("Browser.setDownloadBehavior",
            {"behavior": "deny", "browserContextId": "CTX-NEW", "eventsEnabled": True}, None) in b2.calls
    assert after["policy"]["ready"] is True
