"""REQUIRED 1: strict URL validation and finite, bounded numeric validation.
Every DENY happens before ANY send_raw (trusted or model-origin)."""
import asyncio
import json

import pytest

import browser_harness.cdp_policy as cp

from .policy_harness import make_policy_daemon, model, new_loop, run

BAD_URLS = [
    "", "https://", "https:///p", "https://:443/", "https://a..b/", "https://-a.example/",
    "https://a_b.example/", "https://x.example./",
    "https://user@x.example/", "https://u:p@x.example/", "https://@x.example/",
    "https://x.example:0/", "https://x.example:65536/", "https://x.example:/", "https://x.example:08/",
    "https://x.example:abc/", "https://x.example:1:2/", "https://[::1]:99999/",
    "https://x.ex\x00ample/", "https://x.example/\n", "https://x.example/\t", "https://x.example/ a",
    "https://x.example/\x7f",
    "https://éxample.com/", "https://x.example/café", "https://х.example/",
    "about:blank#x", "about:blank?x", "about:blank/", "ABOUT:BLANK", "about:srcdoc",
    "HTTPS://x.example/", "https:x.example", "https:\\\\x.example\\", "https:/x.example/",
    "https://1.2.3/", "https://01.2.3.4/", "https://0x7f.0.0.1/", "https://256.1.1.1/",
    "https://2130706433/", "https://[::1%25eth0]/", "https://[zz]/", "https://[::1/",
    "ftp://x.example/", "file:///etc/passwd", "javascript:1", "data:,x", "chrome://version",
    "https://x.example/" + "a" * 9000,
]
GOOD_URLS = [
    "about:blank", "https://x.example/", "http://x.example:8080/p?q=1#f", "https://xn--xmple-rqa.com/",
    "https://x.example/caf%C3%A9", "https://127.0.0.1/", "https://[::1]:8443/", "http://localhost/",
]


@pytest.fixture(autouse=True)
def _loop():
    loop = new_loop()
    try:
        yield loop
    finally:
        loop.close()
        asyncio.set_event_loop(None)


@pytest.mark.parametrize("url", BAD_URLS)
def test_bad_urls_rejected(url):
    assert cp.top_level_url_allowed(url) is False


@pytest.mark.parametrize("url", [None, 7, b"https://x.example/", ["https://x.example/"]])
def test_non_string_urls_rejected(url):
    assert cp.top_level_url_allowed(url) is False


@pytest.mark.parametrize("url", GOOD_URLS)
def test_good_urls_allowed(url):
    assert cp.top_level_url_allowed(url) is True


def _zero_send_deny(d, method, params):
    n = len(d.cdp.calls)
    r = model(d, method, params)
    assert "error" in r, r
    assert len(d.cdp.calls) == n, d.cdp.calls[n:]


@pytest.mark.parametrize("url", BAD_URLS[:20] + ["https://éxample.com/", "about:blank#x"])
def test_navigate_bad_url_zero_send(url):
    _zero_send_deny(make_policy_daemon(), "Page.navigate", {"url": url})


def test_navigate_good_url_sent_after_refresh():
    d = make_policy_daemon()
    assert "result" in model(d, "Page.navigate", {"url": "https://xn--xmple-rqa.com/"})
    assert d.cdp.count("Page.navigate") == 1


NAN, INF = float("nan"), float("inf")
BAD_NUMERIC = [
    ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": NAN, "y": 1}),
    ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": 1, "y": INF}),
    ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": -INF, "y": 1}),
    ("Input.dispatchMouseEvent", {"type": "mouseWheel", "x": 1, "y": 1, "deltaY": NAN}),
    ("Input.dispatchMouseEvent", {"type": "mouseWheel", "x": 1, "y": 1, "deltaX": 1e7}),
    ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": -1, "y": 1}),
    ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": 100_001, "y": 1}),
    ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": 10 ** 400, "y": 1}),
    ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": "1", "y": 1}),
    ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": True, "y": 1}),
    ("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": None, "y": 1}),
    ("Input.dispatchMouseEvent", {"type": "mousePressed", "x": 1, "y": 1, "clickCount": 11}),
    ("Input.dispatchMouseEvent", {"type": "mousePressed", "x": 1, "y": 1, "clickCount": 1.0}),
    ("Input.dispatchMouseEvent", {"type": "mousePressed", "x": 1, "y": 1, "modifiers": 16}),
    ("Input.dispatchKeyEvent", {"type": "keyDown", "windowsVirtualKeyCode": 0x10000}),
    ("Input.dispatchKeyEvent", {"type": "keyDown", "nativeVirtualKeyCode": -1}),
    ("Page.captureScreenshot", {"quality": 101}),
    ("Page.captureScreenshot", {"quality": NAN}),
    ("DOM.getDocument", {"depth": 1001}),
    ("DOM.querySelector", {"nodeId": 0, "selector": "a"}),
    ("DOM.getBoxModel", {"nodeId": 2 ** 31}),
    ("Accessibility.getFullAXTree", {"depth": -2}),
]


@pytest.mark.parametrize("method,params", BAD_NUMERIC)
def test_non_finite_or_out_of_range_numbers_zero_send(method, params):
    _zero_send_deny(make_policy_daemon(), method, params)


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_json_wire_nan_and_infinity_denied(token):
    # Python's json accepts these literals: prove the IPC decode path is covered.
    req = json.loads('{"method": "Input.dispatchMouseEvent", "params": '
                     '{"type": "mouseMoved", "x": %s, "y": 1}}' % token)
    d = make_policy_daemon()
    n = len(d.cdp.calls)
    assert "error" in run(d.handle(req))
    assert len(d.cdp.calls) == n


def test_in_range_finite_numbers_allowed():
    d = make_policy_daemon()
    r = model(d, "Input.dispatchMouseEvent",
              {"type": "mousePressed", "x": 10.5, "y": 0, "button": "left", "clickCount": 1})
    assert "result" in r


@pytest.mark.parametrize("method,params", [
    ("Runtime.evaluate", {"expression": "1", "contextId": 3}),         # unknown key
    ("Runtime.evaluate", {"expression": 5}),
    ("Runtime.evaluate", "not-an-object"),
    ("Target.createTarget", {"url": "https://x.example/"}),
    ("Target.createTarget", {"url": "about:blank", "browserContextId": "DEFAULT", "x": 1}),
    ("Target.attachToTarget", {"targetId": "T1"}),                      # flatten missing
    ("Target.getTargets", {"filter": [{}]}),
])
def test_shape_violations_zero_send(method, params):
    _zero_send_deny(make_policy_daemon(), method, params)


def test_create_target_forces_hermes_context():
    d = make_policy_daemon()
    model(d, "Target.createTarget", {"url": "about:blank", "browserContextId": "DEFAULT"})
    sent = [p for m, p, _s in d.cdp.calls if m == "Target.createTarget"][-1]
    assert sent["browserContextId"] == "CTX-HERMES"
