"""ensure_daemon during a browser outage: a live daemon whose configured BU_CDP_URL endpoint is
unreachable is NOT replaced (a replacement would only wait out get_ws_url and fail) and the call
fails fast; once the endpoint answers again, an unhealthy daemon is still replaced."""
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from browser_harness import admin

NOT_READY = {"error": "policy: policy not operational (not ready)"}


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens: connections are refused
    return port


@pytest.fixture
def endpoint():
    """A loopback DevTools-like HTTP endpoint answering /json/version with ``status``."""
    servers = []

    def make(status=200):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = json.dumps({"webSocketDebuggerUrl": "ws://127.0.0.1:1/devtools/browser/x"}).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"
    yield make
    for srv in servers:
        srv.shutdown()


@pytest.fixture
def daemon(monkeypatch):
    """A live daemon that answers ping but whose CDP probe is not healthy; records what
    ensure_daemon does with it. Spawning a replacement is recorded and refused."""
    calls = {"probes": 0, "restart": 0, "stop_remote": 0, "spawn": 0}
    state = {"alive": True, "probe": NOT_READY, "kind": "cdp"}

    def request(_s, _t, req):
        calls["probes"] += 1
        return state["probe"]

    def restart(name=None, require_clean=False):
        calls["restart"] += 1
        state["alive"] = False

    def spawn(*a, **k):
        calls["spawn"] += 1
        raise RuntimeError("spawned")

    monkeypatch.setattr(admin, "daemon_alive", lambda name=None: state["alive"])
    monkeypatch.setattr(admin.ipc, "connect", lambda name, timeout=None: (object(), None))
    monkeypatch.setattr(admin.ipc, "request", request)
    monkeypatch.setattr(admin, "daemon_browser_kind", lambda name=None: state["kind"])
    monkeypatch.setattr(admin, "restart_daemon", restart)
    monkeypatch.setattr(admin, "stop_remote_daemon", lambda name=None: calls.__setitem__(
        "stop_remote", calls["stop_remote"] + 1))
    monkeypatch.setattr(admin.subprocess, "Popen", spawn)
    monkeypatch.delenv("BU_CDP_WS", raising=False)
    return calls, state


def test_live_daemon_is_kept_and_call_fails_fast_while_browser_unreachable(daemon, monkeypatch):
    calls, _ = daemon
    monkeypatch.setenv("BU_CDP_URL", f"http://127.0.0.1:{_closed_port()}")
    t = time.monotonic()
    with pytest.raises(RuntimeError, match="browser-unavailable") as exc:
        admin.ensure_daemon()
    assert time.monotonic() - t < 3.0
    assert calls["restart"] == 0 and calls["spawn"] == 0 and calls["stop_remote"] == 0
    assert calls["probes"] == 2  # the existing health probe still ran first
    assert "left in place" in str(exc.value)


def test_unrestricted_daemon_is_not_accepted_either_while_browser_unreachable(daemon, monkeypatch):
    """No policy information is trusted to skip the restart: the call fails, never returns."""
    calls, state = daemon
    state["probe"] = {"error": "no close frame received or sent"}
    monkeypatch.setenv("BU_CDP_URL", f"http://127.0.0.1:{_closed_port()}")
    with pytest.raises(RuntimeError, match="browser-unavailable"):
        admin.ensure_daemon()
    assert calls["restart"] == 0 and calls["spawn"] == 0


def test_unhealthy_daemon_is_still_replaced_once_the_endpoint_answers(daemon, monkeypatch, endpoint):
    calls, _ = daemon
    monkeypatch.setenv("BU_CDP_URL", endpoint(200))
    with pytest.raises(RuntimeError, match="spawned"):
        admin.ensure_daemon()
    assert calls["restart"] == 1 and calls["spawn"] == 1


@pytest.mark.parametrize("status", [403, 404, 500])
def test_any_http_answer_counts_as_reachable(daemon, monkeypatch, endpoint, status):
    calls, _ = daemon
    monkeypatch.setenv("BU_CDP_URL", endpoint(status))
    with pytest.raises(RuntimeError, match="spawned"):
        admin.ensure_daemon()
    assert calls["restart"] == 1


def test_healthy_daemon_returns_without_probing_the_endpoint(daemon, monkeypatch):
    calls, state = daemon
    state["probe"] = {"result": {"targetInfos": []}}
    probed = []
    monkeypatch.setattr(admin, "_cdp_url_unreachable", lambda env=None: probed.append(1))
    monkeypatch.setenv("BU_CDP_URL", f"http://127.0.0.1:{_closed_port()}")
    admin.ensure_daemon()
    assert probed == [] and calls["restart"] == 0 and calls["spawn"] == 0


def test_bu_cdp_ws_keeps_the_replacement_path(daemon, monkeypatch):
    """The daemon resolves BU_CDP_WS first; BU_CDP_URL reachability is irrelevant then."""
    calls, _ = daemon
    monkeypatch.setenv("BU_CDP_URL", f"http://127.0.0.1:{_closed_port()}")
    monkeypatch.setenv("BU_CDP_WS", "ws://127.0.0.1:1/devtools/browser/x")
    with pytest.raises(RuntimeError, match="spawned"):
        admin.ensure_daemon()
    assert calls["restart"] == 1


@pytest.mark.parametrize("kind", ["cloud", None])
def test_cloud_or_unknown_daemon_cleanup_path_is_unchanged(daemon, monkeypatch, kind):
    calls, state = daemon
    state["kind"] = kind
    probed = []
    monkeypatch.setattr(admin, "_cdp_url_unreachable", lambda env=None: probed.append(1))
    monkeypatch.setenv("BU_CDP_URL", f"http://127.0.0.1:{_closed_port()}")
    with pytest.raises(RuntimeError, match="spawned"):
        admin.ensure_daemon()
    assert calls["stop_remote"] == 1 and probed == []


def test_dead_daemon_keeps_the_spawn_path(daemon, monkeypatch):
    """No live daemon (dead process / socket without a peer): recovery spawns as before."""
    calls, state = daemon
    state["alive"] = False
    monkeypatch.setenv("BU_CDP_URL", f"http://127.0.0.1:{_closed_port()}")
    with pytest.raises(RuntimeError, match="spawned"):
        admin.ensure_daemon()
    assert calls["spawn"] == 1 and calls["probes"] == 0 and calls["restart"] == 0


def test_local_mode_is_unchanged(daemon, monkeypatch):
    calls, _ = daemon
    monkeypatch.delenv("BU_CDP_URL", raising=False)
    monkeypatch.setattr(admin, "_is_local_chrome_mode", lambda env=None: False)
    with pytest.raises(RuntimeError, match="spawned"):
        admin.ensure_daemon()
    assert calls["restart"] == 1


def test_env_argument_overrides_process_env(daemon, monkeypatch, endpoint):
    calls, _ = daemon
    monkeypatch.setenv("BU_CDP_URL", endpoint(200))
    with pytest.raises(RuntimeError, match="browser-unavailable"):
        admin.ensure_daemon(env={"BU_CDP_URL": f"http://127.0.0.1:{_closed_port()}"})
    assert calls["restart"] == 0


# ── _cdp_url_unreachable unit semantics ──────────────────────────────────────────────────
def test_probe_reports_refused_endpoint(monkeypatch):
    url = f"http://127.0.0.1:{_closed_port()}/"
    got = admin._cdp_url_unreachable({"BU_CDP_URL": url})
    assert got is not None and got[0] == url.rstrip("/")


def test_probe_uses_get_ws_url_request_shape_and_timeout(monkeypatch):
    seen = []

    def fake(url, timeout=None):
        seen.append((url, timeout))
        raise TimeoutError("timed out")
    monkeypatch.setattr(admin.urllib.request, "urlopen", fake)
    got = admin._cdp_url_unreachable({"BU_CDP_URL": "http://127.0.0.1:9/"})
    assert seen == [("http://127.0.0.1:9/json/version", 5)]
    assert isinstance(got[1], TimeoutError)


def test_probe_reports_malformed_url():
    assert admin._cdp_url_unreachable({"BU_CDP_URL": "not a url"}) is not None


def test_probe_ignores_absent_url_and_ws_precedence(monkeypatch):
    monkeypatch.delenv("BU_CDP_URL", raising=False)
    monkeypatch.delenv("BU_CDP_WS", raising=False)
    assert admin._cdp_url_unreachable({}) is None
    assert admin._cdp_url_unreachable({"BU_CDP_URL": "http://127.0.0.1:9", "BU_CDP_WS": "ws://x"}) is None


def test_probe_reachable_endpoint(endpoint):
    assert admin._cdp_url_unreachable({"BU_CDP_URL": endpoint(200)}) is None
