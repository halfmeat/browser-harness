"""Real-namespace proof of the management peer boundary (not mocked).

The full-path tests (REQUIRED 4, below) drive the production ``daemon.serve`` →
``Daemon.handle`` → management decision from real client processes. The first
two tests are a supplementary direct check: a tiny AF_UNIX server runs
``cdp_policy.verify_host_peer`` on each accepted connection. A same-namespace child (ordinary subprocess) is ALLOWED; a
child launched in fresh PID + network + mount namespaces via ``bwrap`` — the
same primitive that will sandbox the Hermes model workload in Phase 2 — is
DENIED, even though it runs under the same Unix uid.

Skipped when bwrap is unavailable or cannot create user namespaces (some CI).
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

import pytest

import browser_harness.cdp_policy as cp

BWRAP = shutil.which("bwrap")
PY = sys.executable
_CONNECT = (
    "import socket,sys\n"
    "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
    "s.connect(sys.argv[1])\n"
    "s.sendall(b'x')\n"
    "sys.stdout.write(s.recv(16).decode())\n"
)


def _bwrap_usable():
    if not BWRAP:
        return False
    try:
        r = subprocess.run([BWRAP, "--unshare-pid", "--unshare-net", "--dev-bind", "/", "/",
                            PY, "-c", "print(1)"], capture_output=True, timeout=30)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


requires_bwrap = pytest.mark.skipif(not _bwrap_usable(),
                                    reason="bwrap unavailable or cannot create namespaces")


class _PeerServer:
    """Accepts one connection, runs verify_host_peer, replies ALLOW/DENY."""

    def __init__(self, sock_path):
        self.result = None
        self.detail = None
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(sock_path)
        self._srv.listen(1)
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        conn, _ = self._srv.accept()
        with conn:
            conn.recv(16)
            ok, detail = cp.verify_host_peer(conn)
            self.result, self.detail = ok, detail
            conn.sendall(b"ALLOW" if ok else b"DENY")

    def join(self, timeout=30):
        self._t.join(timeout)

    def close(self):
        try:
            self._srv.close()
        except OSError:
            pass


@pytest.fixture
def peer_server():
    d = tempfile.mkdtemp(prefix="bh-peer-", dir="/var/tmp")
    sock_path = os.path.join(d, "s.sock")
    srv = _PeerServer(sock_path)
    try:
        yield srv, sock_path
    finally:
        srv.close()
        shutil.rmtree(d, ignore_errors=True)


def test_same_namespace_peer_is_allowed(peer_server):
    srv, sock_path = peer_server
    out = subprocess.run([PY, "-c", _CONNECT, sock_path], capture_output=True, text=True, timeout=30)
    srv.join()
    assert out.stdout == "ALLOW", (out.stdout, out.stderr, srv.detail)
    assert srv.result is True


@requires_bwrap
def test_sandboxed_namespace_peer_is_denied(peer_server):
    srv, sock_path = peer_server
    # Same uid, but fresh pid+net+mnt namespaces (the Phase-2 model sandbox shape).
    cmd = [BWRAP, "--unshare-pid", "--unshare-net", "--dev-bind", "/", "/",
           PY, "-c", _CONNECT, sock_path]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    srv.join()
    assert out.stdout == "DENY", (out.stdout, out.stderr, srv.detail)
    assert srv.result is False
    assert srv.detail["reason"].startswith("ns_mismatch:"), srv.detail


# ── REQUIRED 4: the full production management path ─────────────────────────
# AF_UNIX client → production daemon.serve() → writer.get_extra_info("socket")
# → production Daemon.handle(req, peer) → policy management decision → side
# effect (connection_status / shutdown) or denial. No step is stubbed except the
# browser (FakeBrowser) and stop_remote (recorded, so a call would be visible).
_REQUEST = (
    "import socket,sys\n"
    "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
    "s.connect(sys.argv[1])\n"
    "s.sendall((sys.argv[2]+'\\n').encode())\n"
    "buf=b''\n"
    "while not buf.endswith(b'\\n'):\n"
    "    c=s.recv(65536)\n"
    "    if not c: break\n"
    "    buf+=c\n"
    "sys.stdout.write(buf.decode())\n"
)
_SANDBOX = [BWRAP, "--unshare-pid", "--unshare-net", "--dev-bind", "/", "/"] if BWRAP else []


@pytest.fixture
def served(monkeypatch):
    """A policy-mode Daemon served by the production serve() on a private AF_UNIX path."""
    import asyncio
    from pathlib import Path

    import browser_harness._ipc as ipc
    import browser_harness.daemon as daemon_mod
    from tests.unit.policy_harness import make_policy_daemon, new_loop

    rt = tempfile.mkdtemp(prefix="bh-mgmt-", dir="/var/tmp")
    monkeypatch.setattr(ipc, "_RUNTIME", Path(rt))
    monkeypatch.setattr(daemon_mod, "NAME", "bhpolicy")
    stops = []
    monkeypatch.setattr(daemon_mod, "stop_remote", lambda strict=False: stops.append(strict))
    logs = []
    monkeypatch.setattr(daemon_mod, "log", logs.append)
    sock = str(ipc._sock_path(daemon_mod.NAME))
    loop, d, task = new_loop(), None, None

    async def until_bound():
        while not os.path.exists(sock):
            await asyncio.sleep(0.01)

    def call(req, sandboxed):
        cmd = (_SANDBOX if sandboxed else []) + [PY, "-I", "-c", _REQUEST, sock, json.dumps(req)]

        async def go():
            p = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = await asyncio.wait_for(p.communicate(), 60)
            assert out, err
            return json.loads(out)
        return loop.run_until_complete(go())

    try:  # setup failures included, so the runtime dir is always removed
        d = make_policy_daemon()
        task = loop.create_task(daemon_mod.serve(d))
        loop.run_until_complete(asyncio.wait_for(until_bound(), 10))
        yield d, call, stops, logs
    finally:
        if task is not None:
            d.stop.set()
            loop.run_until_complete(asyncio.wait_for(task, 10))
        loop.close()
        asyncio.set_event_loop(None)
        shutil.rmtree(rt, ignore_errors=True)


def _frozen(d):
    return (d.policy.registry.snapshot(), len(d.cdp.calls), d.stop.is_set(), d._shutting_down)


def test_full_path_same_namespace_management_allowed(served):
    d, call, stops, logs = served
    n = len(d.cdp.calls)
    r = call({"meta": "connection_status"}, sandboxed=False)
    assert r["target_id"] == "T1" and r["session_id"] == "S1", r
    assert d.cdp.calls[n:] == [("Target.getTargetInfo", {"targetId": "T1"}, None)]
    assert call({"meta": "shutdown"}, sandboxed=False) == {"ok": True}
    assert stops == [True] and d.stop.is_set()


@requires_bwrap
@pytest.mark.parametrize("meta", ["connection_status", "shutdown"])
def test_full_path_sandboxed_same_uid_management_denied(served, meta):
    d, call, stops, logs = served
    before = _frozen(d)
    r = call({"meta": meta}, sandboxed=True)
    assert r == {"error": "management request denied by policy"}
    assert _frozen(d) == before          # no state mutation, no CDP, stop unchanged
    assert stops == [] and not d.stop.is_set()
    assert any(f"{meta!r} denied (ns_mismatch:" in line for line in logs), logs


@requires_bwrap
def test_full_path_sandboxed_peer_still_gets_model_safe_ping(served):
    _d, call, _stops, _logs = served
    r = call({"meta": "ping"}, sandboxed=True)
    assert r["pong"] is True and r["policy"]["ready"] is True
