"""Defensive CDP policy for ``BH_CDP_POLICY=v1`` (Owner Security Contract v1).

Every incoming IPC request to the daemon is UNTRUSTED (model origin). Trusted
daemon-internal CDP calls are a separate code path (``Daemon._trusted_send``);
origin is separated by code, never by a client-supplied flag.

Enforcement surfaces, all fail-closed:

* model-facing CDP method allowlist + strict per-method validation, Hermes
  ownership checks, and a TRUSTED refresh of the already-owned target's live state
  (``Target.getTargetInfo`` + ``Page.getFrameTree``) BEFORE any model-origin
  ``send_raw``;
* model-facing meta allowlist with ownership filtering (``set_session`` is
  untrusted → validated owned pair); every unknown meta is denied;
* management meta (``shutdown`` / ``connection_status``) require a kernel-backed
  host-peer identity check (same uid + same pid/net/mnt namespaces as the daemon).

Ownership arises ONLY from: trusted daemon startup creation; a successful,
allowed ``Target.createTarget`` confirmed by trusted ``Target.getTargetInfo``; an
iframe whose parent chain to an owned page is proven by trusted calls inside the
daemon's TRUSTED discovery flow (lifecycle event → trusted getTargetInfo +
frame-tree proof → registration). ``Target.getTargets`` and model-named ids
never create authority; the model only ever sees already-registered targets.

Synchronization: registry mutations are synchronous (atomic between awaits on the
daemon's single event loop). Each model operation captures a token (generation +
the owned session/target it acts on) and revalidates it after EVERY await; a
token that no longer holds means DENY with no registry commit. Event-driven
revocations (navigation, target destroyed, detach) therefore cannot leave a model
action committing against stale ownership.

Policy mode is selected only by the trusted host environment variable
``BH_CDP_POLICY``; a workspace ``.env`` cannot turn it on, off, or change it (the
selector is captured at daemon-module import, before any ``.env`` load).

External security contract (LISA-Hermes Phase 2): the browser_exec model workload
MUST run in a sandbox that gives it a PID namespace AND a network namespace
separate from the host daemon/management process, so a same-uid sandboxed model
fails the management peer check; Hermes MUST launch the daemon with
``BH_CDP_POLICY=v1`` and verify the exact attestation (``ready`` true, version
``v1``) before every model turn, failing closed otherwise. Upstream unrestricted
mode is never an acceptable fallback for LISA-Hermes.
"""
from __future__ import annotations

import asyncio
import ipaddress
import math
import os
import re
import socket
import struct
import sys
from urllib.parse import urlsplit

POLICY_VERSION = "v1"
POLICY_ENV_VAR = "BH_CDP_POLICY"

# SO_PEERPIDFD — Linux UAPI (include/uapi/asm-generic/socket.h), kernel >= 6.5.
# CPython's stdlib does not export the constant, so the UAPI value is pinned
# here, isolated and covered by tests. Never substitute pidfd_open(peer_pid):
# that reintroduces the PID-reuse race SO_PEERPIDFD exists to close.
SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)

# Namespaces a management peer must share with the daemon (strict; never skipped).
REQUIRED_PEER_NAMESPACES = ("pid", "net", "mnt")

# Model-facing CDP method allowlist; everything else is denied by default.
MODEL_CDP_METHODS = frozenset({
    "Page.navigate", "Page.captureScreenshot", "Page.handleJavaScriptDialog",
    "DOM.getDocument", "DOM.querySelector", "DOM.getBoxModel",
    "Accessibility.getFullAXTree",
    "Runtime.evaluate",
    "Input.dispatchMouseEvent", "Input.dispatchKeyEvent", "Input.insertText",
    "Target.getTargets", "Target.createTarget", "Target.attachToTarget",
    "Target.detachFromTarget", "Target.activateTarget", "Target.closeTarget",
    "Browser.getVersion",
})

# Methods that act on a CDP session; that session must be owned and its target
# must pass the trusted live-state refresh first.
SESSION_SCOPED = frozenset({
    "Runtime.evaluate", "Page.navigate", "Page.captureScreenshot",
    "Page.handleJavaScriptDialog", "DOM.getDocument", "DOM.querySelector",
    "DOM.getBoxModel", "Accessibility.getFullAXTree", "Input.dispatchMouseEvent",
    "Input.dispatchKeyEvent", "Input.insertText",
})

MODEL_META = frozenset({"ping", "session", "current_tab", "pending_dialog", "drain_events"})
UNTRUSTED_META = frozenset({"set_session"})
MANAGEMENT_META = frozenset({"shutdown", "connection_status"})

_MAX_STR = 200_000      # expression / inserted text
_MAX_SHORT = 4_096      # selectors, keys, prompt text, ids
_MAX_URL = 8_192
_MAX_LIST = 64
_MAX_ID = (1 << 31) - 1
_COORD_MAX = 100_000.0
_DELTA_MAX = 1_000_000.0
_VK_MAX = 0xFFFF

# Upper bound for each trusted state-refresh call; a hung refresh is a DENY.
TRUSTED_TIMEOUT = 5.0


class PolicyConfigError(Exception):
    """``BH_CDP_POLICY`` held a value other than unset/empty/'v1' — fail closed."""


class Denied(Exception):
    """A model-origin request policy refuses. ``str`` is the client-facing reason."""


def resolve_selector(raw):
    """Map a raw ``BH_CDP_POLICY`` value to None (upstream mode) or ``POLICY_VERSION``.

    Any other non-empty value is a configuration error (fail closed) — never a
    silent fallback to non-policy mode."""
    if raw is None or raw == "":
        return None
    if raw == POLICY_VERSION:
        return POLICY_VERSION
    raise PolicyConfigError(
        f"invalid {POLICY_ENV_VAR}={raw!r}: expected unset/empty or {POLICY_VERSION!r}"
    )


# Captured from the TRUSTED host environment at import, which in the daemon
# process happens before daemon.py loads any workspace .env.
_CAPTURED_RAW = os.environ.get(POLICY_ENV_VAR)


def captured_raw():
    return _CAPTURED_RAW


# ── Kernel-backed host-peer identity ─────────────────────────────────────────
def _peer_credentials(sock):
    """(pid, uid, gid) of the connected peer via SO_PEERCRED."""
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def _peer_pidfd(sock):
    """A pidfd for the connecting process via SO_PEERPIDFD (stable identity,
    immune to PID reuse). Caller must close it. Raises OSError if unsupported."""
    raw = sock.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4)
    return struct.unpack("i", raw)[0]


def _pidfd_live_pid(pidfd):
    """Current PID the pidfd refers to (from /proc/self/fdinfo), or -1 if the
    process has exited. Ties the numeric PID we read /proc for to the pidfd."""
    with open(f"/proc/self/fdinfo/{pidfd}", encoding="ascii") as f:
        for line in f:
            if line.startswith("Pid:"):
                return int(line.split()[1])
    raise OSError("SO_PEERPIDFD fdinfo had no Pid field")


def _namespace_inodes(pid, which=REQUIRED_PEER_NAMESPACES):
    """{ns: inode} for /proc/<pid>/ns/<ns>. ``pid`` may be 'self'."""
    return {ns: os.stat(f"/proc/{pid}/ns/{ns}").st_ino for ns in which}


def daemon_namespaces(which=REQUIRED_PEER_NAMESPACES):
    return _namespace_inodes("self", which)


def verify_host_peer(sock, *, daemon_uid=None, daemon_ns=None,
                     required=REQUIRED_PEER_NAMESPACES):
    """(allowed, detail) for a management request from ``sock``.

    Allowed only when the peer has the daemon's uid AND shares every required
    namespace. Any missing credential, unavailable pidfd, vanished peer,
    inconsistent identity, or unreadable namespace denies. No fail-open path."""
    if sys.platform != "linux":
        return False, {"reason": "unsupported_platform"}
    daemon_uid = os.getuid() if daemon_uid is None else daemon_uid
    try:
        _pid, uid, _gid = _peer_credentials(sock)
    except OSError as e:
        return False, {"reason": "no_peercred", "error": str(e)}
    if uid != daemon_uid:
        return False, {"reason": "uid_mismatch", "peer_uid": uid}
    try:
        pidfd = _peer_pidfd(sock)
    except OSError as e:
        return False, {"reason": "no_peerpidfd", "error": str(e)}
    try:
        pid_before = _pidfd_live_pid(pidfd)
        if pid_before <= 0:
            return False, {"reason": "peer_gone"}
        try:
            peer_ns = _namespace_inodes(pid_before, required)
        except OSError as e:
            return False, {"reason": "peer_ns_unreadable", "error": str(e)}
        # Re-confirm the pidfd still names the same live process: a PID that was
        # reused mid-check would show a different value (or -1) here.
        pid_after = _pidfd_live_pid(pidfd)
        if pid_after <= 0 or pid_after != pid_before:
            return False, {"reason": "peer_identity_changed"}
    except OSError as e:
        return False, {"reason": "peer_check_failed", "error": str(e)}
    finally:
        try:
            os.close(pidfd)
        except OSError:
            pass
    try:
        self_ns = daemon_ns if daemon_ns is not None else _namespace_inodes("self", required)
    except OSError as e:
        return False, {"reason": "daemon_ns_unreadable", "error": str(e)}
    for ns in required:
        if peer_ns.get(ns) is None or self_ns.get(ns) is None or peer_ns[ns] != self_ns[ns]:
            return False, {"reason": f"ns_mismatch:{ns}", "peer": peer_ns.get(ns),
                           "daemon": self_ns.get(ns)}
    return True, {"peer_pid": pid_before, "peer_uid": uid, "namespaces": peer_ns}


def management_isolation_available():
    """Whether this platform can prove host-peer isolation at all. When False,
    policy mode must report not-ready / fail closed (no management lifecycle)."""
    if sys.platform != "linux":
        return False, "non-linux platform"
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        fd = _peer_pidfd(a)
        os.close(fd)
    except OSError as e:
        return False, f"SO_PEERPIDFD unavailable: {e}"
    finally:
        a.close()
        b.close()
    try:
        _namespace_inodes("self")
    except OSError as e:
        return False, f"namespace inodes unreadable: {e}"
    return True, "ok"


# ── Strict URL validation ────────────────────────────────────────────────────
_DNS_LABEL = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_HEXISH = re.compile(r"\A0[xX][0-9A-Fa-f]*\Z")


def _valid_host(host):
    """DNS hostname, strict dotted-quad IPv4, or bracketed IPv6 (no zone id).
    Numeric-looking hosts must be an exact dotted quad (no shorthand/octal/hex)."""
    if not host:
        return False
    if host.startswith("["):
        if not host.endswith("]") or "%" in host:
            return False
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return False
        return True
    if len(host) > 253 or host.endswith(".") or "[" in host or "]" in host:
        return False
    labels = host.split(".")
    if labels[-1].isdigit() or _HEXISH.match(labels[-1]):
        if len(labels) != 4:
            return False
        for label in labels:
            if not label.isdigit() or (len(label) > 1 and label[0] == "0") or int(label) > 255:
                return False
        return True
    return all(_DNS_LABEL.match(label) for label in labels)


def http_url_allowed(url):
    """Absolute http(s) URL with an exact lowercase scheme, a valid non-empty host,
    a valid port if present, and no userinfo, control/space/non-ASCII characters,
    backslashes or ambiguous authority. No repair or fallback."""
    if not isinstance(url, str) or not url or len(url) > _MAX_URL:
        return False
    if any(c <= " " or c > "~" for c in url) or "\\" in url:
        return False
    if url.startswith("https://"):
        rest = url[len("https://"):]
    elif url.startswith("http://"):
        rest = url[len("http://"):]
    else:
        return False
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or parts.netloc != authority:
        return False
    if not authority or "@" in authority:
        return False
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return False
        host, after = authority[:end + 1], authority[end + 1:]
    else:
        host, sep, port = authority.partition(":")
        if sep and ":" in port:
            return False
        after = f":{port}" if sep else ""
    if after:
        if not after.startswith(":"):
            return False
        port = after[1:]
        if not port.isdigit() or (len(port) > 1 and port[0] == "0") or not 1 <= int(port) <= 65535:
            return False
    return _valid_host(host)


def top_level_url_allowed(url):
    """An owned top-level page may hold an http(s) URL (strict) or EXACTLY
    'about:blank'. Anything else — other schemes, about:blank variants, malformed
    or unknown — is not allowed (deny / revoke)."""
    return url == "about:blank" or http_url_allowed(url)


# ── Ownership registry ───────────────────────────────────────────────────────
class OwnershipRegistry:
    """Authoritative record of what the daemon (Hermes) owns in the current
    connection generation. Ownership never derives from a URL, a name, a target
    merely appearing in Target.getTargets, or a pre-existing user tab."""

    def __init__(self):
        self.generation = 0
        self.connected = False
        self.browser_context_id = None
        self.context_generation = 0
        self.download_deny_generation = 0
        self.discovery_generation = 0
        self.initial_ready = False
        self.monitoring_failed = False
        # target_id -> {"type": "page"|"iframe", "parent": target_id|None, "url": str|None}
        self._targets = {}
        self._revoked = set()
        self._sessions = {}           # session_id -> target_id
        self._page_monitored = set()  # sessions whose critical Page.enable succeeded
        self.current_target_id = None
        self.current_session_id = None
        # callables(sessions: set, targets: set) fired after ownership is lost
        self.revoke_listeners = []

    # -- generations / connection --
    def begin_generation(self, browser_context_id):
        """Start a fresh connection generation. Nothing from an older generation
        stays owned; download-deny and monitoring must be reinstalled for it."""
        self.generation += 1
        self.connected = True
        self.browser_context_id = browser_context_id
        self.context_generation = self.generation
        self.initial_ready = False
        self.monitoring_failed = False
        self._targets.clear()
        self._sessions.clear()
        self._page_monitored.clear()
        self.current_target_id = None
        self.current_session_id = None

    def mark_disconnected(self):
        """CDP connection lost / reconnect beginning: nothing is usable until a new
        generation completes the full startup contract."""
        self.connected = False
        self.initial_ready = False
        targets = set(self._targets)
        sessions = set(self._sessions)
        self._revoked |= targets
        self._targets.clear()
        self._sessions.clear()
        self._page_monitored.clear()
        self.current_target_id = None
        self.current_session_id = None
        self._notify(sessions, targets)

    def infrastructure_ok(self):
        """Connection-level invariants every model-facing operation requires."""
        g = self.generation
        return (self.connected and g > 0 and self.initial_ready
                and bool(self.browser_context_id) and self.context_generation == g
                and self.download_deny_generation == g and self.discovery_generation == g
                and not self.monitoring_failed)

    def context_matches(self, browser_context_id):
        return bool(self.browser_context_id) and browser_context_id == self.browser_context_id

    # -- targets --
    def add_page(self, target_id, url):
        if not self.connected or not target_id or target_id in self._revoked or target_id in self._targets:
            return False
        self._targets[target_id] = {"type": "page", "parent": None, "url": url}
        return True

    def add_iframe(self, target_id, parent_id, url=None):
        if (not self.connected or not target_id or target_id in self._revoked
                or target_id in self._targets or not self.target_owned(parent_id)):
            return False
        self._targets[target_id] = {"type": "iframe", "parent": parent_id, "url": url}
        return True

    def target_owned(self, target_id):
        return target_id in self._targets and target_id not in self._revoked

    def target_type(self, target_id):
        info = self._targets.get(target_id)
        return info["type"] if info and target_id not in self._revoked else None

    def target_url(self, target_id):
        info = self._targets.get(target_id)
        return info["url"] if info else None

    def set_target_url(self, target_id, url):
        if self.target_owned(target_id):
            self._targets[target_id]["url"] = url

    def owned_target_ids(self):
        return set(self._targets) - self._revoked

    def is_revoked(self, target_id):
        return target_id in self._revoked

    def parent_chain(self, target_id):
        """[target, parent, ..., root page] if every link is owned and the chain
        ends at an owned page; None if broken/cyclic."""
        chain, seen, cur = [], set(), target_id
        while cur is not None:
            if cur in seen or not self.target_owned(cur):
                return None
            seen.add(cur)
            chain.append(cur)
            info = self._targets[cur]
            if info["type"] == "page":
                return chain if info["parent"] is None else None
            cur = info["parent"]
        return None

    def _descendants(self, target_id):
        out, changed = {target_id}, True
        while changed:
            changed = False
            for tid, info in self._targets.items():
                if tid not in out and info["parent"] in out:
                    out.add(tid)
                    changed = True
        return out

    # -- sessions --
    def register_session(self, session_id, target_id):
        if not session_id or not self.target_owned(target_id) or session_id in self._sessions:
            return False
        self._sessions[session_id] = target_id
        return True

    def session_owned(self, session_id):
        tid = self._sessions.get(session_id)
        return tid is not None and self.target_owned(tid)

    def target_for_session(self, session_id):
        return self._sessions.get(session_id) if self.session_owned(session_id) else None

    def session_for_target(self, target_id):
        for sid in sorted(self._sessions):
            if self._sessions[sid] == target_id and self.session_owned(sid):
                return sid
        return None

    def mark_page_monitored(self, session_id):
        if self.session_owned(session_id):
            self._page_monitored.add(session_id)

    def page_monitored(self, session_id):
        return session_id in self._page_monitored and self.session_owned(session_id)

    def forget_session(self, session_id):
        """A session detached (model detach or Target.detachedFromTarget). The
        target stays owned; the session and anything current on it do not."""
        if session_id not in self._sessions:
            return
        self._sessions.pop(session_id, None)
        self._page_monitored.discard(session_id)
        if self.current_session_id == session_id:
            self.current_session_id = None
            self.current_target_id = None
        self._notify({session_id}, set())

    def set_current(self, session_id, target_id):
        self.current_session_id = session_id
        self.current_target_id = target_id

    def current_pair_valid(self):
        """Current page owned, current session owned and bound to it, critical Page
        monitoring installed on it, and its last known top-level state allowed."""
        t, s = self.current_target_id, self.current_session_id
        return (t is not None and s is not None and self.target_type(t) == "page"
                and self.target_for_session(s) == t and self.page_monitored(s)
                and top_level_url_allowed(self.target_url(t)))

    # -- revocation --
    def revoke_target(self, target_id):
        """Permanently revoke a target, every descendant iframe (recursively) and
        every session on them; clear current state if affected. A later return to
        a safe URL never restores ownership."""
        if not target_id:
            return
        targets = self._descendants(target_id) if target_id in self._targets else {target_id}
        self._revoked |= targets
        for tid in targets:
            self._targets.pop(tid, None)
        sessions = {sid for sid, tid in self._sessions.items() if tid in targets}
        for sid in sessions:
            self._sessions.pop(sid, None)
            self._page_monitored.discard(sid)
        if self.current_target_id in targets or self.current_session_id in sessions:
            self.current_target_id = None
            self.current_session_id = None
        self._notify(sessions, targets)

    def _notify(self, sessions, targets):
        for cb in list(self.revoke_listeners):
            cb(set(sessions), set(targets))

    def snapshot(self):
        """Comparable view of ownership state (tests: 'does not mutate')."""
        return (self.generation, dict((k, dict(v)) for k, v in self._targets.items()),
                frozenset(self._revoked), dict(self._sessions), frozenset(self._page_monitored),
                self.current_target_id, self.current_session_id)


# ── Parameter validators (model-facing CDP) ──────────────────────────────────
def _require_dict(params):
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise Denied("params must be an object")
    return params


def _only_keys(params, allowed):
    extra = set(params) - set(allowed)
    if extra:
        raise Denied(f"unexpected params: {sorted(extra)}")


def _bool(params, key):
    if key in params and not isinstance(params[key], bool):
        raise Denied(f"{key} must be a boolean")


def _int(params, key, lo, hi):
    if key in params:
        v = params[key]
        if type(v) is not int:  # rejects bool (isinstance(True, int) is True) and floats
            raise Denied(f"{key} must be an integer")
        if v < lo or v > hi:
            raise Denied(f"{key} out of range")


def _finite_number(params, key, lo, hi):
    if key in params:
        v = params[key]
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise Denied(f"{key} must be a number")
        try:
            finite = math.isfinite(v)
        except OverflowError:
            finite = False
        if not finite or v < lo or v > hi:
            raise Denied(f"{key} must be a finite number in range")


def _str(params, key, maxlen=_MAX_SHORT, required=False):
    if key not in params:
        if required:
            raise Denied(f"{key} is required")
        return
    v = params[key]
    if not isinstance(v, str):
        raise Denied(f"{key} must be a string")
    if len(v) > maxlen:
        raise Denied(f"{key} too long")


def _empty(params, method):
    if _require_dict(params):
        raise Denied(f"{method} takes no params")
    return {}


def _v_page_navigate(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"url"})
    _str(p, "url", maxlen=_MAX_URL, required=True)
    if not top_level_url_allowed(p["url"]):
        raise Denied("navigation blocked: only strict http(s) URLs or exactly about:blank")
    return {"url": p["url"]}


def _v_capture_screenshot(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"format", "captureBeyondViewport", "quality"})
    if "format" in p and p["format"] not in ("png", "jpeg", "webp"):
        raise Denied("unsupported screenshot format")
    _bool(p, "captureBeyondViewport")
    _int(p, "quality", 0, 100)
    return dict(p)


def _v_handle_dialog(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"accept", "promptText"})
    if "accept" not in p:
        raise Denied("accept is required")
    _bool(p, "accept")
    _str(p, "promptText")
    return dict(p)


def _v_get_document(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"depth", "pierce"})
    _int(p, "depth", -1, 1000)
    _bool(p, "pierce")
    return dict(p)


def _v_query_selector(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"nodeId", "selector"})
    if "nodeId" not in p:
        raise Denied("nodeId is required")
    _int(p, "nodeId", 1, _MAX_ID)
    _str(p, "selector", required=True)
    return dict(p)


def _v_get_box_model(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"nodeId", "backendNodeId"})
    if ("nodeId" in p) == ("backendNodeId" in p):
        raise Denied("getBoxModel needs exactly one of nodeId / backendNodeId")
    _int(p, "nodeId", 1, _MAX_ID)
    _int(p, "backendNodeId", 1, _MAX_ID)
    return dict(p)


def _v_ax_tree(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"depth"})
    _int(p, "depth", -1, 1000)
    return dict(p)


def _v_runtime_evaluate(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"expression", "returnByValue", "awaitPromise"})
    _str(p, "expression", maxlen=_MAX_STR, required=True)
    _bool(p, "returnByValue")
    _bool(p, "awaitPromise")
    return dict(p)


_MOUSE_TYPES = ("mousePressed", "mouseReleased", "mouseMoved", "mouseWheel")
_MOUSE_BUTTONS = ("none", "left", "middle", "right", "back", "forward")
_KEY_TYPES = ("keyDown", "keyUp", "rawKeyDown", "char")


def _v_mouse(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"type", "x", "y", "button", "clickCount", "deltaX", "deltaY", "modifiers"})
    if p.get("type") not in _MOUSE_TYPES:
        raise Denied("invalid mouse event type")
    if "x" not in p or "y" not in p:
        raise Denied("x and y are required")
    _finite_number(p, "x", 0.0, _COORD_MAX)
    _finite_number(p, "y", 0.0, _COORD_MAX)
    _finite_number(p, "deltaX", -_DELTA_MAX, _DELTA_MAX)
    _finite_number(p, "deltaY", -_DELTA_MAX, _DELTA_MAX)
    _int(p, "clickCount", 0, 10)
    _int(p, "modifiers", 0, 15)
    if "button" in p and p["button"] not in _MOUSE_BUTTONS:
        raise Denied("invalid mouse button")
    return dict(p)


def _v_key(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"type", "key", "code", "text", "modifiers",
                   "windowsVirtualKeyCode", "nativeVirtualKeyCode", "commands"})
    if p.get("type") not in _KEY_TYPES:
        raise Denied("invalid key event type")
    for k in ("key", "code", "text"):
        _str(p, k)
    _int(p, "modifiers", 0, 15)
    _int(p, "windowsVirtualKeyCode", 0, _VK_MAX)
    _int(p, "nativeVirtualKeyCode", 0, _VK_MAX)
    if "commands" in p:
        c = p["commands"]
        if not isinstance(c, list) or len(c) > _MAX_LIST or not all(
                isinstance(x, str) and 0 < len(x) <= 64 for x in c):
            raise Denied("invalid key commands")
    return dict(p)


def _v_insert_text(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"text"})
    _str(p, "text", maxlen=_MAX_STR, required=True)
    return dict(p)


def _v_get_targets(params, reg):
    return _empty(params, "Target.getTargets")


def _v_create_target(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"url", "background", "browserContextId"})
    if p.get("url") != "about:blank":
        raise Denied("Target.createTarget: only exactly about:blank")
    _bool(p, "background")
    # Force the Hermes context — a model-supplied context is never honored.
    out = {"url": "about:blank", "browserContextId": reg.browser_context_id}
    if "background" in p:
        out["background"] = p["background"]
    return out


def _v_attach(params, reg):
    # Only an ALREADY-owned target may be attached (pages from trusted creation,
    # iframes from trusted discovery); the daemon's attach flow then refreshes
    # its live state with trusted calls.
    p = _require_dict(params)
    _only_keys(p, {"targetId", "flatten"})
    _str(p, "targetId", required=True)
    if not reg.target_owned(p["targetId"]):
        raise Denied("target not owned")
    if p.get("flatten") is not True:
        raise Denied("Target.attachToTarget requires flatten=true")
    return {"targetId": p["targetId"], "flatten": True}


def _v_detach(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"sessionId"})
    _str(p, "sessionId", required=True)
    if not reg.session_owned(p["sessionId"]):
        raise Denied("session not owned")
    return {"sessionId": p["sessionId"]}


def _v_owned_page_op(params, reg):
    p = _require_dict(params)
    _only_keys(p, {"targetId"})
    _str(p, "targetId", required=True)
    if reg.target_type(p["targetId"]) != "page":
        raise Denied("target not owned")
    return {"targetId": p["targetId"]}


def _v_get_version(params, reg):
    return _empty(params, "Browser.getVersion")


_VALIDATORS = {
    "Page.navigate": _v_page_navigate,
    "Page.captureScreenshot": _v_capture_screenshot,
    "Page.handleJavaScriptDialog": _v_handle_dialog,
    "DOM.getDocument": _v_get_document,
    "DOM.querySelector": _v_query_selector,
    "DOM.getBoxModel": _v_get_box_model,
    "Accessibility.getFullAXTree": _v_ax_tree,
    "Runtime.evaluate": _v_runtime_evaluate,
    "Input.dispatchMouseEvent": _v_mouse,
    "Input.dispatchKeyEvent": _v_key,
    "Input.insertText": _v_insert_text,
    "Target.getTargets": _v_get_targets,
    "Target.createTarget": _v_create_target,
    "Target.attachToTarget": _v_attach,
    "Target.detachFromTarget": _v_detach,
    "Target.activateTarget": _v_owned_page_op,
    "Target.closeTarget": _v_owned_page_op,
    "Browser.getVersion": _v_get_version,
}


def classify_meta(meta):
    """'model' | 'untrusted' | 'management' | 'unknown' for a meta operation."""
    if meta in MODEL_META:
        return "model"
    if meta in UNTRUSTED_META:
        return "untrusted"
    if meta in MANAGEMENT_META:
        return "management"
    return "unknown"


def _frame_ids(tree):
    """Every frame id in a Page.getFrameTree result (recursive)."""
    out, stack = set(), [tree]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        frame = node.get("frame")
        if isinstance(frame, dict) and isinstance(frame.get("id"), str):
            out.add(frame["id"])
        children = node.get("childFrames")
        if isinstance(children, list):
            stack.extend(children)
    return out


class PolicyEngine:
    """Single policy object held by the daemon in policy mode. ``trusted`` below is
    the daemon's internal CDP channel (``async (method, params, session_id)``); the
    engine only ever passes it ids taken from its own registry (or, for the
    iframe proof, a model-named id whose result is never returned to the model)."""

    def __init__(self, registry=None, daemon_ns=None):
        self.version = POLICY_VERSION
        self.registry = registry if registry is not None else OwnershipRegistry()
        self._daemon_ns = daemon_ns  # cached inode map; None → read live each check
        avail, detail = management_isolation_available()
        self.management_available = avail
        self.management_detail = detail

    # -- management peer gate --
    def check_management_peer(self, peer_sock):
        """(allowed, detail). Denies when isolation is unavailable or the peer is
        not the host (fail closed; a None socket cannot be verified → deny)."""
        if not self.management_available:
            return False, {"reason": "management_isolation_unavailable",
                           "detail": self.management_detail}
        if peer_sock is None:
            return False, {"reason": "no_peer_socket"}
        return verify_host_peer(peer_sock, daemon_ns=self._daemon_ns)

    # -- static validation --
    def validate(self, method, params):
        """Allowlist + strict params + static ownership. Raises Denied; any
        unexpected validator exception is normalized to a controlled Denied."""
        if method not in MODEL_CDP_METHODS:
            raise Denied(f"method not permitted: {method}")
        try:
            return _VALIDATORS[method](params, self.registry)
        except Denied:
            raise
        except Exception as e:  # never let a validator bug fail open or escape
            raise Denied(f"invalid request ({type(e).__name__})") from None

    def check_set_session(self, session_id, target_id):
        """Validate a model set_session as an owned (session, page target) pair."""
        reg = self.registry
        if not isinstance(session_id, str) or not isinstance(target_id, str) or not session_id or not target_id:
            raise Denied("set_session requires session_id and target_id")
        if reg.target_type(target_id) != "page":
            raise Denied("set_session: target not owned")
        if reg.target_for_session(session_id) != target_id:
            raise Denied("set_session: session not owned for that target")

    # -- trusted live-state refresh --
    async def _target_info(self, trusted, target_id):
        try:
            info = (await asyncio.wait_for(trusted("Target.getTargetInfo", {"targetId": target_id}, None),
                                           TRUSTED_TIMEOUT)).get("targetInfo")
        except Exception as e:
            raise Denied(f"trusted state refresh failed ({type(e).__name__})") from None
        if not isinstance(info, dict):
            raise Denied("trusted state refresh returned no target info")
        return info

    def _revoke_deny(self, target_id, why):
        self.registry.revoke_target(target_id)
        raise Denied(why)

    async def refresh_target(self, trusted, target_id, session_id=None, frames=True):
        """Prove the CURRENT live state of an already-owned target before a model
        action. Pages: Target.getTargetInfo (+ Page.getFrameTree on an owned
        session when ``frames``: top-level frame identity == target, URLs agree).
        Iframes: the iframe still exists in the Hermes context and its owning page
        refreshes clean. ``frames=False`` (dialog handling: the renderer is blocked)
        uses only browser-side Target.getTargetInfo. Malformed/unknown/contradictory
        state → DENY + revoke; forbidden active URL → permanent revoke; trusted
        errors/timeouts → DENY (fail closed)."""
        reg = self.registry
        ttype = reg.target_type(target_id)
        if ttype == "iframe":
            chain = reg.parent_chain(target_id)
            if chain is None:
                self._revoke_deny(target_id, "iframe parent chain no longer owned")
            info = await self._target_info(trusted, target_id)
            if (info.get("targetId") != target_id or info.get("type") != "iframe"
                    or not reg.context_matches(info.get("browserContextId"))):
                self._revoke_deny(target_id, "contradictory iframe state")
            root = chain[-1]
            await self.refresh_target(trusted, root, reg.session_for_target(root), frames)
            return info
        if ttype != "page":
            raise Denied("target not owned")
        info = await self._target_info(trusted, target_id)
        if (info.get("targetId") != target_id or info.get("type") != "page"
                or not reg.context_matches(info.get("browserContextId"))):
            self._revoke_deny(target_id, "contradictory target state")
        url = info.get("url")
        if not isinstance(url, str):
            self._revoke_deny(target_id, "unknown top-level URL")
        if session_id is not None and frames:
            try:
                tree = (await asyncio.wait_for(trusted("Page.getFrameTree", {}, session_id),
                                               TRUSTED_TIMEOUT)).get("frameTree")
            except Exception as e:
                raise Denied(f"trusted frame refresh failed ({type(e).__name__})") from None
            frame = tree.get("frame") if isinstance(tree, dict) else None
            if not isinstance(frame, dict) or frame.get("parentId") or frame.get("id") != target_id:
                self._revoke_deny(target_id, "top-level frame identity not proven")
            # CDP Frame.url excludes the fragment (Frame.urlFragment carries it);
            # TargetInfo.url includes it. Anything else is contradictory.
            f_url, frag = frame.get("url"), frame.get("urlFragment") or ""
            if not isinstance(f_url, str) or not isinstance(frag, str) or url not in (f_url, f_url + frag):
                self._revoke_deny(target_id, "contradictory top-level URL")
        if not top_level_url_allowed(url):
            self._revoke_deny(target_id, "forbidden or malformed active URL")
        reg.set_target_url(target_id, url)
        return info

    # -- trusted iframe discovery (the only way an iframe becomes owned) --
    def discovery_candidate(self, method, params):
        """Target id of a not-yet-owned iframe in the Hermes context announced by a
        browser lifecycle event (trusted observation), else None. Grants nothing:
        the daemon must still run ``discover_iframe`` with trusted calls."""
        if method not in ("Target.targetCreated", "Target.targetInfoChanged") or not isinstance(params, dict):
            return None
        info = params.get("targetInfo")
        if not isinstance(info, dict) or info.get("type") != "iframe":
            return None
        tid, reg = info.get("targetId"), self.registry
        if (not isinstance(tid, str) or not tid or reg.target_owned(tid) or reg.is_revoked(tid)
                or not reg.context_matches(info.get("browserContextId"))
                or not isinstance(info.get("parentFrameId"), str)):
            return None
        return tid

    async def _frame_owner(self, trusted, parent_frame, gen):
        """The owned target whose frame tree holds ``parent_frame`` (the frame
        directly, or a same-process child frame of an owned session), with a fully
        owned parent chain and a clean trusted refresh; None if not proven."""
        reg = self.registry
        for owner in sorted(reg.owned_target_ids()):
            if reg.generation != gen or not reg.target_owned(owner) or reg.parent_chain(owner) is None:
                continue
            sid = reg.session_for_target(owner)
            if owner != parent_frame:
                if sid is None:
                    continue
                try:
                    tree = (await asyncio.wait_for(trusted("Page.getFrameTree", {}, sid),
                                                   TRUSTED_TIMEOUT)).get("frameTree")
                except Exception:
                    continue
                if parent_frame not in _frame_ids(tree) or not reg.session_owned(sid):
                    continue
            await self.refresh_target(trusted, owner, sid if reg.target_type(owner) == "page" else None)
            return owner
        return None

    async def discover_iframe(self, trusted, target_id):
        """TRUSTED discovery: register ``target_id`` as an owned iframe only after
        trusted calls prove (a) it is an iframe, (b) in the Hermes browser context,
        (c) whose parentFrameId belongs to an owned page/iframe, (d) whose whole
        parent chain is owned, and the owner refreshes clean. Model input never
        reaches this path. Returns True when registered; Denied/False otherwise."""
        reg = self.registry
        gen = reg.generation
        if not reg.infrastructure_ok() or reg.target_owned(target_id) or reg.is_revoked(target_id):
            return False
        info = await self._target_info(trusted, target_id)
        parent_frame = info.get("parentFrameId")
        if (info.get("targetId") != target_id or info.get("type") != "iframe"
                or not reg.context_matches(info.get("browserContextId"))
                or not isinstance(parent_frame, str) or not parent_frame):
            return False
        owner = await self._frame_owner(trusted, parent_frame, gen)
        if (owner is None or reg.generation != gen or not reg.infrastructure_ok()
                or reg.parent_chain(owner) is None):
            return False
        return reg.add_iframe(target_id, owner, info.get("url"))

    # -- model-visible views (never mutate ownership) --
    def filter_targets(self, result):
        """Target.getTargets post-filter: only targets ALREADY registered as owned."""
        if not isinstance(result, dict):
            return {"targetInfos": []}
        infos = result.get("targetInfos")
        if not isinstance(infos, list):
            return {"targetInfos": []}
        reg = self.registry
        owned = [t for t in infos if isinstance(t, dict) and reg.target_owned(t.get("targetId"))
                 and reg.context_matches(t.get("browserContextId"))]
        return {"targetInfos": owned}

    async def visible_targets(self, trusted, result):
        """Model-visible Target.getTargets: only ALREADY-owned targets in the Hermes
        context, each re-verified by a trusted live refresh (pages with an owned
        session: + frame tree). The entry returned is the FRESH trusted TargetInfo,
        never the possibly stale one from the browser listing. Refresh error/timeout
        hides the entry; forbidden/contradictory state also revokes it (inside
        refresh_target). Never registers anything (no authority from getTargets)."""
        reg = self.registry
        gen = reg.generation
        fresh, seen = [], set()
        for t in self.filter_targets(result)["targetInfos"]:
            tid = t["targetId"]
            if tid in seen or reg.generation != gen or not reg.target_owned(tid):
                continue
            seen.add(tid)
            sid = reg.session_for_target(tid) if reg.target_type(tid) == "page" else None
            try:
                info = await self.refresh_target(trusted, tid, sid)
            except Denied:
                continue
            fresh.append((tid, info))
        if reg.generation != gen:
            return {"targetInfos": []}
        # Re-check after ALL awaits: a later refresh may have revoked an earlier
        # entry (e.g. an iframe's root page).
        return {"targetInfos": [dict(info) for tid, info in fresh
                                if reg.target_owned(tid) and reg.context_matches(info.get("browserContextId"))]}

    # -- event observation (defense in depth / state update) --
    def observe_event(self, method, params, session_id):
        """Fold browser events into ownership state. Never grants authority; only
        updates known URLs or revokes. Raising here is treated as monitoring loss
        by the caller."""
        reg = self.registry
        if not isinstance(params, dict):
            return
        if method == "Page.frameNavigated":
            frame = params.get("frame")
            if not isinstance(frame, dict) or frame.get("parentId"):
                return
            tid = reg.target_for_session(session_id)
            if tid is None or reg.target_type(tid) != "page":
                return
            url = frame.get("url")
            if top_level_url_allowed(url):
                reg.set_target_url(tid, url)
            else:
                reg.revoke_target(tid)
        elif method == "Target.targetInfoChanged":
            info = params.get("targetInfo")
            if not isinstance(info, dict):
                return
            tid = info.get("targetId")
            ttype = reg.target_type(tid)
            if ttype is None:
                return
            if info.get("type") != ttype or not reg.context_matches(info.get("browserContextId")):
                reg.revoke_target(tid)
            elif ttype == "page":
                url = info.get("url")
                if top_level_url_allowed(url):
                    reg.set_target_url(tid, url)
                else:
                    reg.revoke_target(tid)
        elif method in ("Target.targetDestroyed", "Target.targetCrashed"):
            tid = params.get("targetId")
            if reg.target_owned(tid):
                reg.revoke_target(tid)
        elif method == "Target.detachedFromTarget":
            sid = params.get("sessionId")
            if isinstance(sid, str):
                reg.forget_session(sid)

    # -- attestation --
    def attestation(self, live_state=False):
        """``live_state`` is the result of the daemon's trusted live refresh of the
        current pair made for THIS attestation; ``ready`` requires it."""
        reg = self.registry
        g = reg.generation
        infra = reg.infrastructure_ok() and self.management_available
        current_ok = reg.current_pair_valid()
        monitoring = (reg.discovery_generation == g and g > 0 and not reg.monitoring_failed
                      and reg.page_monitored(reg.current_session_id))
        return {
            "policy_mode": True,
            "policy_version": self.version,
            "connected": reg.connected,
            "connection_generation": g,
            "registry_ready": reg.initial_ready,
            "hermes_context_ready": bool(reg.browser_context_id) and reg.context_generation == g and g > 0,
            "download_deny_installed": reg.download_deny_generation == g and g > 0,
            "monitoring_installed": bool(monitoring),
            "management_peer_protection": self.management_available,
            "current_pair_valid": current_ok,
            "live_state_verified": live_state is True,
            "ready": bool(self.version == POLICY_VERSION and infra and current_ok and monitoring
                          and live_state is True),
        }
