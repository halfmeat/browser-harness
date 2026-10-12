"""CDP WS holder + IPC relay (Unix socket on POSIX, TCP loopback on Windows). One daemon per BU_NAME."""
import asyncio, json, os, platform, socket, sys, time, urllib.error, urllib.request
from urllib.parse import urlparse
from collections import deque
from pathlib import Path

from . import _ipc as ipc
from . import auth
from . import cdp_policy  # imported before _load_env(): captures BH_CDP_POLICY from the trusted host env
from . import paths
from cdp_use.client import CDPClient


def _load_env():
    repo_root = Path(__file__).resolve().parents[2]
    workspace = paths.workspace_dir()
    for p in (repo_root / ".env", workspace / ".env"):
        if not p.exists():
            continue
        _load_env_file(p)


def _load_env_file(p):
    for line in p.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env()

# Resolved from the value cdp_policy captured at import, i.e. from the trusted
# host environment BEFORE the workspace .env above could touch it: None =
# upstream-compatible mode, "v1" = hardened policy mode. An unrecognized value
# raises here and the daemon never serves (fail closed).
POLICY_MODE = cdp_policy.resolve_selector(cdp_policy.captured_raw())

# Sentinel: _enforce_policy() returns it when a request is allowed to fall
# through to the normal meta handlers in handle().
_POLICY_PASS = object()
# Budget for ping's trusted live-state check (client ping timeout is 1 s).
_PING_LIVE_TIMEOUT = 0.75

NAME = os.environ.get("BU_NAME", "default")
SOCK = ipc.sock_addr(NAME)
LOG = str(ipc.log_path(NAME))
PID = str(ipc.pid_path(NAME))
BUF = 500
_MAC_PROFILES = (
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Google/Chrome Canary",
    "Library/Application Support/Comet",
    "Library/Application Support/Arc/User Data",
    "Library/Application Support/Dia/User Data",
    "Library/Application Support/Microsoft Edge",
    "Library/Application Support/Microsoft Edge Beta",
    "Library/Application Support/Microsoft Edge Dev",
    "Library/Application Support/Microsoft Edge Canary",
    "Library/Application Support/BraveSoftware/Brave-Browser",
    "Library/Application Support/BraveSoftware/Brave-Origin",
)
_LINUX_PROFILES = (
    ".config/google-chrome",
    ".config/chromium",
    ".config/chromium-browser",
    ".config/microsoft-edge",
    ".config/microsoft-edge-beta",
    ".config/microsoft-edge-dev",
    ".var/app/org.chromium.Chromium/config/chromium",
    ".var/app/com.google.Chrome/config/google-chrome",
    ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
    ".var/app/com.microsoft.Edge/config/microsoft-edge",
)
_WINDOWS_PROFILES = (  # relative to %LOCALAPPDATA%; SxS = Canary channel
    "Google/Chrome/User Data",
    "Google/Chrome SxS/User Data",
    "Google/Chrome Beta/User Data",
    "Google/Chrome Dev/User Data",
    "Chromium/User Data",
    "Microsoft/Edge/User Data",
    "Microsoft/Edge Beta/User Data",
    "Microsoft/Edge Dev/User Data",
    "Microsoft/Edge SxS/User Data",
    "BraveSoftware/Brave-Browser/User Data",
)


def _publish_own_pid(path=PID, pid=None):
    """Atomically retain or publish this daemon's PID record.

    The parent may already have published a process-start fingerprint while
    holding the spawn lock. Never truncate that record: another cold caller
    must not observe an empty PID file and start a sibling daemon.
    """
    pid = pid or os.getpid()
    target = Path(path)
    try:
        published = target.read_text()
        try:
            published_pid = int(json.loads(published)["pid"])
        except (json.JSONDecodeError, TypeError, KeyError):
            published_pid = int(published.split()[0])
    except (FileNotFoundError, OSError, ValueError, IndexError):
        published = str(pid)
        published_pid = pid
    if published_pid != pid:
        published = str(pid)
    tmp = target.with_name(f"{target.name}.{pid}.tmp")
    tmp.write_text(published)
    os.replace(tmp, target)


def profile_dirs(system=None):
    system = system or platform.system()
    if system == "Windows":
        local = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local")
        return [local / p for p in _WINDOWS_PROFILES]
    if system == "Darwin":
        return [Path.home() / p for p in _MAC_PROFILES]
    return [Path.home() / p for p in _LINUX_PROFILES]


PROFILES = profile_dirs()
INTERNAL = ("chrome://", "chrome-untrusted://", "devtools://", "chrome-extension://", "about:")
BU_API = "https://api.browser-use.com/api/v3"
REMOTE_ID = os.environ.get("BU_BROWSER_ID")
_REMOTE_STOPPED = False
BROWSER_KIND = "cloud" if REMOTE_ID else ("cdp" if (os.environ.get("BU_CDP_WS") or os.environ.get("BU_CDP_URL")) else "local")
# Chrome 144+ shows a per-connection popup, and the connection that raised it is
# the only thing keeping it on screen. There is deliberately no approval
# deadline: expiry would drop the sheet and make a later attempt create another
# connection and another prompt. Chrome/process death and explicit cancellation
# still terminate the pending connection.
LOCAL_HANDSHAKE_TIMEOUT = None
# How long get_ws_url() keeps waiting for DevToolsActivePort before giving up
NO_TOGGLE_GRACE = 3
TOGGLE_BOOT_GRACE = 12
# Cancellation should make an in-flight CDP call finish immediately. Keep the
# drain bounded anyway so shutdown fails closed if a client ignores cancellation.
RECOVERY_CANCEL_DRAIN_TIMEOUT = 2
TAB_MARKER_JS = "if(!document.title.startsWith('\U0001F434'))document.title='\U0001F434 '+document.title"


def tab_marker_enabled():
    """Whether the cosmetic controlled-tab title marker should be added."""
    return os.environ.get("BH_TAB_MARKER", "").strip().lower() not in {"0", "false", "no", "off"}


def _devtools_port_live(base):
    """True when something is listening on the profile's DevToolsActivePort port.

    A stale file left behind by a closed browser must not count as a running
    instance — it would route recovery to "click Allow" on a popup that can't
    exist."""
    try:
        port = int((base / "DevToolsActivePort").read_text(encoding="utf-8", errors="replace").splitlines()[0].strip())
    except (OSError, ValueError, IndexError):
        return False
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


def remote_debugging_user_enabled():
    """chrome://inspect's "Allow remote debugging" toggle

    True only when a toggle-on profile also has a live DevTools port.
    False if a profile records it off, None when no profile records it."""
    seen = None
    for base in PROFILES:
        try:
            state = json.loads((base / "Local State").read_text(encoding="utf-8", errors="replace"))
            enabled = ((state.get("devtools") or {}).get("remote_debugging") or {}).get("user-enabled")
        except (OSError, ValueError, AttributeError):
            continue
        if enabled is True and _devtools_port_live(base):
            return True
        if enabled is False:
            seen = False
    return seen


def remote_debugging_toggle_profiles():
    """Profile dirs whose chrome://inspect toggle is recorded on in Local State"""
    out = []
    for base in PROFILES:
        try:
            state = json.loads((base / "Local State").read_text(encoding="utf-8", errors="replace"))
            if ((state.get("devtools") or {}).get("remote_debugging") or {}).get("user-enabled") is True:
                out.append(base)
        except (OSError, ValueError, AttributeError):
            continue
    return out


def browser_running_for_profile(base):
    """True when a running browser instance holds this user-data-dir (POSIX)"""
    try:
        target = os.readlink(str(base / "SingletonLock"))
    except OSError:
        return False
    try:
        pid = int(target.rsplit("-", 1)[-1])
    except ValueError:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True  # pid exists but belongs to another user


def supported_browser_running():
    """Is any browser whose profile we scan actually running?"""
    if platform.system() == "Windows":
        # Chromium on Windows uses a named mutex instead of SingletonLock —
        import subprocess
        try:
            out = subprocess.check_output(["tasklist"], text=True, errors="replace", timeout=5).lower()
        except Exception:
            return True  # can't tell — assume running so recovery stays on the popup/toggle path
        return any(n in out for n in ("chrome.exe", "msedge.exe", "chromium.exe", "brave.exe", "helium.exe"))
    return any(browser_running_for_profile(base) for base in PROFILES)


def log(msg):
    open(LOG, "a", encoding="utf-8", errors="replace").write(f"{msg}\n")


def _safe_connection_label(url):
    """Log only endpoint topology, never CDP credentials or provider session paths."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            return "<redacted-cdp-endpoint>"
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{host}{port}"
    except (TypeError, ValueError):
        return "<redacted-cdp-endpoint>"


async def _silent(coro):
    try:
        await coro
    except Exception:
        pass


def _ws_from_devtools_active_port(http_url: str) -> str | None:
    """When /json/version returns 404 (Chrome 147+ default profile), match DevToolsActivePort by port."""
    p = urlparse(http_url)
    want_port = str(p.port) if p.port else ""
    if not want_port:
        return None
    host = p.hostname or "127.0.0.1"
    if ":" in host:  # urlparse strips IPv6 brackets; restore them for the ws:// URL
        host = f"[{host}]"
    for base in PROFILES:
        try:
            active = (base / "DevToolsActivePort").read_text(encoding="utf-8", errors="replace").splitlines()
        except (FileNotFoundError, NotADirectoryError):
            continue
        port = active[0].strip() if active else ""
        ws_path = active[1].strip() if len(active) > 1 else ""
        if port == want_port and ws_path:
            return f"ws://{host}:{port}{ws_path}"
    return None


def get_ws_url():
    if url := os.environ.get("BU_CDP_WS"):
        return url
    if url := os.environ.get("BU_CDP_URL"):
        # HTTP DevTools endpoint (e.g. http://127.0.0.1:9333) — resolve to ws via /json/version.
        # Use this for a dedicated automation Chrome on a non-default profile, which avoids the
        # M144 "Allow remote debugging" dialog and the M136 default-profile lockdown.
        deadline = time.time() + 30
        last_err = None
        base_url = url.rstrip("/")
        while time.time() < deadline:
            try:
                return json.loads(urllib.request.urlopen(f"{base_url}/json/version", timeout=5).read())["webSocketDebuggerUrl"]
            except urllib.error.HTTPError as e:
                last_err = e
                if e.code == 403:
                    raise RuntimeError("permission-blocked: Chrome is reachable, but the per-session Allow remote debugging popup has not been accepted")
                if e.code == 404 and (ws := _ws_from_devtools_active_port(url)):
                    return ws
                time.sleep(1)
            except Exception as e:
                last_err = e
                time.sleep(1)
        hint = "is the dedicated automation Chrome running? Launch it with --remote-debugging-port=<port> --user-data-dir=<dedicated dir>"
        if platform.system() == "Windows":
            hint += "; on Windows also check that a firewall/antivirus isn't blocking localhost connections"
        raise RuntimeError(f"BU_CDP_URL={url} unreachable after 30s: {last_err} -- {hint}")
    deadline = time.time() + 30
    next_liveness_check = 0.0
    while time.time() < deadline:
        for base in PROFILES:
            try:
                active = (base / "DevToolsActivePort").read_text(encoding="utf-8", errors="replace").splitlines()
            except (FileNotFoundError, NotADirectoryError):
                continue
            port = active[0].strip() if active else ""
            ws_path = active[1].strip() if len(active) > 1 else ""
            if not port:
                continue
            # Resolve the live WS URL via /json/version instead of trusting the path stored
            # alongside the port in DevToolsActivePort: if Chrome was previously launched
            # with a different --user-data-dir on the same port, that file is left behind
            # with a stale browser UUID and the WS upgrade returns 404.
            try:
                return json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1).read())["webSocketDebuggerUrl"]
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    raise RuntimeError("permission-blocked: Chrome is reachable, but the per-session Allow remote debugging popup has not been accepted")
                # Chrome 147+ disables /json/* HTTP discovery on the default user-data-dir;
                # the ws path Chrome wrote to DevToolsActivePort still works.
                if e.code == 404 and ws_path:
                    return f"ws://127.0.0.1:{port}{ws_path}"
            except (OSError, KeyError, ValueError):
                pass
        # Closed browser leaves stale DevToolsActivePort files
        now = time.time()
        if now >= next_liveness_check:
            if not supported_browser_running():
                raise RuntimeError(
                    "chrome-not-running: no supported Chromium-family browser is running -- start Chrome, then retry"
                )
            next_liveness_check = now + 2
        # The browser is running but the port isn't up; waiting 30s
        grace = TOGGLE_BOOT_GRACE if remote_debugging_toggle_profiles() else NO_TOGGLE_GRACE
        if now > deadline - 30 + grace:
            break
        time.sleep(0.2)
    for probe_port in (9222, 9223):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{probe_port}/json/version", timeout=1) as r:
                return json.loads(r.read())["webSocketDebuggerUrl"]
        except urllib.error.HTTPError as e:
            if e.code == 403:
                raise RuntimeError("permission-blocked: Chrome is reachable, but the per-session Allow remote debugging popup has not been accepted")
        except (OSError, KeyError, ValueError):
            continue
    if remote_debugging_user_enabled() is False:
        raise RuntimeError('remote debugging is turned off for this browser instance — enable chrome://inspect/#remote-debugging (tick "Allow remote debugging for this browser instance")')
    raise RuntimeError(f"DevToolsActivePort not found in {[str(p) for p in PROFILES]} — enable chrome://inspect/#remote-debugging, or set BU_CDP_WS for a remote browser")


def stop_remote(strict=False):
    global _REMOTE_STOPPED
    if not REMOTE_ID:
        return True
    if _REMOTE_STOPPED:
        return True
    last_error = None
    for attempt in range(3):
        try:
            key = auth.get_browser_use_api_key()
            req = urllib.request.Request(
                f"{BU_API}/browsers/{REMOTE_ID}",
                data=json.dumps({"action": "stop"}).encode(),
                method="PATCH",
                headers={"X-Browser-Use-API-Key": key, "Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=15).read()
            _REMOTE_STOPPED = True
            log(f"stopped remote browser {REMOTE_ID}")
            return True
        except Exception as e:
            last_error = e
            log(f"stop_remote attempt {attempt + 1}/3 failed ({REMOTE_ID}): {e}")
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
    if strict:
        raise RuntimeError(f"failed to stop remote browser {REMOTE_ID}: {last_error}")
    return False


def is_real_page(t):
    return t["type"] == "page" and not t.get("url", "").startswith(INTERNAL)


def is_reusable_blank_page(t):
    """A plain about:blank tab that is safe to attach to and navigate"""
    url = t.get("url", "")
    return (
        t["type"] == "page"
        and (url == "about:blank" or url.startswith("about:blank#"))
        and not t.get("title", "").startswith("Starting agent ")
    )


def is_inspect_tab(t):
    """A chrome://inspect tab — normally the one the permission flow opened"""
    return t["type"] == "page" and t.get("url", "").startswith("chrome://inspect")


def harness_opened_inspect():
    """True when admin's recovery flow opened a chrome://inspect tab that is
    still awaiting cleanup (the marker survives until the next connect)."""
    try:
        return paths.inspect_marker().exists()
    except OSError:
        return False


def is_reusable_new_tab_page(t):
    """The browser's own New Tab Page, ex: from a fresh launch"""
    return t["type"] == "page" and t.get("url", "").startswith(
        ("chrome://newtab", "chrome://new-tab-page", "edge://newtab", "about:newtab")
    )


class _PatientCDPClient(CDPClient):
    """CDPClient whose local Chrome approval handshake has no deadline."""

    async def start(self):
        import websockets
        if self.ws is not None:
            raise RuntimeError("Client is already started")
        connect_kwargs = {"max_size": self.max_ws_frame_size, "open_timeout": LOCAL_HANDSHAKE_TIMEOUT}
        if self.additional_headers:
            connect_kwargs["additional_headers"] = self.additional_headers
        self.ws = await websockets.connect(self.url, **connect_kwargs)
        self._message_handler_task = asyncio.create_task(self._handle_messages())


class Daemon:
    def __init__(self):
        self.cdp = None
        self.session = None
        self.target_id = None
        self.dedicated_target_id = None
        self._dedicated_target_lock = asyncio.Lock()
        self._session_state_lock = asyncio.Lock()
        self._active_recoveries = 0
        self._recovery_tasks = set()
        self._recoveries_idle = asyncio.Event()
        self._recoveries_idle.set()
        self._shutting_down = False
        self._session_replacements = {}
        self.events = deque(maxlen=BUF)
        self.dialog = None
        self.dialog_session = None
        self.dialog_generation = None  # policy mode: connection generation the dialog was seen in
        self.stop = None  # asyncio.Event, set inside start()
        # In policy mode every IPC request is screened in handle() before any
        # model-origin send_raw; None keeps the daemon upstream-compatible.
        self.policy = None
        self._policy_watch = None
        self._policy_discovering = {}  # iframe target_id -> trusted discovery task
        if POLICY_MODE == cdp_policy.POLICY_VERSION:
            self._attach_policy(cdp_policy.PolicyEngine())

    def _attach_policy(self, engine):
        """Enable policy mode with ``engine`` and wire revocation → meta cleanup."""
        self.policy = engine
        engine.registry.revoke_listeners.append(self._policy_on_revoke)

    async def attach_first_page(self, replaces_session=None, enable_domains=True):
        """Attach to a real page (or any page). Sets self.session. Returns attached target or None."""
        targets = (await self.cdp.send_raw("Target.getTargets"))["targetInfos"]
        # Named daemons (BU_NAME != "default") share one browser with other
        # daemons — attaching to the first page makes parallel daemons fight
        # over a single tab (navigations clobber each other). Give each named
        # daemon its own dedicated tab instead. REMOTE_ID (cloud) browsers are
        # already exclusive to this daemon, so first-page attach stays.
        if NAME != "default" and not REMOTE_ID:
            # The permission recovery flow can leave chrome://inspect open.
            # Clean it up before returning from this early path as well.
            if BROWSER_KIND == "local":
                await self._close_inspect_tabs(targets)
            pages_by_id = {t["targetId"]: t for t in targets if t["type"] == "page"}
            # A stale CDP session does not necessarily mean its tab disappeared.
            # Reattach to the current tab first, then the daemon's dedicated tab.
            page = pages_by_id.get(self.target_id) or pages_by_id.get(self.dedicated_target_id)
            if page is None:
                # Two stale IPC requests can recover concurrently. Recheck
                # inside a narrow lock so they share one replacement tab.
                async with self._dedicated_target_lock:
                    refreshed = (await self.cdp.send_raw("Target.getTargets"))["targetInfos"]
                    pages_by_id = {t["targetId"]: t for t in refreshed if t["type"] == "page"}
                    page = pages_by_id.get(self.target_id) or pages_by_id.get(self.dedicated_target_id)
                    if page is None:
                        tid = (await self.cdp.send_raw(
                            "Target.createTarget", {"url": "about:blank", "background": True}
                        ))["targetId"]
                        self.dedicated_target_id = tid
                        log(f"named daemon {NAME}: created dedicated tab ({tid})")
                        page = {"targetId": tid, "url": "about:blank", "type": "page"}
            tid = page["targetId"]
            self.session = (await self.cdp.send_raw(
                "Target.attachToTarget", {"targetId": tid, "flatten": True}
            ))["sessionId"]
            self._record_session_replacement(replaces_session, self.session)
            self.target_id = tid
            log(f"attached {tid} ({page.get('url','')[:80]}) session={self.session}")
            if enable_domains:
                await self._enable_default_domains(self.session)
            return page

        pages = [t for t in targets if is_real_page(t)]
        if not pages:
            # Fresh browser (ex: BU cloud) starts w about:blank; reuse it
            pages = [t for t in targets if is_reusable_blank_page(t)]
        if not pages:
            # Freshly launched browser (ex: harness relaunching closed Chrome)
            # starts with just the New Tab Page. Reuse it — creating about:blank
            pages = [t for t in targets if is_reusable_new_tab_page(t)]
        take_over = None
        if not pages and harness_opened_inspect():
            # After perms granted, only tab is often chrome://inspect
            # Attach to it instead of creating a new about:blank
            inspect_tabs = [t for t in targets if is_inspect_tab(t)]
            if inspect_tabs:
                pages = [inspect_tabs[0]]
                take_over = inspect_tabs[0]["targetId"]
        if not pages:
            # No usable pages - create one instead of attaching to omnibox popup.
            tid = (await self.cdp.send_raw(
                "Target.createTarget", {"url": "about:blank", "background": True}
            ))["targetId"]
            log(f"no real pages found, created about:blank ({tid})")
            pages = [{"targetId": tid, "url": "about:blank", "type": "page"}]
        self.session = (await self.cdp.send_raw(
            "Target.attachToTarget", {"targetId": pages[0]["targetId"], "flatten": True}
        ))["sessionId"]
        self._record_session_replacement(replaces_session, self.session)
        self.target_id = pages[0]["targetId"]
        log(f"attached {pages[0]['targetId']} ({pages[0].get('url','')[:80]}) session={self.session}")
        if take_over:
            try:
                await self.cdp.send_raw("Page.navigate", {"url": "about:blank"}, session_id=self.session)
                log(f"took over inspect tab {take_over} -> about:blank")
            except Exception as e:
                log(f"take over inspect tab {take_over}: {e}")
        if BROWSER_KIND == "local":
            await self._close_inspect_tabs(targets)
        if enable_domains:
            await self._enable_default_domains(self.session)
        return pages[0]

    async def _close_inspect_tabs(self, targets):
        """Close chrome://inspect tabs left open by the permission recovery flow"""
        if not harness_opened_inspect():
            return
        for t in targets:
            if t["targetId"] != self.target_id and is_inspect_tab(t):
                try:
                    await self.cdp.send_raw("Target.closeTarget", {"targetId": t["targetId"]})
                    log(f"closed leftover chrome://inspect tab {t['targetId']}")
                except Exception as e:
                    log(f"close inspect tab {t['targetId']}: {e}")
        try:
            paths.inspect_marker().unlink()
        except OSError:
            pass

    async def _enable_default_domains(self, session_id):
        """Enable Page/DOM/Runtime/Network on a CDP session.

        Used by both initial attach and set_session (called after switch_tab/
        new_tab). Without this, helpers that depend on Network.* events —
        notably wait_for_network_idle() — silently stop receiving events
        after a tab switch, because each fresh CDP session starts with all
        domains disabled.

        Runs the four enables in parallel via gather so the worst-case time is
        bounded by a single CDP round trip rather than four sequential ones —
        important on the set_session path, where the helper's IPC socket has
        a 5s read timeout.
        """
        async def enable_one(d):
            try:
                await asyncio.wait_for(
                    self.cdp.send_raw(f"{d}.enable", session_id=session_id),
                    timeout=4,
                )
            except Exception as e:
                log(f"enable {d} on {session_id}: {e}")
        await asyncio.gather(*(enable_one(d) for d in ("Page", "DOM", "Runtime", "Network")))

    def _record_session_replacement(self, stale_session, replacement_session):
        """Remember which recovered session still controls the same tab."""
        if not stale_session or not replacement_session or stale_session == replacement_session:
            return
        # Preserve chains so requests delayed across multiple recoveries still
        # land on their original tab, never whichever tab is current now.
        for source, replacement in list(self._session_replacements.items()):
            if replacement == stale_session:
                self._session_replacements[source] = replacement_session
        self._session_replacements[stale_session] = replacement_session
        while len(self._session_replacements) > 32:
            self._session_replacements.pop(next(iter(self._session_replacements)))

    def _begin_recovery(self):
        """Register the current IPC handler unless shutdown has started."""
        if self._shutting_down:
            return None
        task = asyncio.current_task()
        if task is None:
            return None
        self._recovery_tasks.add(task)
        self._active_recoveries += 1
        self._recoveries_idle.clear()
        return task

    def _finish_recovery(self, task):
        self._recovery_tasks.discard(task)
        self._active_recoveries -= 1
        if self._active_recoveries == 0:
            self._recoveries_idle.set()

    async def _cancel_and_drain_recoveries(self):
        """Cancel active stale-session handlers and wait a bounded time."""
        current = asyncio.current_task()
        tasks = [
            task for task in self._recovery_tasks
            if task is not current and not task.done()
        ]
        for task in tasks:
            task.cancel()
        if tasks:
            _done, pending = await asyncio.wait(
                tasks, timeout=RECOVERY_CANCEL_DRAIN_TIMEOUT
            )
            if pending:
                return False
        return self._recoveries_idle.is_set()

    def _schedule_tab_marker(self, session_id):
        """Mark the controlled tab without extending the synchronous IPC path."""
        if not tab_marker_enabled():
            return None
        # Policy mode: only ever touch the current, valid, owned page.
        if self.policy is not None:
            reg = self.policy.registry
            if session_id is None or session_id != reg.current_session_id or not reg.current_pair_valid():
                return None
        return asyncio.create_task(_silent(asyncio.wait_for(
            self.cdp.send_raw(
                "Runtime.evaluate",
                {"expression": TAB_MARKER_JS},
                session_id=session_id,
            ),
            timeout=2,
        )))

    def _record_event(self, method, params, session_id=None):
        if self.policy is not None:
            self._policy_observe(method, params, session_id)
            # Policy mode buffers/surfaces only events of currently owned sessions:
            # browser-level and foreign/revoked-session events never reach the model.
            if not (isinstance(session_id, str) and self.policy.registry.session_owned(session_id)):
                return
        self.events.append({"method": method, "params": params, "session_id": session_id})
        if method == "Page.javascriptDialogOpening":
            self.dialog = params
            self.dialog_session = session_id
            self.dialog_generation = self.policy.registry.generation if self.policy is not None else None
        elif method == "Page.javascriptDialogClosed":
            if self.policy is None or self.dialog_session == session_id:
                self.dialog = None
                self.dialog_session = None
        elif method in ("Page.loadEventFired", "Page.domContentEventFired"):
            self._schedule_tab_marker(self.session)

    def _install_event_tap(self):
        orig = self.cdp._event_registry.handle_event
        async def tap(method, params, session_id=None):
            self._record_event(method, params, session_id)
            return await orig(method, params, session_id)
        self.cdp._event_registry.handle_event = tap

    async def _new_cdp_client(self):
        # get_ws_url() may poll (urllib + time.sleep) until the browser is back;
        # run it off the event-loop thread so IPC (ping → ready=false) stays responsive.
        url = await asyncio.to_thread(get_ws_url)
        log(f"connecting to {_safe_connection_label(url)}")
        cdp = _PatientCDPClient(url) if BROWSER_KIND == "local" else CDPClient(url)
        await cdp.start()
        return cdp

    async def start(self):
        self.stop = asyncio.Event()
        url = get_ws_url()
        log(f"connecting to {_safe_connection_label(url)}")
        self.cdp = _PatientCDPClient(url) if BROWSER_KIND == "local" else CDPClient(url)
        if BROWSER_KIND == "local":
            # Allow while this handshake is still parked on the popup
            log("handshake-wait: if Chrome shows an 'Allow remote debugging?' popup, click Allow")
        try:
            await self.cdp.start()
        except Exception as e:
            if os.environ.get("BU_CDP_WS"):
                raise RuntimeError(
                    f"CDP WS handshake failed: {e} -- remote browser WebSocket connection failed. "
                    "This can happen when network policy blocks the connection, the WS URL is wrong or expired, or the remote endpoint is down. "
                    "If you use Browser Use cloud, verify auth and get a fresh URL via start_remote_daemon()."
                )
            if BROWSER_KIND == "local" and ("timed out" in str(e).lower() or "403" in str(e)) and remote_debugging_user_enabled():
                raise RuntimeError(
                    "permission-blocked: Chrome did not approve the remote debugging connection; "
                    "browser-harness did not retry or create another connection"
                )
            raise RuntimeError(f"CDP WS handshake failed: {e} -- click Allow in Chrome if prompted, then retry")
        if self.policy is not None:
            # Monitoring is live BEFORE policy can become ready.
            self._install_event_tap()
            await self._start_policy()
            self._policy_watch = asyncio.create_task(self._watch_policy_connection())
        else:
            await self.attach_first_page()
            self._install_event_tap()

    # ── policy mode (BH_CDP_POLICY=v1) ───────────────────────────────────────
    async def _trusted_send(self, method, params=None, session_id=None):
        """Daemon-internal (trusted) CDP channel. Never reachable from IPC input:
        only daemon code chooses the method, and ids come from the registry."""
        return await self.cdp.send_raw(method, params or {}, session_id=session_id)

    async def _enable_policy_monitoring(self, session_id):
        """Page.enable is CRITICAL in policy mode (navigation + dialog monitoring):
        failure raises. The remaining default domains are best effort."""
        await asyncio.wait_for(self._trusted_send("Page.enable", {}, session_id), timeout=4)
        self.policy.registry.mark_page_monitored(session_id)

        async def enable_one(d):
            try:
                await asyncio.wait_for(self._trusted_send(f"{d}.enable", {}, session_id), timeout=4)
            except Exception as e:
                log(f"enable {d} on {session_id}: {e}")
        await asyncio.gather(*(enable_one(d) for d in ("DOM", "Runtime", "Network")))

    async def _start_policy(self):
        """Hardened policy-mode startup contract. Each step is a TRUSTED internal
        CDP call; any failure raises so the generation never becomes ready with a
        partial policy (fail closed, no unrestricted fallback).

        Order: create a separate Hermes browser context → install download-deny
        on it → enable target lifecycle monitoring → create about:blank inside it
        and confirm it → register → attach → register session → critical Page
        monitoring → current pair → ready. Never attaches to a pre-existing page."""
        pol, reg = self.policy, self.policy.registry
        if not pol.management_available:
            raise RuntimeError(
                f"policy v1 fail-closed: management peer isolation unavailable on this "
                f"platform ({pol.management_detail})"
            )
        send = self._trusted_send
        ctx = (await send("Target.createBrowserContext", {}))["browserContextId"]
        reg.begin_generation(ctx)
        gen = reg.generation
        # Deny downloads for the whole Hermes context. No downloadPath. Model IPC
        # can never reach this method (not allowlisted).
        await send("Browser.setDownloadBehavior", {
            "behavior": "deny", "browserContextId": ctx, "eventsEnabled": True})
        reg.download_deny_generation = gen
        await send("Target.setDiscoverTargets", {"discover": True})
        reg.discovery_generation = gen
        tid = (await send("Target.createTarget", {
            "url": "about:blank", "browserContextId": ctx, "background": True}))["targetId"]
        info = (await send("Target.getTargetInfo", {"targetId": tid})).get("targetInfo") or {}
        if (info.get("targetId") != tid or info.get("type") != "page"
                or not reg.context_matches(info.get("browserContextId")) or info.get("url") != "about:blank"):
            raise RuntimeError("policy v1 fail-closed: initial Hermes page not confirmed in the Hermes context")
        if not reg.add_page(tid, "about:blank"):
            raise RuntimeError("policy v1 fail-closed: could not register initial Hermes target")
        sid = (await send("Target.attachToTarget", {"targetId": tid, "flatten": True}))["sessionId"]
        if not reg.register_session(sid, tid):
            raise RuntimeError("policy v1 fail-closed: could not register initial Hermes session")
        try:
            await self._enable_policy_monitoring(sid)
        except Exception as e:
            raise RuntimeError(f"policy v1 fail-closed: critical Page monitoring failed: {e}") from None
        if reg.generation != gen or not reg.session_owned(sid):
            raise RuntimeError("policy v1 fail-closed: ownership changed during startup")
        reg.set_current(sid, tid)
        self.session = sid
        self.target_id = tid
        reg.initial_ready = True
        log(f"policy v1 ready: context={ctx} generation={gen}")

    def _policy_observe(self, method, params, session_id):
        try:
            self.policy.observe_event(method, params, session_id)
            candidate = self.policy.discovery_candidate(method, params)
        except Exception as e:  # a broken monitor must never fail open
            self.policy.registry.monitoring_failed = True
            log(f"policy: event monitoring failed ({type(e).__name__}); not ready")
            return
        if candidate is not None and candidate not in self._policy_discovering:
            self._policy_discovering[candidate] = asyncio.create_task(self._policy_discover(candidate))

    async def _policy_discover(self, target_id):
        """TRUSTED iframe discovery, triggered only by browser lifecycle events.
        This — not model-origin Target.getTargets or attach — is what registers an
        iframe (after the parent-chain proof in PolicyEngine.discover_iframe)."""
        try:
            if await self.policy.discover_iframe(self._trusted_send, target_id):
                log(f"policy: iframe {target_id} registered by trusted discovery")
        except cdp_policy.Denied as e:
            log(f"policy: iframe {target_id} not registered ({e})")
        except Exception as e:
            log(f"policy: iframe discovery error ({type(e).__name__}); not registered")
        finally:
            self._policy_discovering.pop(target_id, None)

    async def _policy_cancel_discovery(self):
        tasks = list(self._policy_discovering.values())
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

    def _policy_on_revoke(self, sessions, targets):
        """Ownership lost: drop model-visible meta state tied to it."""
        if sessions:
            self.events = deque((e for e in self.events if e.get("session_id") not in sessions), maxlen=BUF)
            if self.dialog_session in sessions:
                self.dialog = None
                self.dialog_session = None
        if self.policy.registry.current_session_id is None:
            self.session = None
            self.target_id = None

    async def _watch_policy_connection(self):
        """Policy mode: a dropped CDP connection immediately makes the policy
        not-ready, then a full policy reinstall is attempted on a new connection."""
        while not self._shutting_down:
            task = getattr(self.cdp, "_message_handler_task", None)
            if task is None:
                return
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                if not task.done():
                    raise
            except Exception:
                pass
            if self._shutting_down:
                return
            self._policy_connection_lost()
            if not await self._policy_reconnect():
                return

    def _policy_connection_lost(self):
        self.policy.registry.mark_disconnected()
        self.session = None
        self.target_id = None
        log("policy: CDP connection lost; not ready until the policy is reinstalled")

    async def _policy_reconnect(self, attempts=3):
        """New connection → new generation → new Hermes context → download-deny →
        monitoring → owned page/session → only then ready. Never adopts a foreign
        tab. On failure the policy stays not-ready (fail closed)."""
        reg = self.policy.registry
        old_ctx = reg.browser_context_id
        for attempt in range(attempts):
            if self._shutting_down:
                return False
            try:
                self.cdp = await self._new_cdp_client()
                self._install_event_tap()
                await self._start_policy()
                if old_ctx and old_ctx != reg.browser_context_id:
                    try:
                        await self._trusted_send("Target.disposeBrowserContext", {"browserContextId": old_ctx})
                    except Exception:
                        pass
                log(f"policy: reconnected, generation={reg.generation}")
                return True
            except Exception as e:
                log(f"policy: reconnect attempt {attempt + 1}/{attempts} failed: {e}")
                failed_ctx = reg.browser_context_id
                reg.mark_disconnected()
                if failed_ctx and failed_ctx != old_ctx and self.cdp is not None:
                    await self._trusted_cleanup("Target.disposeBrowserContext", {"browserContextId": failed_ctx})
                await asyncio.sleep(min(2 ** attempt, 5))
        return False

    def _policy_current_dialog_open(self):
        """A JS dialog is CONFIRMED open on the current owned pair: reported by
        Page.javascriptDialogOpening on the current, owned, Page-monitored session
        in this connection generation (foreign/revoked sessions never record a
        dialog) and not yet closed. Only this enables ping's degraded check."""
        reg = self.policy.registry
        sid = reg.current_session_id
        return (self.dialog is not None and sid is not None and self.dialog_session == sid
                and self.dialog_generation == reg.generation and reg.page_monitored(sid)
                and reg.current_pair_valid())

    async def _policy_live_check(self):
        """Trusted live refresh of the current (session, page) pair for the ping
        attestation, bounded so ping stays responsive. FULL refresh
        (Target.getTargetInfo + Page.getFrameTree identity/URL) unless a dialog is
        confirmed open on the current owned pair: the dialog blocks the renderer,
        so only then the degraded browser-side Target.getTargetInfo check is used.
        Any doubt → False; forbidden/contradictory state is revoked by the refresh."""
        reg = self.policy.registry
        if not reg.infrastructure_ok() or not reg.current_pair_valid():
            return False
        tid, sid, gen = reg.current_target_id, reg.current_session_id, reg.generation
        frames = not self._policy_current_dialog_open()
        try:
            await asyncio.wait_for(
                self.policy.refresh_target(self._trusted_send, tid, sid, frames=frames), _PING_LIVE_TIMEOUT)
        except Exception:
            return False
        return (self._token_ok(gen, sid, tid) and reg.current_target_id == tid
                and reg.current_session_id == sid and reg.current_pair_valid())

    def _token_ok(self, gen, session_id=None, target_id=None):
        """Revalidated after every await of a model operation."""
        reg = self.policy.registry
        return (reg.generation == gen and reg.infrastructure_ok()
                and (session_id is None or reg.session_owned(session_id))
                and (target_id is None or reg.target_owned(target_id)))

    async def _model_send(self, method, params, session_id=None):
        """The single model-origin dispatch, reached only after validation,
        ownership and trusted state checks. Returns (ok, result_or_error)."""
        try:
            return True, await self.cdp.send_raw(method, params, session_id=session_id)
        except Exception as e:
            return False, str(e)

    async def _trusted_cleanup(self, method, params):
        try:
            await asyncio.wait_for(self._trusted_send(method, params), timeout=5)
        except Exception as e:
            log(f"policy: trusted cleanup {method} failed: {e}")

    async def _enforce_policy(self, req, meta, peer):
        """Screen one model-origin IPC request. Returns ``_POLICY_PASS`` only for a
        management meta whose peer passed the kernel check; everything else
        (including ``ping`` with its live attestation) is fully handled here. A denied request performs ZERO
        privileged action. Unexpected errors are normalized to a controlled deny
        (never left to the outer serve() handler)."""
        try:
            return await self._policy_dispatch(req, meta, peer)
        except cdp_policy.Denied as d:
            return {"error": f"policy: {d}"}
        except Exception as e:
            log(f"policy: internal error, request denied ({type(e).__name__}: {e})")
            return {"error": "policy: request denied (internal error)"}

    async def _policy_dispatch(self, req, meta, peer):
        pol, reg = self.policy, self.policy.registry
        if meta is not None:
            kind = cdp_policy.classify_meta(meta)
            if kind == "management":
                ok, detail = pol.check_management_peer(peer)
                if not ok:
                    log(f"policy: management meta {meta!r} denied ({detail.get('reason')})")
                    return {"error": "management request denied by policy"}
                return _POLICY_PASS
            if kind == "untrusted":
                return await self._policy_set_session(req)
            if kind == "model":
                if meta == "ping":
                    live = await self._policy_live_check()
                    return {"pong": True, "pid": os.getpid(), "browser_kind": BROWSER_KIND,
                            "policy": pol.attestation(live_state=live)}
                return await self._policy_model_meta(meta)
            raise cdp_policy.Denied(f"meta not permitted: {meta}")
        method = req.get("method")
        if not isinstance(method, str):
            raise cdp_policy.Denied("request had neither a known meta nor a method")
        if not reg.infrastructure_ok():
            raise cdp_policy.Denied("policy not operational (not ready)")
        norm = pol.validate(method, req.get("params"))
        session_id = req.get("session_id")
        if session_id is not None and not isinstance(session_id, str):
            raise cdp_policy.Denied("session_id must be a string")
        if method in cdp_policy.SESSION_SCOPED:
            return await self._policy_session_call(method, norm, session_id)
        if method in ("Target.getTargets", "Browser.getVersion"):
            gen = reg.generation
            ok, res = await self._model_send(method, norm)
            if not ok:
                return {"error": res}
            if method == "Target.getTargets":
                # Every owned entry passes a trusted live refresh before exposure.
                res = await pol.visible_targets(self._trusted_send, res)
                if not self._token_ok(gen):
                    raise cdp_policy.Denied("connection changed during target listing")
            return {"result": res}
        handler = {
            "Target.createTarget": self._policy_create_target,
            "Target.attachToTarget": self._policy_attach,
            "Target.detachFromTarget": self._policy_detach,
            "Target.activateTarget": self._policy_activate,
            "Target.closeTarget": self._policy_close,
        }.get(method)
        if handler is None:
            raise cdp_policy.Denied(f"method not permitted: {method}")
        return await handler(norm)

    async def _policy_session_call(self, method, norm, session_id):
        pol, reg = self.policy, self.policy.registry
        explicit = session_id is not None
        sid = session_id if explicit else reg.current_session_id
        if sid is None or not reg.session_owned(sid):
            raise cdp_policy.Denied("session not owned")
        if not explicit and not reg.current_pair_valid():
            raise cdp_policy.Denied("no valid owned current page")
        tid = reg.target_for_session(sid)
        gen = reg.generation
        # An open JS dialog blocks the renderer, so Page.getFrameTree could hang;
        # dialog handling refreshes via browser-side Target.getTargetInfo only.
        await pol.refresh_target(self._trusted_send, tid, sid,
                                 frames=method != "Page.handleJavaScriptDialog")
        if not self._token_ok(gen, sid, tid):
            raise cdp_policy.Denied("ownership changed during state refresh")
        ok, res = await self._model_send(method, norm, sid)
        if not self._token_ok(gen, sid, tid):
            raise cdp_policy.Denied("ownership lost during call; result discarded")
        return {"result": res} if ok else {"error": res}

    async def _policy_create_target(self, norm):
        pol, reg = self.policy, self.policy.registry
        gen = reg.generation
        ok, res = await self._model_send("Target.createTarget", norm)
        if not ok:
            return {"error": res}
        tid = res.get("targetId") if isinstance(res, dict) else None
        if not isinstance(tid, str) or not tid:
            raise cdp_policy.Denied("createTarget returned no target")
        try:
            if not self._token_ok(gen):
                raise cdp_policy.Denied("connection changed; new target discarded")
            info = await pol._target_info(self._trusted_send, tid)
            if (info.get("targetId") != tid or info.get("type") != "page"
                    or not reg.context_matches(info.get("browserContextId")) or info.get("url") != "about:blank"):
                raise cdp_policy.Denied("new target not confirmed in the Hermes context")
            if not self._token_ok(gen) or not reg.add_page(tid, "about:blank"):
                raise cdp_policy.Denied("ownership changed; new target discarded")
        except cdp_policy.Denied:
            await self._trusted_cleanup("Target.closeTarget", {"targetId": tid})
            raise
        return {"result": res}

    async def _policy_attach(self, norm):
        pol, reg = self.policy, self.policy.registry
        tid = norm["targetId"]
        # Only an already-registered target (trusted creation / trusted iframe
        # discovery). A model-named unknown id is never proven or adopted here.
        if not reg.target_owned(tid):
            raise cdp_policy.Denied("target not owned")
        gen = reg.generation
        sid_for_refresh = reg.session_for_target(tid) if reg.target_type(tid) == "page" else None
        await pol.refresh_target(self._trusted_send, tid, sid_for_refresh)
        if not self._token_ok(gen, target_id=tid):
            raise cdp_policy.Denied("ownership changed before attach")
        ok, res = await self._model_send("Target.attachToTarget", norm)
        if not ok:
            return {"error": res}
        sid = res.get("sessionId") if isinstance(res, dict) else None
        if not isinstance(sid, str) or not sid:
            raise cdp_policy.Denied("attach returned no session")
        committed = self._token_ok(gen, target_id=tid) and reg.register_session(sid, tid)
        if not committed:
            await self._trusted_cleanup("Target.detachFromTarget", {"sessionId": sid})
            raise cdp_policy.Denied("ownership changed during attach; session discarded")
        return {"result": res}

    async def _policy_detach(self, norm):
        pol, reg = self.policy, self.policy.registry
        sid = norm["sessionId"]
        tid = reg.target_for_session(sid)
        if tid is None:
            raise cdp_policy.Denied("session not owned")
        gen = reg.generation
        # Same live-state proof as every other model action on an owned target.
        await pol.refresh_target(self._trusted_send, tid, sid)
        if not self._token_ok(gen, sid, tid) or reg.target_for_session(sid) != tid:
            raise cdp_policy.Denied("ownership changed during state refresh")
        ok, res = await self._model_send("Target.detachFromTarget", norm)
        if ok and reg.generation == gen:
            reg.forget_session(sid)
        return {"result": res} if ok else {"error": res}

    async def _policy_activate(self, norm):
        pol, reg = self.policy, self.policy.registry
        tid = norm["targetId"]
        gen = reg.generation
        await pol.refresh_target(self._trusted_send, tid, reg.session_for_target(tid))
        if not self._token_ok(gen, target_id=tid):
            raise cdp_policy.Denied("ownership changed during state refresh")
        ok, res = await self._model_send("Target.activateTarget", norm)
        if not self._token_ok(gen, target_id=tid):
            raise cdp_policy.Denied("ownership lost during call; result discarded")
        return {"result": res} if ok else {"error": res}

    async def _policy_close(self, norm):
        pol, reg = self.policy, self.policy.registry
        tid = norm["targetId"]
        gen = reg.generation
        await pol.refresh_target(self._trusted_send, tid, reg.session_for_target(tid))
        if not self._token_ok(gen, target_id=tid):
            raise cdp_policy.Denied("ownership changed during state refresh")
        ok, res = await self._model_send("Target.closeTarget", norm)
        if ok and reg.generation == gen:
            reg.revoke_target(tid)  # closed → permanently gone, with every descendant
        return {"result": res} if ok else {"error": res}

    async def _policy_set_session(self, req):
        """Untrusted meta: switch the current page only to an owned (session, page)
        pair that passes a trusted live-state refresh and gets critical Page
        monitoring installed."""
        pol, reg = self.policy, self.policy.registry
        if not reg.infrastructure_ok():
            raise cdp_policy.Denied("policy not operational (not ready)")
        sid, tid = req.get("session_id"), req.get("target_id")
        pol.check_set_session(sid, tid)
        gen = reg.generation
        await pol.refresh_target(self._trusted_send, tid, sid)
        if not self._token_ok(gen, sid, tid):
            raise cdp_policy.Denied("ownership changed during state refresh")
        if not reg.page_monitored(sid):
            try:
                await self._enable_policy_monitoring(sid)
            except Exception:
                raise cdp_policy.Denied("critical page monitoring could not be installed") from None
            if not self._token_ok(gen, sid, tid) or not reg.page_monitored(sid):
                raise cdp_policy.Denied("ownership changed during monitoring setup")
        reg.set_current(sid, tid)
        self.session = sid
        self.target_id = tid
        self._schedule_tab_marker(sid)
        return {"session_id": sid}

    async def _policy_model_meta(self, meta):
        """Model-safe meta with ownership filtering; nothing stale/foreign leaks."""
        pol, reg = self.policy, self.policy.registry
        if meta == "drain_events":
            out = [e for e in self.events
                   if isinstance(e.get("session_id"), str) and reg.session_owned(e["session_id"])]
            self.events.clear()
            return {"events": out}
        if meta == "pending_dialog":
            visible = (self.dialog is not None and self.dialog_session is not None
                       and self.dialog_session == reg.current_session_id and reg.current_pair_valid())
            return {"dialog": self.dialog if visible else None}
        if not reg.infrastructure_ok() or not reg.current_pair_valid():
            raise cdp_policy.Denied("no valid owned current page")
        if meta == "session":
            return {"session_id": reg.current_session_id}
        # current_tab: consume a trusted live-state refresh of the owned current page
        tid, sid, gen = reg.current_target_id, reg.current_session_id, reg.generation
        info = await pol.refresh_target(self._trusted_send, tid, sid)
        if not self._token_ok(gen, sid, tid) or reg.current_target_id != tid or not reg.current_pair_valid():
            raise cdp_policy.Denied("current page changed")
        return {"targetId": tid, "url": info.get("url", ""), "title": info.get("title", "")}

    async def handle(self, req, peer=None):
        # Token guard for Windows TCP loopback: any local process can otherwise
        # connect and issue CDP commands. expected_token() is None on POSIX so
        # this check is a no-op there (AF_UNIX + chmod 600 is the boundary).
        expected = ipc.expected_token()
        if expected is not None and req.get("token") != expected:
            return {"error": "unauthorized"}
        meta = req.get("meta")
        # Policy mode: screen EVERY request before any model-origin send_raw.
        # ``peer`` is the connecting socket (host-peer identity for management
        # meta). Non-policy mode leaves behavior exactly as upstream.
        if self.policy is not None:
            decision = await self._enforce_policy(req, meta, peer)
            if decision is not _POLICY_PASS:
                return decision
        # Liveness probe — lets clients confirm the listener is actually this
        # daemon and not an unrelated process that reused our port post-crash.
        # `pid` lets restart_daemon() verify the live daemon's identity before
        # signaling — protects against SIGTERM-by-stale-pid-file after PID reuse.
        if meta == "ping":        return {"pong": True, "pid": os.getpid(), "browser_kind": BROWSER_KIND}
        if meta == "drain_events":
            out = list(self.events); self.events.clear()
            return {"events": out}
        if meta == "session":     return {"session_id": self.session}
        if meta == "current_tab":
            # Resolve the attached page's target info server-side. Helpers can't
            # send Target.getTargetInfo themselves: daemon strips session_id for
            # any Target.* method (browser-level call), and without a targetId
            # Chrome silently returns the *browser* target.
            if not self.target_id:
                return {"error": "not_attached"}
            try:
                info = (await self.cdp.send_raw("Target.getTargetInfo", {"targetId": self.target_id}))["targetInfo"]
            except Exception:
                return {"error": "cdp_disconnected"}
            return {"targetId": info.get("targetId"), "url": info.get("url", ""), "title": info.get("title", "")}
        if meta == "connection_status":
            if not self.target_id:
                return {"error": "not_attached"}
            try:
                info = (await self.cdp.send_raw("Target.getTargetInfo", {"targetId": self.target_id}))["targetInfo"]
            except Exception:
                return {"error": "cdp_disconnected"}
            page = None
            if is_real_page(info):
                page = {
                    "targetId": info.get("targetId"),
                    "title": info.get("title") or "(untitled)",
                    "url": info.get("url") or "",
                }
            return {"target_id": self.target_id, "session_id": self.session, "page": page}
        if meta == "set_session":
            async with self._session_state_lock:
                old_session = self.session
                self.session = req.get("session_id")
                self.target_id = req.get("target_id") or self.target_id
                new_session = self.session
            # Run the old-session Network.disable (defense in depth — keeps
            # background-tab traffic out of the global event buffer; the
            # consumer-side filter in wait_for_network_idle is the actual
            # correctness gate) in parallel with the four enables on the new
            # session. Different sessions, independent CDP requests. Keeps
            # the synchronous reply under the helper's 5s IPC read timeout
            # even on a remote daemon — sequentially these would have stacked
            # to ~22s worst case.
            tasks = []
            if old_session and old_session != new_session:
                async def disable_old():
                    try:
                        await asyncio.wait_for(
                            self.cdp.send_raw("Network.disable", session_id=old_session),
                            timeout=2,
                        )
                    except Exception: pass
                tasks.append(disable_old())
            tasks.append(self._enable_default_domains(new_session))
            await asyncio.gather(*tasks)
            # 🐴 tab-marker title prefix is purely cosmetic — fire-and-forget so
            # it doesn't add to the synchronous IPC budget.
            self._schedule_tab_marker(new_session)
            return {"session_id": new_session}
        if meta == "pending_dialog": return {"dialog": self.dialog}
        if meta == "shutdown":
            # Flip the barrier synchronously with recovery registration, then
            # cancel/drain existing handlers. In particular, a CDP replay that
            # never answers must not prevent Cloud cleanup from being attempted.
            if self._shutting_down:
                return {"error": "shutdown already in progress"}
            self._shutting_down = True
            if not await self._cancel_and_drain_recoveries():
                # Preserve the daemon as a retryable cleanup authority. The
                # strict caller will leave its endpoint and PID file intact.
                self._shutting_down = False
                return {"error": "stale-session recovery did not stop"}
            try:
                stop_remote(strict=True)
            except Exception as e:
                # A failed Cloud stop must leave the daemon usable so a later
                # shutdown request can retry the billable-browser cleanup.
                async with self._session_state_lock:
                    self._shutting_down = False
                return {"error": str(e)}
            self.stop.set()
            return {"ok": True}

        method = req["method"]
        params = req.get("params") or {}
        # Browser-level Target.* calls must not use a session (stale or otherwise).
        # For everything else, explicit session in req wins; else default.
        sid = None if method.startswith("Target.") else (req.get("session_id") or self.session)
        try:
            return {"result": await self.cdp.send_raw(method, params, session_id=sid)}
        except Exception as e:
            msg = str(e)
            if "Session with given id not found" in msg and sid:
                # Explicit session callers asked for that exact session; do not
                # silently redirect them to the daemon's current tab.
                if req.get("session_id"):
                    return {"error": msg}
                recovery_task = self._begin_recovery()
                if recovery_task is None:
                    return {"error": "daemon is shutting down"}
                try:
                    recovered_here = False
                    async with self._session_state_lock:
                        if self._shutting_down:
                            return {"error": "daemon is shutting down"}
                        replacement_session = self._session_replacements.get(sid)
                        if replacement_session is None and sid == self.session:
                            log(f"stale session {sid}, re-attaching")
                            if not await self.attach_first_page(
                                replaces_session=sid, enable_domains=False
                            ):
                                return {"error": msg}
                            replacement_session = self._session_replacements.get(sid)
                            recovered_here = replacement_session is not None
                    if recovered_here:
                        await self._enable_default_domains(replacement_session)
                    # Retry only on a session known to replace this exact stale
                    # session. self.session may instead have changed because the
                    # user deliberately switched tabs while this request waited.
                    if replacement_session:
                        try:
                            return {"result": await self.cdp.send_raw(
                                method, params, session_id=replacement_session
                            )}
                        except Exception as retry_error:
                            return {"error": str(retry_error)}
                finally:
                    self._finish_recovery(recovery_task)
            return {"error": msg}


async def serve(d):
    async def handler(reader, writer):
        try:
            line = await reader.readline()
            if not line: return
            # The connecting socket carries the peer's kernel identity (uid +
            # pid/net/mnt namespaces) used to gate management meta in policy mode.
            peer = writer.get_extra_info("socket")
            resp = await d.handle(json.loads(line), peer=peer)
            writer.write((json.dumps(resp, default=str) + "\n").encode())
            await writer.drain()
        except Exception as e:
            log(f"conn: {e}")
            try:
                writer.write((json.dumps({"error": str(e)}) + "\n").encode())
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()

    serve_task = asyncio.create_task(ipc.serve(NAME, handler))
    stop_task = asyncio.create_task(d.stop.wait())
    await asyncio.sleep(0.05)  # let serve() bind so sock_addr() resolves to the live endpoint
    log(f"listening on {ipc.sock_addr(NAME)} (name={NAME}, remote={REMOTE_ID or 'local'})")
    try:
        await asyncio.wait({serve_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
        if serve_task.done(): await serve_task  # surfaces a serve crash
    finally:
        for t in (serve_task, stop_task):
            t.cancel()
            try: await t
            except (asyncio.CancelledError, Exception): pass
        # A server crash/cancellation does not pass through meta=shutdown.
        # Establish the same recovery barrier before touching owned targets.
        d._shutting_down = True
        recoveries_drained = await d._cancel_and_drain_recoveries()
        # Named non-cloud daemons create one dedicated background tab. Shutdown
        # has blocked new recovery and drained active recovery before setting
        # d.stop (or finalization established the barrier after a server crash).
        # Take the same locks, in the same order as recovery, so cleanup closes
        # exactly the final daemon-owned target and never races creation.
        if recoveries_drained:
            async with d._session_state_lock:
                async with d._dedicated_target_lock:
                    if d.dedicated_target_id and d.cdp:
                        try:
                            await d.cdp.send_raw(
                                "Target.closeTarget", {"targetId": d.dedicated_target_id}
                            )
                            d.dedicated_target_id = None
                        except Exception as e:
                            log(f"close dedicated tab on shutdown: {e}")
        else:
            log("skip dedicated-tab cleanup: stale-session recovery did not stop")
        if d.policy is not None:
            # Stop connection watching (no reconnect during shutdown) and drop the
            # Hermes context with its tabs; best effort.
            if d._policy_watch is not None:
                d._policy_watch.cancel()
                try:
                    await d._policy_watch
                except (asyncio.CancelledError, Exception):
                    pass
            await d._policy_cancel_discovery()
            d.policy.registry.mark_disconnected()
            ctx = d.policy.registry.browser_context_id
            if ctx and d.cdp:
                try:
                    await d.cdp.send_raw("Target.disposeBrowserContext", {"browserContextId": ctx})
                except Exception as e:
                    log(f"dispose Hermes context on shutdown: {e}")
        ipc.cleanup_endpoint(NAME)


async def main():
    d = Daemon()
    await d.start()
    await serve(d)


def already_running():
    # Ping handshake (not a bare connect) so a stale .port file + port reuse
    # after a daemon crash doesn't make us mistake an unrelated listener for ours.
    return ipc.ping(NAME, timeout=1.0)


if __name__ == "__main__":
    if already_running():
        print(f"daemon already running on {SOCK}", file=sys.stderr)
        sys.exit(0)
    open(LOG, "w").close()
    _publish_own_pid()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log(f"fatal: {e}")
        sys.exit(1)
    finally:
        stop_remote()
        try: os.unlink(PID)
        except FileNotFoundError: pass
