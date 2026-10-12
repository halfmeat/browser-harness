"""Shared harness for the BH_CDP_POLICY=v1 policy tests (not collected itself).

The browser side is a synthetic CDP endpoint (``FakeBrowser``) holding live target /
session / frame-tree state, so the daemon's TRUSTED refreshes see state changes
that no event announced. Everything is enforced at the single point,
``Daemon.handle``, before any model-origin send_raw.
"""
import asyncio

import browser_harness.cdp_policy as cp
from browser_harness.daemon import Daemon


class _Reg:
    async def handle_event(self, *a, **k):
        return True


class FakeBrowser:
    """Synthetic CDP endpoint with live state. Records every send_raw (trusted and
    model-origin alike — they share the wire). ``fail[method]`` raises,
    ``hooks[method]`` runs (async) before the result is returned."""

    def __init__(self, ctx_prefix="CTX-HERMES", tid_prefix="T", sid_prefix="S"):
        self.calls = []
        self._tid_prefix, self._sid_prefix = tid_prefix, sid_prefix
        self.targets = {}
        self.sessions = {}
        self.frame_overrides = {}
        self.child_frames = {}
        self.fail = {}
        self.hooks = {}
        self._n = 0
        self._s = 0
        self._ctx_prefix = ctx_prefix
        self._ctx_n = 0
        self._event_registry = _Reg()
        self._message_handler_task = None

    async def start(self):
        return None

    def add_target(self, tid, ttype="page", url="https://user.example/", ctx="DEFAULT", parent_frame=None):
        t = {"targetId": tid, "type": ttype, "url": url, "browserContextId": ctx, "title": f"title-{tid}"}
        if parent_frame is not None:
            t["parentFrameId"] = parent_frame
        self.targets[tid] = t
        return t

    def set_url(self, tid, url):
        self.targets[tid]["url"] = url

    def count(self, method):
        return sum(1 for m, _p, _s in self.calls if m == method)

    def methods(self):
        return [m for m, _p, _s in self.calls]

    async def emit(self, method, params, session_id=None):
        """Deliver a browser event through the (daemon-tapped) event registry."""
        await self._event_registry.handle_event(method, params, session_id)

    def _tree(self, sid):
        if sid in self.frame_overrides:
            return self.frame_overrides[sid]
        tid = self.sessions[sid]
        t = self.targets[tid]
        frame = {"id": tid, "url": t["url"], "loaderId": "L"}
        if t["type"] == "iframe":
            frame["parentId"] = t.get("parentFrameId")
        children = [{"frame": {"id": f, "parentId": tid, "url": "https://child.example/"}}
                    for f in self.child_frames.get(tid, [])]
        return {"frame": frame, "childFrames": children}

    async def send_raw(self, method, params=None, session_id=None):
        params = dict(params or {})
        self.calls.append((method, params, session_id))
        if method in self.hooks:
            await self.hooks[method](params, session_id)
        if method in self.fail:
            raise self.fail[method]
        if session_id is not None and session_id not in self.sessions:
            raise RuntimeError("Session with given id not found")
        if method == "Target.createBrowserContext":
            self._ctx_n += 1
            return {"browserContextId": self._ctx_prefix if self._ctx_n == 1 else f"{self._ctx_prefix}-{self._ctx_n}"}
        if method == "Target.createTarget":
            self._n += 1
            tid = f"{self._tid_prefix}{self._n}"
            self.add_target(tid, "page", "about:blank", params.get("browserContextId"))
            return {"targetId": tid}
        if method == "Target.getTargetInfo":
            tid = params.get("targetId")
            if tid not in self.targets:
                raise RuntimeError("No target with given id found")
            return {"targetInfo": dict(self.targets[tid])}
        if method == "Target.getTargets":
            return {"targetInfos": [dict(t) for t in self.targets.values()]}
        if method == "Target.attachToTarget":
            tid = params["targetId"]
            if tid not in self.targets:
                raise RuntimeError("No target with given id found")
            self._s += 1
            sid = f"{self._sid_prefix}{self._s}"
            self.sessions[sid] = tid
            return {"sessionId": sid}
        if method == "Target.detachFromTarget":
            if self.sessions.pop(params.get("sessionId"), None) is None:
                raise RuntimeError("No session with given id")
            return {}
        if method == "Target.closeTarget":
            tid = params.get("targetId")
            if self.targets.pop(tid, None) is None:
                raise RuntimeError("No target with given id found")
            for sid in [s for s, t in self.sessions.items() if t == tid]:
                del self.sessions[sid]
            return {"success": True}
        if method == "Page.getFrameTree":
            return {"frameTree": self._tree(session_id)}
        if method == "Browser.getVersion":
            return {"product": "FakeChrome/1"}
        if method.endswith(".enable") or method in (
                "Browser.setDownloadBehavior", "Target.setDiscoverTargets",
                "Target.activateTarget", "Target.disposeBrowserContext"):
            return {}
        return {"ok": method}


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def new_loop():
    """Python 3.14 has no implicit loop; Daemon's asyncio primitives bind to the
    loop current at first await, so each test uses exactly one loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop


def make_policy_daemon(browser=None, start=True):
    """A Daemon in policy mode on a FakeBrowser, event tap installed, startup run."""
    d = Daemon()
    d._attach_policy(cp.PolicyEngine())
    d.cdp = browser if browser is not None else FakeBrowser()
    d.stop = asyncio.Event()
    d._install_event_tap()
    if start:
        run(d._start_policy())
    return d


def model(d, method, params=None, session_id=None):
    """One model-origin IPC CDP request through the single enforcement point."""
    req = {"method": method, "params": params}
    if session_id is not None:
        req["session_id"] = session_id
    return run(d.handle(req))


def meta(d, name, **kw):
    return run(d.handle({"meta": name, **kw}))


def settle(d):
    """Let scheduled trusted discovery tasks finish."""
    async def _s():
        for _ in range(3):
            await asyncio.sleep(0)
        tasks = list(d._policy_discovering.values())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    run(_s())


def announce_iframe(d, tid, parent_frame, ctx="CTX-HERMES", url="https://frame.example/"):
    """Browser creates an OOPIF target and announces it (Target.targetCreated)."""
    info = d.cdp.add_target(tid, "iframe", url, ctx, parent_frame=parent_frame)
    run(d.cdp.emit("Target.targetCreated", {"targetInfo": dict(info)}))
    settle(d)


def visible_ids(d):
    r = model(d, "Target.getTargets", {})
    return sorted(t["targetId"] for t in r["result"]["targetInfos"])
