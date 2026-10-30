from __future__ import annotations
import asyncio, ipaddress, time
from pathlib import Path
from urllib.parse import urlparse
from .config import Options
from .models import Finding
from .registry import MODULES, PHASE_ORDER
from .httpclient import HttpClient
from .store import fingerprint, DATA_DIR
from . import modules as _modules  # noqa: F401

class Context:
    def __init__(self, target, kind, opt, http, state, log, scan_id, data_dir):
        self.target = target; self.kind = kind; self.opt = opt
        self.http = http; self.state = state; self._log = log
        self.scan_id = scan_id; self.data_dir = data_dir

    @property
    def domain(self):
        return self.state["domain"]

    @property
    def base_url(self):
        raw = self.state.get("base_url") or (
            self.target if self.target.startswith("http") else "https://" + self.target)
        return raw.rstrip("/")

    @property
    def screens_dir(self):
        return self.data_dir / self.scan_id / "screens"

    async def log(self, msg, level="info"):
        await self._log(msg, level)

    def remember(self, bucket, *values):
        s = self.state.setdefault(bucket, set())
        for v in values:
            if v:
                s.add(v)

class Engine:
    def __init__(self, scan_id, target, kind, opt, store=None, data_dir=None):
        self.scan_id = scan_id; self.target = target; self.kind = kind; self.opt = opt
        self.store = store
        self.data_dir = Path(data_dir or (DATA_DIR / "artifacts"))
        self.history = []
        self.subs = set()
        self.findings = []
        self.state = {"urls": set(), "subdomains": set(), "endpoints": set(), "hosts": set(),
                      "domain": self._domain_of(target), "base_url": None}
        self.status = "pending"
        self.started = time.time()

    @staticmethod
    def _domain_of(target):
        t = target if "://" in target else "//" + target
        parsed = urlparse(t)
        return parsed.hostname or target.split("@", 1)[-1].split("/")[0].split(":")[0]

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @classmethod
    def detect_kind(cls, target: str) -> str:
        t = target.strip()
        if t.startswith(("http://", "https://")):
            return "url"
        host = cls._domain_of(t)
        if cls._is_ip(host):
            return "ip"
        return "domain"

    def _applies(self, m):
        if not m.kinds:
            return True
        if self.kind in m.kinds:
            return True
        if self.kind == "ip" and "url" in m.kinds:
            return True
        if self.kind == "url" and "domain" in m.kinds and not self._is_ip(self.state["domain"]):
            return True
        return False

    async def emit(self, kind, **data):
        ev = {"kind": kind, "ts": time.time(), "scan_id": self.scan_id}
        ev.update(data)
        self.history.append(ev)
        for q in list(self.subs):
            await q.put(ev)

    def subscribe(self):
        q = asyncio.Queue()
        self.subs.add(q)
        return q

    def unsubscribe(self, q):
        self.subs.discard(q)

    async def _log(self, msg, level="info"):
        await self.emit("log", message=msg, level=level)

    async def run(self):
        self.status = "running"
        await self.emit("scan_start", target=self.target, profile=self.opt.profile)
        http = HttpClient(self.opt)
        ctx = Context(self.target, self.kind, self.opt, http, self.state,
                      self._log, self.scan_id, self.data_dir)
        try:
            for phase in PHASE_ORDER:
                mods = [m for m in MODULES.values()
                        if m.phase == phase and self.opt.profile in m.profiles
                        and self._applies(m)
                        and (not self.opt.only_modules or m.id in self.opt.only_modules)]
                if not mods:
                    continue
                await self.emit("phase", phase=phase.value, modules=[m.id for m in mods])
                sem = asyncio.Semaphore(max(2, self.opt.concurrency // 4))

                async def run_mod(m, sem=sem, ctx=ctx):
                    async with sem:
                        await self.emit("module_start", module=m.id, name=m.name)
                        try:
                            async for f in m().run(ctx):
                                self.findings.append(f)
                                await self.emit("finding",
                                                finding=dict(f.to_dict(), fp=fingerprint(f)))
                        except Exception as e:
                            await self.emit("module_error", module=m.id,
                                            error=type(e).__name__ + ": " + str(e))
                        await self.emit("module_done", module=m.id)

                await asyncio.gather(*(run_mod(m) for m in mods))
        except asyncio.CancelledError:
            self.status = "stopped"
            await self.emit("log", message="Scan stopped by user.", level="warn")
        except Exception as e:
            await self.emit("log", message=f"Engine error: {type(e).__name__}: {e}", level="err")
        finally:
            await http.aclose()
            if self.status != "stopped":
                self.status = "done"
            diff = await self._persist_and_diff()
            await self.emit("scan_diff", **diff)
            await self.emit("scan_done", status=self.status, elapsed=round(time.time() - self.started, 1),
                            total=len(self.findings), surface=self.surface_stats())
            await self._send_webhook(diff)

    async def _send_webhook(self, diff):
        if not self.opt.webhook_url:
            return
        import httpx
        counts = {}
        for f in self.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1

        elapsed = round(time.time() - self.started, 1)
        summary = (
            f"🎯 **WebStrike Scan Complete**\n"
            f"• Target: `{self.target}` ({self.opt.profile})\n"
            f"• Duration: {elapsed}s | Total Findings: {len(self.findings)}\n"
            f"• Critical: {counts.get('critical', 0)} | High: {counts.get('high', 0)} | Medium: {counts.get('medium', 0)} | Low: {counts.get('low', 0)}\n"
            f"• Delta: {diff.get('new', 0)} new findings, {diff.get('resolved', 0)} resolved"
        )
        payload = {
            "content": summary,
            "text": summary,
            "scan_id": self.scan_id,
            "target": self.target,
            "findings_count": len(self.findings),
            "severity_counts": counts,
            "elapsed": elapsed,
            "delta": diff
        }
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                await client.post(self.opt.webhook_url, json=payload)
        except Exception as e:
            await self.emit("log", message=f"Webhook delivery failed: {e}", level="err")

    async def _persist_and_diff(self):
        out = {"new_fps": [], "new": 0, "resolved": 0, "prev": None}
        if not self.store:
            return out
        try:
            prev_id = await self.store.previous_scan(self.target, self.scan_id)
            if prev_id:
                prev_fps = await self.store.load_fingerprints(prev_id)
                curr_fps = {fingerprint(f) for f in self.findings}
                out["new_fps"] = sorted(curr_fps - prev_fps)
                out["new"] = len(out["new_fps"])
                out["resolved"] = len(prev_fps - curr_fps)
                out["prev"] = prev_id
            await self.store.save_scan(self)
        except Exception as e:
            await self.emit("log", message="persistence error: " + str(e), level="err")
        return out

    def surface_stats(self):
        return {"urls": len(self.state["urls"]), "subdomains": len(self.state["subdomains"]),
                "endpoints": len(self.state["endpoints"]), "hosts": len(self.state["hosts"])}
