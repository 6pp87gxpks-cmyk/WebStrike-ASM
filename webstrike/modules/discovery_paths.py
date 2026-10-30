import asyncio

from ..models import Finding, Severity
from ..registry import Phase, register
from ..wordlists import COMMON_PATHS
from .base import Module


@register
class PathDiscovery(Module):
    id = "paths"
    name = "Content Discovery"
    phase = Phase.DISCOVERY
    profiles = {"balanced", "danger"}
    kinds = {"domain", "url"}

    async def run(self, ctx):
        base = ctx.base_url
        r0 = await ctx.http.probe(f"{base}/webstrike-nx-{ctx.scan_id}")
        base_status = r0.status_code if r0 else 404
        baseline = len(r0.text) if r0 else 0
        words = ctx.opt.wordlist or COMMON_PATHS

        async def check(path):
            r = await ctx.http.probe(f"{base}/{path}")
            if not r:
                return None
            if r.status_code not in (200, 201, 204, 301, 302, 401, 403, 500):
                return None
            if r.status_code == 200 and base_status == 200 and baseline > 0 and abs(len(r.text) - baseline) < 20:
                return None
            return path, r.status_code, len(r.text)

        for res in await asyncio.gather(*(check(p) for p in words)):
            if not res:
                continue
            p, code, size = res
            sev = Severity.LOW
            if code in (401, 403):
                sev = Severity.MEDIUM
            if any(k in p for k in ("admin", "api", "graphql", "swagger", "debug", "actuator")):
                sev = Severity.MEDIUM
            ctx.remember("endpoints", f"{base}/{p}")
            yield Finding(
                self.id,
                f"/{p} [{code}]",
                sev,
                category="discovery",
                url=f"{base}/{p}",
                evidence=f"status={code} size={size}",
            )
