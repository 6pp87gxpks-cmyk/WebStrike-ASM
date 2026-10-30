from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from ..wordlists import SENSITIVE_FILES
from .base import Module
import asyncio, re

@register
class Exposure(Module):
    id = "exposure"; name = "Exposed Files & VCS"; phase = Phase.DISCOVERY
    profiles = {"balanced", "danger"}; kinds = {"domain", "url"}
    HIGH = (".env", ".git", ".aws", ".htpasswd", "id_rsa", "credentials", ".npmrc", "git-credentials")

    async def run(self, ctx):
        base = ctx.base_url

        # Baseline probe to catch wildcard 200 responses on SPAs
        r0 = await ctx.http.probe(f"{base}/webstrike-nx-{ctx.scan_id}")
        base_status = r0.status_code if r0 else 404
        baseline = len(r0.text) if r0 else 0

        async def check(p):
            r = await ctx.http.probe(f"{base}/{p}")
            if not r or r.status_code != 200 or len(r.text) <= 2:
                return None
            if base_status == 200 and baseline > 0 and abs(len(r.text) - baseline) < 20:
                return None
            return p, r

        for res in await asyncio.gather(*(check(p) for p in SENSITIVE_FILES)):
            if not res: continue
            p, r = res
            sev = Severity.HIGH if any(h in p for h in self.HIGH) else Severity.MEDIUM
            conf = Confidence.CERTAIN
            if re.search(r"<!doctype\s+html|<html", r.text[:300], re.I) and p not in (".DS_Store",):
                conf = Confidence.TENTATIVE
            yield Finding(self.id, f"Exposed: {p}", sev, conf, category="exposure",
                          url=str(r.url), evidence=r.text[:200].replace("\n", " "))
