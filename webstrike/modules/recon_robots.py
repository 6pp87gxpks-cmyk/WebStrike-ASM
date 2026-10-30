from ..registry import register, Phase
from ..models import Finding, Severity
from .base import Module

@register
class Robots(Module):
    id = "robots"; name = "robots / sitemap / .well-known"; phase = Phase.RECON
    profiles = {"passive", "balanced", "danger"}; kinds = {"domain", "url"}

    async def run(self, ctx):
        for path in ("robots.txt", "sitemap.xml", ".well-known/security.txt", "humans.txt"):
            r = await ctx.http.probe(f"{ctx.base_url}/{path}")
            if r and r.status_code == 200 and len(r.text) > 5:
                yield Finding(self.id, f"/{path}", Severity.LOW, category="surface",
                              url=str(r.url), evidence=r.text[:300])
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                        ctx.remember("endpoints", line.split(":", 1)[-1].strip())
