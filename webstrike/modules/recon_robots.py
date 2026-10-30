import re
from urllib.parse import urlparse
from ..registry import register, Phase
from ..models import Finding, Severity
from .base import Module

LOC_RE = re.compile(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", re.I)

@register
class Robots(Module):
    id = "robots"; name = "robots / sitemap / .well-known"; phase = Phase.RECON
    profiles = {"passive", "balanced", "danger"}; kinds = {"domain", "url"}

    async def run(self, ctx):
        domain = ctx.domain.lower()
        for path in ("robots.txt", "sitemap.xml", ".well-known/security.txt", "humans.txt"):
            r = await ctx.http.probe(f"{ctx.base_url}/{path}")
            if r and r.status_code == 200 and len(r.text) > 5:
                yield Finding(self.id, f"/{path}", Severity.LOW, category="surface",
                              url=str(r.url), evidence=r.text[:300])
                if path == "robots.txt":
                    for line in r.text.splitlines():
                        line = line.split("#", 1)[0].strip()
                        low = line.lower()
                        if low.startswith(("disallow:", "allow:")):
                            val = line.split(":", 1)[-1].strip()
                            if val and val != "/" and not val.startswith("*"):
                                clean_val = val.split("*")[0].rstrip("$")
                                if clean_val.startswith("/"):
                                    ctx.remember("endpoints", clean_val)
                        elif low.startswith("sitemap:"):
                            sm_url = line.split(":", 1)[-1].strip()
                            if sm_url.startswith("http"):
                                ctx.remember("urls", sm_url)
                elif path == "sitemap.xml":
                    for loc in LOC_RE.findall(r.text)[:200]:
                        parsed = urlparse(loc)
                        if parsed.hostname and (parsed.hostname.lower() == domain or parsed.hostname.lower().endswith("." + domain)):
                            ctx.remember("urls", loc)
                            if parsed.path:
                                ctx.remember("endpoints", parsed.path)
