import re
from urllib.parse import urljoin, urlparse
from ..registry import register, Phase
from ..models import Finding, Severity
from .base import Module

SCRIPT_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
ENDPOINT_RE = re.compile(r"""["'](/[a-zA-Z0-9_\-./]{2,}(?:\?[^"']*)?)["']""")

@register
class JSIntel(Module):
    id = "js"; name = "JavaScript Intelligence"; phase = Phase.ANALYSIS
    profiles = {"balanced", "danger"}; kinds = {"domain", "url"}

    async def run(self, ctx):
        base = ctx.base_url
        r = await ctx.http.probe(base)
        if not r:
            return
        page_url = str(r.url)
        scripts = {urljoin(page_url, s) for s in SCRIPT_RE.findall(r.text)}
        scripts |= {
            u for u in ctx.state.get("urls", set())
            if urlparse(str(u)).path.lower().endswith(".js")
        }
        ctx.remember("urls", *scripts)
        endpoints = set()
        for s in sorted(scripts)[:60]:
            js = await ctx.http.probe(s)
            if not js or js.status_code != 200:
                continue
            for ep in ENDPOINT_RE.findall(js.text):
                endpoints.add(ep)
            if "sourceMappingURL=" in js.text:
                yield Finding(self.id, "Sourcemap reference", Severity.MEDIUM, category="js",
                              url=s, evidence="source map exposed -> source recoverable")
                sm = js.text.split("sourceMappingURL=")[-1].strip().split()[0].strip("*/ ").strip()
                smr = await ctx.http.probe(urljoin(s, sm))
                if smr and smr.status_code == 200:
                    yield Finding(self.id, "Sourcemap reachable", Severity.HIGH, category="js",
                                  url=urljoin(s, sm))
        for ep in sorted(endpoints):
            ctx.remember("endpoints", ep)
        yield Finding(self.id, f"{len(scripts)} scripts, {len(endpoints)} endpoints", Severity.INFO,
                      category="js", evidence="JS analysis complete")
        for ep in sorted(endpoints)[:200]:
            yield Finding(self.id, f"Endpoint: {ep}", Severity.LOW, category="endpoints", evidence=ep)
