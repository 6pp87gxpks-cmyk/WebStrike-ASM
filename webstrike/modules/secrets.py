import re
from urllib.parse import urljoin
from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from ..wordlists import SECRET_PATTERNS
from .base import Module

SKIP_CT = ("image/", "font/", "octet-stream", "video/", "audio/", "wasm")

@register
class Secrets(Module):
    id = "secrets"; name = "Secret Scanning"; phase = Phase.ENRICH
    profiles = {"balanced", "danger"}; kinds = {"domain", "url"}

    async def run(self, ctx):
        candidates = set(ctx.state.get("urls", set()))
        for ep in ctx.state.get("endpoints", set()):
            s = str(ep)
            candidates.add(s if s.startswith("http") else urljoin(ctx.base_url, s))
        seen_urls, seen_keys = set(), set()
        for url in sorted(candidates)[:150]:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            r = await ctx.http.probe(url)
            if not r or r.status_code >= 400:
                continue
            ct = r.headers.get("content-type", "")
            if any(x in ct for x in SKIP_CT):
                continue
            body = r.text
            if len(body) > 2_000_000:
                body = body[:2_000_000]
            for name, pat in SECRET_PATTERNS.items():
                for m in re.finditer(pat, body):
                    val = m.group(0)[:120]
                    key = (name, val)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    yield Finding(self.id, f"Secret: {name}", Severity.HIGH, Confidence.TENTATIVE,
                                  category="secrets", url=url, evidence=val)
