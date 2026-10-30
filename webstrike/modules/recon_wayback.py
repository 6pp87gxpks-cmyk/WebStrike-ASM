import re
from urllib.parse import urlparse

from ..models import Finding, Severity
from ..registry import Phase, register
from .base import Module


@register
class Wayback(Module):
    id = "wayback"
    name = "Historical URLs"
    phase = Phase.RECON
    profiles = {"balanced", "danger"}
    kinds = {"domain"}

    async def run(self, ctx):
        urls = set()
        sources = (
            f"https://web.archive.org/cdx/search/cdx?url=*.{ctx.domain}/*&output=text&fl=original&collapse=urlkey&limit=500",
            f"https://otx.alienvault.com/api/v1/indicators/domain/{ctx.domain}/url_list?limit=500",
        )
        for src in sources:
            r = await ctx.http.probe(src)
            if not r or r.status_code != 200:
                continue
            if "alienvault.com" in src:
                try:
                    data = r.json()
                    for item in data.get("url_list", []):
                        u = item.get("url")
                        if u and u.startswith("http"):
                            urls.add(u)
                except Exception:
                    pass
            else:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        urls.add(line)

        params = set()
        for u in urls:
            ctx.remember("urls", u)
            query = urlparse(u).query
            for p in re.findall(r"([^=&]+)=", query):
                params.add(p)

        yield Finding(
            self.id,
            f"{len(urls)} historical URLs",
            Severity.INFO,
            category="surface",
            evidence="wayback/otx",
        )
        for p in sorted(params):
            yield Finding(
                self.id,
                f"Parameter: {p}",
                Severity.LOW,
                category="params",
                evidence=p,
            )
