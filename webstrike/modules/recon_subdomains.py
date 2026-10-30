import asyncio, dns.resolver
from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from ..wordlists import SUBDOMAIN_WORDS
from .base import Module

@register
class Subdomains(Module):
    id = "subdomains"; name = "Subdomains + Takeover"; phase = Phase.RECON
    profiles = {"balanced", "danger"}; kinds = {"domain"}
    TAKEOVER = {"s3": "amazonaws.com", "heroku": "herokudns.com", "github": "github.io",
                "azure": "azurewebsites.net", "shopify": "myshopify.com", "fastly": "fastly.net",
                "cloudfront": "cloudfront.net", "wordpress": "wordpress.com", "surge": "surge.sh"}

    async def run(self, ctx):
        names = set()
        # certificate transparency
        try:
            r = await ctx.http.probe(f"https://crt.sh/?q=%25.{ctx.domain}&output=json")
            if r and r.status_code == 200:
                for e in r.json():
                    for n in str(e.get("name_value", "")).splitlines():
                        n = n.strip().lower().lstrip("*.")
                        if n == ctx.domain or n.endswith("." + ctx.domain):
                            names.add(n)
        except Exception:
            pass
        yield Finding(self.id, f"CT: {len(names)} names", Severity.INFO, category="surface", evidence="crt.sh")

        async def brute(w):
            host = f"{w}.{ctx.domain}"
            try:
                ans = await asyncio.to_thread(dns.resolver.resolve, host, "A", lifetime=4)
                return host, [a.to_text() for a in ans]
            except Exception:
                return None

        for res in await asyncio.gather(*(brute(w) for w in SUBDOMAIN_WORDS)):
            if res: names.add(res[0])

        sorted_names = sorted(names)[:100]
        for n in sorted_names:
            ctx.remember("subdomains", n)
            ctx.remember("hosts", n)
            yield Finding(self.id, "Subdomain", Severity.INFO, category="surface", target=n, evidence=n)

        sem = asyncio.Semaphore(15)
        async def check_takeover(n):
            async with sem:
                try:
                    cname = await asyncio.to_thread(dns.resolver.resolve, n, "CNAME", lifetime=3)
                    target = str(cname[0]).rstrip(".").lower()
                    for svc, sig in self.TAKEOVER.items():
                        if target == sig or target.endswith("." + sig):
                            try:
                                await asyncio.to_thread(dns.resolver.resolve, n, "A", lifetime=3)
                            except Exception:
                                return Finding(self.id, f"Possible takeover ({svc})", Severity.HIGH, Confidence.TENTATIVE,
                                               category="takeover", target=n, url=f"https://{n}",
                                               evidence=f"dangling CNAME → {target}")
                except Exception:
                    pass
                return None

        for tf in await asyncio.gather(*(check_takeover(n) for n in sorted_names)):
            if tf:
                yield tf
