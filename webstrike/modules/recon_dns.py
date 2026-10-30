import asyncio, dns.resolver, whois as whois_lib
from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from .base import Module

@register
class DNSRecon(Module):
    id = "dns"; name = "DNS & WHOIS"; phase = Phase.RECON
    profiles = {"passive", "balanced", "danger"}; kinds = {"domain"}

    async def run(self, ctx):
        for rt in ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA"]:
            try:
                ans = await asyncio.to_thread(dns.resolver.resolve, ctx.domain, rt, lifetime=6)
            except Exception:
                continue
            for r in ans:
                txt = r.to_text().strip('"')
                if rt == "TXT" and txt.startswith("v=spf1"):
                    yield Finding(self.id, "SPF record", Severity.INFO, category="dns", target=ctx.domain, evidence=txt)
                else:
                    yield Finding(self.id, f"{rt} record", Severity.INFO, category="dns", target=ctx.domain, evidence=txt)
        for name, label in ((f"_dmarc.{ctx.domain}", "DMARC"), (f"default._domainkey.{ctx.domain}", "DKIM")):
            try:
                ans = await asyncio.to_thread(dns.resolver.resolve, name, "TXT", lifetime=6)
                for r in ans:
                    yield Finding(self.id, f"{label} record", Severity.INFO, category="dns", target=name, evidence=r.to_text().strip('"'))
            except Exception:
                pass
        try:
            w = await asyncio.to_thread(whois_lib.whois, ctx.domain)
            for f in ("registrar", "org", "country", "creation_date", "expiration_date", "name_servers", "emails"):
                v = w.get(f) if isinstance(w, dict) else getattr(w, f, None)
                if v:
                    yield Finding(self.id, f"WHOIS: {f}", Severity.INFO, category="whois", target=ctx.domain,
                                  evidence=str(v)[:300])
        except Exception:
            pass
