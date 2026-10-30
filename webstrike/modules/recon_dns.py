import asyncio

import dns.resolver
import whois as whois_lib

from ..models import Finding, Severity
from ..registry import Phase, register
from .base import Module

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA")
WHOIS_FIELDS = (
    "registrar",
    "org",
    "country",
    "creation_date",
    "expiration_date",
    "name_servers",
    "emails",
)


@register
class DNSRecon(Module):
    id = "dns"
    name = "DNS & WHOIS"
    phase = Phase.RECON
    profiles = {"passive", "balanced", "danger"}
    kinds = {"domain"}

    async def run(self, ctx):
        for rtype in RECORD_TYPES:
            try:
                ans = await asyncio.to_thread(dns.resolver.resolve, ctx.domain, rtype, lifetime=6)
            except Exception:
                continue
            for r in ans:
                txt = r.to_text().strip('"')
                if rtype == "TXT" and txt.startswith("v=spf1"):
                    yield Finding(self.id, "SPF record", Severity.INFO, category="dns", target=ctx.domain, evidence=txt)
                else:
                    yield Finding(self.id, f"{rtype} record", Severity.INFO, category="dns", target=ctx.domain, evidence=txt)

        for name, label in (
            (f"_dmarc.{ctx.domain}", "DMARC"),
            (f"default._domainkey.{ctx.domain}", "DKIM"),
        ):
            try:
                ans = await asyncio.to_thread(dns.resolver.resolve, name, "TXT", lifetime=6)
                for r in ans:
                    yield Finding(
                        self.id,
                        f"{label} record",
                        Severity.INFO,
                        category="dns",
                        target=name,
                        evidence=r.to_text().strip('"'),
                    )
            except Exception:
                pass

        try:
            w = await asyncio.to_thread(whois_lib.whois, ctx.domain)
            for field in WHOIS_FIELDS:
                val = w.get(field) if isinstance(w, dict) else getattr(w, field, None)
                if val:
                    yield Finding(
                        self.id,
                        f"WHOIS: {field}",
                        Severity.INFO,
                        category="whois",
                        target=ctx.domain,
                        evidence=str(val)[:300],
                    )
        except Exception:
            pass
