from __future__ import annotations
from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from .base import Module

WAF_SIGNATURES = [
    ("Cloudflare WAF / Edge", ("cf-ray", "cf-cache-status", "cf-mitigated"), ("__cf_bm", "cf_clearance"), ("cloudflare",)),
    ("AWS WAF / CloudFront", ("x-amz-cf-id", "x-amz-cf-pop", "x-amzn-waf-action"), ("aws-waf-token",), ("cloudfront", "awselb")),
    ("Akamai Kona / Edge", ("x-akamai-transformed", "akamai-grn", "x-akamai-request-id"), ("ak_bmsc", "bm_sv"), ("akamighost", "akamai")),
    ("Imperva / Incapsula WAF", ("x-iinfo", "x-cdn"), ("incap_ses_", "visid_incap_"), ("incapsula", "imperva")),
    ("Sucuri CloudProxy WAF", ("x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"), ("sucuri_cloudproxy",), ("sucuri",)),
    ("Fastly / Signal Sciences", ("x-fastly-request-id", "fastly-restarts", "x-sigsci-requestid"), (), ("fastly",)),
    ("F5 BIG-IP ASM / TrafficShield", ("x-wa-info", "x-cnection"), ("ts", "bigipserver"), ("big-ip", "bigip")),
    ("Azure Front Door / WAF", ("x-azure-ref", "x-fd-healthprobe"), (), ("azurefrontdoor",)),
    ("ModSecurity WAF", ("x-mod-security", "x-modsecurity"), (), ("mod_security", "modsecurity", "owasp_crs")),
]


@register
class WAFDetector(Module):
    id = "waf"
    name = "WAF & Edge Shield Detection"
    phase = Phase.RECON
    profiles = {"passive", "balanced", "danger"}
    kinds = {"domain", "url", "ip"}

    async def run(self, ctx):
        base = ctx.base_url
        r = await ctx.http.probe(base)
        if not r and base.startswith("https://"):
            r = await ctx.http.probe(base.replace("https://", "http://", 1))
        if not r:
            return

        hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}
        server_str = " ".join([
            hdrs.get("server", ""),
            hdrs.get("via", ""),
            hdrs.get("x-cdn", ""),
            hdrs.get("x-powered-by", ""),
        ])
        cookie_names = [c.name.lower() for c in r.cookies.jar]
        set_cookie_raw = hdrs.get("set-cookie", "")

        detected = []
        for waf_name, hdr_keys, cookie_prefixes, server_tokens in WAF_SIGNATURES:
            reasons = []
            for hk in hdr_keys:
                if hk in hdrs:
                    reasons.append(f"header:{hk}")
            for cp in cookie_prefixes:
                if any(cn.startswith(cp) for cn in cookie_names) or cp in set_cookie_raw:
                    reasons.append(f"cookie:{cp}*")
            for st in server_tokens:
                if st in server_str:
                    reasons.append(f"server:{st}")
            if reasons:
                detected.append((waf_name, ", ".join(reasons[:4])))

        if detected:
            for waf_name, evidence_str in detected:
                yield Finding(
                    self.id,
                    f"WAF / Edge Protection: {waf_name}",
                    Severity.INFO,
                    Confidence.CERTAIN,
                    category="infra",
                    url=str(r.url),
                    evidence=f"Detected via {evidence_str}",
                    meta={"waf": waf_name, "detected": True}
                )
        else:
            yield Finding(
                self.id,
                "No Known WAF Signature Detected",
                Severity.LOW,
                Confidence.TENTATIVE,
                category="infra",
                url=str(r.url),
                evidence="Standard HTTP response headers/cookies showed no known WAF/CDN shield signatures",
                meta={"waf": None, "detected": False}
            )
