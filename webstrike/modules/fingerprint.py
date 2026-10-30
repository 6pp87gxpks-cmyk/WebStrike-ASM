import re
from ..registry import register, Phase
from ..models import Finding, Severity
from .base import Module

TECH = {
    "WordPress": r"wp-content|wp-includes", "Drupal": r"Drupal\.settings",
    "Joomla": r"/components/com_", "React": r"react(?:-dom)?[.\-][\w.]+\.js|__REACT",
    "Vue.js": r"vue(?:\.runtime)?[.\-][\w.]+\.js", "Angular": r"ng-version",
    "Next.js": r"__NEXT_DATA__|/_next/", "jQuery": r"jquery[.\-][\d.]+(?:\.min)?\.js",
    "Bootstrap": r"bootstrap[.\-][\d.]+", "Laravel": r"laravel_session|XSRF-TOKEN",
    "Django": r"csrfmiddlewaretoken", "Rails": r"rails|_session_id",
    "PHP": r"\.php", "ASP.NET": r"__VIEWSTATE", "Cloudflare": r"cloudflare",
    "Shopify": r"cdn\.shopify\.com", "Nginx": r"nginx", "Apache": r"apache",
}
SEC_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
               "x-content-type-options", "referrer-policy", "permissions-policy"]

@register
class Fingerprint(Module):
    id = "fingerprint"; name = "Fingerprint & Headers"; phase = Phase.DISCOVERY
    profiles = {"passive", "balanced", "danger"}; kinds = {"domain", "url"}

    async def run(self, ctx):
        base = ctx.base_url
        r = await ctx.http.probe(base)
        if not r and base.startswith("https://"):
            r = await ctx.http.probe(base.replace("https://", "http://", 1))
        if not r:
            yield Finding(self.id, "Host unreachable", Severity.INFO, category="http", evidence=base)
            return
        ctx.state["base_url"] = str(r.url)
        ctx.remember("urls", str(r.url))
        yield Finding(self.id, f"HTTP {r.status_code}", Severity.INFO, category="http",
                      url=str(r.url), evidence=f"server={r.headers.get('server','?')}")
        for h in ("server", "x-powered-by", "via", "x-generator", "x-aspnet-version"):
            if h in r.headers:
                yield Finding(self.id, f"Header: {h}", Severity.INFO, category="http",
                              url=str(r.url), evidence=r.headers[h])
        body = r.text
        for tech, sig in TECH.items():
            if re.search(sig, body, re.I):
                yield Finding(self.id, f"Technology: {tech}", Severity.INFO, category="tech",
                              url=str(r.url), evidence=tech)
        for h in SEC_HEADERS:
            if h not in r.headers:
                yield Finding(self.id, f"Missing header: {h}", Severity.LOW, category="headers",
                              url=str(r.url))
        for c in r.cookies.jar:
            rest = {k.lower(): v for k, v in (getattr(c, "_rest", None) or {}).items()}
            flags = []
            if not c.secure:
                flags.append("no Secure")
            if "httponly" not in rest:
                flags.append("no HttpOnly")
            if flags:
                yield Finding(self.id, f"Cookie flags: {c.name}", Severity.LOW, category="cookies",
                              url=str(r.url), evidence=", ".join(flags))
