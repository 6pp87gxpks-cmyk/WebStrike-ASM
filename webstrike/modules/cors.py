from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from .base import Module

@register
class CORS(Module):
    id = "cors"; name = "CORS Misconfiguration"; phase = Phase.ANALYSIS
    profiles = {"balanced", "danger"}; kinds = {"domain", "url"}

    async def run(self, ctx):
        url = ctx.base_url
        evil = "https://evil.webstrike.io"
        r = await ctx.http.probe(url, headers={"Origin": evil})
        if not r: return
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower()
        if acao == evil:
            sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
            yield Finding(self.id, "CORS reflects arbitrary Origin", sev, Confidence.CERTAIN,
                          category="cors", url=url, evidence=f"ACAO={acao} ACAC={acac or 'false'}")
        elif acao == "*" and acac == "true":
            yield Finding(self.id, "CORS wildcard with credentials", Severity.MEDIUM,
                          category="cors", url=url, evidence=f"ACAO={acao} ACAC={acac}")
        elif acao == "*":
            yield Finding(self.id, "CORS wildcard", Severity.LOW, category="cors", url=url, evidence="ACAO=*")
