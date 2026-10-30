from ..registry import register, Phase
from ..models import Finding, Severity
from .base import Module

PATHS = ["swagger.json", "openapi.json", "swagger/v1/swagger.json", "api-docs",
         "swagger-ui.html", "swagger-ui/", "docs", "redoc", "openapi.yaml"]

@register
class Swagger(Module):
    id = "swagger"; name = "API Docs / Swagger"; phase = Phase.ANALYSIS
    profiles = {"balanced", "danger"}; kinds = {"domain", "url"}

    async def run(self, ctx):
        for p in PATHS:
            url = f"{ctx.base_url}/{p}"
            r = await ctx.http.probe(url)
            if not r or r.status_code != 200:
                continue
            ct = r.headers.get("content-type", "").lower()
            sample = r.text[:1000].lower()
            if p.endswith(".json"):
                if "text/html" in ct and not r.text.lstrip().startswith("{"):
                    continue
                hit = any(k in sample for k in ('"swagger"', '"openapi"', '"paths"'))
            elif p.endswith(".yaml"):
                if "text/html" in ct or sample.lstrip().startswith(("<!doctype", "<html")):
                    continue
                hit = any(k in sample for k in ("openapi:", "swagger:", "paths:"))
            else:
                hit = any(k in sample for k in ("swagger-ui", "redoc", '"openapi"', '"swagger"', '"paths"'))
            if hit:
                yield Finding(self.id, f"API spec exposed: /{p}", Severity.HIGH, category="api",
                              url=url, evidence=r.text[:150].replace("\n", " "))
