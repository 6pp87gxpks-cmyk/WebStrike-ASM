from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from .base import Module

PATHS = ["graphql", "graphiql", "api/graphql", "v1/graphql", "query", "gql"]

@register
class GraphQL(Module):
    id = "graphql"; name = "GraphQL"; phase = Phase.ANALYSIS
    profiles = {"balanced", "danger"}; kinds = {"domain", "url"}

    async def run(self, ctx):
        base = ctx.base_url
        for p in PATHS:
            url = f"{base}/{p}"
            r = await ctx.http.probe(url)
            is_gql = False
            if r:
                body_lower = r.text.lower()
                ct = r.headers.get("content-type", "").lower()
                if "graphql" in ct or "graphql" in body_lower or '{"errors":' in r.text or "must provide an operation" in body_lower or "query missing" in body_lower or "__schema" in r.text:
                    is_gql = True

            # Probe introspection via POST (standard) or GET params
            intro = await ctx.http.probe(url, method="POST", json={"query": "{__schema{types{name}}}"},
                                         headers={"Content-Type": "application/json"})
            if not intro or intro.status_code != 200 or "__schema" not in intro.text:
                intro = await ctx.http.probe(url, params={"query": "{__schema{types{name}}}"})

            if intro and "__schema" in intro.text:
                is_gql = True

            if is_gql:
                yield Finding(self.id, f"GraphQL endpoint: /{p}", Severity.MEDIUM, category="graphql", url=url)
                if intro and "__schema" in intro.text:
                    yield Finding(self.id, "GraphQL introspection ENABLED", Severity.HIGH, category="graphql",
                                  url=url, evidence="schema dump possible")
