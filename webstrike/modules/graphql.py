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
            if r and r.status_code in (200, 400, 405):
                body_lower = r.text[:2000].lower()
                ct = r.headers.get("content-type", "").lower()
                is_json = "json" in ct or r.text.lstrip().startswith("{")
                if "graphql" in ct:
                    is_gql = True
                elif is_json and (
                    '{"errors":' in r.text
                    or "must provide query" in body_lower
                    or "must provide an operation" in body_lower
                    or "query missing" in body_lower
                    or '"__schema"' in r.text
                ):
                    is_gql = True
                elif r.status_code == 200 and (
                    "graphiql" in body_lower or "graphql-playground" in body_lower or "apollo-server" in body_lower
                ):
                    is_gql = True

            # Probe introspection via POST (standard) or GET params
            intro = await ctx.http.probe(url, method="POST", json={"query": "{__schema{types{name}}}"},
                                         headers={"Content-Type": "application/json"})
            if not intro or intro.status_code != 200 or '"__schema"' not in intro.text:
                intro = await ctx.http.probe(url, params={"query": "{__schema{types{name}}}"})

            intro_ok = bool(
                intro
                and intro.status_code == 200
                and ("json" in intro.headers.get("content-type", "").lower() or intro.text.lstrip().startswith("{"))
                and '"__schema"' in intro.text
                and '"types"' in intro.text
            )
            if intro_ok:
                is_gql = True

            if is_gql:
                yield Finding(self.id, f"GraphQL endpoint: /{p}", Severity.MEDIUM, category="graphql", url=url)
                if intro_ok:
                    yield Finding(self.id, "GraphQL introspection ENABLED", Severity.HIGH, category="graphql",
                                  url=url, evidence="schema dump possible")
