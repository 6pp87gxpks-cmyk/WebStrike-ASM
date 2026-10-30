from ..models import Confidence, Finding, Severity
from ..registry import Phase, register
from .base import Module

_SKIP_PREFIXES = ("www", "api", "app", "mail", "dev", "test", "staging", "prod")
_ACCESS_TAGS = (
    "AccessDenied",
    "AccountRequiresHttps",
    "AuthorizationFailure",
    "InvalidResourceName",
    "<?xml",
)


@register
class Buckets(Module):
    id = "buckets"
    name = "Cloud Bucket Discovery"
    phase = Phase.ENRICH
    profiles = {"danger"}
    kinds = {"domain"}

    async def run(self, ctx):
        parts = [p for p in ctx.domain.split(".") if p not in _SKIP_PREFIXES]
        name = parts[0] if parts else ctx.domain.split(".")[0]
        if not name or len(name) < 3:
            return

        candidates = {
            name,
            f"{name}-dev",
            f"{name}-prod",
            f"{name}-staging",
            f"{name}-backup",
            f"{name}-assets",
            f"{name}-static",
            f"{name}-media",
            f"{name}-uploads",
        }

        providers = [
            ("AWS S3", "https://{c}.s3.amazonaws.com/"),
            ("GCP Bucket", "https://storage.googleapis.com/{c}/"),
            ("Azure Blob", "https://{c}.blob.core.windows.net/$root"),
        ]

        for c in sorted(candidates):
            for prov_name, tpl in providers:
                url = tpl.format(c=c)
                r = await ctx.http.probe(url)
                if not r or r.status_code not in (200, 403):
                    continue
                body = r.text[:600]
                if r.status_code == 200 and "<ListBucketResult" not in body and "<EnumerationResults" not in body:
                    continue
                if r.status_code == 403 and not any(x in body for x in _ACCESS_TAGS):
                    continue
                sev = Severity.HIGH if r.status_code == 200 else Severity.MEDIUM
                status_text = "publicly listable" if r.status_code == 200 else "exists (403 AccessDenied)"
                yield Finding(
                    self.id,
                    f"{prov_name}: {c}",
                    sev,
                    Confidence.FIRM,
                    category="cloud",
                    url=url,
                    evidence=f"{prov_name} container {status_text} (HTTP {r.status_code})",
                )
