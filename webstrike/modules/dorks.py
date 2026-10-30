from ..models import Finding, Severity
from ..registry import Phase, register
from .base import Module

TEMPLATES = [
    "site:{t}",
    "site:{t} -www",
    "site:{t} filetype:pdf",
    "site:{t} inurl:admin",
    'site:{t} intitle:"index of"',
    "site:{t} ext:sql",
    "site:{t} ext:log",
    '"@{t}" -site:{t}',
    'site:github.com "{t}"',
    'site:pastebin.com "{t}"',
]


@register
class Dorks(Module):
    id = "dorks"
    name = "Google Dorks"
    phase = Phase.ENRICH
    profiles = {"passive", "balanced", "danger"}
    kinds = {"domain"}

    async def run(self, ctx):
        for tpl in TEMPLATES:
            yield Finding(
                self.id,
                tpl.format(t=ctx.domain),
                Severity.INFO,
                category="dorks",
                evidence="google",
            )
