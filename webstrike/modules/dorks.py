from ..registry import register, Phase
from ..models import Finding, Severity
from .base import Module

TEMPLATES = ['site:{t}', 'site:{t} -www', 'site:{t} filetype:pdf', 'site:{t} inurl:admin',
             'site:{t} intitle:"index of"', 'site:{t} ext:sql', 'site:{t} ext:log',
             '"@{t}" -site:{t}', 'site:github.com "{t}"', 'site:pastebin.com "{t}"']

@register
class Dorks(Module):
    id = "dorks"; name = "Google Dorks"; phase = Phase.ENRICH
    profiles = {"passive", "balanced", "danger"}; kinds = {"domain", "url"}

    async def run(self, ctx):
        for t in TEMPLATES:
            yield Finding(self.id, t.format(t=ctx.domain), Severity.INFO, category="dorks", evidence="google")
