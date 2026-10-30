from __future__ import annotations
from ..registry import Phase

class Module:
    id = "base"; name = ""; phase = Phase.RECON
    profiles = {"balanced", "danger"}
    kinds = {"domain", "url", "ip"}

    async def run(self, ctx):
        raise NotImplementedError
        yield
