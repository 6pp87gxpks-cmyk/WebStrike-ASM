from __future__ import annotations

from enum import Enum

MODULES: dict[str, type] = {}


class Phase(str, Enum):
    RECON = "recon"
    DISCOVERY = "discovery"
    ANALYSIS = "analysis"
    ENRICH = "enrich"


PHASE_ORDER = [
    Phase.RECON,
    Phase.DISCOVERY,
    Phase.ANALYSIS,
    Phase.ENRICH,
]


def register(cls):
    MODULES[cls.id] = cls
    return cls
