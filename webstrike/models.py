from __future__ import annotations
import time, uuid
from dataclasses import dataclass, field, asdict
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"
    @property
    def rank(self): return {"critical":0,"high":1,"medium":2,"low":3,"info":4}[self.value]

class Confidence(str, Enum):
    CERTAIN = "certain"; FIRM = "firm"; TENTATIVE = "tentative"

@dataclass
class Finding:
    module: str
    title: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.FIRM
    category: str = "general"
    target: str = ""
    url: str = ""
    evidence: str = ""
    meta: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    ts: float = field(default_factory=time.time)

    def __post_init__(self):
        if isinstance(self.severity, str) and not isinstance(self.severity, Severity):
            try:
                self.severity = Severity(self.severity.lower())
            except ValueError:
                self.severity = Severity.INFO
        if isinstance(self.confidence, str) and not isinstance(self.confidence, Confidence):
            try:
                self.confidence = Confidence(self.confidence.lower())
            except ValueError:
                self.confidence = Confidence.FIRM

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        d["confidence"] = self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence)
        return d
