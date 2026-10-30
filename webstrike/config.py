from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict

PROFILES = ("passive", "balanced", "danger")

@dataclass
class Options:
    profile: str = "balanced"
    concurrency: int = 30
    timeout: float = 15.0
    rate: float = 0.0                # req/sec, 0 = unlimited
    retries: int = 2
    proxy: Optional[str] = None
    verify_tls: bool = True
    user_agent: str = "WebStrike/1.1 (+recon)"
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    bearer: Optional[str] = None
    basic: Optional[str] = None         # "user:pass"
    wordlist: Optional[List[str]] = None
    max_urls: int = 3000
    only_modules: Optional[List[str]] = None
    webhook_url: Optional[str] = None

    def __post_init__(self):
        if self.profile not in PROFILES:
            self.profile = "balanced"
        self.concurrency = max(1, min(200, int(self.concurrency or 30)))
        self.timeout = max(1.0, float(self.timeout or 15.0))
        self.rate = max(0.0, float(self.rate or 0.0))
        self.retries = max(0, min(10, int(self.retries if self.retries is not None else 2)))
