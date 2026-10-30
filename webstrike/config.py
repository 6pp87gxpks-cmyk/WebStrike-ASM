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
    user_agent: str = "WebStrike/1.0 (+recon)"
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    bearer: Optional[str] = None
    basic: Optional[str] = None         # "user:pass"
    wordlist: Optional[List[str]] = None
    max_urls: int = 3000
    only_modules: Optional[List[str]] = None
    webhook_url: Optional[str] = None
