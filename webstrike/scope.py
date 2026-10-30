"""Scope control: which targets this WebStrike instance is allowed to scan."""
from __future__ import annotations
import ipaddress
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

DEFAULT_SCOPE: Dict = {"enforce": False, "domains": []}

_HOST_RE = re.compile(r"^(?:\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


def target_host(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t
    try:
        return (urlparse(t).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def normalize_entry(entry: str) -> Optional[str]:
    """Accepts 'example.com', '*.example.com', 'https://example.com/x', IPs or CIDRs."""
    e = (entry or "").strip().lower()
    if not e:
        return None
    try:
        return str(ipaddress.ip_network(e, strict=False))
    except ValueError:
        pass
    wildcard = e.startswith("*.")
    host = target_host(e[2:] if wildcard else e)
    if not host:
        return None
    norm = ("*." + host) if wildcard else host
    return norm if _HOST_RE.match(norm) else None


def normalize_list(entries: List[str]) -> List[str]:
    out: List[str] = []
    for e in entries or []:
        n = normalize_entry(e)
        if n and n not in out:
            out.append(n)
    return out


def host_in_scope(host: str, allowed: List[str]) -> bool:
    """'example.com' allows example.com and all its subdomains; '*.example.com'
    allows only subdomains; IP / CIDR entries match addresses."""
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    for entry in allowed or []:
        if ip is not None:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
            continue
        if entry.startswith("*."):
            if host.endswith(entry[1:]):
                return True
        elif host == entry or host.endswith("." + entry):
            return True
    return False
