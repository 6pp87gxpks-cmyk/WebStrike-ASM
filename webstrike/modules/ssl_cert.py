from __future__ import annotations
import asyncio
import datetime
import socket
import ssl
from urllib.parse import urlparse
from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from .base import Module

@register
class SSLCertificateHealth(Module):
    id = "ssl"
    name = "SSL/TLS Health & Expiry"
    phase = Phase.RECON
    profiles = {"passive", "balanced", "danger"}
    kinds = {"domain", "url"}

    async def run(self, ctx):
        hostname = ctx.domain
        parsed = urlparse(ctx.base_url)
        port = parsed.port if (parsed.scheme == "https" and parsed.port) else 443

        def parse_verified():
            ssl_ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=4.0) as sock:
                with ssl_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return cert

        try:
            cert = await asyncio.to_thread(parse_verified)
            verified = True
        except ssl.SSLCertVerificationError as e:
            verified = False
            cert = None
            yield Finding(
                self.id,
                f"SSL Certificate Verification Failed: {e.verify_message if hasattr(e, 'verify_message') else 'Invalid cert'}",
                Severity.HIGH,
                Confidence.CERTAIN,
                category="crypto",
                target=hostname,
                evidence=str(e)[:180]
            )
        except Exception:
            # Port 443 may not be SSL
            return

        if not cert:
            return

        # Parse expiry date
        not_after_str = cert.get("notAfter", "")
        expire_date = None
        days_left = None
        if not_after_str:
            try:
                # e.g. "May 15 12:00:00 2026 GMT"
                dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                dt = dt.replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                expire_date = dt
                days_left = (expire_date - now).days
            except Exception:
                pass

        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"
        subject_cn = subject_dict.get("commonName") or hostname

        is_self_signed = (issuer_dict.get("commonName") == subject_dict.get("commonName")) and (issuer_dict.get("organizationName") == subject_dict.get("organizationName"))

        if is_self_signed:
            yield Finding(
                self.id,
                "Self-Signed SSL Certificate",
                Severity.HIGH,
                Confidence.CERTAIN,
                category="crypto",
                target=hostname,
                evidence=f"Issuer matches subject: {subject_cn}"
            )

        if days_left is not None:
            if days_left < 0:
                yield Finding(
                    self.id,
                    f"SSL Certificate EXPIRED ({abs(days_left)} days ago)",
                    Severity.CRITICAL,
                    Confidence.CERTAIN,
                    category="crypto",
                    target=hostname,
                    evidence=f"Expired on {not_after_str} (Issuer: {issuer_org})"
                )
            elif days_left <= 15:
                yield Finding(
                    self.id,
                    f"SSL Certificate Expires Soon ({days_left} days left)",
                    Severity.HIGH,
                    Confidence.CERTAIN,
                    category="crypto",
                    target=hostname,
                    evidence=f"Expires on {not_after_str} (Issuer: {issuer_org})"
                )
            elif days_left <= 30:
                yield Finding(
                    self.id,
                    f"SSL Certificate Expiring in {days_left} Days",
                    Severity.MEDIUM,
                    Confidence.CERTAIN,
                    category="crypto",
                    target=hostname,
                    evidence=f"Expires on {not_after_str} (Issuer: {issuer_org})"
                )
            else:
                yield Finding(
                    self.id,
                    f"SSL Certificate Valid ({days_left} days left)",
                    Severity.INFO,
                    Confidence.CERTAIN,
                    category="crypto",
                    target=hostname,
                    evidence=f"Issuer: {issuer_org} | Valid until {not_after_str}"
                )
