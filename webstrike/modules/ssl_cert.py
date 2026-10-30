import asyncio
import datetime
import socket
import ssl
from urllib.parse import urlparse

from ..models import Confidence, Finding, Severity
from ..registry import Phase, register
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

        def fetch_cert():
            ssl_ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=4.0) as sock:
                with ssl_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert()

        try:
            cert = await asyncio.to_thread(fetch_cert)
        except ssl.SSLCertVerificationError as exc:
            msg = getattr(exc, "verify_message", None) or "Invalid cert"
            yield Finding(
                self.id,
                f"SSL Certificate Verification Failed: {msg}",
                Severity.HIGH,
                Confidence.CERTAIN,
                category="crypto",
                target=hostname,
                evidence=str(exc)[:180],
            )
            return
        except Exception:
            return

        if not cert:
            return

        not_after_str = cert.get("notAfter", "")
        days_left = None
        if not_after_str:
            try:
                dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                dt = dt.replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                days_left = (dt - now).days
            except Exception:
                pass

        issuer_dict = dict(kv for rdn in cert.get("issuer", ()) for kv in rdn if len(kv) == 2)
        subject_dict = dict(kv for rdn in cert.get("subject", ()) for kv in rdn if len(kv) == 2)
        issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"
        subject_cn = subject_dict.get("commonName") or hostname

        if bool(cert.get("issuer")) and cert.get("issuer") == cert.get("subject"):
            yield Finding(
                self.id,
                "Self-Signed SSL Certificate",
                Severity.HIGH,
                Confidence.CERTAIN,
                category="crypto",
                target=hostname,
                evidence=f"Issuer matches subject: {subject_cn}",
            )

        if days_left is None:
            return

        if days_left < 0:
            yield Finding(
                self.id,
                f"SSL Certificate EXPIRED ({abs(days_left)} days ago)",
                Severity.CRITICAL,
                Confidence.CERTAIN,
                category="crypto",
                target=hostname,
                evidence=f"Expired on {not_after_str} (Issuer: {issuer_org})",
            )
        elif days_left <= 15:
            yield Finding(
                self.id,
                f"SSL Certificate Expires Soon ({days_left} days left)",
                Severity.HIGH,
                Confidence.CERTAIN,
                category="crypto",
                target=hostname,
                evidence=f"Expires on {not_after_str} (Issuer: {issuer_org})",
            )
        elif days_left <= 30:
            yield Finding(
                self.id,
                f"SSL Certificate Expiring in {days_left} Days",
                Severity.MEDIUM,
                Confidence.CERTAIN,
                category="crypto",
                target=hostname,
                evidence=f"Expires on {not_after_str} (Issuer: {issuer_org})",
            )
        else:
            yield Finding(
                self.id,
                f"SSL Certificate Valid ({days_left} days left)",
                Severity.INFO,
                Confidence.CERTAIN,
                category="crypto",
                target=hostname,
                evidence=f"Issuer: {issuer_org} | Valid until {not_after_str}",
            )
