from __future__ import annotations
import asyncio
from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from .base import Module

COMMON_SERVICES = {
    21: ("FTP", Severity.LOW, "File Transfer Protocol"),
    22: ("SSH", Severity.INFO, "Secure Shell"),
    23: ("Telnet", Severity.HIGH, "Unencrypted Telnet service"),
    25: ("SMTP", Severity.INFO, "Mail Transfer Agent"),
    80: ("HTTP", Severity.INFO, "Web server"),
    443: ("HTTPS", Severity.INFO, "Encrypted web server"),
    1433: ("MSSQL", Severity.HIGH, "Microsoft SQL Server exposed"),
    1521: ("Oracle DB", Severity.HIGH, "Oracle Database exposed"),
    3000: ("Node/Dev HTTP", Severity.LOW, "Alternative web service"),
    3306: ("MySQL", Severity.HIGH, "MySQL database service exposed"),
    3389: ("RDP", Severity.MEDIUM, "Remote Desktop Protocol exposed"),
    5432: ("PostgreSQL", Severity.HIGH, "PostgreSQL database service exposed"),
    6379: ("Redis", Severity.CRITICAL, "Redis in-memory cache/database exposed"),
    8000: ("HTTP-Alt", Severity.INFO, "Alternative web port"),
    8080: ("HTTP-Proxy/Web", Severity.INFO, "Common web proxy/app port"),
    8443: ("HTTPS-Alt", Severity.INFO, "Alternative SSL web service"),
    8888: ("HTTP-Alt", Severity.INFO, "Alternative web port"),
    9000: ("FastCGI/Sonar", Severity.MEDIUM, "Internal/FastCGI port exposed"),
    9200: ("Elasticsearch", Severity.CRITICAL, "Elasticsearch cluster REST API exposed"),
    27017: ("MongoDB", Severity.CRITICAL, "MongoDB database service exposed"),
}

@register
class PortScanner(Module):
    id = "ports"
    name = "Port & Service Scanner"
    phase = Phase.RECON
    profiles = {"balanced", "danger"}
    kinds = {"domain", "url", "ip"}

    async def run(self, ctx):
        host = ctx.domain
        sem = asyncio.Semaphore(15)

        async def probe_port(port: int):
            async with sem:
                try:
                    conn = asyncio.open_connection(host, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=1.8)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return port, True
                except Exception:
                    return port, False

        ports_to_check = sorted(COMMON_SERVICES.keys())
        tasks = [probe_port(p) for p in ports_to_check]
        results = await asyncio.gather(*tasks)

        open_ports = []
        for port, is_open in results:
            if not is_open:
                continue
            open_ports.append(port)
            svc_name, sev, desc = COMMON_SERVICES.get(port, ("Unknown", Severity.INFO, "Open TCP port"))

            host_fmt = f"[{host}]" if ":" in host and not host.startswith("[") else host
            target_label = f"{host_fmt}:{port}"
            ctx.remember("hosts", target_label)
            if port in (80, 443, 8000, 8080, 8443, 8888, 3000):
                scheme = "https" if port in (443, 8443) else "http"
                ctx.remember("urls", f"{scheme}://{host_fmt}:{port}")

            yield Finding(
                self.id,
                f"Open Port {port} ({svc_name})",
                sev,
                Confidence.CERTAIN,
                category="network",
                target=target_label,
                evidence=f"{desc} on TCP port {port}"
            )

        if open_ports:
            yield Finding(
                self.id,
                f"Network Surface: {len(open_ports)} open ports",
                Severity.INFO,
                category="surface",
                target=host,
                evidence=f"Open TCP ports: {', '.join(map(str, open_ports))}"
            )
