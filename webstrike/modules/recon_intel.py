from __future__ import annotations
import asyncio
import ipaddress
import dns.resolver
from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from .base import Module

@register
class GeoHostingIntel(Module):
    id = "intel"
    name = "IP Geo & Hosting Intel"
    phase = Phase.RECON
    profiles = {"passive", "balanced", "danger"}
    kinds = {"domain", "url", "ip"}

    async def run(self, ctx):
        host = ctx.domain
        ip = None

        # Check if already an IP address
        try:
            ipaddress.ip_address(host)
            ip = host
        except ValueError:
            for rtype in ("A", "AAAA"):
                try:
                    ans = await asyncio.to_thread(dns.resolver.resolve, host, rtype, lifetime=4)
                    if ans:
                        ip = str(ans[0])
                        break
                except Exception:
                    pass

        if not ip:
            return

        ctx.remember("hosts", ip)

        try:
            ip_obj = ipaddress.ip_address(ip)
            is_public = ip_obj.is_global
        except ValueError:
            is_public = True

        # Query Geolocation & ASN information only for public/global IPs
        info = None
        if is_public:
            try:
                r = await ctx.http.probe(
                    f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,timezone,isp,org,as,query"
                )
                if r and r.status_code == 200:
                    data = r.json()
                    if data.get("status") == "success":
                        info = data
            except Exception:
                pass

        if not info:
            yield Finding(
                self.id,
                f"Target IP: {ip}",
                Severity.INFO,
                category="infra",
                target=host,
                evidence=f"Resolved {host} -> {ip}"
            )
            return

        country = info.get("country", "Unknown")
        city = info.get("city", "Unknown")
        org = info.get("org") or info.get("isp") or "Unknown"
        asn = info.get("as", "")
        lat = info.get("lat")
        lon = info.get("lon")

        # Remember geo metadata in state
        ctx.state["geo"] = {
            "ip": ip,
            "country": country,
            "city": city,
            "org": org,
            "asn": asn,
            "lat": lat,
            "lon": lon,
        }

        # 1. Location Finding
        yield Finding(
            self.id,
            f"Server Location: {city}, {country}",
            Severity.INFO,
            Confidence.CERTAIN,
            category="infra",
            target=host,
            evidence=f"IP: {ip} | Coordinates: {lat}, {lon} ({info.get('timezone', '')})"
        )

        # 2. ISP & ASN Finding
        yield Finding(
            self.id,
            f"Hosting Provider: {org}",
            Severity.INFO,
            Confidence.CERTAIN,
            category="infra",
            target=host,
            evidence=f"ASN: {asn} | IP: {ip}"
        )

        # 3. Cloud / CDN / WAF Detection
        lower_org = (org + " " + asn).lower()
        cdn_tag = None
        if "cloudflare" in lower_org:
            cdn_tag = "Cloudflare CDN / WAF"
        elif "amazon" in lower_org or "cloudfront" in lower_org or "aws" in lower_org:
            cdn_tag = "Amazon Web Services (AWS)"
        elif "google" in lower_org:
            cdn_tag = "Google Cloud Platform (GCP)"
        elif "microsoft" in lower_org or "azure" in lower_org:
            cdn_tag = "Microsoft Azure"
        elif "fastly" in lower_org:
            cdn_tag = "Fastly CDN"
        elif "akamai" in lower_org:
            cdn_tag = "Akamai CDN"
        elif "hetzner" in lower_org:
            cdn_tag = "Hetzner Online"
        elif "digitalocean" in lower_org:
            cdn_tag = "DigitalOcean"
        elif "ovh" in lower_org:
            cdn_tag = "OVHcloud"

        if cdn_tag:
            yield Finding(
                self.id,
                f"Infrastructure: {cdn_tag}",
                Severity.INFO,
                Confidence.CERTAIN,
                category="infra",
                target=host,
                evidence=f"Detected via ASN ({asn}) and ISP ({org})"
            )
