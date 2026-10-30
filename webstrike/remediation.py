"""Remediation & Hardening Knowledge Base for WebStrike findings."""
from __future__ import annotations

REMEDIATION_GUIDE = {
    "exposure": "Remove sensitive configuration and VCS files from public web directories. Ensure .env, .git, and credentials are added to .gitignore and web server block rules.",
    "secrets": "Immediately revoke and rotate the exposed API key or token. Audit access logs for unauthorized activity and store secrets securely in an environment variable manager or vault.",
    "cors": "Avoid reflecting arbitrary 'Origin' headers with 'Access-Control-Allow-Credentials: true'. Explicitly whitelist trusted origins only.",
    "graphql": "Disable GraphQL introspection in production environments. Implement rate limiting and query complexity limits to prevent resource exhaustion.",
    "api": "Restrict public access to internal OpenAPI and Swagger UI documentation, or place documentation behind authentication.",
    "cookies": "Set the 'HttpOnly' flag to protect cookies from XSS theft, 'Secure' to enforce HTTPS transmission, and 'SameSite=Lax' or 'Strict' to mitigate CSRF.",
    "headers": "Implement missing HTTP security headers: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options (DENY/SAMEORIGIN), and X-Content-Type-Options (nosniff).",
    "network": "Restrict database and management ports (e.g. 6379, 27017, 3306, 9200) from listening on public interfaces. Bind to 127.0.0.1 or protect behind a VPN and firewall.",
    "cloud": "Configure cloud storage access control policies (S3 bucket policy, GCP IAM, Azure ACL) to prevent anonymous/public read or write access.",
    "takeover": "Remove dangling CNAME DNS records pointing to decommissioned third-party cloud services (AWS, GitHub, Azure, Heroku).",
    "discovery": "Review publicly exposed administrative endpoints. Enforce multi-factor authentication (MFA) and IP whitelisting.",
    "vuln": "Validate, sanitize, and context-encode all user input. For redirects, use an explicit whitelist of allowed local paths. For database interactions, strictly use parameterized queries.",
    "crypto": "Enforce HTTPS across all assets. Enable HSTS with 'max-age=31536000; includeSubDomains; preload' and configure automatic port 80 to 443 redirects.",
    "infra": "Protect server origin IP behind an enterprise CDN/WAF. Ensure no internal hostnames or direct IP links leak in DNS or response headers.",
}

OWASP_MAPPING = {
    "exposure": ("A01:2021", "Broken Access Control"),
    "discovery": ("A01:2021", "Broken Access Control"),
    "cors": ("A05:2021", "Security Misconfiguration"),
    "headers": ("A05:2021", "Security Misconfiguration"),
    "cookies": ("A02:2021", "Cryptographic Failures"),
    "crypto": ("A02:2021", "Cryptographic Failures"),
    "secrets": ("A07:2021", "Identification & Authentication Failures"),
    "graphql": ("A04:2021", "Insecure Design"),
    "api": ("A04:2021", "Insecure Design"),
    "network": ("A05:2021", "Security Misconfiguration"),
    "cloud": ("A05:2021", "Security Misconfiguration"),
    "takeover": ("A05:2021", "Security Misconfiguration"),
    "vuln": ("A03:2021", "Injection / Validation Failures"),
    "infra": ("A05:2021", "Security Misconfiguration"),
}

def get_remediation(category: str, title: str = "") -> str:
    cat = (category or "").lower()
    if cat in REMEDIATION_GUIDE:
        return REMEDIATION_GUIDE[cat]
    for key, advice in REMEDIATION_GUIDE.items():
        if key in title.lower():
            return advice
    return "Review the asset configuration and follow OWASP security best practices to harden this endpoint."

def get_owasp_tag(category: str, title: str = "") -> tuple[str, str]:
    cat = (category or "").lower()
    if cat in OWASP_MAPPING:
        return OWASP_MAPPING[cat]
    t = title.lower()
    if "redirect" in t:
        return ("A01:2021", "Broken Access Control")
    if "sql" in t or "injection" in t or "reflected" in t:
        return ("A03:2021", "Injection / Validation Failures")
    if "key" in t or "secret" in t:
        return ("A07:2021", "Identification & Authentication Failures")
    return ("A05:2021", "Security Misconfiguration")
