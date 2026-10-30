REMEDIATION_GUIDE = {
    "exposure": "Delete .env, .git, and backup archives from the web root, and block dotfiles at the Nginx/Apache level.",
    "secrets": "Rotate the leaked key right away, check provider logs for usage, and move secrets into env vars instead of frontend code.",
    "cors": "Don't echo back arbitrary Origin headers when Access-Control-Allow-Credentials is true. Match against a fixed allowlist.",
    "graphql": "Turn off schema introspection in production builds and add depth/rate limits to GraphQL queries.",
    "api": "Put Swagger / OpenAPI docs behind auth or restrict them to internal network ranges.",
    "cookies": "Add Secure, HttpOnly, and SameSite=Lax (or Strict) flags on session cookies.",
    "headers": "Add HSTS, Content-Security-Policy, X-Frame-Options (DENY/SAMEORIGIN), and X-Content-Type-Options: nosniff.",
    "network": "Bind internal services (Redis, Mongo, MySQL, Elasticsearch) to localhost or block their ports in the firewall.",
    "cloud": "Lock down bucket ACLs/policies so anonymous users can't list or read objects.",
    "takeover": "Delete the dangling CNAME record or reclaim the external app/bucket name it points to.",
    "discovery": "Put admin panels and debug routes behind authentication, MFA, or VPN/IP allowlists.",
    "vuln": "Escape reflected parameters before rendering HTML, use parameterized SQL queries, and only allow relative URLs on redirects.",
    "crypto": "Force 301 redirects from HTTP to HTTPS and enable HSTS with a long max-age.",
    "infra": "Put origin IPs behind a reverse proxy or CDN/WAF and drop direct A records pointing to the backend host.",
    "js": "Strip .js.map sourcemaps from production builds so raw source files aren't downloadable.",
    "endpoints": "Check that all discovered API routes require auth and proper role checks.",
    "params": "Validate parameter types on the server and escape any values echoed back in responses.",
    "surface": "Make sure login forms post over HTTPS and restrict allowed extensions/MIME types on file upload forms.",
    "http": "Turn off Server and X-Powered-By version banners in your web server config (`server_tokens off` in Nginx).",
    "tech": "Keep CMS cores, plugins, and JS libraries patched; remove unused plugins.",
    "dns": "Set up SPF, DMARC (`p=quarantine` or `p=reject`), DKIM, and CAA records on the domain.",
    "whois": "Turn on registrar lock and WHOIS privacy so admin contacts aren't public.",
    "dorks": "Remove sensitive PDFs, SQL dumps, or logs that search engines have indexed.",
    "screens": "Check captured host screenshots to make sure staging apps or default install pages aren't left open.",
}

OWASP_MAPPING = {
    "exposure": ("A01:2021", "Broken Access Control"),
    "discovery": ("A01:2021", "Broken Access Control"),
    "endpoints": ("A01:2021", "Broken Access Control"),
    "cors": ("A05:2021", "Security Misconfiguration"),
    "headers": ("A05:2021", "Security Misconfiguration"),
    "http": ("A05:2021", "Security Misconfiguration"),
    "js": ("A05:2021", "Security Misconfiguration"),
    "dns": ("A05:2021", "Security Misconfiguration"),
    "whois": ("A05:2021", "Security Misconfiguration"),
    "dorks": ("A05:2021", "Security Misconfiguration"),
    "screens": ("A05:2021", "Security Misconfiguration"),
    "tech": ("A06:2021", "Vulnerable & Outdated Components"),
    "cookies": ("A02:2021", "Cryptographic Failures"),
    "crypto": ("A02:2021", "Cryptographic Failures"),
    "secrets": ("A07:2021", "Identification & Authentication Failures"),
    "graphql": ("A04:2021", "Insecure Design"),
    "api": ("A04:2021", "Insecure Design"),
    "surface": ("A04:2021", "Insecure Design"),
    "network": ("A05:2021", "Security Misconfiguration"),
    "cloud": ("A05:2021", "Security Misconfiguration"),
    "takeover": ("A05:2021", "Security Misconfiguration"),
    "vuln": ("A03:2021", "Injection / Validation Failures"),
    "params": ("A03:2021", "Injection / Validation Failures"),
    "infra": ("A05:2021", "Security Misconfiguration"),
}


def get_remediation(category: str, title: str = "") -> str:
    cat = (category or "").lower()
    if cat in REMEDIATION_GUIDE:
        return REMEDIATION_GUIDE[cat]
    for key, advice in REMEDIATION_GUIDE.items():
        if key in title.lower():
            return advice
    return "Check the endpoint config and restrict unnecessary public access."


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
