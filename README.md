# ⚡ WebStrike — Attack Surface & Security Audit Engine

![Version](https://img.shields.io/badge/version-1.1.0-22d3ee)
![Edition](https://img.shields.io/badge/edition-Free%20%26%20Open%20Source-4dd4ac)
![Modules](https://img.shields.io/badge/modules-22-a855f7)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**WebStrike** is a free, self-hosted web attack surface management (ASM) and defensive security auditing engine. It combines **22 automated reconnaissance and security auditing modules** with a real-time WebSocket dashboard, interactive Attack Surface Graph, side-by-side Scan Comparison (Diff), Scope Allowlist enforcement, and printable OWASP Top 10 Executive Reports.

---

## 🚀 Quick Start (1-Click Launch)

### macOS / Linux
Double-click **`start.command`** (or run `./start.command` in Terminal).
It automatically sets up the Python virtual environment, installs dependencies, and opens `http://127.0.0.1:8777`.

### Windows
Double-click **`start.bat`**.
It automatically sets up `.venv`, installs dependencies, and opens your browser to `http://127.0.0.1:8777`.

### Docker (1-Click Container)
```bash
docker compose up -d --build
```
Then open `http://127.0.0.1:8777`. All scan history and settings persist in `./scans`.

### CLI Mode
```bash
python run.py scan https://example.com -p balanced
```

---

## 🛡️ 22 Built-In Security Modules

| Phase | Module ID | Name | Description |
| :--- | :--- | :--- | :--- |
| **Recon** | `dns` | DNS & WHOIS | A, AAAA, MX, TXT, SPF, DMARC, DKIM, NS, SOA, CAA & WHOIS records |
| **Recon** | `subdomains` | Subdomains + Takeover | Certificate Transparency (`crt.sh`) + DNS brute-force + dangling CNAME takeover checks |
| **Recon** | `intel` | IP Geo & Hosting Intel | ASN, ISP, Geolocation, and Cloud/CDN infrastructure identification |
| **Recon** | `waf` | WAF & Edge Shield Detection | Detects Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, Fastly, F5 BIG-IP, Azure WAF & ModSecurity |
| **Recon** | `ssl` | SSL/TLS Health & Expiry | Certificate verification, self-signed detection, and expiration countdown |
| **Recon** | `headers_grade` | Security Headers Grade | Scores HTTP security headers `0–100` (`A+` to `F`) across HSTS, CSP, XFO, XCTO, Referrer & Permissions-Policy |
| **Recon** | `ports` | Port & Service Scanner | Asynchronous TCP port scanner across 20 critical web, database, and management ports |
| **Recon** | `robots` | robots / sitemap / .well-known | Extracts disallowed paths, sitemaps, and `security.txt` |
| **Recon** | `wayback` | Historical URLs | Queries Wayback Machine CDX & AlienVault OTX for historical endpoints and parameters |
| **Discovery** | `fingerprint` | Fingerprint & Headers | Identifies CMS/frameworks, server headers, and insecure cookie flags (`Secure`, `HttpOnly`) |
| **Discovery** | `crawler` | Web Spider & Forms | Crawls internal links, extracts query parameters, and audits login & file-upload forms |
| **Discovery** | `paths` | Content Discovery | Smart baseline-aware hidden path & admin endpoint discovery |
| **Discovery** | `exposure` | Exposed Files & VCS | Detects exposed `.env`, `.git/HEAD`, backups, keys, and configuration files |
| **Analysis** | `cors` | CORS Misconfiguration | Tests origin reflection and credentialed wildcard CORS policies |
| **Analysis** | `graphql` | GraphQL | Discovers GraphQL endpoints and tests whether schema introspection is enabled |
| **Analysis** | `swagger` | API Docs / Swagger | Detects publicly exposed OpenAPI / Swagger / Redoc specifications |
| **Analysis** | `js` | JavaScript Intelligence | Extracts internal API endpoints from JS bundles and checks for exposed `.map` sourcemaps |
| **Analysis** | `audit` | Active Security Audit | Diagnostic checks for Open Redirects, unescaped parameter reflection, SQL error leakage & HTTP-to-HTTPS enforcement |
| **Enrich** | `secrets` | Secret Scanning | Scans responses and JS assets for leaked AWS keys, JWTs, API tokens, and private keys |
| **Enrich** | `buckets` | Cloud Bucket Discovery | Checks AWS S3, Google Cloud Storage, and Azure Blob containers for public access |
| **Enrich** | `dorks` | Google Dorks | Generates targeted search queries for exposed documents, logs, and code leaks |
| **Enrich** | `screenshots` | Headless Screenshots | Captures headless Chromium screenshots of discovered web assets |

---

## 🔄 Updating & Backups

- **1-Click Git Update**: Open **Updates & Backup** in the top navigation bar and click **Install Update (git pull)** to pull the latest changes directly from GitHub.
- **1-Click JSON Backup & Restore**: Export all scan history, findings, and scope rules with **Download Backup (.json)** and import them on any machine using **Restore Backup (.json)**.
- **Automatic Database Migrations**: SQLite schema upgrades run automatically on startup via `PRAGMA user_version` and create a timestamped `.bak` copy before migrating.

---

## ⚖️ Legal & Authorized Use Notice
WebStrike is intended strictly for **authorized security testing, defensive auditing, and educational use**. Always confirm you own or have explicit written permission to test a target before launching a scan.
