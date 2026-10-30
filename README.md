# WebStrike

![Version](https://img.shields.io/badge/version-1.1.0-22d3ee)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Self-hosted recon and web security scanner with a live web UI and CLI. Runs locally, stores history in SQLite, and doesn't need external accounts or API keys to work.

## Running it

On **macOS / Linux**, run `./start.command` (or double-click it in Finder). It'll set up `.venv` on the first run, install what's in `requirements.txt`, and open `http://127.0.0.1:8777`.

On **Windows**, double-click `start.bat`.

If you prefer running it manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py web
```

For headless screenshots (`screenshots` module), grab the Chromium binary once:

```bash
.venv/bin/playwright install chromium
```

### CLI

You don't have to use the browser UI. To run a scan straight from the terminal:

```bash
python run.py scan https://example.com -p balanced
```

Pick specific modules with `-m`:

```bash
python run.py scan example.com -p passive -m dns,ssl,waf,headers_grade
```

### Docker

```bash
docker compose up -d --build
```

Scan data and SQLite files stay in `./scans`.

## Modules (22)

- **Recon:** `dns` (DNS/WHOIS/SPF/DMARC), `subdomains` (crt.sh + brute + CNAME takeover check), `intel` (IP geo/ASN/CDN), `waf` (Cloudflare/Akamai/AWS/Imperva/etc.), `ssl` (cert expiry & chain check), `headers_grade` (A+ to F header scoring), `ports` (top 20 TCP ports), `robots` (robots.txt, sitemap.xml, security.txt), `wayback` (Wayback CDX + OTX URLs).
- **Discovery:** `fingerprint` (tech stack, server headers, cookie flags), `crawler` (internal links, GET/POST forms, upload/login detection), `paths` (common paths with soft-404 filtering), `exposure` (`.env`, `.git`, backups, key files).
- **Analysis:** `cors` (origin reflection & wildcard checks), `graphql` (endpoints + introspection probe), `swagger` (OpenAPI/Swagger/Redoc specs), `js` (JS endpoints + `.map` sourcemaps), `audit` (open redirect, unescaped reflection, SQL error strings, HTTP->HTTPS check).
- **Enrich:** `secrets` (AWS, Stripe, GitHub, JWT, private keys in responses), `buckets` (S3, GCS, Azure Blob), `dorks` (Google dork queries), `screenshots` (Playwright page captures).

## Updates & Backups

From the top bar (`Updates & Backup`):
- **Download / Restore Backup (.json):** exports or imports your scans, findings, and scope allowlist.
- **Install Update (git pull):** pulls the latest commit if you cloned the repo with Git.

## Note

Only scan hosts you own or have permission to test. Use the **Scope** button in the UI if you want to lock the scanner to specific domains or CIDRs.
