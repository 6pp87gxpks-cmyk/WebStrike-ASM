# Changelog — WebStrike Attack Surface Engine

All notable changes to WebStrike are documented in this file.

## [1.1.0] - 2026-10-30
### Added
- **Versioned Database Migrations (`webstrike/migrations.py`)**: Automatic schema upgrades (`PRAGMA user_version`) with automatic pre-migration `.bak` database backups so your data is never lost during updates.
- **Built-in Update Checker (`webstrike/updates.py`)**: Check for new WebStrike releases directly from the **Updates & Backup** modal in the dashboard.
- **First-Run Setup Wizard (`/setup`)**: New installations launch an interactive setup wizard to create your administrator account and accept the Authorized Use Policy.
- **Target Scope Allowlist (`webstrike/scope.py`)**: Restrict scans to approved domains, wildcard subdomains (`*.example.com`), IPs, and CIDR ranges (`192.168.1.0/24`), plus mandatory pre-scan authorization confirmation.
- **Side-by-Side Scan Comparison (`/api/scan/{sid}/compare/{other_sid}`)**: Compare any two scans in History to see **New**, **Resolved**, and **Unchanged** findings.
- **Security Headers Grading Module (`headers_grade`)**: Scores target HTTP security headers from 0 to 100 (`A+` through `F`) with detailed CSP/HSTS quality checks.
- **SSL/TLS Certificate Health & Expiry Module (`ssl`)**: Checks certificate validity, remaining days, self-signed status, and issuer chain on port 443.
- **Brute-Force Login Protection**: Rate-limits failed login attempts per IP + username.
- **One-Click JSON Backup (`/api/backup`)**: Export all scans, findings, and scope settings from the dashboard.
- **One-Click Launchers**: Added `start.command` (macOS) and `start.bat` (Windows) for zero-terminal installation and launch.

## [1.0.0] - 2026-10-23
### Added
- Initial release with 19 recon, discovery, and parameter auditing modules, interactive Attack Graph, Executive HTML/PDF Report (OWASP Top 10 mapped), and real-time WebSocket dashboard.
