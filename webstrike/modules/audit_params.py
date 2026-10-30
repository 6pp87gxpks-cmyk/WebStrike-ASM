from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..models import Confidence, Finding, Severity
from ..registry import Phase, register
from .base import Module

REDIRECT_PARAMS = {
    "url",
    "redirect",
    "redirect_to",
    "next",
    "dest",
    "destination",
    "return",
    "return_to",
    "target",
    "r",
    "goto",
    "link",
    "out",
    "view",
}

SQL_ERRORS = [
    ("MySQL", "you have an error in your sql syntax"),
    ("MySQL", "mysql_fetch_array()"),
    ("PostgreSQL", "warning: pg_exec()"),
    ("PostgreSQL", "unterminated quoted string at or near"),
    ("MSSQL", "unclosed quotation mark after the character string"),
    ("MSSQL", "microsoft ole db provider for sql server"),
    ("Oracle", "ora-01756"),
    ("SQLite", "sqlite3::query()"),
    ("SQLite", "unrecognized token:"),
]


@register
class AuditParams(Module):
    id = "audit"
    name = "Active Security Audit & Fuzzing"
    phase = Phase.ANALYSIS
    profiles = {"balanced", "danger"}
    kinds = {"domain", "url"}

    async def run(self, ctx):
        candidate_urls = {str(u) for u in ctx.state.get("urls", set()) if "?" in str(u)}

        if ctx.base_url.startswith("https://"):
            dom_fmt = (
                f"[{ctx.domain}]"
                if ":" in ctx.domain and not ctx.domain.startswith("[")
                else ctx.domain
            )
            http_url = "http://" + dom_fmt
            r_http = await ctx.http.probe(http_url, follow_redirects=False)
            if r_http and r_http.status_code == 200:
                yield Finding(
                    self.id,
                    "Insecure HTTP Transport Allowed",
                    Severity.MEDIUM,
                    Confidence.CERTAIN,
                    category="crypto",
                    url=http_url,
                    evidence="HTTP port 80 does not enforce redirect to HTTPS (HSTS disabled or missing redirect)",
                )

        if not candidate_urls:
            return

        tested_params = set()
        for raw_url in sorted(candidate_urls)[:25]:
            p = urlparse(raw_url)
            qs = parse_qs(p.query)

            for param in qs:
                param_key = (p.path, param.lower())
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)

                if param.lower() in REDIRECT_PARAMS:
                    canary_target = "https://example.com"
                    q_mod = dict(qs)
                    q_mod[param] = [canary_target]
                    test_url = urlunparse(
                        (p.scheme, p.netloc, p.path, p.params, urlencode(q_mod, doseq=True), p.fragment)
                    )
                    r_redir = await ctx.http.probe(test_url, follow_redirects=False)
                    if r_redir and r_redir.status_code in (301, 302, 303, 307, 308):
                        loc = r_redir.headers.get("location", "").strip()
                        loc_host = (urlparse(loc).hostname or "").lower()
                        if loc_host == "example.com" or loc.startswith("//example.com"):
                            yield Finding(
                                self.id,
                                f"Open Redirect Vulnerability: ?{param}=",
                                Severity.HIGH,
                                Confidence.CERTAIN,
                                category="vuln",
                                url=raw_url,
                                evidence=f"Target redirected to external host via Location: {loc}",
                            )

                canary_probe = f"ws{ctx.scan_id[:4]}<wstest>'\""
                q_mod = dict(qs)
                q_mod[param] = [canary_probe]
                test_url = urlunparse(
                    (p.scheme, p.netloc, p.path, p.params, urlencode(q_mod, doseq=True), p.fragment)
                )
                r_ref = await ctx.http.probe(test_url)
                if r_ref and r_ref.status_code == 200:
                    ct = r_ref.headers.get("content-type", "").lower()
                    if "text/html" in ct and "<wstest>'" in r_ref.text:
                        yield Finding(
                            self.id,
                            f"Reflected Input (Unescaped): ?{param}=",
                            Severity.MEDIUM,
                            Confidence.FIRM,
                            category="vuln",
                            url=raw_url,
                            evidence="Parameter value reflected unescaped with HTML brackets (<wstest>') in HTTP response",
                        )

                q_mod = dict(qs)
                q_mod[param] = ["1'"]
                test_url = urlunparse(
                    (p.scheme, p.netloc, p.path, p.params, urlencode(q_mod, doseq=True), p.fragment)
                )
                r_sql = await ctx.http.probe(test_url)
                if r_sql:
                    body_lower = r_sql.text.lower()
                    for db_type, err_sig in SQL_ERRORS:
                        if err_sig in body_lower:
                            yield Finding(
                                self.id,
                                f"Database Error Leakage ({db_type}): ?{param}=",
                                Severity.HIGH,
                                Confidence.CERTAIN,
                                category="vuln",
                                url=raw_url,
                                evidence=f"Leaked syntax error string '{err_sig}' when injecting single quote in ?{param}=",
                            )
                            break
