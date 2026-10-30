from __future__ import annotations
from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from .base import Module

HEADER_WEIGHTS = [
    ("strict-transport-security", "HSTS", 25),
    ("content-security-policy", "CSP", 30),
    ("x-frame-options", "X-Frame-Options", 15),
    ("x-content-type-options", "X-Content-Type-Options", 15),
    ("referrer-policy", "Referrer-Policy", 8),
    ("permissions-policy", "Permissions-Policy", 7),
]


def _score_to_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


@register
class SecurityHeadersGrade(Module):
    id = "headers_grade"
    name = "Security Headers Grade"
    phase = Phase.RECON
    profiles = {"passive", "balanced", "danger"}
    kinds = {"domain", "url"}

    async def run(self, ctx):
        base = ctx.base_url
        r = await ctx.http.probe(base)
        if not r and base.startswith("https://"):
            r = await ctx.http.probe(base.replace("https://", "http://", 1))
        if not r:
            return

        hdrs = {k.lower(): v for k, v in r.headers.items()}
        score = 0
        present = []
        missing = []
        notes = []

        for key, label, weight in HEADER_WEIGHTS:
            val = hdrs.get(key)
            if val:
                present.append(label)
                earned = weight
                if key == "content-security-policy":
                    low = val.lower()
                    if "'unsafe-inline'" in low or "'unsafe-eval'" in low:
                        earned = max(12, weight - 12)
                        notes.append("CSP allows unsafe-inline/unsafe-eval")
                elif key == "strict-transport-security":
                    if "max-age=0" in val.lower():
                        earned = 0
                        notes.append("HSTS max-age is 0")
                score += earned
            else:
                missing.append(label)

        grade = _score_to_grade(score)
        if score >= 85:
            sev = Severity.INFO
        elif score >= 55:
            sev = Severity.LOW
        else:
            sev = Severity.MEDIUM

        summary_parts = [f"Score: {score}/100 (Grade {grade})"]
        if present:
            summary_parts.append(f"Present: {', '.join(present)}")
        if missing:
            summary_parts.append(f"Missing: {', '.join(missing)}")
        if notes:
            summary_parts.append("Notes: " + "; ".join(notes))

        yield Finding(
            self.id,
            f"Security Headers Grade: {grade} ({score}/100)",
            sev,
            Confidence.CERTAIN,
            category="headers",
            url=str(r.url),
            evidence=" | ".join(summary_parts),
            meta={"grade": grade, "score": score, "present": present, "missing": missing}
        )
