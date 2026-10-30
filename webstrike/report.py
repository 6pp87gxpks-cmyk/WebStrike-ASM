from __future__ import annotations
import html
import time
from typing import List, Dict, Any
from .remediation import get_remediation, get_owasp_tag

def generate_executive_report_html(
    target: str,
    profile: str,
    findings: List[Dict[str, Any]],
    surface: Dict[str, Any],
    elapsed: float,
    scan_id: str,
    started_ts: float = 0.0
) -> str:
    date_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(started_ts or time.time()))

    crit_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
    high_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    med_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium")
    low_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "low")
    info_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "info")

    raw_score = (crit_count * 25) + (high_count * 12) + (med_count * 5) + (low_count * 1)
    risk_score = min(100, raw_score)

    if risk_score >= 70 or crit_count > 0:
        risk_label = "CRITICAL RISK"
        risk_color = "#ff3b6b"
    elif risk_score >= 40 or high_count > 0:
        risk_label = "HIGH RISK"
        risk_color = "#ff7a45"
    elif risk_score >= 15 or med_count > 0:
        risk_label = "MEDIUM RISK"
        risk_color = "#ffd23f"
    elif risk_score > 0:
        risk_label = "LOW RISK"
        risk_color = "#4dd4ac"
    else:
        risk_label = "HEALTHY / SAFE"
        risk_color = "#22d3ee"

    # OWASP Breakdown
    owasp_counts = {}
    for f in findings:
        cat = f.get("category", "")
        title = f.get("title", "")
        code, name = get_owasp_tag(cat, title)
        key = f"{code}: {name}"
        owasp_counts[key] = owasp_counts.get(key, 0) + 1

    owasp_rows = ""
    for tag, count in sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True):
        owasp_rows += f"<tr><td><strong>{html.escape(tag)}</strong></td><td style='text-align:right;'><span class='badge-count'>{count}</span></td></tr>"

    if not owasp_rows:
        owasp_rows = "<tr><td colspan='2' style='color:#7d8ca6;text-align:center;'>No OWASP vulnerabilities identified.</td></tr>"

    # Findings rows
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda x: SEV_ORDER.get(str(x.get("severity", "")).lower(), 9))

    findings_html = ""
    for idx, f in enumerate(sorted_findings, start=1):
        sev = str(f.get("severity", "info")).lower()
        title = f.get("title", "Untitled finding")
        cat = f.get("category", "general")
        loc = f.get("url") or f.get("target") or target
        ev = f.get("evidence", "")
        owasp_code, owasp_name = get_owasp_tag(cat, title)
        rem = get_remediation(cat, title)

        findings_html += f"""
        <div class="finding-card {sev}">
            <div class="finding-header">
                <span class="finding-badge {sev}">{sev.upper()}</span>
                <span class="finding-title">{idx}. {html.escape(title)}</span>
                <span class="finding-owasp">{html.escape(owasp_code)}</span>
            </div>
            <div class="finding-body">
                <div class="finding-row"><span class="lbl">Asset / Location:</span> <code>{html.escape(str(loc))}</code></div>
                <div class="finding-row"><span class="lbl">Category:</span> <span class="tag">{html.escape(cat)}</span></div>
                {f'<div class="finding-row"><span class="lbl">Evidence:</span> <pre class="ev-box">{html.escape(str(ev))}</pre></div>' if ev else ''}
                <div class="finding-row remediation-row">
                    <span class="lbl rem-lbl">Remediation Guidance:</span>
                    <p class="rem-text">{html.escape(rem)}</p>
                </div>
            </div>
        </div>
        """

    if not findings_html:
        findings_html = "<div class='no-findings'>No security findings identified for this scan profile.</div>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>WebStrike Security Audit Report - {html.escape(target)}</title>
<style>
  :root {{
    --bg: #070a11; --panel: #0d121f; --panel2: #141c2e; --border: #1e293b;
    --text: #f1f5f9; --muted: #94a3b8; --accent: #22d3ee; --accent2: #a855f7;
    --crit: #ff3b6b; --high: #ff7a45; --med: #ffd23f; --low: #4dd4ac; --info: #64748b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.6; padding: 40px 20px;
  }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  .toolbar {{ display: flex; justify-content: flex-end; gap: 12px; margin-bottom: 24px; }}
  .btn {{
    background: var(--panel2); border: 1px solid var(--border); color: var(--text);
    padding: 10px 18px; border-radius: 8px; font-weight: 600; font-size: 13px;
    cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 8px;
    transition: 0.15s;
  }}
  .btn:hover {{ border-color: var(--accent); color: var(--accent); }}
  .btn.primary {{ background: linear-gradient(135deg, var(--accent), var(--accent2)); color: #05070d; border: 0; }}
  .header-card {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
    padding: 32px; margin-bottom: 24px; position: relative; overflow: hidden;
  }}
  .header-card::after {{
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
  }}
  .brand {{ display: flex; align-items: center; gap: 14px; margin-bottom: 20px; }}
  .logo {{
    width: 44px; height: 44px; border-radius: 12px; display: grid; place-items: center;
    font-weight: 900; background: linear-gradient(135deg, var(--accent), var(--accent2)); color: #05070d;
  }}
  h1 {{ font-size: 24px; font-weight: 800; letter-spacing: -0.5px; }}
  .meta-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;
    background: var(--panel2); padding: 16px 20px; border-radius: 10px; margin-top: 16px;
    font-size: 13px;
  }}
  .meta-item span {{ display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; }}
  .meta-item strong {{ color: var(--text); font-family: ui-monospace, monospace; }}
  
  .exec-summary {{
    display: grid; grid-template-columns: 240px 1fr; gap: 20px; margin-bottom: 24px;
  }}
  .score-box {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
    padding: 24px; text-align: center; display: flex; flex-direction: column; justify-content: center;
  }}
  .score-num {{ font-size: 56px; font-weight: 900; line-height: 1; }}
  .score-label {{ font-size: 13px; font-weight: 800; text-transform: uppercase; margin-top: 8px; letter-spacing: 1px; }}
  .counts-box {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
    padding: 24px; display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px;
  }}
  .count-card {{
    background: var(--panel2); border-radius: 10px; padding: 16px 12px; text-align: center;
    border-top: 3px solid;
  }}
  .count-card.crit {{ border-top-color: var(--crit); }}
  .count-card.high {{ border-top-color: var(--high); }}
  .count-card.med {{ border-top-color: var(--med); }}
  .count-card.low {{ border-top-color: var(--low); }}
  .count-card.info {{ border-top-color: var(--info); }}
  .count-card b {{ display: block; font-size: 26px; }}
  .count-card span {{ font-size: 11px; color: var(--muted); text-transform: uppercase; }}

  .section-title {{ font-size: 18px; font-weight: 800; margin: 32px 0 16px; display: flex; align-items: center; gap: 10px; }}
  .surface-grid {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 28px;
  }}
  .surface-stat {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px;
  }}
  .surface-stat b {{ font-size: 22px; display: block; color: var(--accent); }}
  .surface-stat span {{ font-size: 11px; text-transform: uppercase; color: var(--muted); }}

  table.data-table {{
    width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border);
    border-radius: 12px; overflow: hidden; margin-bottom: 28px;
  }}
  table.data-table th, table.data-table td {{ padding: 12px 18px; border-bottom: 1px solid var(--border); font-size: 13px; }}
  table.data-table th {{ background: var(--panel2); color: var(--muted); font-size: 11px; text-transform: uppercase; text-align: left; }}
  .badge-count {{ background: var(--panel2); padding: 3px 10px; border-radius: 12px; font-weight: 700; color: var(--accent); }}

  .finding-card {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    margin-bottom: 16px; overflow: hidden; page-break-inside: avoid;
  }}
  .finding-header {{
    padding: 14px 20px; background: var(--panel2); display: flex; align-items: center; gap: 12px;
    border-bottom: 1px solid var(--border);
  }}
  .finding-badge {{
    font-size: 10px; font-weight: 800; text-transform: uppercase; padding: 3px 8px; border-radius: 4px;
  }}
  .finding-badge.critical {{ background: rgba(255,59,107,0.2); color: var(--crit); }}
  .finding-badge.high {{ background: rgba(255,122,69,0.2); color: var(--high); }}
  .finding-badge.medium {{ background: rgba(255,210,63,0.2); color: var(--med); }}
  .finding-badge.low {{ background: rgba(77,212,172,0.2); color: var(--low); }}
  .finding-badge.info {{ background: rgba(100,116,139,0.2); color: var(--info); }}
  .finding-title {{ font-size: 14px; font-weight: 700; flex: 1; }}
  .finding-owasp {{ font-size: 11px; color: var(--muted); font-family: ui-monospace, monospace; }}
  .finding-body {{ padding: 18px 20px; font-size: 13px; }}
  .finding-row {{ margin-bottom: 10px; }}
  .lbl {{ color: var(--muted); font-size: 11px; text-transform: uppercase; font-weight: 700; display: inline-block; width: 140px; }}
  code {{ font-family: ui-monospace, monospace; background: var(--panel2); padding: 3px 8px; border-radius: 5px; color: var(--accent); }}
  .tag {{ background: var(--panel2); padding: 2px 8px; border-radius: 4px; font-size: 11px; color: var(--muted); }}
  .ev-box {{
    margin-top: 8px; background: #05070d; border: 1px solid var(--border); padding: 10px 14px;
    border-radius: 8px; font-family: ui-monospace, monospace; font-size: 12px; color: #cbd5e1;
    overflow-x: auto; white-space: pre-wrap; word-break: break-all;
  }}
  .remediation-row {{
    margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border);
  }}
  .rem-lbl {{ color: var(--low); }}
  .rem-text {{ margin-top: 4px; color: #cbd5e1; font-size: 12.5px; line-height: 1.5; }}
  .footer {{ text-align: center; color: var(--muted); font-size: 11px; margin-top: 48px; text-transform: uppercase; letter-spacing: 1px; }}

  @media print {{
    body {{ background: #fff; color: #0f172a; padding: 0; }}
    .toolbar {{ display: none; }}
    .header-card, .score-box, .counts-box, .surface-stat, table.data-table, .finding-card {{
      background: #fff; border: 1px solid #cbd5e1; color: #0f172a; box-shadow: none;
    }}
    .meta-grid, .finding-header, .count-card, table.data-table th {{ background: #f8fafc; color: #0f172a; }}
    .ev-box {{ background: #f1f5f9; color: #0f172a; border-color: #cbd5e1; }}
    .lbl {{ color: #475569; }}
    code {{ background: #f1f5f9; color: #0f172a; border: 1px solid #cbd5e1; }}
    .rem-text {{ color: #1e293b; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="toolbar">
    <a href="/" class="btn">&larr; Back to Dashboard</a>
    <button onclick="window.print()" class="btn primary">Print / Save as PDF</button>
  </div>

  <header class="header-card">
    <div class="brand">
      <div class="logo">WS</div>
      <div>
        <h1>WebStrike Executive Security Audit</h1>
        <div style="color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:1px;">Comprehensive Attack Surface &amp; Risk Assessment</div>
      </div>
    </div>
    <div class="meta-grid">
      <div class="meta-item"><span>Target Asset</span><strong>{html.escape(target)}</strong></div>
      <div class="meta-item"><span>Scan Profile</span><strong>{html.escape(profile.upper())}</strong></div>
      <div class="meta-item"><span>Date Generated</span><strong>{html.escape(date_str)}</strong></div>
      <div class="meta-item"><span>Scan ID</span><strong>{html.escape(scan_id)}</strong></div>
    </div>
  </header>

  <section class="exec-summary">
    <div class="score-box">
      <div class="score-num" style="color:{risk_color};">{risk_score}</div>
      <div class="score-label" style="color:{risk_color};">{risk_label}</div>
      <span style="font-size:11px; color:var(--muted); margin-top:6px;">Calculated Asset Risk Score (0-100)</span>
    </div>
    <div class="counts-box">
      <div class="count-card crit"><b>{crit_count}</b><span>Critical</span></div>
      <div class="count-card high"><b>{high_count}</b><span>High</span></div>
      <div class="count-card med"><b>{med_count}</b><span>Medium</span></div>
      <div class="count-card low"><b>{low_count}</b><span>Low</span></div>
      <div class="count-card info"><b>{info_count}</b><span>Info</span></div>
    </div>
  </section>

  <h2 class="section-title">Attack Surface Footprint</h2>
  <div class="surface-grid">
    <div class="surface-stat"><b>{surface.get("hosts", 0)}</b><span>Discovered Hosts / IPs</span></div>
    <div class="surface-stat"><b>{surface.get("subdomains", 0)}</b><span>Subdomains</span></div>
    <div class="surface-stat"><b>{surface.get("endpoints", 0)}</b><span>Discovered Endpoints</span></div>
    <div class="surface-stat"><b>{surface.get("urls", 0)}</b><span>Live URLs Audited</span></div>
  </div>

  <h2 class="section-title">OWASP Top 10 Security Mapping</h2>
  <table class="data-table">
    <thead>
      <tr><th>OWASP 2021 Standard Category</th><th style="text-align:right;">Findings Count</th></tr>
    </thead>
    <tbody>
      {owasp_rows}
    </tbody>
  </table>

  <h2 class="section-title">Vulnerability &amp; Security Findings ({len(findings)})</h2>
  <div class="findings-list">
    {findings_html}
  </div>

  <div class="footer">
    Generated by WebStrike Attack Surface Engine &bull; Confidential Security Document
  </div>
</div>
</body>
</html>
"""
