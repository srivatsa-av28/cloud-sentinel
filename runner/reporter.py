#!/usr/bin/env python3
"""
cloud-sentinel: reporter
Aggregates Cloud Custodian findings into an HTML report and Slack notification.
"""

import os
import json
import glob
import logging
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("cloud-sentinel.reporter")

# AI advisor — imported lazily so reporter works without ANTHROPIC_API_KEY
try:
    from ai_advisor import (
        enrich_findings_with_ai,
        render_ai_remediation_html,
        AI_REMEDIATION_CSS,
    )
    AI_ADVISOR_AVAILABLE = True
except ImportError:
    AI_ADVISOR_AVAILABLE = False
    AI_REMEDIATION_CSS   = ""

# Compliance framework definitions (for rendering posture cards)
try:
    from engine.compliance import FRAMEWORKS
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False
    FRAMEWORKS = {}

PROJECT_ROOT = Path(__file__).parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"

SEVERITY_COLOR = {
    "CRITICAL": "#B91C1C",
    "HIGH":     "#EA580C",
    "MEDIUM":   "#D97706",
    "LOW":      "#4B5563",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "⚪",
}

CLOUD_EMOJI = {
    "aws":   "☁️",
    "azure": "🔷",
    "gcp":   "🟢",
}


def load_latest_results() -> dict:
    """Load the most recent results.json from reports/"""
    run_dirs = sorted(REPORTS_DIR.glob("run_*"), reverse=True)
    if not run_dirs:
        raise FileNotFoundError(f"No run directories found in {REPORTS_DIR}")
    results_file = run_dirs[0] / "results.json"
    if not results_file.exists():
        raise FileNotFoundError(f"results.json not found in {run_dirs[0]}")
    with open(results_file) as f:
        return json.load(f)


def load_results_from_file(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def load_drift_results(path: str) -> dict:
    """Load a drift_results.json produced by drift/detector.py"""
    with open(path) as f:
        return json.load(f)


def collect_all_findings(results: dict) -> list[dict]:
    """Flatten all findings from all policy results."""
    findings = []
    for result in results.get("results", []):
        cloud = result.get("cloud", "unknown")
        for finding in result.get("findings", []):
            finding["cloud"] = cloud
            findings.append(finding)
    return findings


def severity_sort_key(finding: dict) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return order.get(finding.get("severity", "LOW"), 99)


# ─────────────────────────────────────────────
# Compliance Posture Section
# ─────────────────────────────────────────────

GRADE_COLOR = {
    "A": "#16a34a",
    "B": "#65a30d",
    "C": "#d97706",
    "D": "#ea580c",
    "F": "#dc2626",
}


def render_compliance_section(results: dict) -> str:
    """Render the compliance posture dashboard (PCI DSS, ISO 27001, SOC 2, HIPAA, CPS 234)."""
    compliance = results.get("compliance")
    if not compliance:
        return ""

    cards = ""
    for fw_id, fw in compliance.items():
        grade = fw.get("grade", "?")
        score = fw.get("score", 0)
        color = GRADE_COLOR.get(grade, "#94a3b8")
        fw_color = fw.get("color", "#38bdf8")

        failing = fw.get("failing_controls", [])
        failing_str = ", ".join(failing[:6]) + ("…" if len(failing) > 6 else "") if failing else "None"

        cards += f"""
        <div class="compliance-card">
          <div class="cc-header">
            <span class="cc-name" style="color:{fw_color}">{fw.get('framework_short','')}</span>
            <span class="cc-grade" style="background:{color}">{grade}</span>
          </div>
          <div class="cc-score-row">
            <div class="cc-score-bar">
              <div class="cc-score-fill" style="width:{score}%; background:{color}"></div>
            </div>
            <span class="cc-score-val">{score}%</span>
          </div>
          <div class="cc-meta">
            <span>{fw.get('findings_count',0)} finding(s)</span>
            <span>{len(failing)}/{fw.get('total_controls',0)} controls failing</span>
          </div>
          <div class="cc-controls">
            <span class="cc-controls-label">Failing controls:</span> {failing_str}
          </div>
        </div>"""

    return f"""
  <p class="section-title">Compliance Posture</p>
  <div class="compliance-grid">
    {cards}
  </div>"""


COMPLIANCE_CSS = """
  .compliance-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .compliance-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 0.75rem;
    padding: 1.1rem 1.25rem;
  }
  .cc-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.65rem;
  }
  .cc-name { font-size: 0.85rem; font-weight: 700; letter-spacing: 0.02em; }
  .cc-grade {
    width: 1.6rem; height: 1.6rem;
    border-radius: 0.375rem;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.85rem; font-weight: 800; color: #0f172a;
  }
  .cc-score-row { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.6rem; }
  .cc-score-bar {
    flex: 1; height: 6px; border-radius: 9999px;
    background: #0f172a; overflow: hidden;
  }
  .cc-score-fill { height: 100%; border-radius: 9999px; }
  .cc-score-val { font-size: 0.78rem; font-weight: 700; color: #cbd5e1; font-family: monospace; }
  .cc-meta {
    display: flex; justify-content: space-between;
    font-size: 0.7rem; color: #64748b; margin-bottom: 0.5rem;
  }
  .cc-controls {
    font-size: 0.7rem; color: #94a3b8;
    background: #0f172a; border-radius: 0.375rem;
    padding: 0.5rem 0.6rem; line-height: 1.5;
  }
  .cc-controls-label { color: #64748b; font-weight: 600; }
"""


# ─────────────────────────────────────────────
# PSPM Drift Section
# ─────────────────────────────────────────────

DRIFT_TYPE_LABEL = {
    "unmanaged": ("🛑 Unmanaged", "#dc2626", "Created outside Terraform"),
    "drifted":   ("⚠ Drifted",   "#d97706", "Attributes diverged from IaC"),
    "ghost":     ("👻 Ghost",     "#64748b", "In Terraform, missing in cloud"),
}


def render_drift_section(drift_results: dict | None) -> str:
    """Render the PSPM drift detection section."""
    if not drift_results:
        return ""

    s = drift_results.get("summary", {})
    findings = drift_results.get("findings", [])
    findings = sorted(findings, key=severity_sort_key)

    by_drift = s.get("by_drift_type", {"unmanaged": 0, "drifted": 0, "ghost": 0})
    by_owner = s.get("by_owner", [])
    total    = s.get("total_findings", 0)
    tfstate  = drift_results.get("tfstate_path", "")

    # Stat cards
    stat_cards = f"""
    <div class="stat-card" style="border-top:2px solid #dc2626">
      <div class="value" style="color:#fca5a5">{by_drift.get('unmanaged',0)}</div>
      <div class="label">Unmanaged (bypassed Terraform)</div>
    </div>
    <div class="stat-card" style="border-top:2px solid #d97706">
      <div class="value" style="color:#fdba74">{by_drift.get('drifted',0)}</div>
      <div class="label">Drifted from IaC</div>
    </div>
    <div class="stat-card" style="border-top:2px solid #64748b">
      <div class="value" style="color:#cbd5e1">{by_drift.get('ghost',0)}</div>
      <div class="label">Ghost (in TF, not in cloud)</div>
    </div>"""

    # Owner table
    owner_rows = ""
    for o in by_owner[:10]:
        bs = o.get("by_severity", {})
        owner_rows += f"""
        <tr>
          <td class="owner-name">{o['owner']}</td>
          <td>{o['total']}</td>
          <td style="color:#f87171">{bs.get('CRITICAL',0)}</td>
          <td style="color:#fb923c">{bs.get('HIGH',0)}</td>
          <td style="color:#fbbf24">{bs.get('MEDIUM',0)}</td>
        </tr>"""

    # Findings table
    rows_html = ""
    if not findings:
        rows_html = """
        <tr><td colspan="7" style="text-align:center; color:#16a34a; padding:2rem; font-weight:600;">
          ✅ No drift detected — cloud state matches Terraform
        </td></tr>"""
    else:
        for f in findings:
            sev = f.get("severity", "LOW")
            color = SEVERITY_COLOR.get(sev, "#4B5563")
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            cloud = f.get("cloud", "unknown")
            dtype = f.get("drift_type", "")
            label, dcolor, _ = DRIFT_TYPE_LABEL.get(dtype, (dtype, "#94a3b8", ""))
            tf_addr = f.get("tf_address") or "—"

            rows_html += f"""
        <tr>
          <td><span class="drift-type-badge" style="color:{dcolor}; border-color:{dcolor}">{label}</span></td>
          <td><span class="cloud-badge cloud-{cloud}">{CLOUD_EMOJI.get(cloud,'')} {cloud.upper()}</span></td>
          <td><span class="severity-badge" style="background:{color}">{emoji} {sev}</span></td>
          <td class="resource-id">{f.get('resource_id','')}</td>
          <td class="owner-name">{f.get('owner','unassigned')}</td>
          <td>{f.get('violation','')}</td>
          <td class="remediation"><code>{f.get('remediation','')}</code>{
            f'<div class="tf-address">📍 {tf_addr}</div>' if tf_addr != "—" else ''
          }</td>
        </tr>"""

    return f"""
  <p class="section-title">Platform Security Posture Management (PSPM)</p>
  <div class="meta" style="margin-bottom:1rem;">
    Terraform state: <code>{tfstate}</code> &nbsp;|&nbsp; {total} drift finding(s) across {', '.join(c.upper() for c in drift_results.get('clouds_scanned', []))}
  </div>

  <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom:1.5rem;">
    {stat_cards}
  </div>

  <p class="section-title">Findings by Owner</p>
  <div class="findings-table-wrap" style="margin-bottom:2rem;">
    <table class="findings">
      <thead><tr><th>Owner / Team</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th></tr></thead>
      <tbody>{owner_rows}</tbody>
    </table>
  </div>

  <p class="section-title">Drift Findings ({total})</p>
  <div class="findings-table-wrap">
    <table class="findings">
      <thead>
        <tr>
          <th>Type</th><th>Cloud</th><th>Severity</th><th>Resource</th><th>Owner</th><th>Issue</th><th>Remediation</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>"""


DRIFT_CSS = """
  .drift-type-badge {
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 0.375rem;
    border: 1px solid;
    font-size: 0.68rem;
    font-weight: 700;
    white-space: nowrap;
  }
  .owner-name {
    font-family: monospace;
    font-size: 0.78rem;
    color: #fbbf24;
  }
  .tf-address {
    margin-top: 0.3rem;
    font-size: 0.7rem;
    color: #64748b;
    font-family: monospace;
  }
"""


# ─────────────────────────────────────────────
# HTML Report
# ─────────────────────────────────────────────

def generate_html_report(results: dict, output_path: Path, ai_enriched: bool = False, drift_results: dict | None = None) -> Path:
    """Generate a self-contained HTML report from scan results."""
    findings = collect_all_findings(results)
    findings.sort(key=severity_sort_key)
    ai_badge = '<span class="ai-active-badge">🤖 AI Advisor Active</span>' if ai_enriched else ""
    compliance_badge = '<span class="ai-active-badge" style="background:#1a3320;color:#86efac;border-color:#16a34a">📋 Compliance Mapped</span>' if results.get("compliance") else ""
    drift_badge = '<span class="ai-active-badge" style="background:#2e1a0a;color:#fdba74;border-color:#d97706">🛰 PSPM Drift Scan</span>' if drift_results else ""

    s = results.get("summary", {})
    timestamp = results.get("timestamp", "unknown")
    run_id = results.get("run_id", "unknown")
    clouds_scanned = results.get("clouds_scanned", [])

    critical = s.get("by_severity", {}).get("CRITICAL", 0)
    high     = s.get("by_severity", {}).get("HIGH", 0)
    medium   = s.get("by_severity", {}).get("MEDIUM", 0)
    low      = s.get("by_severity", {}).get("LOW", 0)
    total    = s.get("total_findings", 0)

    # Build findings rows
    rows_html = ""
    if not findings:
        rows_html = """
        <tr>
          <td colspan="6" style="text-align:center; color:#16a34a; padding:2rem; font-weight:600;">
            ✅ No findings — all policies passed
          </td>
        </tr>"""
    else:
        for f in findings:
            sev = f.get("severity", "LOW")
            color = SEVERITY_COLOR.get(sev, "#4B5563")
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            cloud = f.get("cloud", "unknown")
            ai    = f.get("ai_remediation")
            ai_block = render_ai_remediation_html(ai) if (ai and AI_ADVISOR_AVAILABLE) else ""
            rows_html += f"""
        <tr>
          <td><span class="cloud-badge cloud-{cloud}">{CLOUD_EMOJI.get(cloud,'')} {cloud.upper()}</span></td>
          <td><code class="policy-name">{f.get('policy_name','')}</code></td>
          <td><span class="severity-badge" style="background:{color}">{emoji} {sev}</span></td>
          <td class="resource-id">{f.get('resource_id','')}</td>
          <td>{f.get('violation','')}</td>
          <td class="remediation">
            {f.get('remediation','')}
            {ai_block}
          </td>
        </tr>"""

    # Cloud breakdown rows
    cloud_rows = ""
    for cloud, count in s.get("by_cloud", {}).items():
        cloud_rows += f"""
            <tr>
              <td>{CLOUD_EMOJI.get(cloud,'')} {cloud.upper()}</td>
              <td>{count}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>cloud-sentinel — CSPM Report {run_id}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
      padding: 2rem;
    }}
    .ai-active-badge {{
      display: inline-block;
      padding: 0.25rem 0.75rem;
      background: #1e3a5f;
      color: #93c5fd;
      border-radius: 9999px;
      font-size: 0.72rem;
      font-weight: 700;
      border: 1px solid #1d4ed8;
      margin-left: 0.75rem;
    }}
    {AI_REMEDIATION_CSS}
    {COMPLIANCE_CSS}
    {DRIFT_CSS}
    .header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 2rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid #1e293b;
    }}
    .header h1 {{ font-size: 1.6rem; font-weight: 700; color: #f8fafc; }}
    .header h1 span {{ color: #38bdf8; }}
    .meta {{ font-size: 0.8rem; color: #64748b; margin-top: 0.3rem; }}
    .status-pill {{
      padding: 0.3rem 0.9rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.05em;
    }}
    .status-critical {{ background: #450a0a; color: #fca5a5; }}
    .status-clean {{ background: #052e16; color: #86efac; }}

    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .stat-card {{
      background: #1e293b;
      border-radius: 0.75rem;
      padding: 1.25rem;
      border: 1px solid #334155;
      text-align: center;
    }}
    .stat-card .value {{
      font-size: 2.2rem;
      font-weight: 800;
      line-height: 1;
      margin-bottom: 0.4rem;
    }}
    .stat-card .label {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
    .critical-val {{ color: #f87171; }}
    .high-val     {{ color: #fb923c; }}
    .medium-val   {{ color: #fbbf24; }}
    .low-val      {{ color: #94a3b8; }}
    .total-val    {{ color: #38bdf8; }}

    .section-title {{
      font-size: 1rem;
      font-weight: 600;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 0.75rem;
    }}
    .cloud-breakdown {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 0.75rem;
      padding: 1rem 1.5rem;
      margin-bottom: 2rem;
      display: inline-block;
      min-width: 220px;
    }}
    .cloud-breakdown table {{ width: 100%; border-collapse: collapse; }}
    .cloud-breakdown td {{ padding: 0.4rem 0.5rem; font-size: 0.875rem; }}
    .cloud-breakdown td:last-child {{ text-align: right; font-weight: 600; color: #38bdf8; }}

    .findings-table-wrap {{
      overflow-x: auto;
      border-radius: 0.75rem;
      border: 1px solid #334155;
    }}
    table.findings {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }}
    table.findings thead tr {{
      background: #1e293b;
    }}
    table.findings th {{
      padding: 0.85rem 1rem;
      text-align: left;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: #64748b;
      white-space: nowrap;
    }}
    table.findings tbody tr {{
      border-top: 1px solid #1e293b;
      transition: background 0.15s;
    }}
    table.findings tbody tr:hover {{ background: #1e293b; }}
    table.findings td {{
      padding: 0.8rem 1rem;
      vertical-align: top;
      color: #cbd5e1;
    }}
    .cloud-badge {{
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 0.375rem;
      font-size: 0.7rem;
      font-weight: 700;
      white-space: nowrap;
    }}
    .cloud-aws   {{ background: #451a03; color: #fdba74; }}
    .cloud-azure {{ background: #172554; color: #93c5fd; }}
    .cloud-gcp   {{ background: #052e16; color: #86efac; }}
    .severity-badge {{
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 0.375rem;
      font-size: 0.7rem;
      font-weight: 700;
      color: white;
      white-space: nowrap;
    }}
    .policy-name {{ font-size: 0.75rem; color: #7dd3fc; background: #0c1929; padding: 0.2rem 0.4rem; border-radius: 0.25rem; }}
    .resource-id {{ font-family: monospace; font-size: 0.78rem; color: #a5b4fc; }}
    .remediation {{ color: #86efac; font-size: 0.8rem; }}

    .footer {{
      margin-top: 2.5rem;
      text-align: center;
      font-size: 0.75rem;
      color: #334155;
    }}
    .footer a {{ color: #38bdf8; text-decoration: none; }}
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>☁️ <span>cloud-sentinel</span> — CSPM Report {ai_badge}{compliance_badge}{drift_badge}</h1>
      <div class="meta">Run ID: {run_id} &nbsp;|&nbsp; {timestamp} &nbsp;|&nbsp; Clouds: {', '.join(c.upper() for c in clouds_scanned)}</div>
    </div>
    <span class="status-pill {'status-critical' if total > 0 else 'status-clean'}">
      {'⚠ FINDINGS DETECTED' if total > 0 else '✅ CLEAN'}
    </span>
  </div>

  <div class="stats-grid">
    <div class="stat-card"><div class="value total-val">{total}</div><div class="label">Total Findings</div></div>
    <div class="stat-card"><div class="value critical-val">{critical}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="value high-val">{high}</div><div class="label">High</div></div>
    <div class="stat-card"><div class="value medium-val">{medium}</div><div class="label">Medium</div></div>
    <div class="stat-card"><div class="value low-val">{low}</div><div class="label">Low</div></div>
    <div class="stat-card"><div class="value" style="color:#e2e8f0">{s.get('total_policies',0)}</div><div class="label">Policies Run</div></div>
  </div>

  <p class="section-title">By Cloud</p>
  <div class="cloud-breakdown">
    <table>{cloud_rows}</table>
  </div>
{render_compliance_section(results)}
  <p class="section-title">Findings ({total})</p>
  <div class="findings-table-wrap">
    <table class="findings">
      <thead>
        <tr>
          <th>Cloud</th>
          <th>Policy</th>
          <th>Severity</th>
          <th>Resource</th>
          <th>Violation</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>
{render_drift_section(drift_results)}
  <div class="footer">
    Generated by <a href="https://github.com/vatsa/cloud-sentinel">cloud-sentinel</a> —
    native CSPM + Compliance Mapping + PSPM drift detection, powered by Claude AI
  </div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

    log.info(f"HTML report written: {output_path}")
    return output_path


# ─────────────────────────────────────────────
# Slack Notification
# ─────────────────────────────────────────────

def build_slack_payload(results: dict) -> dict:
    """Build a Slack Block Kit payload from scan results."""
    s = results.get("summary", {})
    total    = s.get("total_findings", 0)
    critical = s.get("by_severity", {}).get("CRITICAL", 0)
    high     = s.get("by_severity", {}).get("HIGH", 0)
    medium   = s.get("by_severity", {}).get("MEDIUM", 0)
    low      = s.get("by_severity", {}).get("LOW", 0)
    clouds   = results.get("clouds_scanned", [])
    run_id   = results.get("run_id", "unknown")
    timestamp = results.get("timestamp", "")

    status_emoji = "🔴" if critical > 0 else ("🟠" if high > 0 else ("🟡" if medium > 0 else "✅"))
    status_text  = "CRITICAL issues found" if critical > 0 else (
                   "HIGH severity issues found" if high > 0 else (
                   "Issues found" if total > 0 else "All clear — no findings"))

    cloud_summary = " | ".join(
        f"{CLOUD_EMOJI.get(c,'')} {c.upper()}: {s.get('by_cloud',{}).get(c,0)}"
        for c in clouds
    )

    # Top 5 critical/high findings for Slack
    findings = collect_all_findings(results)
    findings.sort(key=severity_sort_key)
    top_findings = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")][:5]

    finding_blocks = []
    for f in top_findings:
        sev = f.get("severity", "")
        finding_blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{SEVERITY_EMOJI.get(sev,'')} *{sev}* — `{f.get('policy_name','')}` "
                    f"[{f.get('cloud','').upper()}]\n"
                    f"> Resource: `{f.get('resource_id','')}`\n"
                    f"> {f.get('violation','')}\n"
                    f"> 💡 _{f.get('remediation','')}_"
                )
            }
        })

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{status_emoji} cloud-sentinel CSPM Scan", "emoji": True}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Status*\n{status_text}"},
                {"type": "mrkdwn", "text": f"*Run ID*\n`{run_id}`"},
                {"type": "mrkdwn", "text": f"*Total Findings*\n{total}"},
                {"type": "mrkdwn", "text": f"*Clouds Scanned*\n{', '.join(c.upper() for c in clouds)}"},
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Severity Breakdown*\n"
                    f"🔴 Critical: *{critical}*   🟠 High: *{high}*   "
                    f"🟡 Medium: *{medium}*   ⚪ Low: *{low}*"
                )
            }
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*By Cloud*\n{cloud_summary}"}
        },
    ]

    if finding_blocks:
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Top Critical / High Findings*"}
        })
        blocks.extend(finding_blocks)

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"🕐 {timestamp} | cloud-sentinel by Vatsa"}
        ]
    })

    return {"blocks": blocks}


def send_slack_notification(results: dict, webhook_url: str) -> bool:
    """Send findings to Slack via Incoming Webhook."""
    payload = build_slack_payload(results)
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode()
            if resp.status == 200 and body == "ok":
                log.info("Slack notification sent successfully")
                return True
            else:
                log.error(f"Slack returned unexpected response: {resp.status} {body}")
                return False
    except urllib.error.HTTPError as e:
        log.error(f"Slack HTTP error: {e.code} {e.reason}")
        return False
    except Exception as e:
        log.error(f"Failed to send Slack notification: {e}")
        return False


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="cloud-sentinel reporter")
    parser.add_argument("--results",      help="Path to results.json (default: latest run)")
    parser.add_argument("--output",       help="Output path for HTML report")
    parser.add_argument("--slack-webhook",help="Slack Incoming Webhook URL (or set SLACK_WEBHOOK_URL env var)")
    parser.add_argument("--no-html",      action="store_true", help="Skip HTML report generation")
    parser.add_argument("--no-slack",     action="store_true", help="Skip Slack notification")
    parser.add_argument("--ai",           action="store_true", help="Enrich findings with AI remediation advice")
    parser.add_argument("--ai-severities",nargs="+", default=["CRITICAL", "HIGH"],
                        help="Severities to enrich with AI (default: CRITICAL HIGH)")
    parser.add_argument("--ai-max",       type=int, default=50,
                        help="Max findings to send to AI advisor (cost control, default: 50)")
    parser.add_argument("--drift-results", default=None,
                        help="Path to drift_results.json from drift/detector.py — adds PSPM section to report")
    args = parser.parse_args()

    # Load results
    if args.results:
        results = load_results_from_file(args.results)
    else:
        results = load_latest_results()

    run_id = results.get("run_id", "unknown")
    ai_enriched = False

    # AI enrichment
    if args.ai:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            log.error("--ai requires ANTHROPIC_API_KEY environment variable")
        elif not AI_ADVISOR_AVAILABLE:
            log.error("ai_advisor module not found — ensure ai_advisor.py is in runner/")
        else:
            log.info("Running AI remediation advisor...")
            all_findings = collect_all_findings(results)
            enriched = enrich_findings_with_ai(
                all_findings,
                api_key,
                severities=set(args.ai_severities),
                max_findings=args.ai_max,
            )
            # Write enriched findings back into results structure
            idx = 0
            for r in results.get("results", []):
                for i in range(len(r.get("findings", []))):
                    if idx < len(enriched):
                        r["findings"][i] = enriched[idx]
                    idx += 1
            ai_enriched = True

    # Drift / PSPM results
    drift_results = None
    if args.drift_results:
        try:
            drift_results = load_drift_results(args.drift_results)
            log.info(f"Loaded drift results: {drift_results['summary']['total_findings']} finding(s)")
        except Exception as e:
            log.error(f"Failed to load drift results from {args.drift_results}: {e}")

    # HTML report
    if not args.no_html:
        output_path = Path(args.output) if args.output else REPORTS_DIR / f"run_{run_id}" / "report.html"
        generate_html_report(results, output_path, ai_enriched=ai_enriched, drift_results=drift_results)
        print(f"📄 HTML report: {output_path}")

    # Slack
    if not args.no_slack:
        webhook_url = args.slack_webhook or os.getenv("SLACK_WEBHOOK_URL")
        if webhook_url:
            send_slack_notification(results, webhook_url)
        else:
            log.warning("No Slack webhook provided — skipping Slack notification")
            log.warning("Set SLACK_WEBHOOK_URL env var or pass --slack-webhook")


if __name__ == "__main__":
    main()
