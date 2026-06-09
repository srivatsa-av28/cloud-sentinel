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
# HTML Report
# ─────────────────────────────────────────────

def generate_html_report(results: dict, output_path: Path) -> Path:
    """Generate a self-contained HTML report from scan results."""
    findings = collect_all_findings(results)
    findings.sort(key=severity_sort_key)

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
            rows_html += f"""
        <tr>
          <td><span class="cloud-badge cloud-{cloud}">{CLOUD_EMOJI.get(cloud,'')} {cloud.upper()}</span></td>
          <td><code class="policy-name">{f.get('policy_name','')}</code></td>
          <td><span class="severity-badge" style="background:{color}">{emoji} {sev}</span></td>
          <td class="resource-id">{f.get('resource_id','')}</td>
          <td>{f.get('violation','')}</td>
          <td class="remediation">{f.get('remediation','')}</td>
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
      <h1>☁️ <span>cloud-sentinel</span> — CSPM Report</h1>
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

  <div class="footer">
    Generated by <a href="https://github.com/vatsa/cloud-sentinel">cloud-sentinel</a> &mdash;
    CSPM-as-code using <a href="https://cloudcustodian.io">Cloud Custodian</a>
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
    parser.add_argument("--results", help="Path to results.json (default: latest run)")
    parser.add_argument("--output", help="Output path for HTML report")
    parser.add_argument("--slack-webhook", help="Slack Incoming Webhook URL (or set SLACK_WEBHOOK_URL env var)")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--no-slack", action="store_true", help="Skip Slack notification")
    args = parser.parse_args()

    # Load results
    if args.results:
        results = load_results_from_file(args.results)
    else:
        results = load_latest_results()

    run_id = results.get("run_id", "unknown")

    # HTML report
    if not args.no_html:
        output_path = Path(args.output) if args.output else REPORTS_DIR / f"run_{run_id}" / "report.html"
        generate_html_report(results, output_path)
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