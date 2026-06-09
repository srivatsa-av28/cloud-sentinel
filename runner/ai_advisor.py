#!/usr/bin/env python3
"""
cloud-sentinel: AI Remediation Advisor
Calls Claude API per finding to generate exact, copy-paste remediation steps
tailored to the specific resource, cloud, and account context.
"""

import os
import json
import time
import logging
import hashlib
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

log = logging.getLogger("cloud-sentinel.ai_advisor")

PROJECT_ROOT = Path(__file__).parent.parent
CACHE_DIR    = PROJECT_ROOT / ".ai_cache"
CACHE_DIR.mkdir(exist_ok=True)

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL             = "claude-sonnet-4-20250514"
MAX_TOKENS        = 1000
MAX_WORKERS       = 4      # parallel API calls
RATE_LIMIT_DELAY  = 0.3    # seconds between calls per worker

# Only run AI advisor on these severities by default (cost control)
DEFAULT_AI_SEVERITIES = {"CRITICAL", "HIGH"}


# ─────────────────────────────────────────────
# Prompt builder
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior cloud security engineer specialising in AWS, Azure, and GCP.
You receive a cloud misconfiguration finding and return a concise, actionable remediation plan.

Rules:
- Give EXACT CLI commands or Terraform/IaC snippets using the real resource ID provided
- Format: structured JSON only — no prose outside the JSON
- CLI commands must be copy-paste ready (no placeholder guessing where the real value is known)
- Always include both a "quick fix" (CLI/console) and an "iac fix" (Terraform/Bicep/gcloud)
- Include a "why it matters" in 1–2 sentences max — BFSI/regulated-environment framing preferred
- Include MITRE ATT&CK or MITRE ATLAS tactic if applicable
- Confidence field: how confident you are the fix is correct given the context (high/medium/low)
- If the resource ID is "unknown", give the generic command template with <placeholders>

Return ONLY valid JSON matching this schema exactly:
{
  "summary": "One-line description of the issue",
  "why_it_matters": "1-2 sentence business/risk impact",
  "mitre_tactic": "e.g. TA0001 Initial Access or null",
  "quick_fix": {
    "type": "cli|console|api",
    "tool": "aws-cli|az-cli|gcloud|portal",
    "commands": ["exact command 1", "exact command 2"]
  },
  "iac_fix": {
    "type": "terraform|bicep|deployment_manager",
    "snippet": "exact HCL or config block"
  },
  "verification": "Command to verify the fix was applied",
  "estimated_effort": "minutes|hours|days",
  "confidence": "high|medium|low",
  "caveats": ["caveat 1 if any"] 
}"""


def build_user_prompt(finding: dict) -> str:
    resource_id   = finding.get("resource_id", "unknown")
    cloud         = finding.get("cloud", "unknown").upper()
    policy_name   = finding.get("policy_name", "unknown")
    severity      = finding.get("severity", "MEDIUM")
    violation     = finding.get("violation", "")
    resource_type = finding.get("resource_type", "unknown")

    # Pull useful context from raw resource data if present
    raw = finding.get("raw", {})
    region  = raw.get("Region") or raw.get("location") or raw.get("zone") or "unknown"
    account = raw.get("account_id") or raw.get("subscriptionId") or raw.get("projectId") or "unknown"
    tags    = raw.get("Tags") or raw.get("tags") or {}

    context_lines = [
        f"Cloud:         {cloud}",
        f"Resource type: {resource_type}",
        f"Resource ID:   {resource_id}",
        f"Region:        {region}",
        f"Account/Sub:   {account}",
        f"Policy:        {policy_name}",
        f"Severity:      {severity}",
        f"Violation:     {violation}",
    ]
    if tags:
        tag_str = ", ".join(f"{k}={v}" for k, v in list(tags.items())[:5])
        context_lines.append(f"Tags:          {tag_str}")

    return "\n".join(context_lines)


# ─────────────────────────────────────────────
# Cache (avoid re-calling API for identical findings)
# ─────────────────────────────────────────────

def _cache_key(finding: dict) -> str:
    """Stable cache key based on policy + resource ID + cloud."""
    key_str = f"{finding.get('cloud')}:{finding.get('policy_name')}:{finding.get('resource_id')}"
    return hashlib.sha256(key_str.encode()).hexdigest()[:16]


def _load_cache(key: str) -> Optional[dict]:
    cache_file = CACHE_DIR / f"{key}.json"
    if cache_file.exists():
        try:
            with open(cache_file) as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _save_cache(key: str, data: dict):
    cache_file = CACHE_DIR / f"{key}.json"
    try:
        with open(cache_file, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


# ─────────────────────────────────────────────
# API call
# ─────────────────────────────────────────────

def call_claude(finding: dict, api_key: str, retries: int = 2) -> dict:
    """Call Claude API for a single finding. Returns parsed remediation dict."""
    cache_key = _cache_key(finding)
    cached = _load_cache(cache_key)
    if cached:
        log.debug(f"Cache hit: {finding.get('policy_name')} / {finding.get('resource_id')}")
        cached["_cached"] = True
        return cached

    payload = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": build_user_prompt(finding)}
        ]
    }

    headers = {
        "Content-Type":         "application/json",
        "x-api-key":            api_key,
        "anthropic-version":    "2023-06-01",
    }

    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                ANTHROPIC_API_URL,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode())

            raw_text = body["content"][0]["text"].strip()

            # Strip markdown fences if model wraps response
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[1]
                raw_text = raw_text.rsplit("```", 1)[0].strip()

            result = json.loads(raw_text)
            result["_cached"] = False
            result["_model"]  = MODEL
            _save_cache(cache_key, result)
            return result

        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                wait = 2 ** (attempt + 1)
                log.warning(f"Rate limited — retrying in {wait}s")
                time.sleep(wait)
            else:
                log.error(f"Claude API HTTP error {e.code}: {e.reason}")
                break
        except json.JSONDecodeError as e:
            log.error(f"Failed to parse Claude response as JSON: {e}")
            break
        except Exception as e:
            log.error(f"Claude API call failed: {e}")
            break

    # Fallback if API fails
    return {
        "summary":          finding.get("violation", "See violation description"),
        "why_it_matters":   "Misconfiguration increases attack surface in regulated environments.",
        "mitre_tactic":     None,
        "quick_fix":        {"type": "console", "tool": "portal", "commands": [finding.get("remediation", "")]},
        "iac_fix":          {"type": "terraform", "snippet": "# Manual remediation required"},
        "verification":     "Manually verify in cloud console",
        "estimated_effort": "hours",
        "confidence":       "low",
        "caveats":          ["AI advisor unavailable — using static remediation"],
        "_cached":          False,
        "_fallback":        True,
    }


# ─────────────────────────────────────────────
# Batch processor
# ─────────────────────────────────────────────

def enrich_findings_with_ai(
    findings: list[dict],
    api_key: str,
    severities: set[str] = DEFAULT_AI_SEVERITIES,
    max_findings: int = 50,
) -> list[dict]:
    """
    Enrich a list of findings with AI remediation advice.
    Runs in parallel with rate limiting. Skips low-severity findings by default.
    Returns findings list with 'ai_remediation' key added to each enriched finding.
    """
    eligible = [
        f for f in findings
        if f.get("severity", "LOW") in severities
    ][:max_findings]

    skipped = len(findings) - len(eligible)
    if skipped:
        log.info(f"AI advisor: skipping {skipped} finding(s) below severity threshold ({severities})")

    if not eligible:
        log.info("No findings eligible for AI enrichment")
        return findings

    log.info(f"AI advisor: enriching {len(eligible)} finding(s) using {MODEL}")
    start = time.time()
    enriched_map = {}

    def enrich_one(finding: dict) -> tuple[str, dict]:
        time.sleep(RATE_LIMIT_DELAY)
        key = _cache_key(finding)
        advice = call_claude(finding, api_key)
        return key, advice

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(enrich_one, f): f for f in eligible}
        done = 0
        for future in as_completed(futures):
            done += 1
            finding = futures[future]
            try:
                key, advice = future.result()
                enriched_map[key] = advice
                cached_label = " (cached)" if advice.get("_cached") else ""
                log.info(f"  [{done}/{len(eligible)}] {finding.get('policy_name')} "
                         f"/ {finding.get('resource_id', 'unknown')[:40]}{cached_label}")
            except Exception as e:
                log.error(f"  [{done}/{len(eligible)}] Failed: {e}")

    # Attach ai_remediation to each finding
    result = []
    for f in findings:
        key = _cache_key(f)
        if key in enriched_map:
            f = dict(f)
            f["ai_remediation"] = enriched_map[key]
        result.append(f)

    elapsed = time.time() - start
    cache_hits = sum(1 for v in enriched_map.values() if v.get("_cached"))
    log.info(f"AI advisor complete: {len(enriched_map)} enriched, "
             f"{cache_hits} from cache, {elapsed:.1f}s elapsed")

    return result


# ─────────────────────────────────────────────
# HTML snippet renderer (used by reporter.py)
# ─────────────────────────────────────────────

def render_ai_remediation_html(ai: dict) -> str:
    """Render AI remediation advice as an HTML block for embedding in the report."""
    if not ai:
        return ""

    confidence_color = {"high": "#16a34a", "medium": "#d97706", "low": "#dc2626"}.get(
        ai.get("confidence", "low"), "#94a3b8"
    )
    mitre = ai.get("mitre_tactic")
    mitre_badge = (
        f'<span class="mitre-badge">{mitre}</span>' if mitre else ""
    )
    caveats = ai.get("caveats", [])
    caveat_html = ""
    if caveats:
        caveat_html = (
            '<div class="ai-caveats">⚠ ' +
            " | ".join(caveats) +
            "</div>"
        )

    # CLI commands
    qf = ai.get("quick_fix", {})
    commands = qf.get("commands", [])
    commands_html = "\n".join(f"<code>{c}</code>" for c in commands if c) if commands else ""

    # IaC snippet
    iac = ai.get("iac_fix", {})
    iac_snippet = iac.get("snippet", "")
    iac_type    = iac.get("type", "terraform")

    verification = ai.get("verification", "")
    effort       = ai.get("estimated_effort", "")
    why          = ai.get("why_it_matters", "")
    fallback     = ai.get("_fallback", False)

    fallback_banner = (
        '<div class="ai-fallback">⚠ AI advisor unavailable — showing static remediation</div>'
        if fallback else ""
    )

    return f"""
<div class="ai-remediation">
  {fallback_banner}
  <div class="ai-header">
    <span class="ai-label">🤖 AI Remediation Advisor</span>
    <span class="confidence-badge" style="background:{confidence_color}">
      Confidence: {ai.get('confidence','?')}
    </span>
    {mitre_badge}
    {"<span class='effort-badge'>⏱ " + effort + "</span>" if effort else ""}
  </div>

  {"<p class='why-matters'><strong>Why it matters:</strong> " + why + "</p>" if why else ""}

  {"<div class='fix-section'><p class='fix-label'>⚡ Quick Fix (" + qf.get('tool','') + ")</p><div class='command-block'>" + commands_html + "</div></div>" if commands_html else ""}

  {"<div class='fix-section'><p class='fix-label'>🏗 IaC Fix (" + iac_type + ")</p><pre class='iac-block'>" + iac_snippet + "</pre></div>" if iac_snippet else ""}

  {"<div class='fix-section'><p class='fix-label'>✅ Verify</p><div class='command-block'><code>" + verification + "</code></div></div>" if verification else ""}

  {caveat_html}
</div>"""


AI_REMEDIATION_CSS = """
  .ai-remediation {
    margin-top: 0.75rem;
    background: #0f172a;
    border: 1px solid #1d4ed8;
    border-left: 3px solid #3b82f6;
    border-radius: 0.5rem;
    padding: 1rem 1.25rem;
    font-size: 0.82rem;
  }
  .ai-fallback {
    color: #fbbf24; font-size: 0.75rem; margin-bottom: 0.5rem;
  }
  .ai-header {
    display: flex; flex-wrap: wrap; gap: 0.5rem;
    align-items: center; margin-bottom: 0.75rem;
  }
  .ai-label { color: #93c5fd; font-weight: 700; font-size: 0.8rem; }
  .confidence-badge {
    padding: 0.15rem 0.5rem; border-radius: 9999px;
    font-size: 0.68rem; font-weight: 700; color: white;
  }
  .mitre-badge {
    padding: 0.15rem 0.5rem; border-radius: 9999px;
    font-size: 0.68rem; font-weight: 700;
    background: #4c1d95; color: #c4b5fd;
  }
  .effort-badge {
    padding: 0.15rem 0.5rem; border-radius: 9999px;
    font-size: 0.68rem; color: #94a3b8;
    background: #1e293b;
  }
  .why-matters {
    color: #cbd5e1; margin-bottom: 0.75rem; line-height: 1.5;
  }
  .fix-section { margin-bottom: 0.75rem; }
  .fix-label {
    font-size: 0.72rem; font-weight: 700; color: #64748b;
    text-transform: uppercase; letter-spacing: 0.05em;
    margin-bottom: 0.35rem;
  }
  .command-block {
    background: #020617; border-radius: 0.375rem;
    padding: 0.6rem 0.875rem;
  }
  .command-block code {
    display: block; color: #86efac;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.78rem; line-height: 1.7;
    white-space: pre-wrap; word-break: break-all;
  }
  .iac-block {
    background: #020617; border-radius: 0.375rem;
    padding: 0.6rem 0.875rem; margin: 0;
    color: #a5b4fc;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.78rem; line-height: 1.7;
    white-space: pre-wrap; word-break: break-all;
    overflow-x: auto;
  }
  .ai-caveats {
    color: #fbbf24; font-size: 0.73rem; margin-top: 0.5rem;
    padding: 0.35rem 0.6rem; background: #1c1400; border-radius: 0.25rem;
  }
"""


# ─────────────────────────────────────────────
# CLI entry point (standalone usage)
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="cloud-sentinel AI advisor (standalone)")
    parser.add_argument("--results",   required=True,  help="Path to results.json")
    parser.add_argument("--output",    required=True,  help="Path to write enriched results.json")
    parser.add_argument("--severities", nargs="+",     default=["CRITICAL", "HIGH"],
                        help="Severities to enrich (default: CRITICAL HIGH)")
    parser.add_argument("--max",        type=int,      default=50,
                        help="Max findings to enrich (cost control)")
    parser.add_argument("--clear-cache", action="store_true",
                        help="Clear the AI response cache before running")
    args = parser.parse_args()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable not set")
        raise SystemExit(1)

    if args.clear_cache:
        for f in CACHE_DIR.glob("*.json"):
            f.unlink()
        log.info("Cache cleared")

    with open(args.results) as f:
        results = json.load(f)

    # Collect all findings
    all_findings = []
    for r in results.get("results", []):
        cloud = r.get("cloud", "unknown")
        for finding in r.get("findings", []):
            finding["cloud"] = cloud
            all_findings.append(finding)

    enriched = enrich_findings_with_ai(
        all_findings,
        api_key,
        severities=set(args.severities),
        max_findings=args.max,
    )

    # Write back
    finding_idx = 0
    for r in results.get("results", []):
        for i in range(len(r.get("findings", []))):
            if finding_idx < len(enriched):
                r["findings"][i] = enriched[finding_idx]
            finding_idx += 1

    results["ai_enriched"] = True
    results["ai_enriched_at"] = datetime.now(timezone.utc).isoformat()

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n✅ Enriched results written to: {args.output}")
