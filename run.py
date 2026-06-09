#!/usr/bin/env python3
"""
cloud-sentinel: CSPM-as-code runner
Orchestrates Cloud Custodian policy execution across AWS, Azure, and GCP
"""

import os
import json
import glob
import subprocess
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("cloud-sentinel")

PROJECT_ROOT = Path(__file__).parent.parent
POLICIES_DIR = PROJECT_ROOT / "policies"
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def get_enabled_clouds() -> list[str]:
    """Determine which clouds to scan based on available credentials."""
    enabled = []

    # AWS
    if os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE"):
        enabled.append("aws")
    else:
        log.warning("AWS credentials not found — skipping AWS scan")

    # Azure
    if os.getenv("AZURE_SUBSCRIPTION_ID") and (
        os.getenv("AZURE_CLIENT_ID") or os.getenv("AZURE_USE_MSI")
    ):
        enabled.append("azure")
    else:
        log.warning("Azure credentials not found — skipping Azure scan")

    # GCP
    if os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("GOOGLE_CLOUD_PROJECT"):
        enabled.append("gcp")
    else:
        log.warning("GCP credentials not found — skipping GCP scan")

    return enabled


def run_custodian_policy(policy_file: Path, cloud: str, output_dir: Path) -> dict:
    """Run a single Cloud Custodian policy file and return results."""
    policy_name = policy_file.stem
    policy_output = output_dir / policy_name

    cmd = [
        "custodian", "run",
        "--output-dir", str(policy_output),
        str(policy_file)
    ]

    # Cloud-specific config
    if cloud == "aws":
        region = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
        cmd.extend(["--region", region])
    elif cloud == "azure":
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")
        if subscription_id:
            cmd.extend(["--subscription-id", subscription_id])
    elif cloud == "gcp":
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "")
        if project_id:
            cmd.extend(["--project", project_id])

    log.info(f"Running policy: {policy_file.name} [{cloud.upper()}]")

    result = {
        "policy_file": str(policy_file),
        "cloud": cloud,
        "status": "unknown",
        "findings": [],
        "error": None
    }

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if proc.returncode == 0:
            result["status"] = "success"
            result["findings"] = parse_custodian_output(policy_output, policy_file)
            log.info(f"  → {len(result['findings'])} finding(s)")
        else:
            result["status"] = "error"
            result["error"] = proc.stderr.strip()
            log.error(f"  → Error: {proc.stderr.strip()[:200]}")

    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = "Policy execution timed out after 300s"
        log.error(f"  → Timed out: {policy_file.name}")
    except FileNotFoundError:
        result["status"] = "error"
        result["error"] = "custodian CLI not found — install c7n: pip install c7n"
        log.error("  → custodian CLI not found")

    return result


def parse_custodian_output(output_dir: Path, policy_file: Path) -> list[dict]:
    """Parse Cloud Custodian output JSON to extract findings."""
    findings = []

    # Load original policy to extract metadata
    import yaml
    try:
        with open(policy_file) as f:
            policy_data = yaml.safe_load(f)
        policies_meta = {p["name"]: p for p in policy_data.get("policies", [])}
    except Exception:
        policies_meta = {}

    # Custodian writes resources.json per policy subdirectory
    for resources_file in output_dir.rglob("resources.json"):
        policy_subdir = resources_file.parent.name
        meta = policies_meta.get(policy_subdir, {})

        try:
            with open(resources_file) as f:
                resources = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        if not resources:
            continue

        # Extract action metadata from policy
        actions = meta.get("actions", [{}])
        action = actions[0] if actions else {}

        for resource in resources:
            finding = {
                "policy_name": policy_subdir,
                "description": meta.get("description", ""),
                "violation": action.get("violation_desc", "Policy violated"),
                "remediation": action.get("action_desc", "Review and remediate"),
                "severity": action.get("severity", "MEDIUM"),
                "resource_id": (
                    resource.get("Name") or
                    resource.get("BucketName") or
                    resource.get("InstanceId") or
                    resource.get("GroupId") or
                    resource.get("DBInstanceIdentifier") or
                    resource.get("id") or
                    resource.get("name") or
                    "unknown"
                ),
                "resource_type": meta.get("resource", "unknown"),
                "raw": resource
            }
            findings.append(finding)

    return findings


def run_all_clouds(clouds: list[str]) -> dict:
    """Run all policies for all enabled clouds and aggregate results."""
    run_timestamp = datetime.now(timezone.utc).isoformat()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = REPORTS_DIR / f"run_{run_id}"
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = {
        "run_id": run_id,
        "timestamp": run_timestamp,
        "clouds_scanned": clouds,
        "summary": {
            "total_policies": 0,
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_cloud": {}
        },
        "results": []
    }

    for cloud in clouds:
        cloud_policies_dir = POLICIES_DIR / cloud
        if not cloud_policies_dir.exists():
            log.warning(f"No policies directory found for {cloud}")
            continue

        cloud_output_dir = output_dir / cloud
        cloud_output_dir.mkdir(exist_ok=True)

        policy_files = list(cloud_policies_dir.glob("*.yml"))
        log.info(f"\n{'='*50}")
        log.info(f"Scanning {cloud.upper()} — {len(policy_files)} policy file(s)")
        log.info(f"{'='*50}")

        cloud_findings = 0

        for policy_file in policy_files:
            result = run_custodian_policy(policy_file, cloud, cloud_output_dir)
            all_results["results"].append(result)
            all_results["summary"]["total_policies"] += 1

            for finding in result.get("findings", []):
                cloud_findings += 1
                all_results["summary"]["total_findings"] += 1
                severity = finding.get("severity", "MEDIUM")
                if severity in all_results["summary"]["by_severity"]:
                    all_results["summary"]["by_severity"][severity] += 1

        all_results["summary"]["by_cloud"][cloud] = cloud_findings

    # Write raw results JSON
    results_file = output_dir / "results.json"
    with open(results_file, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    log.info(f"\nRaw results written to: {results_file}")
    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="cloud-sentinel: CSPM-as-code scanner"
    )
    parser.add_argument(
        "--clouds",
        nargs="+",
        choices=["aws", "azure", "gcp"],
        help="Clouds to scan (default: auto-detect from credentials)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate policies without executing them"
    )
    args = parser.parse_args()

    log.info("cloud-sentinel starting...")

    clouds = args.clouds or get_enabled_clouds()

    if not clouds:
        log.error("No cloud credentials found. Set credentials for at least one provider.")
        raise SystemExit(1)

    log.info(f"Clouds to scan: {', '.join(c.upper() for c in clouds)}")

    if args.dry_run:
        log.info("DRY RUN mode — validating policies only")
        for cloud in clouds:
            policy_files = list((POLICIES_DIR / cloud).glob("*.yml"))
            log.info(f"{cloud.upper()}: {len(policy_files)} policy file(s) found")
        return

    results = run_all_clouds(clouds)

    # Summary output
    s = results["summary"]
    log.info(f"\n{'='*50}")
    log.info(f"SCAN COMPLETE")
    log.info(f"{'='*50}")
    log.info(f"Policies run:    {s['total_policies']}")
    log.info(f"Total findings:  {s['total_findings']}")
    log.info(f"  CRITICAL: {s['by_severity']['CRITICAL']}")
    log.info(f"  HIGH:     {s['by_severity']['HIGH']}")
    log.info(f"  MEDIUM:   {s['by_severity']['MEDIUM']}")
    log.info(f"  LOW:      {s['by_severity']['LOW']}")

    return results


if __name__ == "__main__":
    main()