#!/usr/bin/env python3
"""
cloud-sentinel: main runner
Orchestrates policy scanning across AWS, Azure, and GCP using the native engine.
No Cloud Custodian dependency — all resource fetching is via native SDKs.
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine import load_all_policies, PolicyEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("cloud-sentinel")

POLICIES_DIR = PROJECT_ROOT / "policies"
REPORTS_DIR  = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


def detect_clouds() -> list[str]:
    """Auto-detect which clouds have credentials available."""
    enabled = []

    # AWS
    has_aws = (
        os.getenv("AWS_ACCESS_KEY_ID") or
        os.getenv("AWS_PROFILE") or
        os.getenv("AWS_ROLE_ARN")
    )
    if has_aws:
        enabled.append("aws")
    else:
        log.warning("AWS credentials not found — skipping AWS (set AWS_ACCESS_KEY_ID or AWS_PROFILE)")

    # Azure
    has_azure = os.getenv("AZURE_SUBSCRIPTION_ID") and (
        os.getenv("AZURE_CLIENT_ID") or os.getenv("AZURE_USE_MSI")
    )
    if has_azure:
        enabled.append("azure")
    else:
        log.warning("Azure credentials not found — skipping Azure (set AZURE_SUBSCRIPTION_ID + AZURE_CLIENT_ID)")

    # GCP
    has_gcp = (
        os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or
        os.getenv("GOOGLE_CLOUD_PROJECT")
    )
    if has_gcp:
        enabled.append("gcp")
    else:
        log.warning("GCP credentials not found — skipping GCP (set GOOGLE_CLOUD_PROJECT)")

    return enabled


def register_collectors(engine: PolicyEngine, clouds: list[str]):
    """Register native SDK collectors for each enabled cloud."""

    if "aws" in clouds:
        try:
            from collectors import aws as aws_collector
            region = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
            aws_collector.register_all(engine, region=region)
            log.info(f"AWS collectors registered (region: {region})")
        except ImportError as e:
            log.error(f"AWS collector import failed: {e} — install boto3")

    if "azure" in clouds:
        try:
            from collectors import azure as azure_collector
            sub = os.getenv("AZURE_SUBSCRIPTION_ID")
            azure_collector.register_all(engine, subscription_id=sub)
            log.info(f"Azure collectors registered (subscription: {sub})")
        except ImportError as e:
            log.error(f"Azure collector import failed: {e} — install azure-sdk packages")

    if "gcp" in clouds:
        try:
            from collectors import gcp as gcp_collector
            project = os.getenv("GOOGLE_CLOUD_PROJECT")
            gcp_collector.register_all(engine, project_id=project)
            log.info(f"GCP collectors registered (project: {project})")
        except ImportError as e:
            log.error(f"GCP collector import failed: {e} — install google-cloud packages")


def main():
    parser = argparse.ArgumentParser(
        description="cloud-sentinel: native CSPM scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python runner/run.py                          # auto-detect clouds from credentials
  python runner/run.py --clouds aws             # AWS only
  python runner/run.py --clouds aws gcp         # AWS + GCP
  python runner/run.py --dry-run                # validate policies, no API calls
  python runner/run.py --clouds aws --region eu-west-1
        """
    )
    parser.add_argument("--clouds",  nargs="+", choices=["aws", "azure", "gcp"],
                        help="Clouds to scan (default: auto-detect from env)")
    parser.add_argument("--region",  default=None,
                        help="AWS region override (default: AWS_DEFAULT_REGION or ap-south-1)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate and list policies without making any API calls")
    parser.add_argument("--output",  default=None,
                        help="Path to write results.json (default: reports/run_<timestamp>/results.json)")
    parser.add_argument("--severity-filter", nargs="+",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Only report findings at these severities")
    args = parser.parse_args()

    # Region override
    if args.region:
        os.environ["AWS_DEFAULT_REGION"] = args.region

    # Determine which clouds to scan
    clouds = args.clouds or detect_clouds()
    if not clouds:
        log.error("No cloud credentials found. Set credentials for at least one provider.")
        sys.exit(1)

    log.info(f"cloud-sentinel starting | clouds: {', '.join(c.upper() for c in clouds)}")

    # Load all policies for selected clouds
    policies = load_all_policies(str(POLICIES_DIR), clouds=clouds)
    if not policies:
        log.error(f"No policies found in {POLICIES_DIR} for clouds: {clouds}")
        sys.exit(1)

    log.info(f"Loaded {len(policies)} policy/policies")

    # Dry run — just list policies and exit
    if args.dry_run:
        log.info("DRY RUN — policies validated, no API calls made")
        for p in policies:
            log.info(f"  [{p.cloud.upper()}] {p.name} ({p.severity}) → {p.resource}")
        print(f"\n✅ {len(policies)} policies valid across {len(clouds)} cloud(s)")
        return

    # Build engine
    engine = PolicyEngine(policies)
    register_collectors(engine, clouds)

    # Run scan
    log.info("=" * 60)
    log.info("Starting scan...")
    log.info("=" * 60)

    results = engine.run(clouds=clouds)

    # Apply severity filter if requested
    if args.severity_filter:
        for r in results["results"]:
            r["findings"] = [
                f for f in r["findings"]
                if f.get("severity") in args.severity_filter
            ]
        total = sum(len(r["findings"]) for r in results["results"])
        results["summary"]["total_findings"] = total

    # Write results
    from datetime import datetime, timezone
    run_id     = results["run_id"]
    output_dir = REPORTS_DIR / f"run_{run_id}"
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        output_path = output_dir / "results.json"

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    # Print summary
    s = results["summary"]
    log.info("=" * 60)
    log.info("SCAN COMPLETE")
    log.info("=" * 60)
    log.info(f"Elapsed:         {results.get('elapsed_seconds', 0):.1f}s")
    log.info(f"Policies run:    {s['total_policies']}")
    log.info(f"Total findings:  {s['total_findings']}")
    log.info(f"  CRITICAL: {s['by_severity']['CRITICAL']}")
    log.info(f"  HIGH:     {s['by_severity']['HIGH']}")
    log.info(f"  MEDIUM:   {s['by_severity']['MEDIUM']}")
    log.info(f"  LOW:      {s['by_severity']['LOW']}")
    for cloud, count in s.get("by_cloud", {}).items():
        log.info(f"  {cloud.upper()}: {count} finding(s)")
    log.info(f"\nResults: {output_path}")

    # Exit code 1 if CRITICAL findings (useful for CI gate)
    if s["by_severity"]["CRITICAL"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
