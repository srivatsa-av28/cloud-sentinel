"""
cloud-sentinel: Platform Security Posture Management (PSPM) — Drift Detector

Answers the questions platform/DevOps teams care about:
  - Who bypassed Terraform?       → "unmanaged" resources (in cloud, not in TF state)
  - Which resources drifted?      → "drifted" resources (security attrs differ from TF)
  - Which IAM changes happened
    outside Git?                  → covered by unmanaged + drifted on IAM-relevant resources
  - Which deployment created risk? → drifted findings reference the TF address that should own it
  - Which team owns this finding? → ownership.get_owner() via resource tags

Compares live cloud resources (fetched via the same collectors as the CSPM engine)
against a Terraform state file.
"""

from __future__ import annotations
import os
import sys
import logging
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from drift.tf_parser import load_tfstate, build_tf_index, get_attr
from drift.ownership import get_owner, owner_summary

log = logging.getLogger("cloud-sentinel.drift.detector")


# ── Resource type mapping: cloud-sentinel resource → Terraform resource ───────
#
# id_attr:    the TF attribute that holds the resource's real-world ID
# live_key:   the key in the collector's resource dict holding the same ID

RESOURCE_MAP: dict[tuple[str, str], dict] = {
    ("aws", "s3_bucket"): {
        "tf_types": ["aws_s3_bucket"],
        "tf_id_attr": "bucket",
        "live_id_key": "id",
        "tf_resource_label": "aws_s3_bucket",
    },
    ("aws", "security_group"): {
        "tf_types": ["aws_security_group"],
        "tf_id_attr": "id",
        "live_id_key": "id",
        "tf_resource_label": "aws_security_group",
    },
    ("aws", "ec2_instance"): {
        "tf_types": ["aws_instance"],
        "tf_id_attr": "id",
        "live_id_key": "id",
        "tf_resource_label": "aws_instance",
    },
    ("aws", "ebs_volume"): {
        "tf_types": ["aws_ebs_volume"],
        "tf_id_attr": "id",
        "live_id_key": "id",
        "tf_resource_label": "aws_ebs_volume",
    },
    ("aws", "rds_instance"): {
        "tf_types": ["aws_db_instance"],
        "tf_id_attr": "identifier",
        "live_id_key": "id",
        "tf_resource_label": "aws_db_instance",
    },
    ("azure", "storage_account"): {
        "tf_types": ["azurerm_storage_account"],
        "tf_id_attr": "name",
        "live_id_key": "name",
        "tf_resource_label": "azurerm_storage_account",
    },
    ("azure", "network_security_group"): {
        "tf_types": ["azurerm_network_security_group"],
        "tf_id_attr": "name",
        "live_id_key": "name",
        "tf_resource_label": "azurerm_network_security_group",
    },
    ("gcp", "gcs_bucket"): {
        "tf_types": ["google_storage_bucket"],
        "tf_id_attr": "name",
        "live_id_key": "name",
        "tf_resource_label": "google_storage_bucket",
    },
    ("gcp", "compute_instance"): {
        "tf_types": ["google_compute_instance"],
        "tf_id_attr": "name",
        "live_id_key": "name",
        "tf_resource_label": "google_compute_instance",
    },
    ("gcp", "firewall_rule"): {
        "tf_types": ["google_compute_firewall"],
        "tf_id_attr": "name",
        "live_id_key": "name",
        "tf_resource_label": "google_compute_firewall",
    },
}


# ── Attribute-level drift checks ───────────────────────────────────────────────
#
# For resources that ARE managed by Terraform, check whether security-relevant
# attributes have drifted away from the declared configuration.
# Each check: (tf_attr_path, live_key, label, severity)

ATTRIBUTE_DRIFT_CHECKS: dict[tuple[str, str], list[dict]] = {
    ("aws", "rds_instance"): [
        {"tf_attr": "publicly_accessible", "live_key": "publicly_accessible",
         "label": "Publicly accessible", "severity": "CRITICAL"},
        {"tf_attr": "storage_encrypted", "live_key": "storage_encrypted",
         "label": "Storage encryption", "severity": "HIGH"},
        {"tf_attr": "deletion_protection", "live_key": "deletion_protection",
         "label": "Deletion protection", "severity": "MEDIUM"},
    ],
    ("aws", "ebs_volume"): [
        {"tf_attr": "encrypted", "live_key": "encrypted",
         "label": "Volume encryption", "severity": "HIGH"},
    ],
    ("aws", "ec2_instance"): [
        {"tf_attr": "metadata_options[0].http_tokens", "live_key": "imds_endpoint",
         "label": "IMDS endpoint", "severity": "MEDIUM", "skip": True},
    ],
    ("azure", "storage_account"): [
        {"tf_attr": "allow_nested_items_to_be_public", "live_key": "allow_blob_public_access",
         "label": "Public blob access", "severity": "HIGH"},
        {"tf_attr": "enable_https_traffic_only", "live_key": "https_only",
         "label": "HTTPS-only traffic", "severity": "HIGH"},
    ],
    ("gcp", "gcs_bucket"): [
        {"tf_attr": "uniform_bucket_level_access", "live_key": "uniform_bucket_access",
         "label": "Uniform bucket-level access", "severity": "MEDIUM"},
        {"tf_attr": "versioning[0].enabled", "live_key": "versioning_enabled",
         "label": "Bucket versioning", "severity": "LOW"},
    ],
}


# ── Live resource fetchers (reuse CSPM collectors) ──────────────────────────────

def _fetch_live_resources(cloud: str, resource_type: str, region: str | None,
                           subscription_id: str | None, project_id: str | None) -> list[dict]:
    """Fetch live resources using the same collector functions as the CSPM engine."""
    try:
        if cloud == "aws":
            from collectors import aws as c
            region = region or os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
            fetchers = {
                "s3_bucket":      lambda: c.list_s3_buckets(),
                "security_group": lambda: c.list_security_groups(region=region),
                "ec2_instance":   lambda: c.list_ec2_instances(region=region),
                "ebs_volume":     lambda: c.list_ebs_volumes(region=region),
                "rds_instance":   lambda: c.list_rds_instances(region=region),
            }
        elif cloud == "azure":
            from collectors import azure as c
            sub = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
            fetchers = {
                "storage_account":        lambda: c.list_storage_accounts(subscription_id=sub),
                "network_security_group": lambda: c.list_nsgs(subscription_id=sub),
            }
        elif cloud == "gcp":
            from collectors import gcp as c
            proj = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
            fetchers = {
                "gcs_bucket":       lambda: c.list_gcs_buckets(project_id=proj),
                "compute_instance": lambda: c.list_compute_instances(project_id=proj),
                "firewall_rule":    lambda: c.list_firewall_rules(project_id=proj),
            }
        else:
            return []

        fn = fetchers.get(resource_type)
        if fn is None:
            return []
        return fn()

    except Exception as e:
        log.error(f"Failed to fetch live {cloud}/{resource_type}: {e}")
        return []


# ── Finding builder ─────────────────────────────────────────────────────────────

def make_drift_finding(
    drift_type:   str,    # "unmanaged" | "drifted" | "ghost"
    cloud:        str,
    resource_type: str,
    resource_id:  str,
    severity:     str,
    violation:    str,
    remediation:  str,
    region:       str = "unknown",
    account:      str = "unknown",
    tags:         dict | None = None,
    tf_address:   str | None = None,
) -> dict:
    tags = tags or {}
    return {
        "policy_name":   f"drift-{drift_type}",
        "drift_type":    drift_type,
        "cloud":         cloud,
        "resource_type": resource_type,
        "resource_id":   resource_id,
        "region":        region,
        "account":       account,
        "severity":      severity,
        "violation":     violation,
        "remediation":   remediation,
        "owner":         get_owner(tags),
        "tags":          tags,
        "tf_address":    tf_address,
        "detected_at":   datetime.now(timezone.utc).isoformat(),
    }


# ── Core drift comparison ────────────────────────────────────────────────────────

def compare_resource_type(
    cloud: str,
    resource_type: str,
    tf_index: dict,
    region: str | None,
    subscription_id: str | None,
    project_id: str | None,
) -> list[dict]:
    """Run drift detection for a single (cloud, resource_type) pair."""
    mapping = RESOURCE_MAP.get((cloud, resource_type))
    if not mapping:
        return []

    live_resources = _fetch_live_resources(cloud, resource_type, region, subscription_id, project_id)
    if not live_resources:
        log.info(f"  [{cloud}/{resource_type}] no live resources found — skipping")

    # Build TF-managed index: live_id -> {address, attributes}
    tf_managed: dict[str, dict] = {}
    for tf_type in mapping["tf_types"]:
        for entry in tf_index.get(tf_type, []):
            tf_id = get_attr(entry["attributes"], mapping["tf_id_attr"])
            if tf_id:
                tf_managed[str(tf_id)] = entry

    findings = []
    live_ids_seen = set()

    for res in live_resources:
        rid = str(res.get(mapping["live_id_key"]) or res.get("id") or res.get("name") or "")
        if not rid:
            continue
        live_ids_seen.add(rid)

        region_val  = res.get("region", "unknown")
        account_val = res.get("account", "unknown")
        tags        = res.get("tags") or {}

        tf_entry = tf_managed.get(rid)

        if tf_entry is None:
            # ── Created outside Terraform (bypassed Terraform) ──
            findings.append(make_drift_finding(
                drift_type="unmanaged",
                cloud=cloud,
                resource_type=resource_type,
                resource_id=rid,
                severity="HIGH",
                violation=(
                    f"{resource_type.replace('_', ' ')} '{rid}' exists in {cloud.upper()} "
                    f"but is not declared in Terraform state — likely created via console/CLI"
                ),
                remediation=(
                    f"terraform import {mapping['tf_resource_label']}.<name> {rid}  "
                    f"# or codify and re-create via IaC"
                ),
                region=region_val,
                account=account_val,
                tags=tags,
            ))
        else:
            # ── Resource is managed — check for attribute drift ──
            checks = ATTRIBUTE_DRIFT_CHECKS.get((cloud, resource_type), [])
            tf_attrs = tf_entry["attributes"]

            for check in checks:
                if check.get("skip"):
                    continue
                tf_val   = get_attr(tf_attrs, check["tf_attr"])
                live_val = res.get(check["live_key"])

                if tf_val is None or live_val is None:
                    continue

                if bool(tf_val) != bool(live_val):
                    findings.append(make_drift_finding(
                        drift_type="drifted",
                        cloud=cloud,
                        resource_type=resource_type,
                        resource_id=rid,
                        severity=check["severity"],
                        violation=(
                            f"{check['label']} drifted on '{rid}': "
                            f"Terraform declares {tf_val!r}, live value is {live_val!r}"
                        ),
                        remediation=(
                            f"Run 'terraform plan' against {tf_entry['address']} to confirm drift, "
                            f"then 'terraform apply' to enforce IaC state — "
                            f"or update the .tf source if this change was intentional"
                        ),
                        region=region_val,
                        account=account_val,
                        tags=tags,
                        tf_address=tf_entry["address"],
                    ))

    # ── Resources declared in Terraform but missing from live cloud (ghost resources) ──
    for tf_id, tf_entry in tf_managed.items():
        if tf_id not in live_ids_seen:
            findings.append(make_drift_finding(
                drift_type="ghost",
                cloud=cloud,
                resource_type=resource_type,
                resource_id=tf_id,
                severity="MEDIUM",
                violation=(
                    f"{resource_type.replace('_', ' ')} '{tf_id}' is declared in Terraform "
                    f"({tf_entry['address']}) but does not exist in {cloud.upper()} — "
                    f"possibly deleted outside Terraform"
                ),
                remediation=(
                    f"Run 'terraform plan' to confirm; if intentionally deleted, run "
                    f"'terraform state rm {tf_entry['address']}'"
                ),
                tf_address=tf_entry["address"],
            ))

    log.info(
        f"  [{cloud.upper()}/{resource_type}] "
        f"live={len(live_resources)} tf_managed={len(tf_managed)} "
        f"findings={len(findings)}"
    )
    return findings


# ── Main entry point ─────────────────────────────────────────────────────────────

def run_drift_detection(
    tfstate_path: str,
    clouds: list[str],
    region: str | None = None,
    subscription_id: str | None = None,
    project_id: str | None = None,
) -> dict:
    """
    Run PSPM drift detection across the given clouds against a Terraform state file.
    Returns a results dict compatible with reporter.py.
    """
    run_id  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    started = datetime.now(timezone.utc)

    log.info(f"Loading Terraform state: {tfstate_path}")
    tf_resources = load_tfstate(tfstate_path)
    tf_index     = build_tf_index(tf_resources)

    all_findings: list[dict] = []

    log.info("Comparing live cloud state against Terraform state...")
    for (cloud, resource_type) in RESOURCE_MAP:
        if cloud not in clouds:
            continue
        findings = compare_resource_type(
            cloud, resource_type, tf_index, region, subscription_id, project_id
        )
        all_findings.extend(findings)

    # Summary
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_drift_type = {"unmanaged": 0, "drifted": 0, "ghost": 0}
    by_cloud: dict[str, int] = {}

    for f in all_findings:
        sev = f.get("severity", "LOW")
        if sev in by_severity:
            by_severity[sev] += 1
        dt = f.get("drift_type", "")
        if dt in by_drift_type:
            by_drift_type[dt] += 1
        c = f.get("cloud", "unknown")
        by_cloud[c] = by_cloud.get(c, 0) + 1

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()

    return {
        "run_id":           run_id,
        "type":             "drift",
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds":  round(elapsed, 2),
        "clouds_scanned":   clouds,
        "tfstate_path":     tfstate_path,
        "summary": {
            "total_findings":  len(all_findings),
            "by_severity":     by_severity,
            "by_drift_type":   by_drift_type,
            "by_cloud":        by_cloud,
            "by_owner":        owner_summary(all_findings),
        },
        "findings": all_findings,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse
    import json

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    parser = argparse.ArgumentParser(
        description="cloud-sentinel PSPM — Terraform drift detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python drift/detector.py --tfstate terraform.tfstate --clouds aws
  python drift/detector.py --tfstate state.json --clouds aws azure gcp --output reports/drift.json

Note: for remote Terraform backends (S3/Azure/GCS), pull state locally first:
  terraform state pull > state.json
        """
    )
    parser.add_argument("--tfstate", required=True, help="Path to terraform.tfstate (or pulled state JSON)")
    parser.add_argument("--clouds", nargs="+", choices=["aws", "azure", "gcp"], required=True)
    parser.add_argument("--region", default=None, help="AWS region (default: AWS_DEFAULT_REGION)")
    parser.add_argument("--subscription-id", default=None, help="Azure subscription ID")
    parser.add_argument("--project-id", default=None, help="GCP project ID")
    parser.add_argument("--output", default=None, help="Output path for drift_results.json")
    args = parser.parse_args()

    results = run_drift_detection(
        tfstate_path=args.tfstate,
        clouds=args.clouds,
        region=args.region,
        subscription_id=args.subscription_id,
        project_id=args.project_id,
    )

    output_path = Path(args.output) if args.output else PROJECT_ROOT / "reports" / f"drift_{results['run_id']}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    s = results["summary"]
    print("\n" + "=" * 60)
    print("PSPM DRIFT DETECTION COMPLETE")
    print("=" * 60)
    print(f"Total findings: {s['total_findings']}")
    print(f"  Unmanaged (bypassed Terraform): {s['by_drift_type']['unmanaged']}")
    print(f"  Drifted (attribute mismatch):   {s['by_drift_type']['drifted']}")
    print(f"  Ghost (in TF, missing in cloud): {s['by_drift_type']['ghost']}")
    print(f"\nBy severity: CRITICAL={s['by_severity']['CRITICAL']} HIGH={s['by_severity']['HIGH']} "
          f"MEDIUM={s['by_severity']['MEDIUM']} LOW={s['by_severity']['LOW']}")
    print(f"\nBy owner:")
    for o in s["by_owner"][:10]:
        print(f"  {o['owner']:20s} {o['total']:3d} finding(s)")
    print(f"\nResults: {output_path}")


if __name__ == "__main__":
    main()
