"""
cloud-sentinel policy engine
Runs policies against collected resources and produces structured findings.
"""

from __future__ import annotations
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable

from engine.schema import Policy

log = logging.getLogger("cloud-sentinel.engine")


# ── Finding model ─────────────────────────────────────────────────────────────

def make_finding(
    policy:      Policy,
    resource:    dict,
    cloud:       str,
    region:      str  = "unknown",
    account:     str  = "unknown",
) -> dict:
    """Build a structured finding dict from a matched policy + resource."""
    resource_id = (
        resource.get("id") or
        resource.get("name") or
        resource.get("Name") or
        resource.get("BucketName") or
        resource.get("InstanceId") or
        resource.get("GroupId") or
        resource.get("DBInstanceIdentifier") or
        resource.get("resource_id") or
        "unknown"
    )
    return {
        "policy_name":   policy.name,
        "cloud":         cloud,
        "resource_type": policy.resource,
        "resource_id":   str(resource_id),
        "region":        region,
        "account":       account,
        "severity":      policy.severity,
        "violation":     policy.violation,
        "remediation":   policy.remediation,
        "mitre":         policy.mitre,
        "description":   policy.description,
        "tags":          resource.get("tags") or resource.get("Tags") or {},
        "raw":           resource,
        "detected_at":   datetime.now(timezone.utc).isoformat(),
    }


# ── Engine ────────────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Runs a list of Policy objects against resources fetched by collector callables.

    Usage:
        engine = PolicyEngine(policies)
        engine.register_collector("aws", "s3_bucket", my_aws_collector.list_s3_buckets)
        results = engine.run(clouds=["aws"])
    """

    def __init__(self, policies: list[Policy]):
        self.policies   = policies
        self._collectors: dict[tuple[str, str], Callable] = {}
        self._findings:   list[dict] = []

    def register_collector(self, cloud: str, resource_type: str, fn: Callable):
        """Register a collector function for a given cloud + resource type."""
        self._collectors[(cloud, resource_type)] = fn

    def _get_resources(self, cloud: str, resource_type: str) -> tuple[list[dict], str]:
        """
        Call the registered collector and return (resources, error_msg).
        Collectors must return a list of dicts. Each dict should include
        'id' (or a recognisable ID key), 'region', 'account', and optional 'tags'.
        """
        key = (cloud, resource_type)
        fn  = self._collectors.get(key)
        if fn is None:
            return [], f"No collector registered for {cloud}/{resource_type}"
        try:
            resources = fn()
            if not isinstance(resources, list):
                return [], f"Collector {cloud}/{resource_type} returned non-list"
            return resources, ""
        except Exception as e:
            return [], str(e)

    def run(self, clouds: list[str] | None = None) -> dict:
        """
        Run all registered policies.
        Returns a results dict compatible with reporter.py / ai_advisor.py.
        """
        run_id    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        started   = time.time()
        clouds    = clouds or list({p.cloud for p in self.policies})
        self._findings = []

        policy_results = []
        resource_cache: dict[tuple[str, str], list[dict]] = {}

        # Group policies by cloud + resource type to avoid duplicate API calls
        from itertools import groupby
        from operator import attrgetter

        sorted_policies = sorted(self.policies, key=lambda p: (p.cloud, p.resource))

        for policy in sorted_policies:
            if policy.cloud not in clouds:
                continue

            cache_key = (policy.cloud, policy.resource)

            # Fetch resources once per cloud+type
            if cache_key not in resource_cache:
                resources, err = self._get_resources(policy.cloud, policy.resource)
                if err:
                    log.warning(f"Collector error [{policy.cloud}/{policy.resource}]: {err}")
                resource_cache[cache_key] = resources

            resources = resource_cache[cache_key]
            findings  = []

            for resource in resources:
                try:
                    matched = policy.evaluate(resource)
                except Exception as e:
                    log.debug(f"Policy '{policy.name}' eval error on resource: {e}")
                    matched = False

                if matched:
                    region  = resource.get("region", "unknown")
                    account = resource.get("account", "unknown")
                    finding = make_finding(policy, resource, policy.cloud, region, account)
                    findings.append(finding)
                    self._findings.append(finding)

            log.info(
                f"[{policy.cloud.upper()}] {policy.name}: "
                f"checked {len(resources)} resource(s) → {len(findings)} finding(s)"
            )

            policy_results.append({
                "policy":    policy.name,
                "cloud":     policy.cloud,
                "resource":  policy.resource,
                "severity":  policy.severity,
                "checked":   len(resources),
                "findings":  findings,
                "status":    "success",
            })

        elapsed = time.time() - started

        # Build summary
        by_sev   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_cloud = {}
        for f in self._findings:
            sev = f.get("severity", "LOW")
            if sev in by_sev:
                by_sev[sev] += 1
            c = f.get("cloud", "unknown")
            by_cloud[c] = by_cloud.get(c, 0) + 1

        return {
            "run_id":         run_id,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "clouds_scanned": clouds,
            "summary": {
                "total_policies": len(policy_results),
                "total_findings": len(self._findings),
                "by_severity":    by_sev,
                "by_cloud":       by_cloud,
            },
            "results": policy_results,
        }

    @property
    def findings(self) -> list[dict]:
        return list(self._findings)
