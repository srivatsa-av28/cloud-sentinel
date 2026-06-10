"""
cloud-sentinel GCP collector
Fetches resources from GCP using google-cloud-python SDKs.
Authenticates via Application Default Credentials (ADC).
"""

from __future__ import annotations
import logging
import os

log = logging.getLogger("cloud-sentinel.collectors.gcp")


def _project_id() -> str:
    project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCLOUD_PROJECT", "")
    if not project:
        raise EnvironmentError(
            "GCP project not set. Export GOOGLE_CLOUD_PROJECT=<your-project-id>"
        )
    return project


# ── GCS Buckets ───────────────────────────────────────────────────────────────

def list_gcs_buckets(project_id: str | None = None) -> list[dict]:
    from google.cloud import storage

    project = project_id or _project_id()

    try:
        client  = storage.Client(project=project)
        buckets = list(client.list_buckets())
    except Exception as e:
        log.error(f"GCS list_buckets failed: {e}")
        return []

    resources = []
    for b in buckets:
        # IAM policy — check for public members
        iam_bindings = []
        public_access = False
        try:
            policy = b.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = list(binding.get("members", []))
                iam_bindings.append({
                    "role":    binding.get("role", ""),
                    "members": members,
                })
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    public_access = True
        except Exception:
            pass

        resources.append({
            "id":                   b.name,
            "name":                 b.name,
            "region":               b.location or "unknown",
            "account":              project,
            "tags":                 dict(b.labels or {}),
            "storage_class":        b.storage_class or "",
            "location_type":        b.location_type or "",
            "public_access":        public_access,
            "uniform_bucket_access": b.iam_configuration.uniform_bucket_level_access_enabled if b.iam_configuration else False,
            "versioning_enabled":   b.versioning_enabled,
            "requester_pays":       b.requester_pays,
            "iam_bindings":         iam_bindings,
        })

    log.info(f"GCS: fetched {len(resources)} bucket(s)")
    return resources


# ── Compute Instances ─────────────────────────────────────────────────────────

def list_compute_instances(project_id: str | None = None) -> list[dict]:
    from googleapiclient import discovery
    from google.oauth2 import google_auth_httplib2
    import google.auth

    project = project_id or _project_id()

    try:
        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
        )
        service    = discovery.build("compute", "v1", credentials=credentials)
        aggregated = service.instances().aggregatedList(project=project).execute()
    except Exception as e:
        log.error(f"GCP compute instances.aggregatedList failed: {e}")
        return []

    resources = []
    for zone_name, zone_data in aggregated.get("items", {}).items():
        instances = zone_data.get("instances", [])
        for i in instances:
            zone = zone_name.replace("zones/", "")

            # Service accounts
            service_accounts = i.get("serviceAccounts", [])
            using_default_sa = any(
                "-compute@developer.gserviceaccount.com" in sa.get("email", "")
                for sa in service_accounts
            )

            # Metadata
            metadata_items = i.get("metadata", {}).get("items", [])
            meta_dict = {m.get("key"): m.get("value") for m in metadata_items}
            serial_port_enabled = meta_dict.get("serial-port-enable") in ("1", "true", "TRUE")

            # Network interfaces
            network_ifaces = i.get("networkInterfaces", [])
            has_public_ip  = any(
                ni.get("accessConfigs")
                for ni in network_ifaces
            )

            # Shielded VM
            shielded = i.get("shieldedInstanceConfig", {})

            resources.append({
                "id":                       i["id"],
                "name":                     i.get("name", ""),
                "region":                   zone,
                "account":                  project,
                "tags":                     i.get("labels", {}),
                "zone":                     zone,
                "status":                   i.get("status", ""),
                "machine_type":             i.get("machineType", "").split("/")[-1],
                "using_default_sa":         using_default_sa,
                "service_accounts":         service_accounts,
                "serial_port_enabled":      serial_port_enabled,
                "has_public_ip":            has_public_ip,
                "network_interfaces":       network_ifaces,
                "metadata":                 meta_dict,
                "deletion_protection":      i.get("deletionProtection", False),
                "secure_boot":              shielded.get("enableSecureBoot", False),
                "vtpm":                     shielded.get("enableVtpm", False),
                "integrity_monitoring":     shielded.get("enableIntegrityMonitoring", False),
            })

    log.info(f"GCP: fetched {len(resources)} compute instance(s)")
    return resources


# ── Firewall Rules ────────────────────────────────────────────────────────────

def list_firewall_rules(project_id: str | None = None) -> list[dict]:
    from googleapiclient import discovery
    import google.auth

    project = project_id or _project_id()

    try:
        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
        )
        service = discovery.build("compute", "v1", credentials=credentials)
        result  = service.firewalls().list(project=project).execute()
        rules   = result.get("items", [])
    except Exception as e:
        log.error(f"GCP firewall rules.list failed: {e}")
        return []

    resources = []
    for r in rules:
        source_ranges = r.get("sourceRanges", [])
        allowed       = r.get("allowed", [])
        direction     = r.get("direction", "INGRESS")
        disabled      = r.get("disabled", False)

        open_to_internet = "0.0.0.0/0" in source_ranges or "::/0" in source_ranges
        open_ssh  = _gcp_has_port(allowed, 22)  and open_to_internet and direction == "INGRESS"
        open_rdp  = _gcp_has_port(allowed, 3389) and open_to_internet and direction == "INGRESS"
        open_all  = any(a.get("IPProtocol") == "all" for a in allowed) and open_to_internet and direction == "INGRESS"

        resources.append({
            "id":               r.get("id", ""),
            "name":             r.get("name", ""),
            "region":           "global",
            "account":          project,
            "tags":             {},
            "network":          r.get("network", "").split("/")[-1],
            "direction":        direction,
            "priority":         r.get("priority", 1000),
            "disabled":         disabled,
            "source_ranges":    source_ranges,
            "target_tags":      r.get("targetTags", []),
            "allowed":          allowed,
            "denied":           r.get("denied", []),
            "open_to_internet": open_to_internet,
            "open_ssh":         open_ssh,
            "open_rdp":         open_rdp,
            "open_all_ports":   open_all,
        })

    log.info(f"GCP: fetched {len(resources)} firewall rule(s)")
    return resources


def _gcp_has_port(allowed: list, port: int) -> bool:
    for a in allowed:
        proto = a.get("IPProtocol", "")
        if proto == "all":
            return True
        if proto != "tcp":
            continue
        for p in a.get("ports", []):
            if str(p) == str(port):
                return True
            if "-" in str(p):
                try:
                    lo, hi = str(p).split("-")
                    if int(lo) <= port <= int(hi):
                        return True
                except Exception:
                    pass
    return False


# ── Collector registry helper ─────────────────────────────────────────────────

def register_all(engine, project_id: str | None = None):
    """Register all GCP collectors with the policy engine."""
    from functools import partial
    project = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")

    engine.register_collector("gcp", "gcs_bucket",      partial(list_gcs_buckets,         project_id=project))
    engine.register_collector("gcp", "compute_instance", partial(list_compute_instances,   project_id=project))
    engine.register_collector("gcp", "firewall_rule",    partial(list_firewall_rules,      project_id=project))
