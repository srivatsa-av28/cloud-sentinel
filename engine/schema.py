"""
cloud-sentinel policy schema
Defines the structure, validation, and object model for policy YAML files.

Policy YAML structure:
  policies:
    - name: s3-bucket-public-access
      cloud: aws
      resource: s3_bucket
      description: "Detect S3 buckets without public access block"
      severity: HIGH
      filters:
        - field: public_access_block.BlockPublicAcls
          op: eq
          value: false
        - or:
          - field: tags.Env
            op: eq
            value: prod
          - field: tags.Tier
            op: eq
            value: data
      metadata:
        violation: "S3 bucket does not block public access"
        remediation: "Enable S3 Block Public Access"
        mitre: "TA0009 Collection"
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Optional

# ── Supported clouds and resource types ───────────────────────────────────────

SUPPORTED_CLOUDS = {"aws", "azure", "gcp"}

RESOURCE_TYPES = {
    "aws": [
        "s3_bucket", "iam_user", "iam_account", "security_group",
        "ec2_instance", "ebs_volume", "rds_instance",
    ],
    "azure": [
        "storage_account", "network_security_group", "sql_server",
        "key_vault", "vm",
    ],
    "gcp": [
        "gcs_bucket", "compute_instance", "firewall_rule",
    ],
}

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

# ── Filter operators ───────────────────────────────────────────────────────────

OPERATORS = {
    "eq":           lambda a, b: a == b,
    "ne":           lambda a, b: a != b,
    "gt":           lambda a, b: a is not None and a > b,
    "lt":           lambda a, b: a is not None and a < b,
    "gte":          lambda a, b: a is not None and a >= b,
    "lte":          lambda a, b: a is not None and a <= b,
    "in":           lambda a, b: a in b,
    "not_in":       lambda a, b: a not in b,
    "contains":     lambda a, b: b in (a or ""),
    "not_contains": lambda a, b: b not in (a or ""),
    "exists":       lambda a, b: a is not None,
    "not_exists":   lambda a, b: a is None,
    "regex":        lambda a, b: bool(re.search(b, str(a or ""))),
    "startswith":   lambda a, b: str(a or "").startswith(b),
    "endswith":     lambda a, b: str(a or "").endswith(b),
}


# ── Filter model ──────────────────────────────────────────────────────────────

@dataclass
class Filter:
    """A single field-level filter condition."""
    field:  str
    op:     str
    value:  Any = None

    def evaluate(self, resource: dict) -> bool:
        actual = _resolve_field(resource, self.field)
        fn = OPERATORS.get(self.op)
        if fn is None:
            raise ValueError(f"Unknown operator: '{self.op}'")
        try:
            return fn(actual, self.value)
        except Exception:
            return False


@dataclass
class CompositeFilter:
    """A logical AND / OR / NOT grouping of filters."""
    logic:    str               # "and" | "or" | "not"
    children: list              # list of Filter | CompositeFilter

    def evaluate(self, resource: dict) -> bool:
        if self.logic == "and":
            return all(c.evaluate(resource) for c in self.children)
        elif self.logic == "or":
            return any(c.evaluate(resource) for c in self.children)
        elif self.logic == "not":
            return not self.children[0].evaluate(resource)
        raise ValueError(f"Unknown logic: '{self.logic}'")


def _resolve_field(resource: dict, field_path: str) -> Any:
    """
    Resolve a dotted field path against a resource dict.
    e.g. "public_access_block.BlockPublicAcls" -> resource["public_access_block"]["BlockPublicAcls"]
    Supports list indexing: "rules[0].port"
    Returns None if any segment is missing.
    """
    parts = field_path.split(".")
    current = resource
    for part in parts:
        if current is None:
            return None
        # Handle list index e.g. rules[0]
        m = re.match(r"^(\w+)\[(\d+)\]$", part)
        if m:
            key, idx = m.group(1), int(m.group(2))
            current = current.get(key) if isinstance(current, dict) else None
            if isinstance(current, list) and idx < len(current):
                current = current[idx]
            else:
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


# ── Policy model ──────────────────────────────────────────────────────────────

@dataclass
class Policy:
    name:        str
    cloud:       str
    resource:    str
    severity:    str
    filters:     list               # list of Filter | CompositeFilter
    description: str = ""
    metadata:    dict = field(default_factory=dict)

    def evaluate(self, resource: dict) -> bool:
        """Return True if ALL top-level filters match (implicit AND at top level)."""
        return all(f.evaluate(resource) for f in self.filters)

    @property
    def violation(self) -> str:
        return self.metadata.get("violation", self.description or self.name)

    @property
    def remediation(self) -> str:
        return self.metadata.get("remediation", "Review and remediate")

    @property
    def mitre(self) -> Optional[str]:
        return self.metadata.get("mitre")


# ── YAML → object parser ──────────────────────────────────────────────────────

def parse_filter(raw: dict) -> "Filter | CompositeFilter":
    """Recursively parse a raw filter dict into a Filter or CompositeFilter."""
    if "or" in raw:
        return CompositeFilter("or", [parse_filter(c) for c in raw["or"]])
    if "and" in raw:
        return CompositeFilter("and", [parse_filter(c) for c in raw["and"]])
    if "not" in raw:
        child = raw["not"]
        return CompositeFilter("not", [parse_filter(child if isinstance(child, dict) else child[0])])

    # Leaf filter
    field_name = raw.get("field")
    op         = raw.get("op", "eq")
    value      = raw.get("value")

    if not field_name:
        raise ValueError(f"Filter missing 'field' key: {raw}")
    if op not in OPERATORS:
        raise ValueError(f"Unknown operator '{op}' in filter: {raw}")

    return Filter(field=field_name, op=op, value=value)


def parse_policy(raw: dict, source_file: str = "") -> Policy:
    """Parse a single raw policy dict into a Policy object."""
    errors = []

    name     = raw.get("name", "")
    cloud    = raw.get("cloud", "").lower()
    resource = raw.get("resource", "")
    severity = raw.get("severity", "MEDIUM").upper()
    desc     = raw.get("description", "")
    metadata = raw.get("metadata", {})

    if not name:
        errors.append("missing 'name'")
    if cloud not in SUPPORTED_CLOUDS:
        errors.append(f"'cloud' must be one of {SUPPORTED_CLOUDS}, got '{cloud}'")
    if resource not in RESOURCE_TYPES.get(cloud, []):
        errors.append(
            f"'resource' '{resource}' not supported for cloud '{cloud}'. "
            f"Valid: {RESOURCE_TYPES.get(cloud, [])}"
        )
    if severity not in SEVERITIES:
        errors.append(f"'severity' must be one of {SEVERITIES}, got '{severity}'")

    if errors:
        loc = f" [{source_file}]" if source_file else ""
        raise ValueError(f"Policy '{name}'{loc} validation errors: {'; '.join(errors)}")

    raw_filters = raw.get("filters", [])
    filters = [parse_filter(f) for f in raw_filters]

    return Policy(
        name=name,
        cloud=cloud,
        resource=resource,
        severity=severity,
        description=desc,
        filters=filters,
        metadata=metadata,
    )


def load_policies_from_yaml(path: str) -> list[Policy]:
    """Load and parse all policies from a YAML file."""
    import yaml
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "policies" not in data:
        raise ValueError(f"{path}: must have top-level 'policies' key")
    return [parse_policy(p, source_file=path) for p in data["policies"]]


def load_all_policies(policies_dir: str, clouds: list[str] | None = None) -> list[Policy]:
    """Load all policies from policies/<cloud>/*.yml directories."""
    import glob, os
    all_policies = []
    base = policies_dir
    clouds_to_load = clouds or list(SUPPORTED_CLOUDS)

    for cloud in clouds_to_load:
        pattern = os.path.join(base, cloud, "*.yml")
        for f in sorted(glob.glob(pattern)):
            try:
                policies = load_policies_from_yaml(f)
                all_policies.extend(policies)
            except Exception as e:
                import logging
                logging.getLogger("cloud-sentinel.schema").warning(f"Skipping {f}: {e}")

    return all_policies
