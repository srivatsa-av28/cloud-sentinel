"""
cloud-sentinel drift: Terraform state parser
Reads a Terraform state file (local JSON, version 4) and builds an index
of managed resources keyed by Terraform resource type.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path

log = logging.getLogger("cloud-sentinel.drift.tf_parser")


def load_tfstate(path: str) -> list[dict]:
    """
    Load a Terraform state file and return its raw 'resources' list.
    Supports local state files (terraform.tfstate, *.tfstate.json).
    Remote state (S3/Azure/GCS backends) must be pulled locally first via
    `terraform state pull > state.json`.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Terraform state file not found: {path}")

    with open(p) as f:
        state = json.load(f)

    version = state.get("version")
    if version is not None and version < 4:
        log.warning(f"Terraform state version {version} detected — only v4+ is fully supported")

    resources = state.get("resources", [])
    log.info(f"Loaded Terraform state: {len(resources)} resource block(s) from {path}")
    return resources


def build_tf_index(resources: list[dict]) -> dict[str, list[dict]]:
    """
    Build an index of Terraform resources grouped by their TF resource type.

    Returns:
        {
          "aws_s3_bucket": [
            {"address": "aws_s3_bucket.assets", "name": "assets", "attributes": {...}},
            ...
          ],
          "aws_security_group": [...],
          ...
        }
    """
    index: dict[str, list[dict]] = {}

    for r in resources:
        # Skip data sources — only track managed resources
        if r.get("mode") != "managed":
            continue

        tf_type = r.get("type", "")
        name    = r.get("name", "")
        module  = r.get("module", "")

        for inst in r.get("instances", []):
            attrs   = inst.get("attributes", {})
            address = f"{module + '.' if module else ''}{tf_type}.{name}"
            if "index_key" in inst:
                address += f"[{inst['index_key']!r}]"

            index.setdefault(tf_type, []).append({
                "address":    address,
                "name":       name,
                "module":     module,
                "attributes": attrs,
            })

    for tf_type, entries in index.items():
        log.info(f"  {tf_type}: {len(entries)} instance(s)")

    return index


def get_attr(attributes: dict, path: str):
    """
    Resolve a dotted/indexed attribute path against a TF instance's attributes dict.
    Supports list indexing for nested blocks, e.g. 'versioning[0].enabled'.
    Returns None if not found.
    """
    import re
    parts   = path.split(".")
    current = attributes

    for part in parts:
        if current is None:
            return None
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
