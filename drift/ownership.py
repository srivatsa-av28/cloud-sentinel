"""
cloud-sentinel drift: ownership mapping
Determines which team/owner a resource belongs to based on its tags/labels.
Used to answer: "Which team owns this finding?"
"""

from __future__ import annotations

# Tag keys checked in priority order (case-sensitive first, then lowercase fallback)
OWNERSHIP_TAG_KEYS = [
    "Owner", "owner",
    "Team", "team",
    "Squad", "squad",
    "CostCenter", "cost_center", "cost-center",
    "ManagedBy", "managed_by", "managed-by",
    "Application", "application", "app",
]

UNASSIGNED = "unassigned"


def get_owner(tags: dict | None) -> str:
    """
    Return the owning team/individual for a resource based on its tags.
    Falls back to 'unassigned' if no recognised ownership tag is present.
    """
    if not tags:
        return UNASSIGNED

    for key in OWNERSHIP_TAG_KEYS:
        value = tags.get(key)
        if value:
            return str(value)

    return UNASSIGNED


def group_findings_by_owner(findings: list[dict]) -> dict[str, list[dict]]:
    """Group a list of findings by their resolved owner."""
    groups: dict[str, list[dict]] = {}
    for f in findings:
        owner = f.get("owner") or get_owner(f.get("tags", {}))
        groups.setdefault(owner, []).append(f)
    return groups


def owner_summary(findings: list[dict]) -> list[dict]:
    """
    Build a summary table: owner -> finding counts by severity.
    Returns a list sorted by total findings descending.
    """
    groups = group_findings_by_owner(findings)
    summary = []

    for owner, items in groups.items():
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in items:
            sev = f.get("severity", "LOW")
            if sev in by_sev:
                by_sev[sev] += 1

        summary.append({
            "owner": owner,
            "total": len(items),
            "by_severity": by_sev,
        })

    summary.sort(key=lambda x: x["total"], reverse=True)
    return summary
