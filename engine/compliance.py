"""
cloud-sentinel compliance engine
Maps findings to PCI DSS, ISO 27001, SOC 2, and HIPAA controls.
Produces per-framework posture scores and control coverage reports.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

# ── Framework control definitions ─────────────────────────────────────────────

FRAMEWORKS = {
    "pci_dss": {
        "name": "PCI DSS v4.0",
        "short": "PCI DSS",
        "color": "#1d4ed8",
        "controls": {
            "1.3":  "Restrict inbound and outbound traffic to that which is necessary",
            "2.2":  "Develop configuration standards for all system components",
            "3.5":  "Primary account number (PAN) is secured wherever stored",
            "6.3":  "Security vulnerabilities are identified and addressed",
            "7.2":  "Access to system components is appropriately defined and assigned",
            "8.2":  "User identification and related accounts for users and administrators are strictly managed",
            "8.4":  "Multi-factor authentication is implemented to secure access",
            "10.2": "Audit logs are implemented to support detection of anomalies",
            "10.3": "Audit logs are protected from destruction and unauthorized modifications",
            "11.3": "External and internal vulnerabilities are regularly identified and addressed",
        }
    },
    "iso_27001": {
        "name": "ISO/IEC 27001:2022",
        "short": "ISO 27001",
        "color": "#0f766e",
        "controls": {
            "A.5.15":  "Access control",
            "A.5.16":  "Identity management",
            "A.5.17":  "Authentication information",
            "A.5.22":  "Monitoring, review and change management of supplier services",
            "A.7.4":   "Physical security monitoring",
            "A.8.3":   "Information access restriction",
            "A.8.5":   "Secure authentication",
            "A.8.9":   "Configuration management",
            "A.8.11":  "Data masking",
            "A.8.12":  "Data leakage prevention",
            "A.8.15":  "Logging",
            "A.8.20":  "Networks security",
            "A.8.21":  "Security of network services",
            "A.8.24":  "Use of cryptography",
        }
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "short": "SOC 2",
        "color": "#7c3aed",
        "controls": {
            "CC6.1":  "Logical and physical access controls restrict access",
            "CC6.2":  "New internal and external users are registered and authorized",
            "CC6.3":  "Access is removed when no longer required",
            "CC6.6":  "Logical access security measures protect against threats",
            "CC6.7":  "Transmission of data is restricted to authorized users",
            "CC7.1":  "Detection and monitoring procedures identify configuration changes",
            "CC7.2":  "Anomalies and security incidents are identified and reported",
            "CC8.1":  "Changes are authorized, designed, developed, tested, and deployed",
            "CC9.2":  "Identified risks are managed through risk mitigation activities",
        }
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "short": "HIPAA",
        "color": "#b45309",
        "controls": {
            "164.308(a)(1)": "Security management process",
            "164.308(a)(3)": "Workforce authorization and supervision",
            "164.308(a)(4)": "Information access management",
            "164.308(a)(5)": "Security awareness and training",
            "164.310(a)(1)": "Facility access controls",
            "164.310(d)(1)": "Device and media controls",
            "164.312(a)(1)": "Access control",
            "164.312(a)(2)": "Automatic logoff and encryption",
            "164.312(b)":    "Audit controls",
            "164.312(c)(1)": "Integrity controls",
            "164.312(e)(1)": "Transmission security",
        }
    },
    "apra_cps234": {
        "name": "APRA CPS 234",
        "short": "CPS 234",
        "color": "#0369a1",
        "controls": {
            "15":   "Define information security roles and responsibilities",
            "16":   "Maintain information security capability commensurate with threats",
            "17":   "Implement controls to protect information assets",
            "18":   "Classify information assets by criticality and sensitivity",
            "19":   "Assess control effectiveness annually",
            "20":   "Test controls commensurate with risk and regularity",
            "21":   "Implement access controls and privileged access management",
            "22":   "Notify APRA of material information security incidents",
            "36":   "Third-party and related-party information security",
        }
    },
}


# ── Policy → framework control mappings ───────────────────────────────────────
# Format: policy_name → {framework: [control_ids]}

POLICY_FRAMEWORK_MAP: dict[str, dict[str, list[str]]] = {

    # ── AWS S3 ──
    "s3-bucket-public-access-not-blocked": {
        "pci_dss":    ["1.3", "6.3"],
        "iso_27001":  ["A.8.3", "A.8.12"],
        "soc2":       ["CC6.1", "CC6.6"],
        "hipaa":      ["164.312(a)(1)", "164.312(e)(1)"],
        "apra_cps234": ["17", "18"],
    },
    "s3-bucket-encryption-disabled": {
        "pci_dss":    ["3.5"],
        "iso_27001":  ["A.8.24"],
        "soc2":       ["CC6.7"],
        "hipaa":      ["164.312(a)(2)", "164.312(e)(1)"],
        "apra_cps234": ["17"],
    },
    "s3-bucket-logging-disabled": {
        "pci_dss":    ["10.2", "10.3"],
        "iso_27001":  ["A.8.15"],
        "soc2":       ["CC7.1", "CC7.2"],
        "hipaa":      ["164.312(b)"],
        "apra_cps234": ["20"],
    },

    # ── AWS IAM ──
    "root-account-mfa-disabled": {
        "pci_dss":    ["8.4"],
        "iso_27001":  ["A.8.5"],
        "soc2":       ["CC6.1", "CC6.2"],
        "hipaa":      ["164.308(a)(3)", "164.312(a)(1)"],
        "apra_cps234": ["21"],
    },
    "iam-user-no-mfa": {
        "pci_dss":    ["8.4"],
        "iso_27001":  ["A.8.5"],
        "soc2":       ["CC6.1", "CC6.6"],
        "hipaa":      ["164.312(a)(1)"],
        "apra_cps234": ["21"],
    },
    "iam-admin-policy-directly-attached": {
        "pci_dss":    ["7.2"],
        "iso_27001":  ["A.5.15", "A.8.3"],
        "soc2":       ["CC6.3"],
        "hipaa":      ["164.308(a)(4)", "164.312(a)(1)"],
        "apra_cps234": ["21"],
    },
    "iam-access-key-not-rotated": {
        "pci_dss":    ["8.2"],
        "iso_27001":  ["A.5.17"],
        "soc2":       ["CC6.1"],
        "hipaa":      ["164.308(a)(5)"],
        "apra_cps234": ["21"],
    },

    # ── AWS Compute ──
    "security-group-open-ssh": {
        "pci_dss":    ["1.3", "11.3"],
        "iso_27001":  ["A.8.20", "A.8.21"],
        "soc2":       ["CC6.6", "CC6.7"],
        "hipaa":      ["164.312(e)(1)"],
        "apra_cps234": ["17"],
    },
    "security-group-open-rdp": {
        "pci_dss":    ["1.3", "11.3"],
        "iso_27001":  ["A.8.20", "A.8.21"],
        "soc2":       ["CC6.6", "CC6.7"],
        "hipaa":      ["164.312(e)(1)"],
        "apra_cps234": ["17"],
    },
    "security-group-unrestricted-ingress": {
        "pci_dss":    ["1.3"],
        "iso_27001":  ["A.8.20"],
        "soc2":       ["CC6.6"],
        "hipaa":      ["164.312(e)(1)"],
        "apra_cps234": ["17"],
    },
    "ec2-imdsv2-not-required": {
        "pci_dss":    ["6.3", "2.2"],
        "iso_27001":  ["A.8.9"],
        "soc2":       ["CC6.6"],
        "hipaa":      ["164.312(a)(1)"],
        "apra_cps234": ["17"],
    },
    "ebs-volume-unencrypted": {
        "pci_dss":    ["3.5"],
        "iso_27001":  ["A.8.24"],
        "soc2":       ["CC6.7"],
        "hipaa":      ["164.312(a)(2)"],
        "apra_cps234": ["17"],
    },
    "rds-publicly-accessible": {
        "pci_dss":    ["1.3"],
        "iso_27001":  ["A.8.20", "A.8.21"],
        "soc2":       ["CC6.6"],
        "hipaa":      ["164.312(e)(1)"],
        "apra_cps234": ["17", "18"],
    },
    "rds-storage-not-encrypted": {
        "pci_dss":    ["3.5"],
        "iso_27001":  ["A.8.24"],
        "soc2":       ["CC6.7"],
        "hipaa":      ["164.312(a)(2)"],
        "apra_cps234": ["17"],
    },

    # ── Azure ──
    "azure-storage-public-blob-access": {
        "pci_dss":    ["1.3", "6.3"],
        "iso_27001":  ["A.8.3", "A.8.12"],
        "soc2":       ["CC6.1", "CC6.6"],
        "hipaa":      ["164.312(a)(1)"],
        "apra_cps234": ["17", "18"],
    },
    "azure-storage-https-not-enforced": {
        "pci_dss":    ["6.3"],
        "iso_27001":  ["A.8.24"],
        "soc2":       ["CC6.7"],
        "hipaa":      ["164.312(e)(1)"],
        "apra_cps234": ["17"],
    },
    "azure-nsg-any-any-inbound": {
        "pci_dss":    ["1.3"],
        "iso_27001":  ["A.8.20"],
        "soc2":       ["CC6.6"],
        "hipaa":      ["164.312(e)(1)"],
        "apra_cps234": ["17"],
    },
    "azure-sql-public-network-access": {
        "pci_dss":    ["1.3"],
        "iso_27001":  ["A.8.20", "A.8.21"],
        "soc2":       ["CC6.6"],
        "hipaa":      ["164.312(e)(1)"],
        "apra_cps234": ["17", "18"],
    },
    "azure-keyvault-soft-delete-disabled": {
        "pci_dss":    ["10.3"],
        "iso_27001":  ["A.8.24"],
        "soc2":       ["CC9.2"],
        "hipaa":      ["164.312(c)(1)"],
        "apra_cps234": ["17"],
    },

    # ── GCP ──
    "gcp-gcs-bucket-public-access": {
        "pci_dss":    ["1.3", "6.3"],
        "iso_27001":  ["A.8.3", "A.8.12"],
        "soc2":       ["CC6.1", "CC6.6"],
        "hipaa":      ["164.312(a)(1)"],
        "apra_cps234": ["17", "18"],
    },
    "gcp-gcs-uniform-access-disabled": {
        "pci_dss":    ["2.2"],
        "iso_27001":  ["A.8.9"],
        "soc2":       ["CC6.1"],
        "hipaa":      ["164.312(a)(1)"],
        "apra_cps234": ["17"],
    },
    "gcp-firewall-open-ssh": {
        "pci_dss":    ["1.3", "11.3"],
        "iso_27001":  ["A.8.20", "A.8.21"],
        "soc2":       ["CC6.6", "CC6.7"],
        "hipaa":      ["164.312(e)(1)"],
        "apra_cps234": ["17"],
    },
    "gcp-firewall-open-rdp": {
        "pci_dss":    ["1.3", "11.3"],
        "iso_27001":  ["A.8.20", "A.8.21"],
        "soc2":       ["CC6.6", "CC6.7"],
        "hipaa":      ["164.312(e)(1)"],
        "apra_cps234": ["17"],
    },
    "gcp-default-service-account": {
        "pci_dss":    ["7.2"],
        "iso_27001":  ["A.5.15", "A.5.16"],
        "soc2":       ["CC6.3"],
        "hipaa":      ["164.308(a)(4)"],
        "apra_cps234": ["21"],
    },
    "gcp-serial-port-enabled": {
        "pci_dss":    ["2.2"],
        "iso_27001":  ["A.8.9"],
        "soc2":       ["CC6.6"],
        "hipaa":      ["164.308(a)(1)"],
        "apra_cps234": ["17"],
    },
}


# ── Compliance enrichment ──────────────────────────────────────────────────────

def enrich_finding_with_compliance(finding: dict) -> dict:
    """Add compliance framework mappings to a finding dict."""
    policy_name = finding.get("policy_name", "")
    mappings    = POLICY_FRAMEWORK_MAP.get(policy_name, {})

    compliance = {}
    for fw_id, control_ids in mappings.items():
        fw_def  = FRAMEWORKS.get(fw_id, {})
        controls_def = fw_def.get("controls", {})
        compliance[fw_id] = {
            "framework_name":  fw_def.get("name", fw_id),
            "framework_short": fw_def.get("short", fw_id),
            "color":           fw_def.get("color", "#888"),
            "controls": [
                {
                    "id":          cid,
                    "description": controls_def.get(cid, ""),
                }
                for cid in control_ids
            ]
        }

    finding["compliance"] = compliance
    return finding


def enrich_all_findings(findings: list[dict]) -> list[dict]:
    return [enrich_finding_with_compliance(f) for f in findings]


# ── Posture scoring ───────────────────────────────────────────────────────────

@dataclass
class FrameworkPosture:
    framework_id:   str
    framework_name: str
    framework_short: str
    color:          str
    total_controls: int
    failing_controls: set = field(default_factory=set)
    passing_controls: set = field(default_factory=set)
    findings_count: int = 0
    critical_count: int = 0
    high_count:     int = 0

    @property
    def checked_controls(self) -> set:
        return self.failing_controls | self.passing_controls

    @property
    def score(self) -> int:
        """0-100 posture score. 100 = no failing controls."""
        if not self.total_controls:
            return 100
        failing = len(self.failing_controls)
        return max(0, round(100 * (1 - failing / self.total_controls)))

    @property
    def coverage(self) -> int:
        """% of total controls that have at least one policy mapped."""
        if not self.total_controls:
            return 0
        return round(100 * len(self.checked_controls) / self.total_controls)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90: return "A"
        if s >= 80: return "B"
        if s >= 70: return "C"
        if s >= 60: return "D"
        return "F"

    @property
    def status(self) -> str:
        if self.critical_count > 0: return "critical"
        if self.high_count > 0:     return "high"
        if self.findings_count > 0: return "medium"
        return "pass"


def calculate_posture(findings: list[dict]) -> dict[str, FrameworkPosture]:
    """
    Calculate compliance posture for each framework given a list of findings.
    Returns a dict of framework_id → FrameworkPosture.
    """
    postures: dict[str, FrameworkPosture] = {}

    # Initialise posture for every framework
    for fw_id, fw_def in FRAMEWORKS.items():
        postures[fw_id] = FrameworkPosture(
            framework_id=fw_id,
            framework_name=fw_def["name"],
            framework_short=fw_def["short"],
            color=fw_def["color"],
            total_controls=len(fw_def["controls"]),
        )

    # Populate all possible passing controls from the policy map
    for policy_name, fw_map in POLICY_FRAMEWORK_MAP.items():
        for fw_id, control_ids in fw_map.items():
            if fw_id in postures:
                postures[fw_id].passing_controls.update(control_ids)

    # Mark controls as failing based on actual findings
    for finding in findings:
        policy_name = finding.get("policy_name", "")
        severity    = finding.get("severity", "LOW")
        fw_map      = POLICY_FRAMEWORK_MAP.get(policy_name, {})

        for fw_id, control_ids in fw_map.items():
            if fw_id not in postures:
                continue
            p = postures[fw_id]
            p.findings_count += 1
            p.failing_controls.update(control_ids)
            # Remove from passing once it's failing
            p.passing_controls -= set(control_ids)

            if severity == "CRITICAL":
                p.critical_count += 1
            elif severity == "HIGH":
                p.high_count += 1

    return postures


def posture_to_dict(posture: FrameworkPosture) -> dict:
    """Serialise a FrameworkPosture to a JSON-safe dict."""
    return {
        "framework_id":    posture.framework_id,
        "framework_name":  posture.framework_name,
        "framework_short": posture.framework_short,
        "color":           posture.color,
        "score":           posture.score,
        "grade":           posture.grade,
        "status":          posture.status,
        "coverage":        posture.coverage,
        "total_controls":  posture.total_controls,
        "failing_controls": sorted(posture.failing_controls),
        "passing_controls": sorted(posture.passing_controls),
        "findings_count":  posture.findings_count,
        "critical_count":  posture.critical_count,
        "high_count":      posture.high_count,
    }


def add_compliance_to_results(results: dict) -> dict:
    """
    Main entry point — enriches a full results dict (from engine.run()) with:
    - compliance mappings on each finding
    - framework posture scores at the top level
    """
    all_findings = []
    for r in results.get("results", []):
        enriched = []
        for finding in r.get("findings", []):
            enriched_finding = enrich_finding_with_compliance(finding)
            enriched.append(enriched_finding)
            all_findings.append(enriched_finding)
        r["findings"] = enriched

    postures = calculate_posture(all_findings)
    results["compliance"] = {
        fw_id: posture_to_dict(p)
        for fw_id, p in postures.items()
    }
    results["compliance_enriched"] = True
    return results
