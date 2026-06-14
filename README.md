# ☁️ cloud-sentinel

**A native, AI-augmented CSPM + PSPM platform** — multi-cloud security posture scanning across AWS, Azure, and GCP, built entirely on native cloud SDKs (boto3, azure-sdk, google-cloud) with zero third-party policy engine dependencies.

cloud-sentinel goes beyond traditional CSPM by automatically mapping every finding to **PCI DSS, ISO 27001, SOC 2, HIPAA, and APRA CPS 234**, generating **AI-powered remediation advice** via Claude, and detecting **Terraform drift** so platform teams can answer: *who bypassed IaC, what drifted, and who owns it.*

---

## What It Does

| Capability | Description |
|---|---|
| **CSPM Engine** | Native policy engine (no Cloud Custodian) — evaluates YAML-defined policies against live AWS/Azure/GCP resources fetched via official SDKs |
| **Compliance Mapping** | Every finding auto-maps to PCI DSS v4.0, ISO 27001:2022, SOC 2, HIPAA, and APRA CPS 234 controls, with per-framework posture scores (0–100) and letter grades |
| **AI Remediation Advisor** | Calls Claude per CRITICAL/HIGH finding to generate exact CLI commands, Terraform/IaC snippets, MITRE ATT&CK mapping, and verification steps |
| **PSPM Drift Detection** | Compares live cloud state against Terraform state — flags unmanaged resources (bypassed IaC), attribute drift, and ghost resources, with team ownership attribution |
| **HTML + Slack Reporting** | Self-contained dark-themed HTML report with compliance dashboard + drift section; Slack notification with top findings |
| **GitHub Actions Pipeline** | Scheduled + on-push scanning, parallel per-cloud jobs, CI gate on CRITICAL findings |

---

## Pipeline Flow

```
Push / Schedule
      │
      ▼
GitHub Actions
      │
      ├─► Validate policies (schema + dry-run)
      │
      ├─► Scan AWS  ──┐
      ├─► Scan Azure ─┼─► Merge results ──► Compliance Mapping ──► AI Advisor ──► HTML Report + Slack
      └─► Scan GCP  ──┘
                                                  │
                                                  ▼
                                          PSPM Drift Detection
                                       (vs. Terraform state)
```

---

## Project Structure

```
cloud-sentinel/
├── engine/
│   ├── schema.py        # Policy YAML parser, Filter/CompositeFilter evaluator
│   ├── engine.py         # PolicyEngine — runs policies against collectors
│   └── compliance.py     # PCI DSS / ISO 27001 / SOC 2 / HIPAA / CPS 234 mapping + scoring
├── collectors/
│   ├── aws.py            # boto3: S3, IAM, Security Groups, EC2, EBS, RDS
│   ├── azure.py          # azure-sdk: Storage, NSGs, SQL Servers, Key Vaults
│   └── gcp.py             # google-cloud: GCS, Compute, Firewall Rules
├── drift/
│   ├── tf_parser.py       # Reads Terraform state (v4 JSON)
│   ├── ownership.py       # Resolves resource owner from tags
│   └── detector.py        # PSPM: unmanaged / drifted / ghost resource detection
├── policies/
│   ├── aws/               # s3.yml, iam.yml, compute.yml
│   ├── azure/              # storage_network.yml
│   └── gcp/                # compute_storage.yml
├── runner/
│   ├── run.py              # Main CSPM scan orchestrator
│   ├── reporter.py          # HTML report + Slack notification generator
│   └── ai_advisor.py         # Claude API remediation advisor
├── reports/                  # Output dir (gitignored)
├── .github/workflows/
│   └── cspm.yml               # Scheduled + on-push CI pipeline
├── requirements.txt
└── README.md
```

---

## Policies Covered (25 across 3 clouds)

| Cloud | Policy | Severity |
|-------|--------|----------|
| AWS | S3 bucket public access not blocked | HIGH |
| AWS | S3 bucket encryption disabled | HIGH |
| AWS | S3 bucket logging disabled | MEDIUM |
| AWS | Root account MFA disabled | CRITICAL |
| AWS | IAM user without MFA (console access) | HIGH |
| AWS | AdministratorAccess directly attached to user | HIGH |
| AWS | IAM access key not rotated in 90 days | MEDIUM |
| AWS | Security group allows SSH from 0.0.0.0/0 | CRITICAL |
| AWS | Security group allows RDP from 0.0.0.0/0 | CRITICAL |
| AWS | Security group unrestricted ingress (all ports) | CRITICAL |
| AWS | EC2 instance not enforcing IMDSv2 | HIGH |
| AWS | EBS volume unencrypted | HIGH |
| AWS | RDS instance publicly accessible | CRITICAL |
| AWS | RDS instance storage not encrypted | HIGH |
| Azure | Storage account allows public blob access | HIGH |
| Azure | Storage account not enforcing HTTPS-only | HIGH |
| Azure | NSG with any-to-any inbound rule | CRITICAL |
| Azure | SQL Server with public network access | HIGH |
| Azure | Key Vault soft-delete disabled | MEDIUM |
| GCP | GCS bucket grants access to allUsers / allAuthenticatedUsers | CRITICAL |
| GCP | GCS bucket without uniform bucket-level access | MEDIUM |
| GCP | Firewall rule allows SSH from 0.0.0.0/0 | CRITICAL |
| GCP | Firewall rule allows RDP from 0.0.0.0/0 | CRITICAL |
| GCP | GCE instance using default service account | HIGH |
| GCP | GCE instance with serial port enabled | MEDIUM |

Every policy is mapped to one or more compliance frameworks — see `engine/compliance.py`.

---

## Compliance Frameworks

cloud-sentinel automatically scores your environment against:

| Framework | Controls Tracked |
|---|---|
| **PCI DSS v4.0** | 10 controls — access, encryption, logging, vulnerability management |
| **ISO/IEC 27001:2022** | 14 controls — access control, crypto, network security, logging |
| **SOC 2 Type II** | 9 controls — CC6 (access), CC7 (monitoring), CC8/CC9 (change & risk) |
| **HIPAA Security Rule** | 11 controls — access, transmission security, audit, integrity |
| **APRA CPS 234** | 9 controls — asset classification, access management, incident notification |

Each framework gets a **posture score (0–100)**, a **letter grade (A–F)**, and a list of **failing control IDs** — shown in the HTML report and computed automatically on every scan (disable with `--no-compliance`).

---

## Setup

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure credentials

#### AWS
```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=ap-south-1
```

#### Azure
```bash
export AZURE_SUBSCRIPTION_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_TENANT_ID=...
```

#### GCP
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json
export GOOGLE_CLOUD_PROJECT=my-project-id
```

#### AI Advisor (optional)
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

### Run a CSPM scan

```bash
# Auto-detect clouds from credentials, includes compliance mapping
python runner/run.py

# Specific clouds
python runner/run.py --clouds aws azure

# Validate policies without making API calls
python runner/run.py --dry-run

# Skip compliance mapping
python runner/run.py --no-compliance

# Filter by severity
python runner/run.py --severity-filter CRITICAL HIGH
```

### Generate the HTML report

```bash
# HTML report + Slack notification
python runner/reporter.py

# HTML only, no Slack
python runner/reporter.py --no-slack

# With AI remediation advice for CRITICAL/HIGH findings
python runner/reporter.py --ai

# Point to a specific results file
python runner/reporter.py --results reports/run_20250601_120000/results.json
```

### Run PSPM drift detection

Compares live cloud resources against a Terraform state file to find:
- **Unmanaged** — resources created outside Terraform (console/CLI)
- **Drifted** — security attributes diverged from declared IaC
- **Ghost** — declared in Terraform but missing from the cloud

```bash
# Pull remote state locally first (if using S3/Azure/GCS backend)
terraform state pull > state.json

# Run drift detection
python drift/detector.py --tfstate state.json --clouds aws

# Include drift findings in the HTML report
python runner/reporter.py \
  --results reports/run_xxx/results.json \
  --drift-results reports/drift_xxx.json
```

The PSPM report answers:
- *Who bypassed Terraform?* → unmanaged resource findings
- *Which resources drifted?* → attribute-level drift with TF address reference
- *Which deployment created risk?* → `tf_address` points to the exact `.tf` resource
- *Which team owns this finding?* → resolved from `Owner` / `Team` / `Squad` / `CostCenter` tags

---

## GitHub Actions Setup

Add the following secrets to your repository (`Settings → Secrets → Actions`):

| Secret | Description |
|--------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `AWS_DEFAULT_REGION` | AWS region (e.g. `ap-south-1`) |
| `AZURE_CREDENTIALS` | Azure service principal JSON |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID |
| `AZURE_CLIENT_ID` | Azure SP client ID |
| `AZURE_CLIENT_SECRET` | Azure SP client secret |
| `AZURE_TENANT_ID` | Azure tenant ID |
| `GCP_CREDENTIALS_JSON` | GCP service account key JSON |
| `GCP_PROJECT_ID` | GCP project ID |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook URL |
| `ANTHROPIC_API_KEY` | Claude API key — enables AI remediation advisor (optional) |

### Pipeline triggers

| Trigger | Behaviour |
|---------|-----------|
| Push to `main` | Validate + scan if policies/runner changed |
| PR to `main` | Validate + dry-run only (no live scan) |
| Daily `cron: 0 6 * * *` | Full scan (06:00 UTC / 11:30 IST) |
| Manual dispatch | Choose clouds + optional dry-run |

The pipeline fails (exit code 1) if any **CRITICAL** findings are detected — acting as a security gate.

---

## Required IAM Permissions

cloud-sentinel requires **read-only** access — no write/remediation actions are performed.

### AWS (minimum)
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketLogging",
      "s3:GetBucketVersioning",
      "s3:GetBucketTagging",
      "iam:GetAccountSummary",
      "iam:ListUsers",
      "iam:ListMFADevices",
      "iam:GetLoginProfile",
      "iam:ListAttachedUserPolicies",
      "iam:ListAccessKeys",
      "iam:ListUserTags",
      "sts:GetCallerIdentity",
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVolumes",
      "rds:DescribeDBInstances"
    ],
    "Resource": "*"
  }]
}
```

### Azure
Assign the **Reader** built-in role on the subscription. Authentication via `DefaultAzureCredential` (service principal, managed identity, or Azure CLI login).

### GCP
Assign the **Viewer** (`roles/viewer`) role on the project. Authentication via Application Default Credentials (ADC).

---

## Adding New Policies

Policies are plain YAML — no third-party schema. Example:

```yaml
policies:
  - name: my-new-policy
    cloud: aws
    resource: s3_bucket          # must match a resource type in engine/schema.py
    severity: HIGH
    description: "My custom check"
    filters:
      - field: encrypted
        op: eq
        value: false
    metadata:
      violation: "Bucket is not encrypted"
      remediation: "Enable SSE-S3 or SSE-KMS"
      mitre: "TA0009 Collection"
```

**Supported operators**: `eq`, `ne`, `gt`, `lt`, `gte`, `lte`, `in`, `not_in`, `contains`, `not_contains`, `exists`, `not_exists`, `regex`, `startswith`, `endswith`. Combine with `and` / `or` / `not` for nested logic.

To add compliance mappings for a new policy, add an entry to `POLICY_FRAMEWORK_MAP` in `engine/compliance.py`.

Validate before pushing:
```bash
python runner/run.py --dry-run
```

---

## Adding New Resource Types / Collectors

1. Add a fetcher function to `collectors/<cloud>.py` returning a list of normalised resource dicts (must include `id`, `region`, `account`, `tags`)
2. Register it in that file's `register_all()` function
3. Add the resource type to `RESOURCE_TYPES` in `engine/schema.py`
4. Write policies referencing the new `resource:` type

---

## Extending

- **AI Advisor tuning**: adjust `SYSTEM_PROMPT` and `MODEL` in `runner/ai_advisor.py`; responses are cached in `.ai_cache/` to avoid redundant API calls
- **More frameworks**: add a new entry to `FRAMEWORKS` and extend `POLICY_FRAMEWORK_MAP` in `engine/compliance.py`
- **More clouds**: add a `collectors/<cloud>.py`, extend `SUPPORTED_CLOUDS` and `RESOURCE_TYPES` in `engine/schema.py`, add `policies/<cloud>/`
- **Drift for more resource types**: extend `RESOURCE_MAP` and `ATTRIBUTE_DRIFT_CHECKS` in `drift/detector.py`
- **Export to SIEM**: extend `reporter.py` to ship findings to Splunk HEC, AWS Security Hub, or Azure Sentinel
- **Grafana**: `results.json` / `drift_results.json` can be ingested via a JSON datasource or pushed to a time-series store for dashboarding

---

## License

MIT
