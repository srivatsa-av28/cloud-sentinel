# ☁️ cloud-sentinel

**CSPM-as-code** — multi-cloud security posture scanning across AWS, Azure, and GCP using [Cloud Custodian](https://cloudcustodian.io), with automated HTML reporting and Slack notifications via GitHub Actions.

---

## What It Does

cloud-sentinel runs security policy checks across your cloud environments on every push and on a daily schedule. It detects misconfigurations, generates a severity-ranked HTML report, and fires a Slack notification with the top findings.

**Pipeline flow:**

```
Push / Schedule
      │
      ▼
GitHub Actions
      │
      ├─► Validate policies (YAML lint + dry-run)
      │
      ├─► Scan AWS  ──┐
      ├─► Scan Azure ─┼─► Merge results ──► HTML Report + Slack
      └─► Scan GCP  ──┘
```

---

## Policies Covered

| Cloud | Policy | Severity |
|-------|--------|----------|
| AWS | S3 public access block not enabled | HIGH |
| AWS | S3 bucket encryption disabled | HIGH |
| AWS | S3 bucket logging disabled | MEDIUM |
| AWS | Root account MFA disabled | CRITICAL |
| AWS | IAM user without MFA (console access) | HIGH |
| AWS | AdministratorAccess directly attached to user | HIGH |
| AWS | IAM access key not rotated in 90 days | MEDIUM |
| AWS | Security group allows SSH from 0.0.0.0/0 | CRITICAL |
| AWS | Security group allows RDP from 0.0.0.0/0 | CRITICAL |
| AWS | Security group unrestricted ingress (all ports) | CRITICAL |
| AWS | EBS volume unencrypted | HIGH |
| AWS | EC2 instance not enforcing IMDSv2 | HIGH |
| AWS | EC2 instance with public IP (untagged) | MEDIUM |
| AWS | RDS instance publicly accessible | CRITICAL |
| AWS | RDS instance storage not encrypted | HIGH |
| Azure | Storage account allows public blob access | HIGH |
| Azure | Storage account not enforcing HTTPS-only | HIGH |
| Azure | Storage blob encryption disabled | HIGH |
| Azure | NSG with any-to-any inbound rule | CRITICAL |
| Azure | SQL Server with public network access | HIGH |
| Azure | Key Vault soft-delete disabled | MEDIUM |
| GCP | GCS bucket grants access to allUsers | CRITICAL |
| GCP | GCS bucket without uniform bucket-level access | MEDIUM |
| GCP | Firewall rule allows SSH from 0.0.0.0/0 | CRITICAL |
| GCP | Firewall rule allows RDP from 0.0.0.0/0 | CRITICAL |
| GCP | GCE instance using default service account | HIGH |
| GCP | GCE instance with serial port enabled | MEDIUM |

---

## Project Structure

```
cloud-sentinel/
├── policies/
│   ├── aws/
│   │   ├── s3-public-access.yml
│   │   ├── iam-sg-controls.yml
│   │   └── compute-storage-controls.yml
│   ├── azure/
│   │   └── storage-network-controls.yml
│   └── gcp/
│       └── compute-storage-controls.yml
├── runner/
│   ├── run.py          # Orchestrates c7n across all clouds
│   └── reporter.py     # Aggregates findings → HTML + Slack
├── reports/            # Output dir (gitignored)
├── .github/
│   └── workflows/
│       └── cspm.yml    # Scheduled + on-push pipeline
├── requirements.txt
└── README.md
```

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

### 3. Run locally

```bash
# Scan all clouds (auto-detects from credentials)
python runner/run.py

# Scan specific clouds
python runner/run.py --clouds aws azure

# Validate policies without executing
python runner/run.py --dry-run
```

### 4. Generate report

```bash
# HTML report + Slack notification
python runner/reporter.py

# HTML only
python runner/reporter.py --no-slack

# Point to specific results file
python runner/reporter.py --results reports/run_20250601_120000/results.json
```

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

### Pipeline triggers

| Trigger | Behaviour |
|---------|-----------|
| Push to `main` | Validate + scan if policies/runner changed |
| PR to `main` | Validate + dry-run only (no live scan) |
| Daily `cron: 0 6 * * *` | Full scan (06:00 UTC / 11:30 IST) |
| Manual dispatch | Choose clouds + optional dry-run |

---

## Required IAM Permissions

Cloud Custodian requires **read-only** access to evaluate policies. Remediation actions require write access — disabled in this project by default.

### AWS (minimum)
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketLogging",
      "iam:GetAccountSummary",
      "iam:ListUsers",
      "iam:ListMFADevices",
      "iam:ListAttachedUserPolicies",
      "iam:GetCredentialReport",
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
Assign the **Reader** built-in role on the subscription.

### GCP
Assign the **Viewer** (`roles/viewer`) role on the project.

---

## Adding New Policies

1. Create or edit a `.yml` file under `policies/<cloud>/`
2. Follow the Cloud Custodian schema for that resource type
3. Add `violation_desc`, `action_desc`, and `severity` under the `notify` action — the reporter uses these fields
4. Run `python runner/run.py --dry-run` to validate before pushing

---

## Extending

- **Add remediation**: Replace `notify` actions with `mark-for-op` or resource-specific actions (e.g. `s3-set-block-public-access`)
- **Add more clouds**: Cloud Custodian supports Tencent, Alibaba, and OpenStack — add a `policies/<cloud>/` directory and update `runner/run.py`
- **Export to SIEM**: Modify `reporter.py` to ship findings to Splunk HEC, AWS Security Hub, or Azure Sentinel

---

## License

MIT
