cloud-sentinel/
├── policies/
│   ├── aws/          # S3, IAM, EC2, SG rules
│   ├── azure/        # NSG, storage, RBAC rules
│   └── gcp/          # GCS, IAM, firewall rules
├── runner/
│   ├── run.py        # orchestrates c7n across all clouds
│   └── reporter.py   # aggregates findings → HTML + Slack
├── reports/          # output dir (gitignored)
├── .github/
│   └── workflows/
│       └── cspm.yml  # scheduled + on-push pipeline
├── requirements.txt
└── README.md
