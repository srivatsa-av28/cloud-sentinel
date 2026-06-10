"""
cloud-sentinel AWS collector
Fetches resources from AWS using boto3.
Each function returns a list of normalised resource dicts.
"""

from __future__ import annotations
import logging
from typing import Any

log = logging.getLogger("cloud-sentinel.collectors.aws")


def _client(service: str, region: str, session=None):
    import boto3
    if session:
        return session.client(service, region_name=region)
    return boto3.client(service, region_name=region)


def _resource(service: str, region: str, session=None):
    import boto3
    if session:
        return session.resource(service, region_name=region)
    return boto3.resource(service, region_name=region)


def _account_id(session=None) -> str:
    try:
        import boto3
        sts = session.client("sts") if session else boto3.client("sts")
        return sts.get_caller_identity()["Account"]
    except Exception:
        return "unknown"


def _tags_to_dict(tag_list: list) -> dict:
    """Convert AWS [{Key: ..., Value: ...}] tag list to a flat dict."""
    if not tag_list:
        return {}
    return {t.get("Key", ""): t.get("Value", "") for t in tag_list}


# ── S3 ────────────────────────────────────────────────────────────────────────

def list_s3_buckets(session=None) -> list[dict]:
    import boto3
    s3 = session.client("s3") if session else boto3.client("s3")
    account = _account_id(session)

    try:
        response = s3.list_buckets()
        buckets  = response.get("Buckets", [])
    except Exception as e:
        log.error(f"S3 list_buckets failed: {e}")
        return []

    resources = []
    for b in buckets:
        name   = b["Name"]
        region = "us-east-1"

        # Get bucket region
        try:
            loc = s3.get_bucket_location(Bucket=name)
            region = loc.get("LocationConstraint") or "us-east-1"
        except Exception:
            pass

        # Public access block
        pab = {}
        try:
            r = s3.get_public_access_block(Bucket=name)
            pab = r.get("PublicAccessBlockConfiguration", {})
        except Exception:
            pass

        # Encryption
        encryption = {}
        try:
            r = s3.get_bucket_encryption(Bucket=name)
            encryption = r.get("ServerSideEncryptionConfiguration", {})
        except Exception:
            pass

        # Logging
        logging_cfg = {}
        try:
            r = s3.get_bucket_logging(Bucket=name)
            logging_cfg = r.get("LoggingEnabled", {})
        except Exception:
            pass

        # Versioning
        versioning = {}
        try:
            r = s3.get_bucket_versioning(Bucket=name)
            versioning = {"Status": r.get("Status", "Disabled")}
        except Exception:
            pass

        # Tags
        tags = {}
        try:
            r = s3.get_bucket_tagging(Bucket=name)
            tags = _tags_to_dict(r.get("TagSet", []))
        except Exception:
            pass

        resources.append({
            "id":             name,
            "name":           name,
            "region":         region,
            "account":        account,
            "tags":           tags,
            "public_access_block": pab,
            "encryption":     encryption,
            "logging":        logging_cfg,
            "versioning":     versioning,
            # Convenience boolean fields for simple filter rules
            "block_public_acls":       pab.get("BlockPublicAcls", False),
            "ignore_public_acls":      pab.get("IgnorePublicAcls", False),
            "block_public_policy":     pab.get("BlockPublicPolicy", False),
            "restrict_public_buckets": pab.get("RestrictPublicBuckets", False),
            "encrypted":               bool(encryption.get("Rules")),
            "logging_enabled":         bool(logging_cfg),
        })

    log.info(f"S3: fetched {len(resources)} bucket(s)")
    return resources


# ── IAM ───────────────────────────────────────────────────────────────────────

def list_iam_users(session=None) -> list[dict]:
    import boto3
    iam = session.client("iam") if session else boto3.client("iam")
    account = _account_id(session)

    try:
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
    except Exception as e:
        log.error(f"IAM list_users failed: {e}")
        return []

    resources = []
    for u in users:
        username = u["UserName"]

        # MFA devices
        mfa_devices = []
        try:
            r = iam.list_mfa_devices(UserName=username)
            mfa_devices = r.get("MFADevices", [])
        except Exception:
            pass

        # Login profile (console access)
        has_console = False
        try:
            iam.get_login_profile(UserName=username)
            has_console = True
        except iam.exceptions.NoSuchEntityException:
            pass
        except Exception:
            pass

        # Attached policies
        attached_policies = []
        try:
            r = iam.list_attached_user_policies(UserName=username)
            attached_policies = [p["PolicyArn"] for p in r.get("AttachedPolicies", [])]
        except Exception:
            pass

        # Access keys
        access_keys = []
        try:
            r = iam.list_access_keys(UserName=username)
            for k in r.get("AccessKeyMetadata", []):
                if k.get("Status") == "Active":
                    from datetime import datetime, timezone
                    created = k.get("CreateDate")
                    age_days = None
                    if created:
                        age_days = (datetime.now(timezone.utc) - created).days
                    access_keys.append({
                        "id":       k["AccessKeyId"],
                        "status":   k["Status"],
                        "created":  str(created),
                        "age_days": age_days,
                    })
        except Exception:
            pass

        # Tags
        tags = {}
        try:
            r = iam.list_user_tags(UserName=username)
            tags = _tags_to_dict(r.get("Tags", []))
        except Exception:
            pass

        # Max key age (for rotation check)
        max_key_age = max((k["age_days"] for k in access_keys if k["age_days"]), default=None)

        resources.append({
            "id":                 username,
            "name":               username,
            "arn":                u.get("Arn", ""),
            "region":             "global",
            "account":            account,
            "tags":               tags,
            "has_console_access": has_console,
            "mfa_enabled":        len(mfa_devices) > 0,
            "mfa_devices":        mfa_devices,
            "attached_policies":  attached_policies,
            "has_admin_policy":   "arn:aws:iam::aws:policy/AdministratorAccess" in attached_policies,
            "access_keys":        access_keys,
            "active_key_count":   len(access_keys),
            "max_key_age_days":   max_key_age,
            "key_rotation_needed": max_key_age is not None and max_key_age > 90,
        })

    log.info(f"IAM: fetched {len(resources)} user(s)")
    return resources


def list_iam_account(session=None) -> list[dict]:
    """Returns a single-element list representing the AWS account root config."""
    import boto3
    iam     = session.client("iam") if session else boto3.client("iam")
    account = _account_id(session)

    summary = {}
    try:
        r = iam.get_account_summary()
        summary = r.get("SummaryMap", {})
    except Exception as e:
        log.error(f"IAM get_account_summary failed: {e}")

    return [{
        "id":                  account,
        "name":                f"account-{account}",
        "region":              "global",
        "account":             account,
        "tags":                {},
        "root_mfa_enabled":    summary.get("AccountMFAEnabled", 0) == 1,
        "root_has_access_key": summary.get("AccountAccessKeysPresent", 0) > 0,
        "users_no_mfa":        summary.get("AccountSigningCertificatesPresent", 0),
        "summary":             summary,
    }]


# ── Security Groups ───────────────────────────────────────────────────────────

def list_security_groups(region: str = "ap-south-1", session=None) -> list[dict]:
    account = _account_id(session)
    ec2     = _client("ec2", region, session)

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        sgs = []
        for page in paginator.paginate():
            sgs.extend(page.get("SecurityGroups", []))
    except Exception as e:
        log.error(f"EC2 describe_security_groups failed [{region}]: {e}")
        return []

    resources = []
    for sg in sgs:
        ingress = sg.get("IpPermissions", [])
        egress  = sg.get("IpPermissionsEgress", [])

        # Pre-compute dangerous flags
        open_ssh  = _has_open_port(ingress, 22)
        open_rdp  = _has_open_port(ingress, 3389)
        open_all  = _has_open_all(ingress)

        resources.append({
            "id":          sg["GroupId"],
            "name":        sg.get("GroupName", ""),
            "region":      region,
            "account":     account,
            "tags":        _tags_to_dict(sg.get("Tags", [])),
            "description": sg.get("Description", ""),
            "vpc_id":      sg.get("VpcId", ""),
            "ingress":     ingress,
            "egress":      egress,
            "open_ssh":    open_ssh,
            "open_rdp":    open_rdp,
            "open_all_ports": open_all,
        })

    log.info(f"Security Groups [{region}]: fetched {len(resources)}")
    return resources


def _has_open_port(rules: list, port: int) -> bool:
    for rule in rules:
        from_p = rule.get("FromPort", 0)
        to_p   = rule.get("ToPort", 65535)
        if rule.get("IpProtocol") not in ("tcp", "-1"):
            continue
        if not (from_p <= port <= to_p or rule.get("IpProtocol") == "-1"):
            continue
        for cidr in rule.get("IpRanges", []):
            if cidr.get("CidrIp") in ("0.0.0.0/0",):
                return True
        for cidr in rule.get("Ipv6Ranges", []):
            if cidr.get("CidrIpv6") == "::/0":
                return True
    return False


def _has_open_all(rules: list) -> bool:
    for rule in rules:
        if rule.get("IpProtocol") == "-1":
            for cidr in rule.get("IpRanges", []):
                if cidr.get("CidrIp") == "0.0.0.0/0":
                    return True
    return False


# ── EC2 ───────────────────────────────────────────────────────────────────────

def list_ec2_instances(region: str = "ap-south-1", session=None) -> list[dict]:
    account = _account_id(session)
    ec2     = _client("ec2", region, session)

    try:
        paginator = ec2.get_paginator("describe_instances")
        instances = []
        for page in paginator.paginate():
            for r in page.get("Reservations", []):
                instances.extend(r.get("Instances", []))
    except Exception as e:
        log.error(f"EC2 describe_instances failed [{region}]: {e}")
        return []

    # Filter running/stopped only
    instances = [i for i in instances if i.get("State", {}).get("Name") in ("running", "stopped")]

    resources = []
    for i in instances:
        imds   = i.get("MetadataOptions", {})
        resources.append({
            "id":              i["InstanceId"],
            "name":            _tag_value(i.get("Tags", []), "Name") or i["InstanceId"],
            "region":          region,
            "account":         account,
            "tags":            _tags_to_dict(i.get("Tags", [])),
            "state":           i.get("State", {}).get("Name"),
            "instance_type":   i.get("InstanceType", ""),
            "public_ip":       i.get("PublicIpAddress"),
            "private_ip":      i.get("PrivateIpAddress"),
            "imdsv2_required": imds.get("HttpTokens") == "required",
            "imds_endpoint":   imds.get("HttpEndpoint", "enabled"),
            "vpc_id":          i.get("VpcId", ""),
            "subnet_id":       i.get("SubnetId", ""),
            "security_groups": [sg["GroupId"] for sg in i.get("SecurityGroups", [])],
            "iam_profile":     i.get("IamInstanceProfile", {}).get("Arn", ""),
        })

    log.info(f"EC2 instances [{region}]: fetched {len(resources)}")
    return resources


def _tag_value(tags: list, key: str) -> str | None:
    for t in tags:
        if t.get("Key") == key:
            return t.get("Value")
    return None


# ── EBS ───────────────────────────────────────────────────────────────────────

def list_ebs_volumes(region: str = "ap-south-1", session=None) -> list[dict]:
    account = _account_id(session)
    ec2     = _client("ec2", region, session)

    try:
        paginator = ec2.get_paginator("describe_volumes")
        volumes = []
        for page in paginator.paginate():
            volumes.extend(page.get("Volumes", []))
    except Exception as e:
        log.error(f"EBS describe_volumes failed [{region}]: {e}")
        return []

    resources = []
    for v in volumes:
        resources.append({
            "id":          v["VolumeId"],
            "name":        _tag_value(v.get("Tags", []), "Name") or v["VolumeId"],
            "region":      region,
            "account":     account,
            "tags":        _tags_to_dict(v.get("Tags", [])),
            "state":       v.get("State"),
            "size_gb":     v.get("Size"),
            "encrypted":   v.get("Encrypted", False),
            "kms_key_id":  v.get("KmsKeyId", ""),
            "volume_type": v.get("VolumeType", ""),
            "attachments": v.get("Attachments", []),
        })

    log.info(f"EBS volumes [{region}]: fetched {len(resources)}")
    return resources


# ── RDS ───────────────────────────────────────────────────────────────────────

def list_rds_instances(region: str = "ap-south-1", session=None) -> list[dict]:
    account = _account_id(session)
    rds     = _client("rds", region, session)

    try:
        paginator = rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
    except Exception as e:
        log.error(f"RDS describe_db_instances failed [{region}]: {e}")
        return []

    resources = []
    for db in instances:
        resources.append({
            "id":                 db["DBInstanceIdentifier"],
            "name":               db["DBInstanceIdentifier"],
            "region":             region,
            "account":            account,
            "tags":               _tags_to_dict(db.get("TagList", [])),
            "engine":             db.get("Engine", ""),
            "engine_version":     db.get("EngineVersion", ""),
            "instance_class":     db.get("DBInstanceClass", ""),
            "status":             db.get("DBInstanceStatus", ""),
            "publicly_accessible": db.get("PubliclyAccessible", False),
            "storage_encrypted":  db.get("StorageEncrypted", False),
            "multi_az":           db.get("MultiAZ", False),
            "backup_retention":   db.get("BackupRetentionPeriod", 0),
            "deletion_protection": db.get("DeletionProtection", False),
            "endpoint":           db.get("Endpoint", {}).get("Address", ""),
        })

    log.info(f"RDS instances [{region}]: fetched {len(resources)}")
    return resources


# ── Collector registry helper ─────────────────────────────────────────────────

def register_all(engine, region: str = "ap-south-1", session=None):
    """Register all AWS collectors with the policy engine."""
    from functools import partial

    engine.register_collector("aws", "s3_bucket",      partial(list_s3_buckets,      session=session))
    engine.register_collector("aws", "iam_user",       partial(list_iam_users,        session=session))
    engine.register_collector("aws", "iam_account",    partial(list_iam_account,      session=session))
    engine.register_collector("aws", "security_group", partial(list_security_groups,  region=region, session=session))
    engine.register_collector("aws", "ec2_instance",   partial(list_ec2_instances,    region=region, session=session))
    engine.register_collector("aws", "ebs_volume",     partial(list_ebs_volumes,      region=region, session=session))
    engine.register_collector("aws", "rds_instance",   partial(list_rds_instances,    region=region, session=session))
