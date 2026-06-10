"""
cloud-sentinel Azure collector
Fetches resources from Azure using azure-sdk-for-python.
Authenticates via DefaultAzureCredential (env vars, managed identity, CLI).
"""

from __future__ import annotations
import logging
import os

log = logging.getLogger("cloud-sentinel.collectors.azure")


def _credential():
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential()


def _subscription_id() -> str:
    sub = os.getenv("AZURE_SUBSCRIPTION_ID", "")
    if not sub:
        raise EnvironmentError("AZURE_SUBSCRIPTION_ID environment variable not set")
    return sub


def _tags_to_dict(tags) -> dict:
    if not tags:
        return {}
    return dict(tags)


# ── Storage Accounts ──────────────────────────────────────────────────────────

def list_storage_accounts(subscription_id: str | None = None) -> list[dict]:
    from azure.mgmt.storage import StorageManagementClient

    sub  = subscription_id or _subscription_id()
    cred = _credential()

    try:
        client = StorageManagementClient(cred, sub)
        accounts = list(client.storage_accounts.list())
    except Exception as e:
        log.error(f"Azure storage_accounts.list failed: {e}")
        return []

    resources = []
    for a in accounts:
        props = a.properties or {}
        rg    = a.id.split("/")[4] if a.id else "unknown"

        resources.append({
            "id":                    a.id or "",
            "name":                  a.name or "",
            "region":                a.location or "unknown",
            "account":               sub,
            "resource_group":        rg,
            "tags":                  _tags_to_dict(a.tags),
            "kind":                  str(a.kind) if a.kind else "",
            "sku":                   str(a.sku.name) if a.sku else "",
            "allow_blob_public_access": getattr(props, "allow_blob_public_access", True),
            "https_only":            getattr(props, "enable_https_traffic_only", False),
            "blob_encrypted":        _get_nested(props, "encryption.services.blob.enabled", False),
            "file_encrypted":        _get_nested(props, "encryption.services.file.enabled", False),
            "tls_version":           str(getattr(props, "minimum_tls_version", "TLS1_0") or "TLS1_0"),
            "public_network_access": str(getattr(props, "public_network_access", "Enabled") or "Enabled"),
            "provisioning_state":    str(getattr(props, "provisioning_state", "") or ""),
        })

    log.info(f"Azure: fetched {len(resources)} storage account(s)")
    return resources


# ── Network Security Groups ───────────────────────────────────────────────────

def list_nsgs(subscription_id: str | None = None) -> list[dict]:
    from azure.mgmt.network import NetworkManagementClient

    sub  = subscription_id or _subscription_id()
    cred = _credential()

    try:
        client = NetworkManagementClient(cred, sub)
        nsgs   = list(client.network_security_groups.list_all())
    except Exception as e:
        log.error(f"Azure NSG list_all failed: {e}")
        return []

    resources = []
    for nsg in nsgs:
        rg    = nsg.id.split("/")[4] if nsg.id else "unknown"
        rules = nsg.security_rules or []

        # Pre-compute dangerous flags
        any_any_inbound  = _has_any_any_inbound(rules)
        open_ssh_inbound = _has_open_port_inbound(rules, 22)
        open_rdp_inbound = _has_open_port_inbound(rules, 3389)

        serialized_rules = []
        for r in rules:
            serialized_rules.append({
                "name":                       r.name,
                "direction":                  str(r.direction),
                "access":                     str(r.access),
                "priority":                   r.priority,
                "protocol":                   r.protocol,
                "source_port_range":          r.source_port_range,
                "destination_port_range":     r.destination_port_range,
                "source_address_prefix":      r.source_address_prefix,
                "destination_address_prefix": r.destination_address_prefix,
            })

        resources.append({
            "id":               nsg.id or "",
            "name":             nsg.name or "",
            "region":           nsg.location or "unknown",
            "account":          sub,
            "resource_group":   rg,
            "tags":             _tags_to_dict(nsg.tags),
            "rules":            serialized_rules,
            "any_any_inbound":  any_any_inbound,
            "open_ssh":         open_ssh_inbound,
            "open_rdp":         open_rdp_inbound,
        })

    log.info(f"Azure: fetched {len(resources)} NSG(s)")
    return resources


def _has_any_any_inbound(rules) -> bool:
    for r in rules:
        if (str(r.direction) == "Inbound" and
                str(r.access) == "Allow" and
                r.source_address_prefix == "*" and
                r.destination_port_range == "*"):
            return True
    return False


def _has_open_port_inbound(rules, port: int) -> bool:
    for r in rules:
        if str(r.direction) != "Inbound" or str(r.access) != "Allow":
            continue
        src = r.source_address_prefix or ""
        if src not in ("*", "Internet", "0.0.0.0/0"):
            continue
        dst_port = r.destination_port_range or ""
        if dst_port == "*" or dst_port == str(port):
            return True
        if "-" in str(dst_port):
            try:
                lo, hi = dst_port.split("-")
                if int(lo) <= port <= int(hi):
                    return True
            except Exception:
                pass
    return False


# ── SQL Servers ───────────────────────────────────────────────────────────────

def list_sql_servers(subscription_id: str | None = None) -> list[dict]:
    from azure.mgmt.sql import SqlManagementClient

    sub  = subscription_id or _subscription_id()
    cred = _credential()

    try:
        client  = SqlManagementClient(cred, sub)
        servers = list(client.servers.list())
    except Exception as e:
        log.error(f"Azure SQL servers.list failed: {e}")
        return []

    resources = []
    for s in servers:
        rg    = s.id.split("/")[4] if s.id else "unknown"
        props = s.additional_properties or {}

        resources.append({
            "id":                    s.id or "",
            "name":                  s.name or "",
            "region":                s.location or "unknown",
            "account":               sub,
            "resource_group":        rg,
            "tags":                  _tags_to_dict(s.tags),
            "fqdn":                  getattr(s, "fully_qualified_domain_name", ""),
            "state":                 getattr(s, "state", ""),
            "admin_login":           getattr(s, "administrator_login", ""),
            "public_network_access": str(getattr(s, "public_network_access", "Enabled") or "Enabled"),
            "tls_version":           str(getattr(s, "minimal_tls_version", "None") or "None"),
        })

    log.info(f"Azure: fetched {len(resources)} SQL server(s)")
    return resources


# ── Key Vaults ────────────────────────────────────────────────────────────────

def list_key_vaults(subscription_id: str | None = None) -> list[dict]:
    from azure.mgmt.keyvault import KeyVaultManagementClient

    sub  = subscription_id or _subscription_id()
    cred = _credential()

    try:
        client = KeyVaultManagementClient(cred, sub)
        vaults = list(client.vaults.list())
    except Exception as e:
        log.error(f"Azure keyvaults.list failed: {e}")
        return []

    resources = []
    for v in vaults:
        # list() returns VaultListResult which needs get() for full props
        rg    = v.id.split("/")[4] if v.id else "unknown"

        # Fetch full vault details for properties
        props = {}
        try:
            full  = client.vaults.get(rg, v.name)
            props = full.properties or {}
        except Exception:
            pass

        resources.append({
            "id":               v.id or "",
            "name":             v.name or "",
            "region":           v.location or "unknown",
            "account":          sub,
            "resource_group":   rg,
            "tags":             _tags_to_dict(getattr(v, "tags", {})),
            "soft_delete_enabled":     getattr(props, "enable_soft_delete", False),
            "purge_protection_enabled": getattr(props, "enable_purge_protection", False),
            "sku":              str(getattr(getattr(props, "sku", None), "name", "")) if props else "",
            "vault_uri":        getattr(props, "vault_uri", ""),
        })

    log.info(f"Azure: fetched {len(resources)} key vault(s)")
    return resources


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_nested(obj, path: str, default=None):
    """Safely traverse a dotted attribute path on an Azure SDK object."""
    parts   = path.split(".")
    current = obj
    for part in parts:
        if current is None:
            return default
        current = getattr(current, part, None)
    return current if current is not None else default


# ── Collector registry helper ─────────────────────────────────────────────────

def register_all(engine, subscription_id: str | None = None):
    """Register all Azure collectors with the policy engine."""
    from functools import partial
    sub = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")

    engine.register_collector("azure", "storage_account",        partial(list_storage_accounts,  subscription_id=sub))
    engine.register_collector("azure", "network_security_group", partial(list_nsgs,               subscription_id=sub))
    engine.register_collector("azure", "sql_server",             partial(list_sql_servers,        subscription_id=sub))
    engine.register_collector("azure", "key_vault",              partial(list_key_vaults,         subscription_id=sub))
