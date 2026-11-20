"""
Configuration loader and security policy settings for Sentinel ID.

Enforces safe defaults:
- Demo mode by default (no live cloud calls unless explicitly requested)
- Read-only mode by default (remediation disabled unless explicitly toggled)
- Personal test tenant guardrails in Live Mode
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# Least-privilege Read-Only Microsoft Graph application permissions
READ_ONLY_GRAPH_PERMISSIONS: List[str] = [
    "User.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.Directory",
    "IdentityRiskyUser.Read.All",  # Optional: requires Entra ID P2 license
]

# Separate write permissions required ONLY if optional approval-gated remediation is used
WRITE_GRAPH_PERMISSIONS_DOC: List[str] = [
    "User.ReadWrite.All (Disable stale user accounts / revoke sessions)",
    "RoleManagement.ReadWrite.Directory (Remove principals from privileged directory roles)",
    "GroupMember.ReadWrite.All (Remove disabled accounts from security/M365 groups)",
]


@dataclass
class SentinelConfig:
    """Runtime configuration for Sentinel ID."""

    mode: str = field(default_factory=lambda: os.getenv("SENTINEL_MODE", "demo").lower())
    stale_days_threshold: int = field(
        default_factory=lambda: int(os.getenv("SENTINEL_STALE_DAYS", "90"))
    )
    guest_stale_days_threshold: int = field(
        default_factory=lambda: int(os.getenv("SENTINEL_GUEST_STALE_DAYS", "60"))
    )
    max_global_admins: int = field(
        default_factory=lambda: int(os.getenv("SENTINEL_MAX_GLOBAL_ADMINS", "4"))
    )
    allow_remediation: bool = field(
        default_factory=lambda: os.getenv("SENTINEL_ALLOW_REMEDIATION", "false").lower()
        in ("true", "1", "yes")
    )
    redaction_salt: str = field(
        default_factory=lambda: os.getenv(
            "SENTINEL_REDACTION_SALT", "sentinel-id-default-salt-2026"
        )
    )

    # Gemini AI configuration (Current SDK: google-genai, model: gemini-4-hydrogen)
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    gemini_model: str = field(
        default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-4-hydrogen")
    )

    # Microsoft Entra ID Live Mode configuration (Personal test tenant ONLY)
    tenant_id: str = field(default_factory=lambda: os.getenv("ENTRA_TENANT_ID", ""))
    client_id: str = field(default_factory=lambda: os.getenv("ENTRA_CLIENT_ID", ""))
    client_secret: str = field(default_factory=lambda: os.getenv("ENTRA_CLIENT_SECRET", ""))
    tenant_domain: str = field(
        default_factory=lambda: os.getenv("ENTRA_TENANT_DOMAIN", "contosotest.onmicrosoft.com")
    )

    # Audit log & report directories
    audit_log_path: Path = field(
        default_factory=lambda: Path(os.getenv("SENTINEL_AUDIT_LOG", "logs/remediation_audit.log"))
    )

    def is_live_configured(self) -> bool:
        """Check whether valid-looking Entra ID credentials are provided for live mode."""
        placeholders = {
            "",
            "00000000-0000-0000-0000-000000000000",
            "your-client-secret-value-here",
        }
        return (
            self.tenant_id not in placeholders
            and self.client_id not in placeholders
            and self.client_secret not in placeholders
        )

    def has_gemini_key(self) -> bool:
        """Check whether a Gemini API key is configured."""
        return bool(self.gemini_api_key and self.gemini_api_key.strip())
