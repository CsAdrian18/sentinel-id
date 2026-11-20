"""
Domain models for Sentinel ID tenant snapshots, security findings,
remediation actions, and audit reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Severity levels for identity security findings."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class CheckCategory(str, Enum):
    """The 7 core Entra ID audit check categories."""

    MFA_COVERAGE = "1. Users Without MFA Registered"
    STALE_ACCOUNTS = "2. Stale Accounts (Inactive 90+ Days)"
    PRIVILEGED_ROLES = "3. Privileged Directory Roles & Excess Admins"
    RISKY_SIGNINS_USERS = "4. Risky Sign-Ins & Risky Users (Identity Protection)"
    GUEST_ACCOUNTS = "5. Old or Inactive Guest Accounts"
    CONDITIONAL_ACCESS = "6. Conditional Access Policy Gaps"
    DISABLED_ACCOUNT_HYGIENE = "7. Disabled Accounts with Licenses or Group Memberships"


class RemediationActionType(str, Enum):
    """Supported optional human-approved remediation action types."""

    DISABLE_STALE_ACCOUNT = "disable_stale_account"
    REVOKE_SESSIONS = "revoke_sessions"
    REMOVE_FROM_ROLE = "remove_from_role"


@dataclass
class EntraUser:
    """Representation of a Microsoft Entra ID user principal."""

    id: str
    display_name: str
    user_principal_name: str
    mail: str
    user_type: str  # "Member" or "Guest"
    account_enabled: bool
    created_date_time: str
    last_sign_in_date_time: Optional[str]
    mfa_registered: bool
    mfa_methods: List[str] = field(default_factory=list)
    assigned_roles: List[str] = field(default_factory=list)
    assigned_licenses: List[str] = field(default_factory=list)
    group_memberships: List[str] = field(default_factory=list)
    department: str = "General"
    job_title: str = "Staff"
    last_sign_in_ip: Optional[str] = None


@dataclass
class DirectoryRoleAssignment:
    """Representation of an active Entra ID directory role and its members."""

    role_id: str
    role_template_id: str
    display_name: str
    description: str
    is_privileged: bool
    member_user_ids: List[str] = field(default_factory=list)


@dataclass
class RiskyUserRecord:
    """Representation of an Entra ID Identity Protection risky user."""

    user_id: str
    user_principal_name: str
    display_name: str
    risk_level: str  # "high", "medium", "low"
    risk_state: str  # "atRisk", "confirmedCompromised"
    risk_detail: str
    last_updated_date_time: str


@dataclass
class RiskySignInRecord:
    """Representation of an Entra ID risky sign-in event."""

    id: str
    user_id: str
    user_principal_name: str
    app_display_name: str
    ip_address: str
    location: str
    risk_level: str  # "high", "medium", "low"
    risk_Event_types: List[str]
    created_date_time: str


@dataclass
class ConditionalAccessPolicy:
    """Representation of an Entra ID Conditional Access policy (read-only review)."""

    id: str
    display_name: str
    state: str  # "enabled", "disabled", "enabledForReportingButNotEnforced"
    include_users: List[str] = field(default_factory=list)
    include_roles: List[str] = field(default_factory=list)
    exclude_users: List[str] = field(default_factory=list)
    client_app_types: List[str] = field(default_factory=list)
    grant_controls: List[str] = field(default_factory=list)  # e.g. ["mfa"], ["block"]
    session_controls: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TenantSnapshot:
    """Complete read-only point-in-time snapshot of an Entra ID tenant."""

    tenant_id: str
    tenant_name: str
    tenant_domain: str
    mode: str  # "demo" or "live"
    captured_at: str
    supports_identity_protection: bool = True
    identity_protection_status_note: str = "Entra ID P2 / Identity Protection available."
    users: List[EntraUser] = field(default_factory=list)
    roles: List[DirectoryRoleAssignment] = field(default_factory=list)
    risky_users: List[RiskyUserRecord] = field(default_factory=list)
    risky_sign_ins: List[RiskySignInRecord] = field(default_factory=list)
    conditional_access_policies: List[ConditionalAccessPolicy] = field(default_factory=list)


@dataclass
class RemediationProposal:
    """A proposed remediation action that defaults to dry-run and requires human approval."""

    action_id: str
    action_type: RemediationActionType
    finding_id: str
    target_user_id: str
    target_upn: str
    target_display_name: str
    summary: str
    http_method: str
    graph_endpoint: str
    request_body: Dict[str, Any]
    pre_state: Dict[str, Any]
    post_state: Dict[str, Any]
    required_write_permission: str
    role_id: Optional[str] = None
    role_name: Optional[str] = None


@dataclass
class AuditFinding:
    """A single security finding produced by an audit check."""

    finding_id: str
    category: CheckCategory
    title: str
    severity: Severity
    description: str
    impact: str
    recommendation: str
    affected_resource_id: str
    affected_upn: Optional[str] = None
    affected_display_name: Optional[str] = None
    affected_ip: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[RemediationProposal] = None


@dataclass
class AuditReport:
    """Aggregated audit report across all 7 checks."""

    tenant_id: str
    tenant_name: str
    tenant_domain: str
    mode: str
    generated_at: str
    stale_days_threshold: int
    overall_risk_score: int  # 0 (best) to 100 (highest risk)
    security_posture_grade: str  # A, B, C, D, F
    supports_identity_protection: bool
    identity_protection_note: str
    findings: List[AuditFinding] = field(default_factory=list)
    skipped_checks: List[str] = field(default_factory=list)
    ai_executive_summary: str = ""
    ai_model_used: str = ""
    redacted_payload_preview: Dict[str, Any] = field(default_factory=dict)

    @property
    def high_findings(self) -> List[AuditFinding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium_findings(self) -> List[AuditFinding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low_findings(self) -> List[AuditFinding]:
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def remediation_proposals(self) -> List[RemediationProposal]:
        return [f.remediation for f in self.findings if f.remediation is not None]
