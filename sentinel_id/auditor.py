"""
Identity Security Auditor Engine for Sentinel ID.

Implements the 7 core Entra ID security checks:
1. Users without MFA registered
2. Stale accounts (no sign-in for 90+ days, configurable)
3. Accounts with privileged directory roles (Global Admin, etc.) and too many admins
4. Risky sign-ins / risky users (skips gracefully if tenant license does not support it)
5. Guest accounts that are old or inactive
6. Conditional Access gaps (e.g., no policy requiring MFA for admins, legacy auth not blocked)
7. Disabled accounts that still hold licenses or group memberships
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sentinel_id.config import SentinelConfig
from sentinel_id.models import (
    AuditFinding,
    AuditReport,
    CheckCategory,
    EntraUser,
    RemediationActionType,
    RemediationProposal,
    Severity,
    TenantSnapshot,
)

PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Authentication Administrator",
    "Privileged Authentication Administrator",
    "Conditional Access Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
}


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 UTC timestamp into a timezone-aware datetime."""
    if not ts:
        return None
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _days_between(reference: datetime, target_iso: Optional[str]) -> Optional[int]:
    """Return whole days elapsed between target_iso and reference datetime."""
    dt = _parse_iso(target_iso)
    if dt is None:
        return None
    return max(0, (reference - dt).days)


class EntraAuditor:
    """Executes all 7 identity security audit checks against a TenantSnapshot."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        reference_now: Optional[datetime] = None,
    ) -> None:
        self.config = config or SentinelConfig()
        self.reference_now = reference_now

    def _get_now(self, snapshot: TenantSnapshot) -> datetime:
        if self.reference_now:
            return self.reference_now
        parsed = _parse_iso(snapshot.captured_at)
        return parsed or datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # Check 1: Users without MFA registered
    # -------------------------------------------------------------------------
    def check_users_without_mfa(self, snapshot: TenantSnapshot) -> List[AuditFinding]:
        """Flag active accounts lacking multi-factor authentication registration."""
        findings: List[AuditFinding] = []
        idx = 1

        for user in snapshot.users:
            if not user.account_enabled:
                continue
            if user.mfa_registered:
                continue

            has_priv_role = any(r in PRIVILEGED_ROLES for r in user.assigned_roles)
            if has_priv_role:
                severity = Severity.HIGH
                role_label = ", ".join(user.assigned_roles)
                title = f"Privileged administrator without MFA registered ({role_label})"
                impact = (
                    "Single-factor compromise of this privileged account allows full tenant "
                    "takeover, directory manipulation, or data exfiltration."
                )
            elif user.user_type == "Guest":
                severity = Severity.MEDIUM
                title = "Active external guest account without MFA registered"
                impact = (
                    "External partner credentials compromised via phishing or credential stuffing "
                    "can access shared internal resources without a second factor challenge."
                )
            else:
                severity = Severity.HIGH
                title = "Active member user without MFA registered"
                impact = (
                    "Account is vulnerable to password spray, credential stuffing, and phishing "
                    "attacks against corporate Microsoft 365 / Entra ID applications."
                )

            finding_id = f"MFA-{idx:03d}"
            idx += 1

            remediation = RemediationProposal(
                action_id=f"REM-{finding_id}",
                action_type=RemediationActionType.REVOKE_SESSIONS,
                finding_id=finding_id,
                target_user_id=user.id,
                target_upn=user.user_principal_name,
                target_display_name=user.display_name,
                summary=(
                    f"Revoke active sign-in sessions and refresh tokens for {user.user_principal_name} "
                    "to force re-authentication under MFA registration policy."
                ),
                http_method="POST",
                graph_endpoint=f"/users/{user.id}/revokeSignInSessions",
                request_body={},
                pre_state={"activeRefreshTokens": "Valid", "mfaRegistered": False},
                post_state={"activeRefreshTokens": "Revoked (Forces re-auth)", "mfaRegistered": False},
                required_write_permission="User.ReadWrite.All",
            )

            findings.append(
                AuditFinding(
                    finding_id=finding_id,
                    category=CheckCategory.MFA_COVERAGE,
                    title=title,
                    severity=severity,
                    description=(
                        f"Account '{user.display_name}' ({user.user_principal_name}) in department "
                        f"'{user.department}' is active but has 0 MFA authentication methods registered."
                    ),
                    impact=impact,
                    recommendation=(
                        "Require immediate registration of phishing-resistant MFA (FIDO2 security key "
                        "or Microsoft Authenticator number matching) and revoke existing sessions."
                    ),
                    affected_resource_id=user.id,
                    affected_upn=user.user_principal_name,
                    affected_display_name=user.display_name,
                    affected_ip=user.last_sign_in_ip,
                    metadata={
                        "user_type": user.user_type,
                        "roles": user.assigned_roles,
                        "department": user.department,
                    },
                    remediation=remediation,
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Check 2: Stale accounts (no sign-in for 90+ days, configurable)
    # -------------------------------------------------------------------------
    def check_stale_accounts(self, snapshot: TenantSnapshot) -> List[AuditFinding]:
        """Flag enabled member accounts with no sign-in for >= stale_days_threshold."""
        findings: List[AuditFinding] = []
        now = self._get_now(snapshot)
        threshold = self.config.stale_days_threshold
        idx = 1

        for user in snapshot.users:
            if not user.account_enabled:
                continue
            if user.user_type == "Guest":
                # Guests are evaluated specifically in Check 5
                continue

            days_since_signin = _days_between(now, user.last_sign_in_date_time)
            days_since_created = _days_between(now, user.created_date_time) or 0

            is_stale = False
            stale_reason = ""
            inactive_days = 0

            if days_since_signin is not None and days_since_signin >= threshold:
                is_stale = True
                inactive_days = days_since_signin
                stale_reason = f"last signed in {days_since_signin} days ago (threshold: {threshold} days)"
            elif days_since_signin is None and days_since_created >= threshold:
                is_stale = True
                inactive_days = days_since_created
                stale_reason = (
                    f"created {days_since_created} days ago and has NEVER signed in "
                    f"(threshold: {threshold} days)"
                )

            if not is_stale:
                continue

            has_priv_role = any(r in PRIVILEGED_ROLES for r in user.assigned_roles)
            severity = Severity.HIGH if has_priv_role else Severity.MEDIUM
            finding_id = f"STALE-{idx:03d}"
            idx += 1

            remediation = RemediationProposal(
                action_id=f"REM-{finding_id}",
                action_type=RemediationActionType.DISABLE_STALE_ACCOUNT,
                finding_id=finding_id,
                target_user_id=user.id,
                target_upn=user.user_principal_name,
                target_display_name=user.display_name,
                summary=f"Disable stale account {user.user_principal_name} ({inactive_days} days inactive).",
                http_method="PATCH",
                graph_endpoint=f"/users/{user.id}",
                request_body={"accountEnabled": False},
                pre_state={"accountEnabled": True, "inactiveDays": inactive_days},
                post_state={"accountEnabled": False, "inactiveDays": inactive_days},
                required_write_permission="User.ReadWrite.All",
            )

            findings.append(
                AuditFinding(
                    finding_id=finding_id,
                    category=CheckCategory.STALE_ACCOUNTS,
                    title=(
                        f"Stale privileged account ({inactive_days} days inactive)"
                        if has_priv_role
                        else f"Stale active member account ({inactive_days} days inactive)"
                    ),
                    severity=severity,
                    description=(
                        f"Enabled account '{user.display_name}' ({user.user_principal_name}) "
                        f"{stale_reason}."
                    ),
                    impact=(
                        "Dormant accounts are prime targets for attackers because anomalous activity "
                        "often goes unnoticed by an active user owner."
                    ),
                    recommendation=(
                        "Disable the account immediately, verify employment/service status with HR "
                        "or the department owner, and remove any assigned roles or licenses."
                    ),
                    affected_resource_id=user.id,
                    affected_upn=user.user_principal_name,
                    affected_display_name=user.display_name,
                    affected_ip=user.last_sign_in_ip,
                    metadata={
                        "inactive_days": inactive_days,
                        "threshold_days": threshold,
                        "roles": user.assigned_roles,
                        "never_signed_in": days_since_signin is None,
                    },
                    remediation=remediation,
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Check 3: Accounts with privileged directory roles & too many admins
    # -------------------------------------------------------------------------
    def check_privileged_roles(self, snapshot: TenantSnapshot) -> List[AuditFinding]:
        """Audit Global Admin count, privileged role hygiene, and standing admin exposure."""
        findings: List[AuditFinding] = []
        now = self._get_now(snapshot)
        user_by_id: Dict[str, EntraUser] = {u.id: u for u in snapshot.users}
        idx = 1

        global_admin_role = next(
            (r for r in snapshot.roles if r.display_name == "Global Administrator"), None
        )
        ga_member_ids = list(global_admin_role.member_user_ids) if global_admin_role else []
        # Also include any user who has "Global Administrator" in assigned_roles
        for u in snapshot.users:
            if "Global Administrator" in u.assigned_roles and u.id not in ga_member_ids:
                ga_member_ids.append(u.id)

        max_ga = self.config.max_global_admins
        if len(ga_member_ids) > max_ga:
            finding_id = f"PRIV-{idx:03d}"
            idx += 1
            findings.append(
                AuditFinding(
                    finding_id=finding_id,
                    category=CheckCategory.PRIVILEGED_ROLES,
                    title=(
                        f"Excessive Global Administrators ({len(ga_member_ids)} assigned; "
                        f"recommended max is {max_ga})"
                    ),
                    severity=Severity.HIGH,
                    description=(
                        f"The tenant currently has {len(ga_member_ids)} accounts with permanent "
                        f"Global Administrator privileges, exceeding Microsoft's recommended best "
                        f"practice of 2 to {max_ga} Global Admins."
                    ),
                    impact=(
                        "Every Global Administrator holds unrestricted control over the entire cloud "
                        "estate. A large admin footprint drastically expands the blast radius of "
                        "credential compromise."
                    ),
                    recommendation=(
                        "Transition non-emergency Global Administrators to least-privilege specific "
                        "roles (e.g., Security Reader, Exchange Admin) or use Entra ID Privileged "
                        "Identity Management (PIM) for just-in-time elevation."
                    ),
                    affected_resource_id=global_admin_role.role_id if global_admin_role else "role-global-admin",
                    metadata={
                        "global_admin_count": len(ga_member_ids),
                        "recommended_max": max_ga,
                    },
                )
            )

        # Evaluate individual privileged role holders for hygiene risks
        for role in snapshot.roles:
            if not role.is_privileged:
                continue

            for uid in role.member_user_ids:
                user = user_by_id.get(uid)
                if not user:
                    continue

                days_inactive = _days_between(now, user.last_sign_in_date_time)
                is_stale_admin = (
                    days_inactive is not None and days_inactive >= self.config.stale_days_threshold
                ) or (days_inactive is None)
                is_weak_mfa = (not user.mfa_registered) or ("sms" in user.mfa_methods and len(user.mfa_methods) == 1)
                is_non_it_exec = "Chief Executive" in user.job_title or user.department == "Executive"

                if not (is_stale_admin or is_weak_mfa or is_non_it_exec):
                    continue

                reasons: List[str] = []
                if not user.mfa_registered:
                    reasons.append("has NO MFA registered")
                elif "sms" in user.mfa_methods and len(user.mfa_methods) == 1:
                    reasons.append("relies solely on SMS MFA (vulnerable to SIM swapping)")
                if is_stale_admin:
                    reasons.append(
                        f"has not signed in for {days_inactive} days"
                        if days_inactive is not None
                        else "has never signed in"
                    )
                if is_non_it_exec:
                    reasons.append(
                        f"holds an executive business role ('{user.job_title}') that does not "
                        "require standing directory admin rights"
                    )

                finding_id = f"PRIV-{idx:03d}"
                idx += 1

                remediation = RemediationProposal(
                    action_id=f"REM-{finding_id}",
                    action_type=RemediationActionType.REMOVE_FROM_ROLE,
                    finding_id=finding_id,
                    target_user_id=user.id,
                    target_upn=user.user_principal_name,
                    target_display_name=user.display_name,
                    summary=(
                        f"Remove {user.user_principal_name} from privileged role "
                        f"'{role.display_name}'."
                    ),
                    http_method="DELETE",
                    graph_endpoint=f"/directoryRoles/{role.role_id}/members/{user.id}/$ref",
                    request_body={},
                    pre_state={"role": role.display_name, "assignment": "Permanent Active"},
                    post_state={"role": role.display_name, "assignment": "Removed"},
                    required_write_permission="RoleManagement.ReadWrite.Directory",
                    role_id=role.role_id,
                    role_name=role.display_name,
                )

                findings.append(
                    AuditFinding(
                        finding_id=finding_id,
                        category=CheckCategory.PRIVILEGED_ROLES,
                        title=f"High-risk standing assignment in '{role.display_name}'",
                        severity=Severity.HIGH if role.display_name == "Global Administrator" else Severity.MEDIUM,
                        description=(
                            f"Account '{user.display_name}' ({user.user_principal_name}) holds permanent "
                            f"'{role.display_name}' privileges and {'; '.join(reasons)}."
                        ),
                        impact=(
                            "Standing privileged assignments with weak authentication, inactivity, or "
                            "non-administrative business usage violate least privilege."
                        ),
                        recommendation=(
                            f"Remove standing '{role.display_name}' membership from this account and "
                            "enforce phishing-resistant MFA for all remaining administrators."
                        ),
                        affected_resource_id=user.id,
                        affected_upn=user.user_principal_name,
                        affected_display_name=user.display_name,
                        affected_ip=user.last_sign_in_ip,
                        metadata={
                            "role_id": role.role_id,
                            "role_name": role.display_name,
                            "reasons": reasons,
                        },
                        remediation=remediation,
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Check 4: Risky sign-ins / risky users (Entra ID P2; skip gracefully if not)
    # -------------------------------------------------------------------------
    def check_risky_users_and_signins(
        self, snapshot: TenantSnapshot
    ) -> Tuple[List[AuditFinding], Optional[str]]:
        """
        Inspect Entra ID Identity Protection risky users and risky sign-ins.
        If the tenant license does not support it, return 0 findings and a skip note.
        """
        if not snapshot.supports_identity_protection:
            skip_msg = (
                "Check 4 (Risky Sign-Ins / Risky Users) skipped gracefully: "
                f"{snapshot.identity_protection_status_note}"
            )
            return [], skip_msg

        findings: List[AuditFinding] = []
        idx = 1

        for ru in snapshot.risky_users:
            sev = (
                Severity.HIGH
                if ru.risk_level.lower() == "high" or ru.risk_state == "confirmedCompromised"
                else Severity.MEDIUM
                if ru.risk_level.lower() == "medium"
                else Severity.LOW
            )
            finding_id = f"RISK-{idx:03d}"
            idx += 1

            remediation = RemediationProposal(
                action_id=f"REM-{finding_id}",
                action_type=RemediationActionType.REVOKE_SESSIONS,
                finding_id=finding_id,
                target_user_id=ru.user_id,
                target_upn=ru.user_principal_name,
                target_display_name=ru.display_name,
                summary=(
                    f"Revoke all active sessions for risky user {ru.user_principal_name} "
                    f"(risk level: {ru.risk_level})."
                ),
                http_method="POST",
                graph_endpoint=f"/users/{ru.user_id}/revokeSignInSessions",
                request_body={},
                pre_state={"riskState": ru.risk_state, "riskLevel": ru.risk_level, "sessions": "Active"},
                post_state={"riskState": ru.risk_state, "riskLevel": ru.risk_level, "sessions": "Revoked"},
                required_write_permission="User.ReadWrite.All",
            )

            findings.append(
                AuditFinding(
                    finding_id=finding_id,
                    category=CheckCategory.RISKY_SIGNINS_USERS,
                    title=f"Identity Protection flagged risky user ({ru.risk_level.upper()} risk)",
                    severity=sev,
                    description=(
                        f"User '{ru.display_name}' ({ru.user_principal_name}) is in state "
                        f"'{ru.risk_state}' with risk level '{ru.risk_level}'. "
                        f"Telemetry detail: {ru.risk_detail}."
                    ),
                    impact=(
                        "Leaked credentials or anomalous behavioral telemetry indicate the account "
                        "may already be under active adversary control."
                    ),
                    recommendation=(
                        "Revoke active sessions immediately, reset credentials, verify recent "
                        "mailbox/audit activity, and enforce risk-based Conditional Access."
                    ),
                    affected_resource_id=ru.user_id,
                    affected_upn=ru.user_principal_name,
                    affected_display_name=ru.display_name,
                    metadata={
                        "risk_level": ru.risk_level,
                        "risk_state": ru.risk_state,
                        "risk_detail": ru.risk_detail,
                    },
                    remediation=remediation,
                )
            )

        for rsi in snapshot.risky_sign_ins:
            sev = (
                Severity.HIGH
                if rsi.risk_level.lower() == "high"
                else Severity.MEDIUM
                if rsi.risk_level.lower() == "medium"
                else Severity.LOW
            )
            finding_id = f"RISK-{idx:03d}"
            idx += 1
            events_str = ", ".join(rsi.risk_Event_types) if rsi.risk_Event_types else "anomalousSignIn"

            findings.append(
                AuditFinding(
                    finding_id=finding_id,
                    category=CheckCategory.RISKY_SIGNINS_USERS,
                    title=f"Risky sign-in to {rsi.app_display_name} ({events_str})",
                    severity=sev,
                    description=(
                        f"Sign-in by '{rsi.user_principal_name}' to '{rsi.app_display_name}' from "
                        f"IP {rsi.ip_address} ({rsi.location}) triggered risk detections: [{events_str}]."
                    ),
                    impact=(
                        "Sign-ins from anonymous proxies, Tor nodes, password sprays, or impossible "
                        "travel locations strongly correlate with unauthorized access attempts."
                    ),
                    recommendation=(
                        "Investigate sign-in correlation ID in Entra sign-in logs, block malicious "
                        "IP ranges if applicable, and require step-up MFA or password reset on medium/high sign-in risk."
                    ),
                    affected_resource_id=rsi.id,
                    affected_upn=rsi.user_principal_name,
                    affected_ip=rsi.ip_address,
                    metadata={
                        "app_display_name": rsi.app_display_name,
                        "location": rsi.location,
                        "risk_events": rsi.risk_Event_types,
                    },
                )
            )

        return findings, None

    # -------------------------------------------------------------------------
    # Check 5: Guest accounts that are old or inactive
    # -------------------------------------------------------------------------
    def check_guest_accounts(self, snapshot: TenantSnapshot) -> List[AuditFinding]:
        """Flag external B2B guest accounts that are inactive or have never signed in."""
        findings: List[AuditFinding] = []
        now = self._get_now(snapshot)
        guest_threshold = self.config.guest_stale_days_threshold
        idx = 1

        for user in snapshot.users:
            if user.user_type != "Guest" or not user.account_enabled:
                continue

            days_since_signin = _days_between(now, user.last_sign_in_date_time)
            days_since_created = _days_between(now, user.created_date_time) or 0

            is_inactive_guest = False
            reason = ""
            inactive_days = 0

            if days_since_signin is not None and days_since_signin >= guest_threshold:
                is_inactive_guest = True
                inactive_days = days_since_signin
                reason = f"has not signed in for {days_since_signin} days (created {days_since_created} days ago)"
            elif days_since_signin is None and days_since_created >= guest_threshold:
                is_inactive_guest = True
                inactive_days = days_since_created
                reason = f"was invited {days_since_created} days ago and has never signed in"

            if not is_inactive_guest:
                continue

            finding_id = f"GUEST-{idx:03d}"
            idx += 1
            groups_str = ", ".join(user.group_memberships) if user.group_memberships else "None"

            remediation = RemediationProposal(
                action_id=f"REM-{finding_id}",
                action_type=RemediationActionType.DISABLE_STALE_ACCOUNT,
                finding_id=finding_id,
                target_user_id=user.id,
                target_upn=user.user_principal_name,
                target_display_name=user.display_name,
                summary=f"Disable inactive external guest account {user.user_principal_name}.",
                http_method="PATCH",
                graph_endpoint=f"/users/{user.id}",
                request_body={"accountEnabled": False},
                pre_state={"userType": "Guest", "accountEnabled": True, "groups": user.group_memberships},
                post_state={"userType": "Guest", "accountEnabled": False, "groups": user.group_memberships},
                required_write_permission="User.ReadWrite.All",
            )

            findings.append(
                AuditFinding(
                    finding_id=finding_id,
                    category=CheckCategory.GUEST_ACCOUNTS,
                    title=f"Inactive external B2B guest account ({inactive_days} days inactive)",
                    severity=Severity.MEDIUM,
                    description=(
                        f"External guest '{user.display_name}' ({user.user_principal_name}) {reason} "
                        f"while retaining group memberships: [{groups_str}]."
                    ),
                    impact=(
                        "Unmonitored guest accounts maintain standing access to internal Teams, "
                        "SharePoint sites, and directory objects long after vendor engagements end."
                    ),
                    recommendation=(
                        "Disable or remove the guest account and configure quarterly Entra ID "
                        "Access Reviews for all external guest memberships."
                    ),
                    affected_resource_id=user.id,
                    affected_upn=user.user_principal_name,
                    affected_display_name=user.display_name,
                    affected_ip=user.last_sign_in_ip,
                    metadata={
                        "inactive_days": inactive_days,
                        "created_days_ago": days_since_created,
                        "groups": user.group_memberships,
                    },
                    remediation=remediation,
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Check 6: Conditional Access gaps (read-only review)
    # -------------------------------------------------------------------------
    def check_conditional_access_gaps(self, snapshot: TenantSnapshot) -> List[AuditFinding]:
        """
        Perform a strictly read-only posture assessment of Conditional Access policies:
        - Check if an enabled policy enforces MFA for directory admins
        - Check if an enabled policy blocks legacy authentication protocols
        - Flag policies left in report-only or disabled states
        - Flag overly broad user exclusions on active MFA policies
        """
        findings: List[AuditFinding] = []
        policies = snapshot.conditional_access_policies
        idx = 1

        if not policies:
            findings.append(
                AuditFinding(
                    finding_id="CA-001",
                    category=CheckCategory.CONDITIONAL_ACCESS,
                    title="No Conditional Access policies configured in tenant",
                    severity=Severity.HIGH,
                    description="Zero Conditional Access policies were found in the tenant.",
                    impact=(
                        "Without Conditional Access policies, the tenant lacks automated policy "
                        "enforcement for admin MFA, legacy authentication blocking, and risk controls."
                    ),
                    recommendation=(
                        "Deploy baseline Conditional Access policies requiring MFA for all admins "
                        "and users, and blocking legacy authentication protocols."
                    ),
                    affected_resource_id="tenant-ca-policies",
                )
            )
            return findings

        # 1. Check whether an ENABLED policy enforces MFA for admins
        enabled_admin_mfa = [
            p
            for p in policies
            if p.state == "enabled"
            and "mfa" in [g.lower() for g in p.grant_controls]
            and (p.include_roles or "All" in p.include_users)
        ]
        report_only_admin_mfa = [
            p
            for p in policies
            if p.state == "enabledForReportingButNotEnforced"
            and "mfa" in [g.lower() for g in p.grant_controls]
            and p.include_roles
        ]

        if report_only_admin_mfa:
            for pol in report_only_admin_mfa:
                finding_id = f"CA-{idx:03d}"
                idx += 1
                findings.append(
                    AuditFinding(
                        finding_id=finding_id,
                        category=CheckCategory.CONDITIONAL_ACCESS,
                        title=f"Admin MFA policy '{pol.display_name}' is stuck in Report-Only mode",
                        severity=Severity.HIGH,
                        description=(
                            f"Conditional Access policy '{pol.display_name}' ({pol.id}) targets "
                            "privileged directory roles with an MFA grant control, but its state is "
                            "'enabledForReportingButNotEnforced' (Report-Only)."
                        ),
                        impact=(
                            "Report-only policies log evaluation telemetry but do NOT prompt or block "
                            "administrators signing in without MFA."
                        ),
                        recommendation=(
                            "Verify that emergency break-glass accounts are excluded and switch "
                            f"policy '{pol.display_name}' from Report-Only to Enabled."
                        ),
                        affected_resource_id=pol.id,
                        metadata={"policy_name": pol.display_name, "state": pol.state},
                    )
                )
        elif not enabled_admin_mfa:
            finding_id = f"CA-{idx:03d}"
            idx += 1
            findings.append(
                AuditFinding(
                    finding_id=finding_id,
                    category=CheckCategory.CONDITIONAL_ACCESS,
                    title="No enabled Conditional Access policy requiring MFA for administrators",
                    severity=Severity.HIGH,
                    description=(
                        "No active ('enabled') Conditional Access policy was found that enforces "
                        "MFA across privileged directory roles."
                    ),
                    impact=(
                        "Privileged administrators can authenticate using single-factor passwords "
                        "if not covered by an active MFA policy."
                    ),
                    recommendation=(
                        "Create and enable a dedicated Conditional Access policy requiring "
                        "phishing-resistant MFA for all privileged directory roles."
                    ),
                    affected_resource_id="tenant-ca-admin-mfa",
                )
            )

        # 2. Check legacy authentication blocking
        enabled_legacy_block = [
            p
            for p in policies
            if p.state == "enabled"
            and "block" in [g.lower() for g in p.grant_controls]
            and any(c in p.client_app_types for c in ("exchangeActiveSync", "other"))
        ]
        if not enabled_legacy_block:
            disabled_legacy = [
                p
                for p in policies
                if p.state != "enabled"
                and "block" in [g.lower() for g in p.grant_controls]
                and any(c in p.client_app_types for c in ("exchangeActiveSync", "other"))
            ]
            finding_id = f"CA-{idx:03d}"
            idx += 1
            pol_hint = (
                f"Policy '{disabled_legacy[0].display_name}' exists but is '{disabled_legacy[0].state}'."
                if disabled_legacy
                else "No policy targeting 'exchangeActiveSync' and 'other' client app types with a Block control is enabled."
            )
            findings.append(
                AuditFinding(
                    finding_id=finding_id,
                    category=CheckCategory.CONDITIONAL_ACCESS,
                    title="Legacy authentication protocols are not blocked by Conditional Access",
                    severity=Severity.HIGH,
                    description=(
                        "Legacy authentication protocols (POP3, IMAP4, SMTP Basic Auth, older Office "
                        f"clients) are not blocked. {pol_hint}"
                    ),
                    impact=(
                        "Legacy authentication protocols do not support modern MFA and are the "
                        "primary vector for password spray and credential stuffing attacks."
                    ),
                    recommendation=(
                        "Enable a Conditional Access policy targeting All Users and client app types "
                        "'Exchange ActiveSync' and 'Other clients' with the Grant control set to Block."
                    ),
                    affected_resource_id=disabled_legacy[0].id if disabled_legacy else "tenant-ca-legacy-auth",
                )
            )

        # 3. Check overly broad user exclusions on active MFA policies (more than 2 break-glass accounts)
        for pol in policies:
            if (
                pol.state == "enabled"
                and "mfa" in [g.lower() for g in pol.grant_controls]
                and len(pol.exclude_users) > 2
            ):
                finding_id = f"CA-{idx:03d}"
                idx += 1
                findings.append(
                    AuditFinding(
                        finding_id=finding_id,
                        category=CheckCategory.CONDITIONAL_ACCESS,
                        title=(
                            f"Excessive user exclusions ({len(pol.exclude_users)} users) on MFA policy "
                            f"'{pol.display_name}'"
                        ),
                        severity=Severity.MEDIUM,
                        description=(
                            f"Active MFA policy '{pol.display_name}' ({pol.id}) excludes "
                            f"{len(pol.exclude_users)} user accounts. Best practice limits MFA policy "
                            "exclusions strictly to 1-2 emergency break-glass accounts."
                        ),
                        impact=(
                            "Users added to Conditional Access exclusion lists bypass MFA enforcement "
                            "permanently, creating hidden backdoors."
                        ),
                        recommendation=(
                            f"Audit the {len(pol.exclude_users)} excluded accounts in policy "
                            f"'{pol.display_name}' and remove all non-break-glass users from the exclusion list."
                        ),
                        affected_resource_id=pol.id,
                        metadata={
                            "policy_name": pol.display_name,
                            "excluded_count": len(pol.exclude_users),
                        },
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Check 7: Disabled accounts that still hold licenses or group memberships
    # -------------------------------------------------------------------------
    def check_disabled_accounts_hygiene(self, snapshot: TenantSnapshot) -> List[AuditFinding]:
        """Flag disabled user accounts that still consume licenses or belong to groups/roles."""
        findings: List[AuditFinding] = []
        idx = 1

        for user in snapshot.users:
            if user.account_enabled:
                continue

            has_licenses = len(user.assigned_licenses) > 0
            has_groups = len(user.group_memberships) > 0
            has_roles = len(user.assigned_roles) > 0

            if not (has_licenses or has_groups or has_roles):
                continue

            finding_id = f"DISABLED-{idx:03d}"
            idx += 1

            held_items: List[str] = []
            if has_licenses:
                held_items.append(f"licenses ({', '.join(user.assigned_licenses)})")
            if has_groups:
                held_items.append(f"groups ({', '.join(user.group_memberships)})")
            if has_roles:
                held_items.append(f"roles ({', '.join(user.assigned_roles)})")

            sev = Severity.MEDIUM if (has_roles or len(user.assigned_licenses) >= 2) else Severity.LOW

            findings.append(
                AuditFinding(
                    finding_id=finding_id,
                    category=CheckCategory.DISABLED_ACCOUNT_HYGIENE,
                    title=f"Disabled account retains {', '.join(held_items)}",
                    severity=sev,
                    description=(
                        f"Disabled account '{user.display_name}' ({user.user_principal_name}) is "
                        f"blocked from sign-in but still retains {', '.join(held_items)}."
                    ),
                    impact=(
                        "Retained group memberships and roles on offboarded accounts risk accidental "
                        "privilege restoration if re-enabled, and unused licenses waste IT budget."
                    ),
                    recommendation=(
                        "Strip all security group memberships, directory roles, and commercial "
                        "licenses as part of standard joiner-mover-leaver (JML) offboarding automation."
                    ),
                    affected_resource_id=user.id,
                    affected_upn=user.user_principal_name,
                    affected_display_name=user.display_name,
                    affected_ip=user.last_sign_in_ip,
                    metadata={
                        "licenses": user.assigned_licenses,
                        "groups": user.group_memberships,
                        "roles": user.assigned_roles,
                    },
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Risk Score & Posture Grade Calculator
    # -------------------------------------------------------------------------
    @staticmethod
    def calculate_risk_score(findings: List[AuditFinding]) -> Tuple[int, str]:
        """
        Compute an overall tenant risk score from 0 (no risk) to 100 (critical risk)
        and assign a letter security posture grade (A through F).
        """
        raw_points = 0
        for f in findings:
            if f.severity == Severity.HIGH:
                raw_points += 9
            elif f.severity == Severity.MEDIUM:
                raw_points += 4
            else:
                raw_points += 2

        risk_score = min(100, raw_points)

        if risk_score < 20:
            grade = "A"
        elif risk_score < 40:
            grade = "B"
        elif risk_score < 60:
            grade = "C"
        elif risk_score < 80:
            grade = "D"
        else:
            grade = "F"

        return risk_score, grade

    def run_full_audit(self, snapshot: TenantSnapshot) -> AuditReport:
        """Run all 7 identity security audit checks and return a consolidated AuditReport."""
        all_findings: List[AuditFinding] = []
        skipped_checks: List[str] = []

        all_findings.extend(self.check_users_without_mfa(snapshot))
        all_findings.extend(self.check_stale_accounts(snapshot))
        all_findings.extend(self.check_privileged_roles(snapshot))

        risk_findings, skip_note = self.check_risky_users_and_signins(snapshot)
        all_findings.extend(risk_findings)
        if skip_note:
            skipped_checks.append(skip_note)

        all_findings.extend(self.check_guest_accounts(snapshot))
        all_findings.extend(self.check_conditional_access_gaps(snapshot))
        all_findings.extend(self.check_disabled_accounts_hygiene(snapshot))

        risk_score, grade = self.calculate_risk_score(all_findings)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return AuditReport(
            tenant_id=snapshot.tenant_id,
            tenant_name=snapshot.tenant_name,
            tenant_domain=snapshot.tenant_domain,
            mode=snapshot.mode,
            generated_at=now_str,
            stale_days_threshold=self.config.stale_days_threshold,
            overall_risk_score=risk_score,
            security_posture_grade=grade,
            supports_identity_protection=snapshot.supports_identity_protection,
            identity_protection_note=snapshot.identity_protection_status_note,
            findings=all_findings,
            skipped_checks=skipped_checks,
        )
