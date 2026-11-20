"""
Mock Microsoft Entra ID Tenant Generator for Demo Mode.

Generates realistic, deterministic enterprise tenant telemetry so Sentinel ID
runs end-to-end with zero cloud connectivity required.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sentinel_id.models import (
    ConditionalAccessPolicy,
    DirectoryRoleAssignment,
    EntraUser,
    RiskySignInRecord,
    RiskyUserRecord,
    TenantSnapshot,
)


def _iso_days_ago(reference: datetime, days: int) -> str:
    """Return an ISO-8601 UTC timestamp string `days` before `reference`."""
    dt = reference - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_mock_tenant(
    reference_now: Optional[datetime] = None,
    supports_identity_protection: bool = True,
) -> TenantSnapshot:
    """
    Build a realistic mock Entra ID tenant snapshot ("Northwind Cloud Lab")
    containing intentional identity security misconfigurations across all 7 checks.
    """
    now = reference_now or datetime.now(timezone.utc)

    users = [
        # --- Global Administrators (6 total -> triggers excess Global Admins > 4) ---
        EntraUser(
            id="u-1001-ga-breakglass",
            display_name="Emergency BreakGlass 01",
            user_principal_name="bg-admin01@northwindlab.onmicrosoft.com",
            mail="bg-admin01@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 540),
            last_sign_in_date_time=_iso_days_ago(now, 35),
            mfa_registered=True,
            mfa_methods=["fido2SecurityKey"],
            assigned_roles=["Global Administrator"],
            assigned_licenses=[],
            group_memberships=["grp-sec-breakglass"],
            department="Security Operations",
            job_title="Emergency Access Account",
            last_sign_in_ip="198.51.100.10",
        ),
        EntraUser(
            id="u-1002-ga-ciso",
            display_name="Elena Rostova",
            user_principal_name="elena.rostova@northwindlab.onmicrosoft.com",
            mail="elena.rostova@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 400),
            last_sign_in_date_time=_iso_days_ago(now, 1),
            mfa_registered=True,
            mfa_methods=["microsoftAuthenticatorPush", "fido2SecurityKey"],
            assigned_roles=["Global Administrator", "Security Administrator"],
            assigned_licenses=["Microsoft_365_E5"],
            group_memberships=["grp-sec-leadership", "grp-all-employees"],
            department="Information Security",
            job_title="Chief Information Security Officer",
            last_sign_in_ip="198.51.100.22",
        ),
        EntraUser(
            id="u-1003-ga-nomfa",
            display_name="Marcus Vance",
            user_principal_name="marcus.vance@northwindlab.onmicrosoft.com",
            mail="marcus.vance@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 320),
            last_sign_in_date_time=_iso_days_ago(now, 2),
            mfa_registered=False,  # CRITICAL: Global Admin WITHOUT MFA!
            mfa_methods=[],
            assigned_roles=["Global Administrator"],
            assigned_licenses=["Microsoft_365_E5"],
            group_memberships=["grp-it-admins", "grp-all-employees"],
            department="IT Infrastructure",
            job_title="Senior Identity Architect",
            last_sign_in_ip="203.0.113.45",
        ),
        EntraUser(
            id="u-1004-ga-stale",
            display_name="David Kim (Former IT Lead)",
            user_principal_name="david.kim@northwindlab.onmicrosoft.com",
            mail="david.kim@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 610),
            last_sign_in_date_time=_iso_days_ago(now, 142),  # CRITICAL: Stale Global Admin (142 days)
            mfa_registered=True,
            mfa_methods=["sms"],
            assigned_roles=["Global Administrator"],
            assigned_licenses=["Microsoft_365_E5"],
            group_memberships=["grp-it-admins", "grp-all-employees"],
            department="IT Infrastructure",
            job_title="Former IT Director",
            last_sign_in_ip="203.0.113.88",
        ),
        EntraUser(
            id="u-1005-ga-ceo",
            display_name="Arthur Pendelton",
            user_principal_name="arthur.pendelton@northwindlab.onmicrosoft.com",
            mail="arthur.pendelton@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 700),
            last_sign_in_date_time=_iso_days_ago(now, 3),
            mfa_registered=True,
            mfa_methods=["microsoftAuthenticatorPush"],
            assigned_roles=["Global Administrator"],  # Unnecessary standing Global Admin for executive
            assigned_licenses=["Microsoft_365_E5"],
            group_memberships=["grp-exec-board", "grp-all-employees"],
            department="Executive",
            job_title="Chief Executive Officer",
            last_sign_in_ip="198.51.100.50",
        ),
        EntraUser(
            id="u-1006-ga-contractor",
            display_name="Liam O'Connor",
            user_principal_name="liam.oconnor@northwindlab.onmicrosoft.com",
            mail="liam.oconnor@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 210),
            last_sign_in_date_time=_iso_days_ago(now, 12),
            mfa_registered=True,
            mfa_methods=["softwareOath"],
            assigned_roles=["Global Administrator", "Exchange Administrator"],
            assigned_licenses=["Microsoft_365_E3"],
            group_memberships=["grp-it-admins"],
            department="External Migration Team",
            job_title="Cloud Consultant",
            last_sign_in_ip="192.0.2.77",
        ),
        # --- Other Privileged Role Holders ---
        EntraUser(
            id="u-1007-priv-role-nomfa",
            display_name="Priya Nair",
            user_principal_name="priya.nair@northwindlab.onmicrosoft.com",
            mail="priya.nair@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 180),
            last_sign_in_date_time=_iso_days_ago(now, 4),
            mfa_registered=False,  # Privileged Role Admin without MFA
            mfa_methods=[],
            assigned_roles=["Privileged Role Administrator"],
            assigned_licenses=["Microsoft_365_E5"],
            group_memberships=["grp-iam-ops", "grp-all-employees"],
            department="IAM Operations",
            job_title="IAM Engineer",
            last_sign_in_ip="198.51.100.91",
        ),
        # --- Standard Members without MFA ---
        EntraUser(
            id="u-1008-user-nomfa",
            display_name="Chloe Bennett",
            user_principal_name="chloe.bennett@northwindlab.onmicrosoft.com",
            mail="chloe.bennett@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 150),
            last_sign_in_date_time=_iso_days_ago(now, 1),
            mfa_registered=False,
            mfa_methods=[],
            assigned_roles=[],
            assigned_licenses=["Microsoft_365_E3"],
            group_memberships=["grp-finance", "grp-all-employees"],
            department="Finance",
            job_title="Senior Payroll Analyst",
            last_sign_in_ip="203.0.113.19",
        ),
        EntraUser(
            id="u-1009-user-nomfa-sales",
            display_name="Mateo Silva",
            user_principal_name="mateo.silva@northwindlab.onmicrosoft.com",
            mail="mateo.silva@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 95),
            last_sign_in_date_time=_iso_days_ago(now, 5),
            mfa_registered=False,
            mfa_methods=[],
            assigned_roles=[],
            assigned_licenses=["Microsoft_365_E3"],
            group_memberships=["grp-sales", "grp-all-employees"],
            department="Sales",
            job_title="Account Executive",
            last_sign_in_ip="192.0.2.114",
        ),
        # --- Stale Active Accounts (90+ days inactive) ---
        EntraUser(
            id="u-1010-stale-member",
            display_name="Hannah Abbott",
            user_principal_name="hannah.abbott@northwindlab.onmicrosoft.com",
            mail="hannah.abbott@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 380),
            last_sign_in_date_time=_iso_days_ago(now, 118),  # 118 days stale
            mfa_registered=True,
            mfa_methods=["microsoftAuthenticatorPush"],
            assigned_roles=[],
            assigned_licenses=["Microsoft_365_E3"],
            group_memberships=["grp-marketing", "grp-all-employees"],
            department="Marketing",
            job_title="Campaign Manager",
            last_sign_in_ip="198.51.100.140",
        ),
        EntraUser(
            id="u-1011-stale-never-signed-in",
            display_name="Legacy Service Sync",
            user_principal_name="svc-legacy-sync@northwindlab.onmicrosoft.com",
            mail="svc-legacy-sync@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 165),
            last_sign_in_date_time=None,  # Created 165 days ago, never signed in, no MFA
            mfa_registered=False,
            mfa_methods=[],
            assigned_roles=["User Administrator"],
            assigned_licenses=["Microsoft_365_E3"],
            group_memberships=["grp-it-automation"],
            department="IT Operations",
            job_title="Automation Account",
            last_sign_in_ip=None,
        ),
        # --- Old / Inactive Guest Accounts ---
        EntraUser(
            id="u-1012-guest-inactive",
            display_name="Jean-Luc Picard (Vendor Guest)",
            user_principal_name="jl.picard_starfleetpartner.com#EXT#@northwindlab.onmicrosoft.com",
            mail="jl.picard@starfleetpartner.com",
            user_type="Guest",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 290),
            last_sign_in_date_time=_iso_days_ago(now, 134),  # Inactive guest (134 days)
            mfa_registered=False,
            mfa_methods=[],
            assigned_roles=[],
            assigned_licenses=[],
            group_memberships=["grp-ext-vendor-portal", "grp-sharepoint-finance"],
            department="External Vendor",
            job_title="Partner Auditor",
            last_sign_in_ip="192.0.2.201",
        ),
        EntraUser(
            id="u-1013-guest-never-accepted",
            display_name="Dana Scully (External Advisor)",
            user_principal_name="d.scully_fbi-consulting.org#EXT#@northwindlab.onmicrosoft.com",
            mail="d.scully@fbi-consulting.org",
            user_type="Guest",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 120),
            last_sign_in_date_time=None,  # Guest created 120 days ago, never signed in
            mfa_registered=False,
            mfa_methods=[],
            assigned_roles=[],
            assigned_licenses=[],
            group_memberships=["grp-research-collab"],
            department="External Advisory",
            job_title="Forensic Consultant",
            last_sign_in_ip=None,
        ),
        # --- Disabled Accounts Still Holding Licenses or Group Memberships ---
        EntraUser(
            id="u-1014-disabled-with-license-groups",
            display_name="Victor Von Doom (Terminated)",
            user_principal_name="victor.doom@northwindlab.onmicrosoft.com",
            mail="victor.doom@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=False,  # Disabled account
            created_date_time=_iso_days_ago(now, 450),
            last_sign_in_date_time=_iso_days_ago(now, 75),
            mfa_registered=True,
            mfa_methods=["microsoftAuthenticatorPush"],
            assigned_roles=[],
            assigned_licenses=["Microsoft_365_E5", "Power_BI_Pro"],  # Still consuming 2 paid licenses!
            group_memberships=["grp-rnd-core", "grp-vpn-access"],  # Still in security groups!
            department="R&D",
            job_title="Former Principal Scientist",
            last_sign_in_ip="198.51.100.210",
        ),
        EntraUser(
            id="u-1015-disabled-with-groups",
            display_name="Samwise Gamgee (Offboarded)",
            user_principal_name="samwise.gamgee@northwindlab.onmicrosoft.com",
            mail="samwise.gamgee@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=False,
            created_date_time=_iso_days_ago(now, 310),
            last_sign_in_date_time=_iso_days_ago(now, 60),
            mfa_registered=True,
            mfa_methods=["microsoftAuthenticatorPush"],
            assigned_roles=[],
            assigned_licenses=["Microsoft_365_E3"],
            group_memberships=["grp-logistics-team"],
            department="Logistics",
            job_title="Operations Specialist",
            last_sign_in_ip="198.51.100.211",
        ),
        # --- Healthy Compliant Baseline Users ---
        EntraUser(
            id="u-1016-healthy-eng",
            display_name="Grace Hopper",
            user_principal_name="grace.hopper@northwindlab.onmicrosoft.com",
            mail="grace.hopper@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 300),
            last_sign_in_date_time=_iso_days_ago(now, 1),
            mfa_registered=True,
            mfa_methods=["fido2SecurityKey", "microsoftAuthenticatorPush"],
            assigned_roles=[],
            assigned_licenses=["Microsoft_365_E5"],
            group_memberships=["grp-engineering", "grp-all-employees"],
            department="Engineering",
            job_title="Distinguished Engineer",
            last_sign_in_ip="198.51.100.33",
        ),
        EntraUser(
            id="u-1017-healthy-sec",
            display_name="Alan Turing",
            user_principal_name="alan.turing@northwindlab.onmicrosoft.com",
            mail="alan.turing@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 280),
            last_sign_in_date_time=_iso_days_ago(now, 2),
            mfa_registered=True,
            mfa_methods=["fido2SecurityKey"],
            assigned_roles=["Security Reader"],
            assigned_licenses=["Microsoft_365_E5"],
            group_memberships=["grp-sec-analysts", "grp-all-employees"],
            department="Information Security",
            job_title="Cryptography Lead",
            last_sign_in_ip="198.51.100.34",
        ),
        EntraUser(
            id="u-1018-healthy-hr",
            display_name="Ada Lovelace",
            user_principal_name="ada.lovelace@northwindlab.onmicrosoft.com",
            mail="ada.lovelace@northwindlab.onmicrosoft.com",
            user_type="Member",
            account_enabled=True,
            created_date_time=_iso_days_ago(now, 240),
            last_sign_in_date_time=_iso_days_ago(now, 3),
            mfa_registered=True,
            mfa_methods=["microsoftAuthenticatorPush"],
            assigned_roles=[],
            assigned_licenses=["Microsoft_365_E3"],
            group_memberships=["grp-people-ops", "grp-all-employees"],
            department="People Operations",
            job_title="HR Partner",
            last_sign_in_ip="198.51.100.35",
        ),
    ]

    roles = [
        DirectoryRoleAssignment(
            role_id="role-global-admin",
            role_template_id="62e90394-69f5-4237-9190-012177145e10",
            display_name="Global Administrator",
            description="Can manage all aspects of Microsoft Entra ID and Microsoft services.",
            is_privileged=True,
            member_user_ids=[
                "u-1001-ga-breakglass",
                "u-1002-ga-ciso",
                "u-1003-ga-nomfa",
                "u-1004-ga-stale",
                "u-1005-ga-ceo",
                "u-1006-ga-contractor",
            ],
        ),
        DirectoryRoleAssignment(
            role_id="role-priv-role-admin",
            role_template_id="e8611ab8-c189-46e8-94e1-60213ab1f814",
            display_name="Privileged Role Administrator",
            description="Can manage role assignments in Microsoft Entra ID and PIM.",
            is_privileged=True,
            member_user_ids=["u-1007-priv-role-nomfa"],
        ),
        DirectoryRoleAssignment(
            role_id="role-security-admin",
            role_template_id="194ae4cb-b126-40b2-bd5b-6091b380977d",
            display_name="Security Administrator",
            description="Can read security information and reports, and manage configuration.",
            is_privileged=True,
            member_user_ids=["u-1002-ga-ciso"],
        ),
        DirectoryRoleAssignment(
            role_id="role-exchange-admin",
            role_template_id="29232cdf-9323-42fd-ade2-1d097af3e4de",
            display_name="Exchange Administrator",
            description="Can manage all aspects of the Exchange product.",
            is_privileged=True,
            member_user_ids=["u-1006-ga-contractor"],
        ),
        DirectoryRoleAssignment(
            role_id="role-user-admin",
            role_template_id="fe930be7-5e62-47db-91af-98c3a49a38b1",
            display_name="User Administrator",
            description="Can manage all aspects of users and groups, including resetting passwords.",
            is_privileged=True,
            member_user_ids=["u-1011-stale-never-signed-in"],
        ),
        DirectoryRoleAssignment(
            role_id="role-security-reader",
            role_template_id="5d6b6bb7-de71-4623-b4af-96380a352509",
            display_name="Security Reader",
            description="Can read security information and reports across Microsoft Entra ID.",
            is_privileged=False,
            member_user_ids=["u-1017-healthy-sec"],
        ),
    ]

    risky_users = []
    risky_sign_ins = []
    if supports_identity_protection:
        risky_users = [
            RiskyUserRecord(
                user_id="u-1008-user-nomfa",
                user_principal_name="chloe.bennett@northwindlab.onmicrosoft.com",
                display_name="Chloe Bennett",
                risk_level="high",
                risk_state="atRisk",
                risk_detail="aiConfirmedSigninSafe=false; leakedCredentials",
                last_updated_date_time=_iso_days_ago(now, 1),
            ),
            RiskyUserRecord(
                user_id="u-1006-ga-contractor",
                user_principal_name="liam.oconnor@northwindlab.onmicrosoft.com",
                display_name="Liam O'Connor",
                risk_level="medium",
                risk_state="atRisk",
                risk_detail="unfamiliarFeatures; impossibleTravel",
                last_updated_date_time=_iso_days_ago(now, 2),
            ),
        ]
        risky_sign_ins = [
            RiskySignInRecord(
                id="rsi-9001",
                user_id="u-1008-user-nomfa",
                user_principal_name="chloe.bennett@northwindlab.onmicrosoft.com",
                app_display_name="Microsoft Exchange Online",
                ip_address="185.220.101.44",
                location="Anonymous Proxy / Tor Exit Node",
                risk_level="high",
                risk_Event_types=["anonymizedIPAddress", "passwordSpray"],
                created_date_time=_iso_days_ago(now, 1),
            ),
            RiskySignInRecord(
                id="rsi-9002",
                user_id="u-1006-ga-contractor",
                user_principal_name="liam.oconnor@northwindlab.onmicrosoft.com",
                app_display_name="Azure Portal",
                ip_address="45.155.205.10",
                location="Frankfurt, DE (Impossible Travel from Seattle, US)",
                risk_level="medium",
                risk_Event_types=["impossibleTravel", "unfamiliarFeatures"],
                created_date_time=_iso_days_ago(now, 2),
            ),
        ]

    # Conditional Access policies with realistic security gaps:
    # 1. Admin MFA policy is stuck in Report-Only ("enabledForReportingButNotEnforced")
    # 2. Legacy Authentication block policy is "disabled"
    # 3. Overly broad exclusions on All-Users MFA policy (excluding 4 users instead of just break-glass)
    conditional_access_policies = [
        ConditionalAccessPolicy(
            id="ca-pol-001",
            display_name="CA01 - Require MFA for Directory Admins",
            state="enabledForReportingButNotEnforced",  # GAP: Report-only, not enforced!
            include_users=[],
            include_roles=[
                "62e90394-69f5-4237-9190-012177145e10",  # Global Admin
                "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Admin
            ],
            exclude_users=["u-1001-ga-breakglass"],
            client_app_types=["all"],
            grant_controls=["mfa"],
        ),
        ConditionalAccessPolicy(
            id="ca-pol-002",
            display_name="CA02 - Block Legacy Authentication Protocols",
            state="disabled",  # GAP: Disabled policy allows POP/IMAP/SMTP basic auth attacks
            include_users=["All"],
            include_roles=[],
            exclude_users=[],
            client_app_types=["exchangeActiveSync", "other"],
            grant_controls=["block"],
        ),
        ConditionalAccessPolicy(
            id="ca-pol-003",
            display_name="CA03 - Require MFA for All Users on Cloud Apps",
            state="enabled",
            include_users=["All"],
            include_roles=[],
            exclude_users=[
                "u-1001-ga-breakglass",
                "u-1003-ga-nomfa",
                "u-1008-user-nomfa",
                "u-1009-user-nomfa-sales",
            ],  # GAP: Non-break-glass users excluded from MFA policy
            client_app_types=["browser", "mobileAppsAndDesktopClients"],
            grant_controls=["mfa"],
        ),
    ]

    note = (
        "Entra ID P2 / Identity Protection telemetry active."
        if supports_identity_protection
        else "Tenant license does not include Entra ID P2 (Identity Protection); check skipped gracefully."
    )

    return TenantSnapshot(
        tenant_id="a1b2c3d4-e5f6-4789-9012-northwindlab01",
        tenant_name="Northwind Cloud Lab (Demo Tenant)",
        tenant_domain="northwindlab.onmicrosoft.com",
        mode="demo",
        captured_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        supports_identity_protection=supports_identity_protection,
        identity_protection_status_note=note,
        users=users,
        roles=roles,
        risky_users=risky_users,
        risky_sign_ins=risky_sign_ins,
        conditional_access_policies=conditional_access_policies,
    )
