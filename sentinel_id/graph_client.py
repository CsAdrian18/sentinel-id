"""
Read-Only Microsoft Graph Client for Sentinel ID (Live Mode).

Uses MSAL (`ConfidentialClientApplication`) with Client Credentials flow and
strictly read-only least-privilege Graph permissions by default:
- User.Read.All
- Directory.Read.All
- AuditLog.Read.All
- Policy.Read.All
- RoleManagement.Read.Directory
- IdentityRiskyUser.Read.All (optional; degrades gracefully if tenant lacks P2 license)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import msal
import requests

from sentinel_id.config import SentinelConfig
from sentinel_id.models import (
    ConditionalAccessPolicy,
    DirectoryRoleAssignment,
    EntraUser,
    RiskySignInRecord,
    RiskyUserRecord,
    TenantSnapshot,
)

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

PRIVILEGED_ROLE_NAMES = {
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
    "Billing Administrator",
    "Helpdesk Administrator",
    "Intune Administrator",
}


class GraphClientError(Exception):
    """Raised when Microsoft Graph authentication or critical API calls fail."""


class EntraGraphClient:
    """
    Strictly Read-Only client for fetching identity security telemetry from a
    personal test Microsoft Entra ID tenant.
    """

    def __init__(self, config: SentinelConfig) -> None:
        self.config = config
        self._access_token: Optional[str] = None
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def authenticate(self) -> str:
        """Acquire an OAuth2 access token via MSAL Client Credentials flow."""
        if not self.config.is_live_configured():
            raise GraphClientError(
                "Live mode requires ENTRA_TENANT_ID, ENTRA_CLIENT_ID, and ENTRA_CLIENT_SECRET "
                "configured in .env (for a personal test tenant you own)."
            )

        authority = f"https://login.microsoftonline.com/{self.config.tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id=self.config.client_id,
            client_credential=self.config.client_secret,
            authority=authority,
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            err_desc = result.get("error_description") or result.get("error") or "Unknown MSAL error"
            raise GraphClientError(f"MSAL authentication failed: {err_desc}")

        self._access_token = result["access_token"]
        self.session.headers.update({"Authorization": f"Bearer {self._access_token}"})
        return self._access_token

    def _get_paginated(self, endpoint: str, params: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Execute a GET request against Microsoft Graph and follow @odata.nextLink pagination."""
        url = f"{GRAPH_BASE_URL}{endpoint}" if endpoint.startswith("/") else endpoint
        items: List[Dict[str, Any]] = []
        current_params = params

        while url:
            resp = self.session.get(url, params=current_params, timeout=30)
            current_params = None  # Query params are baked into @odata.nextLink
            if resp.status_code != 200:
                raise GraphClientError(
                    f"GET {endpoint} failed with HTTP {resp.status_code}: {resp.text[:300]}"
                )
            payload = resp.json()
            items.extend(payload.get("value", []))
            url = payload.get("@odata.nextLink")

        return items

    def _fetch_mfa_registration_map(self) -> Dict[str, Tuple[bool, List[str]]]:
        """
        Fetch MFA registration status from /reports/authenticationMethods/userRegistrationDetails.
        Falls back gracefully if AuditLog.Read.All report endpoint is restricted.
        """
        mfa_map: Dict[str, Tuple[bool, List[str]]] = {}
        try:
            records = self._get_paginated(
                "/reports/authenticationMethods/userRegistrationDetails"
            )
            for rec in records:
                uid = rec.get("id", "")
                is_mfa = bool(rec.get("isMfaRegistered", False))
                methods = rec.get("methodsRegistered") or []
                if uid:
                    mfa_map[uid] = (is_mfa, list(methods))
        except GraphClientError:
            pass
        return mfa_map

    def _fetch_roles(self) -> Tuple[List[DirectoryRoleAssignment], Dict[str, List[str]]]:
        """Fetch active directory roles and map user IDs to role names."""
        raw_roles = self._get_paginated("/directoryRoles?$expand=members")
        roles: List[DirectoryRoleAssignment] = []
        user_roles_map: Dict[str, List[str]] = {}

        for r in raw_roles:
            role_name = r.get("displayName", "Unknown Role")
            members = r.get("members") or []
            member_ids = [
                m.get("id")
                for m in members
                if m.get("@odata.type", "#microsoft.graph.user") == "#microsoft.graph.user"
                and m.get("id")
            ]
            for uid in member_ids:
                user_roles_map.setdefault(uid, []).append(role_name)

            roles.append(
                DirectoryRoleAssignment(
                    role_id=r.get("id", ""),
                    role_template_id=r.get("roleTemplateId", ""),
                    display_name=role_name,
                    description=r.get("description", ""),
                    is_privileged=role_name in PRIVILEGED_ROLE_NAMES,
                    member_user_ids=member_ids,
                )
            )
        return roles, user_roles_map

    def _fetch_identity_protection(
        self,
    ) -> Tuple[bool, str, List[RiskyUserRecord], List[RiskySignInRecord]]:
        """
        Fetch risky users and risky sign-ins if the tenant has Entra ID P2 licensing.
        Skips gracefully on HTTP 403 / 400 (missing P2 license or optional permission).
        """
        risky_users: List[RiskyUserRecord] = []
        risky_sign_ins: List[RiskySignInRecord] = []

        try:
            raw_risky_users = self._get_paginated(
                "/identityProtection/riskyUsers?$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"
            )
            for ru in raw_risky_users:
                risky_users.append(
                    RiskyUserRecord(
                        user_id=ru.get("id", ""),
                        user_principal_name=ru.get("userPrincipalName", ""),
                        display_name=ru.get("userDisplayName", ""),
                        risk_level=ru.get("riskLevel", "low"),
                        risk_state=ru.get("riskState", "atRisk"),
                        risk_detail=ru.get("riskDetail", ""),
                        last_updated_date_time=ru.get("riskLastUpdatedDateTime", ""),
                    )
                )

            raw_risky_signins = self._get_paginated(
                "/auditLogs/signIns?$filter=riskLevelDuringSignIn ne 'none'&$top=50"
            )
            for rsi in raw_risky_signins:
                loc = rsi.get("location") or {}
                city_country = ", ".join(
                    filter(None, [loc.get("city"), loc.get("countryOrRegion")])
                )
                risky_sign_ins.append(
                    RiskySignInRecord(
                        id=rsi.get("id", ""),
                        user_id=rsi.get("userId", ""),
                        user_principal_name=rsi.get("userPrincipalName", ""),
                        app_display_name=rsi.get("appDisplayName", "Unknown App"),
                        ip_address=rsi.get("ipAddress", ""),
                        location=city_country or "Unknown Location",
                        risk_level=rsi.get("riskLevelDuringSignIn", "low"),
                        risk_Event_types=rsi.get("riskEventTypes_v2") or [],
                        created_date_time=rsi.get("createdDateTime", ""),
                    )
                )
            return (
                True,
                "Entra ID P2 / Identity Protection telemetry retrieved.",
                risky_users,
                risky_sign_ins,
            )
        except GraphClientError as exc:
            msg = str(exc)
            if "403" in msg or "400" in msg or "Premium" in msg or "license" in msg.lower():
                return (
                    False,
                    "Skipped gracefully: Tenant lacks Entra ID P2 license or optional IdentityRiskyUser.Read.All permission.",
                    [],
                    [],
                )
            return (
                False,
                f"Skipped gracefully: Identity Protection endpoint unavailable ({msg[:120]}).",
                [],
                [],
            )

    def _fetch_conditional_access_policies(self) -> List[ConditionalAccessPolicy]:
        """Fetch Conditional Access policies (read-only via Policy.Read.All)."""
        policies: List[ConditionalAccessPolicy] = []
        try:
            raw_policies = self._get_paginated("/identity/conditionalAccess/policies")
            for p in raw_policies:
                conditions = p.get("conditions") or {}
                users_cond = conditions.get("users") or {}
                grant = p.get("grantControls") or {}
                policies.append(
                    ConditionalAccessPolicy(
                        id=p.get("id", ""),
                        display_name=p.get("displayName", "Unnamed Policy"),
                        state=p.get("state", "disabled"),
                        include_users=users_cond.get("includeUsers") or [],
                        include_roles=users_cond.get("includeRoles") or [],
                        exclude_users=users_cond.get("excludeUsers") or [],
                        client_app_types=conditions.get("clientAppTypes") or [],
                        grant_controls=grant.get("builtInControls") or [],
                        session_controls=p.get("sessionControls") or {},
                    )
                )
        except GraphClientError:
            pass
        return policies

    def fetch_tenant_snapshot(self) -> TenantSnapshot:
        """Collect a complete read-only snapshot from the live test tenant."""
        if not self._access_token:
            self.authenticate()

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        roles, user_roles_map = self._fetch_roles()
        mfa_map = self._fetch_mfa_registration_map()

        select_fields = (
            "id,displayName,userPrincipalName,mail,userType,accountEnabled,"
            "createdDateTime,signInActivity,assignedLicenses,department,jobTitle"
        )
        raw_users = self._get_paginated(
            f"/users?$select={select_fields}&$expand=transitiveMemberOf($select=id,displayName)"
        )

        users: List[EntraUser] = []
        for u in raw_users:
            uid = u.get("id", "")
            sign_in = u.get("signInActivity") or {}
            last_sign_in = sign_in.get("lastSignInDateTime") or sign_in.get(
                "lastNonInteractiveSignInDateTime"
            )
            mfa_registered, mfa_methods = mfa_map.get(uid, (False, []))
            raw_licenses = u.get("assignedLicenses") or []
            licenses = [str(lic.get("skuId", "Licensed")) for lic in raw_licenses]
            raw_groups = u.get("transitiveMemberOf") or []
            groups = [
                g.get("displayName") or g.get("id", "")
                for g in raw_groups
                if g.get("@odata.type") == "#microsoft.graph.group"
            ]

            users.append(
                EntraUser(
                    id=uid,
                    display_name=u.get("displayName", "Unknown"),
                    user_principal_name=u.get("userPrincipalName", ""),
                    mail=u.get("mail") or u.get("userPrincipalName", ""),
                    user_type=u.get("userType") or "Member",
                    account_enabled=bool(u.get("accountEnabled", True)),
                    created_date_time=u.get("createdDateTime") or now_str,
                    last_sign_in_date_time=last_sign_in,
                    mfa_registered=mfa_registered,
                    mfa_methods=mfa_methods,
                    assigned_roles=user_roles_map.get(uid, []),
                    assigned_licenses=licenses,
                    group_memberships=groups,
                    department=u.get("department") or "Unassigned",
                    job_title=u.get("jobTitle") or "Unassigned",
                )
            )

        supports_ip, ip_note, risky_users, risky_sign_ins = self._fetch_identity_protection()
        ca_policies = self._fetch_conditional_access_policies()

        return TenantSnapshot(
            tenant_id=self.config.tenant_id,
            tenant_name=f"Live Test Tenant ({self.config.tenant_domain})",
            tenant_domain=self.config.tenant_domain,
            mode="live",
            captured_at=now_str,
            supports_identity_protection=supports_ip,
            identity_protection_status_note=ip_note,
            users=users,
            roles=roles,
            risky_users=risky_users,
            risky_sign_ins=risky_sign_ins,
            conditional_access_policies=ca_policies,
        )
