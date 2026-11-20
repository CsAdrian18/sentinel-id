"""
Unit tests for all 7 identity security audit checks in Sentinel ID.
Uses the realistic mock Entra ID tenant data from `sentinel_id.mock_data`.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinel_id.auditor import EntraAuditor
from sentinel_id.config import SentinelConfig
from sentinel_id.mock_data import generate_mock_tenant
from sentinel_id.models import CheckCategory, Severity


@pytest.fixture
def fixed_now() -> datetime:
    return datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def demo_snapshot(fixed_now: datetime):
    return generate_mock_tenant(reference_now=fixed_now, supports_identity_protection=True)


@pytest.fixture
def auditor(fixed_now: datetime) -> EntraAuditor:
    cfg = SentinelConfig(stale_days_threshold=90, max_global_admins=4)
    return EntraAuditor(config=cfg, reference_now=fixed_now)


def test_check_1_users_without_mfa(auditor: EntraAuditor, demo_snapshot) -> None:
    """Check 1: Flags active users (including privileged admins and guests) lacking MFA."""
    findings = auditor.check_users_without_mfa(demo_snapshot)
    assert len(findings) >= 5
    assert all(f.category == CheckCategory.MFA_COVERAGE for f in findings)

    flagged_upns = {f.affected_upn for f in findings}
    # Global Admin without MFA must be flagged as HIGH severity
    assert "marcus.vance@northwindlab.onmicrosoft.com" in flagged_upns
    marcus_finding = next(
        f for f in findings if f.affected_upn == "marcus.vance@northwindlab.onmicrosoft.com"
    )
    assert marcus_finding.severity == Severity.HIGH
    assert marcus_finding.remediation is not None

    # Disabled users should NOT be flagged in active MFA check
    assert "victor.doom@northwindlab.onmicrosoft.com" not in flagged_upns


def test_check_2_stale_accounts_default_and_configurable(
    fixed_now: datetime, demo_snapshot
) -> None:
    """Check 2: Flags enabled member accounts inactive for 90+ days (and respects custom threshold)."""
    auditor_90 = EntraAuditor(
        config=SentinelConfig(stale_days_threshold=90), reference_now=fixed_now
    )
    findings_90 = auditor_90.check_stale_accounts(demo_snapshot)
    assert len(findings_90) == 3
    assert all(f.category == CheckCategory.STALE_ACCOUNTS for f in findings_90)

    flagged_upns = {f.affected_upn for f in findings_90}
    assert "david.kim@northwindlab.onmicrosoft.com" in flagged_upns  # 142 days stale Global Admin
    assert "hannah.abbott@northwindlab.onmicrosoft.com" in flagged_upns  # 118 days stale
    assert "svc-legacy-sync@northwindlab.onmicrosoft.com" in flagged_upns  # Never signed in (165d old)

    # Tighten threshold to 30 days -> BreakGlass account (35 days since sign-in) should also be flagged
    auditor_30 = EntraAuditor(
        config=SentinelConfig(stale_days_threshold=30), reference_now=fixed_now
    )
    findings_30 = auditor_30.check_stale_accounts(demo_snapshot)
    assert len(findings_30) == 4
    assert "bg-admin01@northwindlab.onmicrosoft.com" in {f.affected_upn for f in findings_30}


def test_check_3_privileged_roles_and_excess_admins(
    auditor: EntraAuditor, demo_snapshot
) -> None:
    """Check 3: Flags >4 Global Administrators and risky standing privileged role assignments."""
    findings = auditor.check_privileged_roles(demo_snapshot)
    assert len(findings) >= 4
    assert all(f.category == CheckCategory.PRIVILEGED_ROLES for f in findings)

    # First finding must flag excess Global Admins (6 > recommended max 4)
    excess_admin_finding = findings[0]
    assert "Excessive Global Administrators" in excess_admin_finding.title
    assert excess_admin_finding.severity == Severity.HIGH
    assert excess_admin_finding.metadata["global_admin_count"] == 6

    # Individual role hygiene findings should propose REMOVE_FROM_ROLE remediation
    role_removals = [f for f in findings if f.remediation is not None]
    assert len(role_removals) >= 3
    assert any(
        f.affected_upn == "arthur.pendelton@northwindlab.onmicrosoft.com" for f in role_removals
    )


def test_check_4_risky_users_and_signins_with_p2_license(
    auditor: EntraAuditor, demo_snapshot
) -> None:
    """Check 4: Detects risky users and risky sign-ins when Identity Protection is supported."""
    findings, skip_note = auditor.check_risky_users_and_signins(demo_snapshot)
    assert skip_note is None
    assert len(findings) == 4
    assert all(f.category == CheckCategory.RISKY_SIGNINS_USERS for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_check_4_skips_gracefully_without_p2_license(fixed_now: datetime) -> None:
    """Check 4: Skips gracefully without errors when tenant license does not support Identity Protection."""
    snapshot_no_p2 = generate_mock_tenant(
        reference_now=fixed_now, supports_identity_protection=False
    )
    auditor = EntraAuditor(reference_now=fixed_now)
    findings, skip_note = auditor.check_risky_users_and_signins(snapshot_no_p2)

    assert findings == []
    assert skip_note is not None
    assert "skipped gracefully" in skip_note.lower()

    full_report = auditor.run_full_audit(snapshot_no_p2)
    assert len(full_report.skipped_checks) == 1
    assert "skipped gracefully" in full_report.skipped_checks[0].lower()


def test_check_5_old_or_inactive_guest_accounts(
    auditor: EntraAuditor, demo_snapshot
) -> None:
    """Check 5: Flags external B2B guest accounts that are old or inactive."""
    findings = auditor.check_guest_accounts(demo_snapshot)
    assert len(findings) == 2
    assert all(f.category == CheckCategory.GUEST_ACCOUNTS for f in findings)

    guest_upns = {f.affected_upn for f in findings}
    assert "jl.picard_starfleetpartner.com#EXT#@northwindlab.onmicrosoft.com" in guest_upns
    assert "d.scully_fbi-consulting.org#EXT#@northwindlab.onmicrosoft.com" in guest_upns


def test_check_6_conditional_access_gaps(auditor: EntraAuditor, demo_snapshot) -> None:
    """Check 6: Detects Report-Only Admin MFA, unblocked legacy auth, and excessive exclusions."""
    findings = auditor.check_conditional_access_gaps(demo_snapshot)
    assert len(findings) == 3
    assert all(f.category == CheckCategory.CONDITIONAL_ACCESS for f in findings)

    titles = " | ".join(f.title for f in findings)
    assert "Report-Only" in titles
    assert "Legacy authentication" in titles
    assert "Excessive user exclusions" in titles
    # Read-only review: Conditional Access findings never auto-mutate policy state
    assert all(f.remediation is None for f in findings)


def test_check_7_disabled_accounts_holding_licenses_or_groups(
    auditor: EntraAuditor, demo_snapshot
) -> None:
    """Check 7: Flags disabled accounts that still hold licenses or group memberships."""
    findings = auditor.check_disabled_accounts_hygiene(demo_snapshot)
    assert len(findings) == 2
    assert all(f.category == CheckCategory.DISABLED_ACCOUNT_HYGIENE for f in findings)

    flagged_upns = {f.affected_upn for f in findings}
    assert "victor.doom@northwindlab.onmicrosoft.com" in flagged_upns
    assert "samwise.gamgee@northwindlab.onmicrosoft.com" in flagged_upns


def test_full_audit_and_risk_score(auditor: EntraAuditor, demo_snapshot) -> None:
    """Verify full audit orchestration across all 7 checks and risk scoring."""
    report = auditor.run_full_audit(demo_snapshot)
    assert 0 <= report.overall_risk_score <= 100
    assert report.security_posture_grade in {"A", "B", "C", "D", "F"}
    assert len(report.findings) >= 20
    assert len(report.high_findings) > 0
    assert len(report.medium_findings) > 0
    assert len(report.low_findings) > 0
