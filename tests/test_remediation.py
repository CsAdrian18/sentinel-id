"""
Unit tests for approval-gated remediation, dry-run enforcement, audit logging,
and Markdown/PDF report export.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sentinel_id.ai_advisor import GeminiSecurityAdvisor
from sentinel_id.auditor import EntraAuditor
from sentinel_id.config import SentinelConfig
from sentinel_id.exporter import ReportExporter
from sentinel_id.mock_data import generate_mock_tenant
from sentinel_id.remediation import RemediationEngine


def test_remediation_dry_run_and_approval_gate(tmp_path: Path) -> None:
    now = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
    snapshot = generate_mock_tenant(reference_now=now)
    auditor = EntraAuditor(reference_now=now)
    report = auditor.run_full_audit(snapshot)

    log_file = tmp_path / "remediation_audit.log"
    cfg = SentinelConfig(audit_log_path=log_file, allow_remediation=False)
    engine = RemediationEngine(config=cfg, audit_log_path=log_file)

    stale_proposal = next(
        p
        for p in report.remediation_proposals
        if p.action_type.value == "disable_stale_account"
        and p.target_upn == "hannah.abbott@northwindlab.onmicrosoft.com"
    )

    # 1. Dry-run preview must NOT mutate user state and must write a DRY_RUN audit log entry
    preview = engine.preview_dry_run(stale_proposal, mode="demo")
    assert preview.required_confirmation_phrase == "APPROVE hannah.abbott@northwindlab.onmicrosoft.com"
    hannah_user = next(u for u in snapshot.users if u.id == stale_proposal.target_user_id)
    assert hannah_user.account_enabled is True

    # 2. Wrong typed confirmation must be REJECTED and leave account enabled
    bad_result = engine.execute_with_approval(
        proposal=stale_proposal,
        typed_confirmation="yes please",
        mode="demo",
        snapshot=snapshot,
    )
    assert bad_result.status == "REJECTED"
    assert hannah_user.account_enabled is True

    # 3. Exact typed confirmation must execute in demo mode and disable the stale account
    good_result = engine.execute_with_approval(
        proposal=stale_proposal,
        typed_confirmation="APPROVE hannah.abbott@northwindlab.onmicrosoft.com",
        mode="demo",
        snapshot=snapshot,
    )
    assert good_result.status == "EXECUTED_DEMO"
    assert hannah_user.account_enabled is False

    # 4. Verify all 3 events (DRY_RUN, REJECTED, EXECUTED_DEMO) were logged with UTC timestamps
    entries = engine.read_audit_log()
    assert len(entries) == 3
    assert [e["status"] for e in entries] == ["DRY_RUN", "REJECTED", "EXECUTED_DEMO"]
    assert all("timestamp_utc" in e for e in entries)


def test_report_exporter_markdown_and_pdf(tmp_path: Path) -> None:
    now = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
    snapshot = generate_mock_tenant(reference_now=now)
    auditor = EntraAuditor(reference_now=now)
    report = auditor.run_full_audit(snapshot)

    advisor = GeminiSecurityAdvisor()
    advisor.generate_executive_summary(report, snapshot=snapshot, force_offline=True)

    md_path = ReportExporter.save_markdown(report, tmp_path / "report.md")
    pdf_path = ReportExporter.save_pdf(report, tmp_path / "report.pdf")

    assert md_path.exists()
    assert "Top 5 Priorities to Fix and Why" in md_path.read_text(encoding="utf-8")
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF")
