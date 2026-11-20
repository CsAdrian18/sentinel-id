"""
Sentinel ID — Interactive Streamlit Security Dashboard

Launch with:
    streamlit run app.py
"""

from __future__ import annotations

import json
import pandas as pd
import plotly.express as px
import streamlit as st

from sentinel_id.ai_advisor import GeminiSecurityAdvisor
from sentinel_id.auditor import EntraAuditor
from sentinel_id.config import (
    READ_ONLY_GRAPH_PERMISSIONS,
    WRITE_GRAPH_PERMISSIONS_DOC,
    SentinelConfig,
)
from sentinel_id.exporter import ReportExporter
from sentinel_id.graph_client import EntraGraphClient, GraphClientError
from sentinel_id.mock_data import generate_mock_tenant
from sentinel_id.models import AuditReport, TenantSnapshot
from sentinel_id.remediation import RemediationEngine

st.set_page_config(
    page_title="Sentinel ID | Entra ID Identity Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def _init_session_state() -> None:
    if "demo_snapshot" not in st.session_state:
        st.session_state.demo_snapshot = generate_mock_tenant(supports_identity_protection=True)
    if "last_remediation_msg" not in st.session_state:
        st.session_state.last_remediation_msg = None


def _load_snapshot_and_report(
    mode: str,
    stale_days: int,
    max_ga: int,
    simulate_p2: bool,
) -> tuple[TenantSnapshot, AuditReport, SentinelConfig]:
    config = SentinelConfig()
    config.mode = mode
    config.stale_days_threshold = stale_days
    config.max_global_admins = max_ga

    if mode == "demo":
        snapshot = st.session_state.demo_snapshot
        if snapshot.supports_identity_protection != simulate_p2:
            snapshot = generate_mock_tenant(supports_identity_protection=simulate_p2)
            st.session_state.demo_snapshot = snapshot
    else:
        client = EntraGraphClient(config)
        snapshot = client.fetch_tenant_snapshot()

    auditor = EntraAuditor(config=config)
    report = auditor.run_full_audit(snapshot)

    advisor = GeminiSecurityAdvisor(config=config)
    advisor.generate_executive_summary(report, snapshot=snapshot)
    return snapshot, report, config


def main() -> None:
    _init_session_state()

    # --- Sidebar Controls ---
    with st.sidebar:
        st.markdown("## 🛡️ Sentinel ID")
        st.caption("AI-Assisted Identity Security Auditor for Microsoft Entra ID")
        st.divider()

        mode_label = st.radio(
            "Operating Mode",
            options=["Demo Mode (Mock Tenant — Zero Cloud)", "Live Mode (Personal Test Tenant)"],
            index=0,
            help="Demo Mode runs 100% locally with mock Entra ID data. Live Mode connects strictly Read-Only to your personal test tenant.",
        )
        mode = "demo" if mode_label.startswith("Demo") else "live"

        stale_days = st.slider(
            "Stale Account Threshold (Days)",
            min_value=30,
            max_value=180,
            value=90,
            step=15,
            help="Accounts with no sign-in activity for this many days are flagged as stale.",
        )
        max_ga = st.number_input(
            "Max Recommended Global Admins",
            min_value=2,
            max_value=10,
            value=4,
            help="Microsoft recommends between 2 and 4 Global Administrators.",
        )

        simulate_p2 = True
        if mode == "demo":
            simulate_p2 = st.checkbox(
                "Simulate Entra ID P2 License (Identity Protection)",
                value=True,
                help="Uncheck to test graceful skipping of Check 4 when a tenant lacks P2 licensing.",
            )
            if st.button("🔄 Reset Demo Tenant Data", use_container_width=True):
                st.session_state.demo_snapshot = generate_mock_tenant(
                    supports_identity_protection=simulate_p2
                )
                st.session_state.last_remediation_msg = None
                st.rerun()

        st.divider()
        st.markdown("### 🔒 Security Posture Guardrails")
        st.success("**Default Access:** Strictly `READ-ONLY`")
        st.info("**AI Privacy:** Deterministic PII Redaction (`HMAC-SHA256`) before Gemini API")
        st.warning("**Remediation:** Off by default • Dry-Run First • Per-Action Typed Approval")

    # --- Load Snapshot & Execute Audit ---
    try:
        snapshot, report, config = _load_snapshot_and_report(
            mode=mode,
            stale_days=stale_days,
            max_ga=int(max_ga),
            simulate_p2=simulate_p2,
        )
    except GraphClientError as exc:
        st.error(f"### Live Mode Connection Blocked\n{exc}")
        st.info(
            "Tip: Switch back to **Demo Mode** in the sidebar to explore the full app with zero cloud access, "
            "or configure your personal test tenant credentials in `.env`."
        )
        return

    # --- Top Banner & KPIs ---
    st.title("🛡️ Sentinel ID — Entra ID Identity Security Auditor")
    st.markdown(
        f"**Tenant:** `{report.tenant_name}` (`{report.tenant_domain}`) &nbsp;|&nbsp; "
        f"**Mode:** `{report.mode.upper()}` (Read-Only Default) &nbsp;|&nbsp; "
        f"**Captured:** `{report.generated_at}`"
    )

    active_users = [u for u in snapshot.users if u.account_enabled]
    mfa_registered_active = [u for u in active_users if u.mfa_registered]
    mfa_pct = (
        int(round((len(mfa_registered_active) / len(active_users)) * 100))
        if active_users
        else 100
    )

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric(
        "Overall Risk Score",
        f"{report.overall_risk_score} / 100",
        delta=f"Posture Grade: {report.security_posture_grade}",
        delta_color="inverse",
    )
    col2.metric("High Severity Findings", len(report.high_findings))
    col3.metric("Medium Severity Findings", len(report.medium_findings))
    col4.metric("Low Severity Findings", len(report.low_findings))
    col5.metric("Active User MFA Coverage", f"{mfa_pct}%", f"{len(mfa_registered_active)}/{len(active_users)} active")

    if report.skipped_checks:
        for skip_note in report.skipped_checks:
            st.warning(f"ℹ️ **Graceful License Degradation:** {skip_note}")

    # --- Visual Charts Row ---
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        sev_df = pd.DataFrame(
            [
                {"Severity": "High", "Count": len(report.high_findings)},
                {"Severity": "Medium", "Count": len(report.medium_findings)},
                {"Severity": "Low", "Count": len(report.low_findings)},
            ]
        )
        fig_sev = px.bar(
            sev_df,
            x="Severity",
            y="Count",
            color="Severity",
            title="Findings by Severity Level",
            color_discrete_map={"High": "#dc2626", "Medium": "#d97706", "Low": "#2563eb"},
            text_auto=True,
        )
        fig_sev.update_layout(height=340, showlegend=False)
        st.plotly_chart(fig_sev, use_container_width=True)

    with chart_col2:
        cat_counts: dict[str, int] = {}
        for f in report.findings:
            cat_counts[f.category.value] = cat_counts.get(f.category.value, 0) + 1
        cat_df = pd.DataFrame(
            [{"Check Category": k, "Findings": v} for k, v in cat_counts.items()]
        )
        if not cat_df.empty:
            fig_cat = px.bar(
                cat_df,
                x="Findings",
                y="Check Category",
                orientation="h",
                title="Findings Across All 7 Audit Checks",
                color="Findings",
                color_continuous_scale="Reds",
                text_auto=True,
            )
            fig_cat.update_layout(height=340, yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig_cat, use_container_width=True)

    # --- Main Navigation Tabs ---
    tab_ai, tab_findings, tab_remediate, tab_export = st.tabs(
        [
            "🤖 AI Executive Brief & PII Redaction Gate",
            "🔍 Detailed Audit Findings (7 Checks)",
            "🛠️ Approval-Gated Remediation (Dry-Run First)",
            "📄 Export Report & Audit Trail",
        ]
    )

    # =========================================================================
    # TAB 1: AI Executive Summary & PII Redaction Inspector
    # =========================================================================
    with tab_ai:
        st.subheader("Plain-English Executive Brief (For Non-Technical Leadership)")
        st.caption(f"Engine: `{report.ai_model_used}`")
        st.markdown(report.ai_executive_summary)

        st.divider()
        with st.expander("🔐 Inspect Anonymized Payload Sent to Gemini (PII Redaction Proof)", expanded=False):
            st.markdown(
                "Before calling the Gemini model, Sentinel ID passes every finding through "
                "`PIIRedactor`. All user display names, email addresses, UPNs, IP addresses, "
                "and object GUIDs are replaced with deterministic salted HMAC-SHA256 tokens "
                "(` [UPN_XXXXXXXX] `, ` [USER_XXXXXXXX] `, ` [IP_XXXXXXXX] `)."
            )
            st.json(report.redacted_payload_preview)

    # =========================================================================
    # TAB 2: Detailed Audit Findings Explorer
    # =========================================================================
    with tab_findings:
        st.subheader("Audit Findings Explorer")
        f_col1, f_col2 = st.columns(2)
        with f_col1:
            selected_severities = st.multiselect(
                "Filter by Severity",
                options=["High", "Medium", "Low"],
                default=["High", "Medium", "Low"],
            )
        with f_col2:
            all_categories = sorted({f.category.value for f in report.findings})
            selected_categories = st.multiselect(
                "Filter by Audit Check Category",
                options=all_categories,
                default=all_categories,
            )

        filtered = [
            f
            for f in report.findings
            if f.severity.value in selected_severities and f.category.value in selected_categories
        ]

        st.markdown(f"Showing **{len(filtered)}** of **{len(report.findings)}** findings.")
        for finding in filtered:
            badge = (
                "🔴 HIGH"
                if finding.severity.value == "High"
                else "🟠 MEDIUM"
                if finding.severity.value == "Medium"
                else "🔵 LOW"
            )
            principal = finding.affected_upn or finding.affected_resource_id
            with st.expander(
                f"{badge} | {finding.finding_id} — {finding.title} ({principal})",
                expanded=(finding.severity.value == "High"),
            ):
                st.markdown(f"**Check Category:** `{finding.category.value}`")
                st.markdown(f"**Affected Principal / Resource:** `{principal}`")
                if finding.affected_display_name:
                    st.markdown(f"**Display Name:** `{finding.affected_display_name}`")
                st.markdown(f"**Technical Finding:** {finding.description}")
                st.markdown(f"**Business & Security Impact:** {finding.impact}")
                st.markdown(f"**Recommended Action:** {finding.recommendation}")
                if finding.remediation:
                    st.info(
                        f"**Approval-Gated Remediation Available (`{finding.remediation.action_id}`):** "
                        f"`{finding.remediation.http_method} {finding.remediation.graph_endpoint}` "
                        f"*(Requires separate `{finding.remediation.required_write_permission}` permission and explicit typed approval in the Remediation tab)*."
                    )

    # =========================================================================
    # TAB 3: Approval-Gated Remediation Console (Dry-Run First)
    # =========================================================================
    with tab_remediate:
        st.subheader("Human-in-the-Loop Remediation Console")
        st.markdown(
            "Sentinel ID is **Read-Only by default**. Remediation actions are optional, "
            "**always run a Dry-Run preview first**, and **require explicit typed approval per action**."
        )

        if st.session_state.last_remediation_msg:
            st.success(st.session_state.last_remediation_msg)

        unlock_remediation = st.toggle(
            "🔓 Unlock Remediation Review & Dry-Run Console",
            value=False,
            help="Unlocks dry-run previews and per-action typed confirmation gates.",
        )

        if not unlock_remediation:
            st.info(
                "Remediation controls are currently **LOCKED (Read-Only Mode)**. "
                "Toggle the switch above to inspect dry-run Graph API calls and approve individual actions."
            )
        else:
            engine = RemediationEngine(config=config)
            proposals = report.remediation_proposals
            if not proposals:
                st.success("No pending remediation actions!")
            else:
                st.markdown(f"**{len(proposals)}** optional remediation actions available for dry-run review:")
                for prop in proposals:
                    with st.container(border=True):
                        st.markdown(
                            f"#### `{prop.action_id}` — {prop.summary} "
                            f"(Finding `{prop.finding_id}`)"
                        )
                        c1, c2 = st.columns([2, 1])
                        with c1:
                            st.markdown(
                                f"- **Target Principal:** `{prop.target_display_name}` (`{prop.target_upn}`)\n"
                                f"- **Action Type:** `{prop.action_type.value}`\n"
                                f"- **Microsoft Graph Endpoint:** `{prop.http_method} {prop.graph_endpoint}`\n"
                                f"- **Request Payload:** `{json.dumps(prop.request_body)}`\n"
                                f"- **Required Write Permission:** `{prop.required_write_permission}` *(Not requested by default)*"
                            )
                        with c2:
                            st.markdown("**State Diff (Pre → Post):**")
                            st.code(
                                f"BEFORE: {json.dumps(prop.pre_state)}\n"
                                f"AFTER:  {json.dumps(prop.post_state)}",
                                language="json",
                            )

                        # Step 1: Run Dry-Run Preview button
                        dry_key = f"dry_done_{prop.action_id}"
                        if st.button(
                            f"1️⃣ Run Dry-Run Preview ({prop.action_id})",
                            key=f"btn_dry_{prop.action_id}",
                        ):
                            preview = engine.preview_dry_run(prop, mode=report.mode)
                            st.session_state[dry_key] = preview

                        if dry_key in st.session_state:
                            preview = st.session_state[dry_key]
                            st.warning(
                                f"**Dry-Run Complete & Logged.** No changes have been applied yet.\n\n"
                                f"To authorize execution of `{preview.http_method} {preview.graph_endpoint}`, "
                                f"type **`{preview.required_confirmation_phrase}`** below:"
                            )
                            typed_val = st.text_input(
                                f"Type `{preview.required_confirmation_phrase}` to confirm:",
                                key=f"input_confirm_{prop.action_id}",
                                placeholder=preview.required_confirmation_phrase,
                            )
                            if st.button(
                                f"2️⃣ Execute Approved Action ({prop.action_id})",
                                key=f"btn_exec_{prop.action_id}",
                                type="primary",
                            ):
                                res = engine.execute_with_approval(
                                    proposal=prop,
                                    typed_confirmation=typed_val,
                                    mode=report.mode,
                                    snapshot=snapshot,
                                )
                                if res.status.startswith("EXECUTED"):
                                    st.session_state.last_remediation_msg = (
                                        f"{res.message} (Audit log timestamp: {res.timestamp})"
                                    )
                                    del st.session_state[dry_key]
                                    st.rerun()
                                else:
                                    st.error(res.message)

    # =========================================================================
    # TAB 4: Export Report (Markdown / PDF) & Immutable Audit Trail
    # =========================================================================
    with tab_export:
        st.subheader("Export Identity Security Audit Report")
        md_content = ReportExporter.to_markdown(report)
        pdf_bytes = ReportExporter.to_pdf_bytes(report)

        dl_col1, dl_col2 = st.columns(2)
        with dl_col1:
            st.download_button(
                label="📥 Download Report as Markdown (.md)",
                data=md_content.encode("utf-8"),
                file_name=f"sentinel_id_audit_{report.mode}.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with dl_col2:
            st.download_button(
                label="📕 Download Report as PDF (.pdf)",
                data=pdf_bytes,
                file_name=f"sentinel_id_audit_{report.mode}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        st.divider()
        st.subheader("📜 Immutable Remediation Audit Log (`logs/remediation_audit.log`)")
        engine = RemediationEngine(config=config)
        log_entries = engine.read_audit_log()
        if not log_entries:
            st.caption("No dry-run or remediation actions logged yet in this session.")
        else:
            st.dataframe(pd.DataFrame(log_entries), use_container_width=True)

        st.divider()
        p_col1, p_col2 = st.columns(2)
        with p_col1:
            st.markdown("#### ✅ Default Read-Only Graph Permissions (Least Privilege)")
            for perm in READ_ONLY_GRAPH_PERMISSIONS:
                st.markdown(f"- `{perm}`")
        with p_col2:
            st.markdown("#### ⚠️ Separate Write Permissions (Remediation Only — Not Requested by Default)")
            for wperm in WRITE_GRAPH_PERMISSIONS_DOC:
                st.markdown(f"- `{wperm}`")


if __name__ == "__main__":
    main()
