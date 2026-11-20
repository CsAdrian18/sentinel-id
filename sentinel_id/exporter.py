"""
Report Exporter for Sentinel ID (Markdown & PDF).

Exports comprehensive identity security audit reports including:
- Overall Risk Score & Security Posture Grade
- Executive AI Summary ("Top 5 things to fix and why")
- Findings breakdown by severity (High / Medium / Low) and check category
- Approval-gated remediation dry-run plan
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

from fpdf import FPDF

from sentinel_id.models import AuditReport


def _ascii_safe(text: str) -> str:
    """Normalize Unicode punctuation to Latin-1 safe characters for standard PDF fonts."""
    replacements = {
        "\u2014": "--",
        "\u2013": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2022": "*",
        "\u2026": "...",
        "\u2192": "->",
        "\u2265": ">=",
    }
    out = text
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out.encode("latin-1", errors="replace").decode("latin-1")


class ReportExporter:
    """Generates Markdown (.md) and PDF (.pdf) reports from an AuditReport."""

    @staticmethod
    def to_markdown(report: AuditReport) -> str:
        """Render the AuditReport as a structured Markdown document."""
        lines = [
            "# Sentinel ID — Microsoft Entra ID Identity Security Audit Report",
            "",
            f"- **Tenant Name:** {report.tenant_name}",
            f"- **Tenant Domain:** `{report.tenant_domain}`",
            f"- **Execution Mode:** `{report.mode.upper()}` (Read-Only Default)",
            f"- **Generated At (UTC):** `{report.generated_at}`",
            f"- **Stale Account Threshold:** `{report.stale_days_threshold} days`",
            f"- **Overall Risk Score:** **{report.overall_risk_score} / 100** (Posture Grade: **{report.security_posture_grade}**)",
            f"- **AI Advisor Engine:** `{report.ai_model_used or 'PII-Redacted Advisor'}`",
            "",
            "## 1. Severity Summary",
            "",
            "| Severity | Finding Count |",
            "|---|---|",
            f"| **High** | {len(report.high_findings)} |",
            f"| **Medium** | {len(report.medium_findings)} |",
            f"| **Low** | {len(report.low_findings)} |",
            f"| **Total Findings** | **{len(report.findings)}** |",
            "",
        ]

        if report.skipped_checks:
            lines.append("## Skipped Checks / Licensing Notes")
            lines.append("")
            for note in report.skipped_checks:
                lines.append(f"- {note}")
            lines.append("")

        lines.extend(
            [
                "## 2. AI Executive Summary (Generated from PII-Redacted Findings)",
                "",
                report.ai_executive_summary or "*No AI summary generated.*",
                "",
                "---",
                "",
                "## 3. Detailed Technical Findings",
                "",
            ]
        )

        for idx, f in enumerate(report.findings, start=1):
            lines.extend(
                [
                    f"### {idx}. [{f.severity.value.upper()}] {f.finding_id} — {f.title}",
                    f"- **Check Category:** {f.category.value}",
                    f"- **Affected Principal / Resource:** `{f.affected_upn or f.affected_resource_id}`",
                    f"- **Finding Details:** {f.description}",
                    f"- **Business & Security Impact:** {f.impact}",
                    f"- **Recommended Fix:** {f.recommendation}",
                ]
            )
            if f.remediation:
                rem = f.remediation
                lines.extend(
                    [
                        f"- **Optional Approval-Gated Remediation (`{rem.action_id}`):**",
                        f"  - **Dry-Run Graph Call:** `{rem.http_method} {rem.graph_endpoint}`",
                        f"  - **Required Write Permission:** `{rem.required_write_permission}` (Not requested by default)",
                        f"  - **Human Approval Gate:** Requires typing `APPROVE {rem.target_upn}`",
                    ]
                )
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def save_markdown(cls, report: AuditReport, output_path: Union[str, Path]) -> Path:
        """Write the Markdown report to disk and return its Path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cls.to_markdown(report), encoding="utf-8")
        return path

    @classmethod
    def to_pdf_bytes(cls, report: AuditReport) -> bytes:
        """Render the AuditReport into a clean PDF document and return raw PDF bytes."""
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        usable_w = pdf.epw

        # Header Banner
        pdf.set_fill_color(15, 23, 42)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(
            usable_w,
            12,
            "Sentinel ID -- Entra ID Security Audit Report",
            new_x="LMARGIN",
            new_y="NEXT",
            fill=True,
        )
        pdf.ln(3)

        # Metadata Box
        pdf.set_text_color(30, 41, 59)
        pdf.set_font("Helvetica", "", 10)
        meta_lines = [
            f"Tenant: {report.tenant_name} ({report.tenant_domain})",
            f"Mode: {report.mode.upper()} (Read-Only Default)   |   Generated: {report.generated_at}",
            f"Overall Risk Score: {report.overall_risk_score}/100 (Posture Grade: {report.security_posture_grade})",
            f"Findings Breakdown: High={len(report.high_findings)} | Medium={len(report.medium_findings)} | Low={len(report.low_findings)} | Total={len(report.findings)}",
            f"AI Summary Engine: {report.ai_model_used or 'PII-Redacted Executive Advisor'}",
        ]
        for line in meta_lines:
            pdf.multi_cell(usable_w, 6, _ascii_safe(line), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # Executive Summary Section
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(
            usable_w,
            8,
            "1. Executive Summary (Top 5 Priorities -- PII Redacted)",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(51, 65, 85)

        summary_clean = (
            (report.ai_executive_summary or "No AI executive summary available.")
            .replace("### ", "")
            .replace("#### ", "")
            .replace("**", "")
        )
        for para in summary_clean.splitlines():
            stripped = para.strip()
            if not stripped or stripped == "---":
                pdf.ln(2)
                continue
            pdf.multi_cell(usable_w, 5, _ascii_safe(stripped), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # Findings Section
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(
            usable_w,
            8,
            "2. Detailed Security Findings & Approval-Gated Remediations",
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.ln(2)

        for idx, f in enumerate(report.findings, start=1):
            pdf.set_font("Helvetica", "B", 10)
            if f.severity.value == "High":
                pdf.set_text_color(185, 28, 28)
            elif f.severity.value == "Medium":
                pdf.set_text_color(180, 83, 9)
            else:
                pdf.set_text_color(29, 78, 216)

            header = f"{idx}. [{f.severity.value.upper()}] {f.finding_id}: {f.title}"
            pdf.multi_cell(usable_w, 5.5, _ascii_safe(header), new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(51, 65, 85)
            body_lines = [
                f"Category: {f.category.value}",
                f"Principal / Resource: {f.affected_upn or f.affected_resource_id}",
                f"Finding: {f.description}",
                f"Impact: {f.impact}",
                f"Recommendation: {f.recommendation}",
            ]
            if f.remediation:
                body_lines.append(
                    f"Optional Remediation (Dry-Run First): {f.remediation.http_method} "
                    f"{f.remediation.graph_endpoint} [Requires typing: APPROVE {f.remediation.target_upn}]"
                )
            for bl in body_lines:
                pdf.multi_cell(usable_w, 4.8, _ascii_safe(bl), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        return bytes(pdf.output())

    @classmethod
    def save_pdf(cls, report: AuditReport, output_path: Union[str, Path]) -> Path:
        """Write the PDF report to disk and return its Path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(cls.to_pdf_bytes(report))
        return path
