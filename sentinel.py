#!/usr/bin/env python3
"""
Sentinel ID — Command-Line Interface (CLI)

Usage examples:
  python sentinel.py --demo
  python sentinel.py --demo --stale-days 60 --export-md reports/audit.md --export-pdf reports/audit.pdf
  python sentinel.py --demo --no-p2-license
  python sentinel.py --demo --remediate
  python sentinel.py --live
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from sentinel_id.ai_advisor import GeminiSecurityAdvisor
from sentinel_id.auditor import EntraAuditor
from sentinel_id.config import READ_ONLY_GRAPH_PERMISSIONS, WRITE_GRAPH_PERMISSIONS_DOC, SentinelConfig
from sentinel_id.exporter import ReportExporter
from sentinel_id.graph_client import EntraGraphClient, GraphClientError
from sentinel_id.mock_data import generate_mock_tenant
from sentinel_id.models import AuditReport, Severity, TenantSnapshot
from sentinel_id.remediation import RemediationEngine

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel.py",
        description="Sentinel ID — AI-Assisted Identity Security Auditor for Microsoft Entra ID",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--demo",
        action="store_true",
        help="Run in Demo Mode using realistic mock Entra ID tenant data (default; zero cloud access).",
    )
    mode_group.add_argument(
        "--live",
        action="store_true",
        help="Connect to a personal test Entra ID tenant configured in .env (Read-Only by default).",
    )
    parser.add_argument(
        "--stale-days",
        type=int,
        default=None,
        help="Override stale account inactivity threshold in days (default: 90).",
    )
    parser.add_argument(
        "--no-p2-license",
        action="store_true",
        help="In Demo Mode, simulate a tenant without Entra ID P2 licensing to test graceful skipping of Check 4.",
    )
    parser.add_argument(
        "--show-redacted",
        action="store_true",
        help="Print a preview of the PII-redacted JSON payload sent to the Gemini AI model.",
    )
    parser.add_argument(
        "--remediate",
        action="store_true",
        help="Launch interactive approval-gated remediation mode (runs Dry-Run first; requires typed confirmation per action).",
    )
    parser.add_argument(
        "--export-md",
        type=str,
        default=None,
        help="Export the full audit report to a Markdown (.md) file at the given path.",
    )
    parser.add_argument(
        "--export-pdf",
        type=str,
        default=None,
        help="Export the full audit report to a PDF (.pdf) file at the given path.",
    )
    return parser


def _severity_badge(sev: Severity) -> str:
    if sev == Severity.HIGH:
        return "[bold white on red] HIGH [/]"
    if sev == Severity.MEDIUM:
        return "[bold black on yellow] MEDIUM [/]"
    return "[bold white on blue] LOW [/]"


def render_cli_report(report: AuditReport, show_redacted: bool = False) -> None:
    """Render the audit report, findings table, and AI executive summary in the terminal."""
    grade_color = "red" if report.overall_risk_score >= 60 else "yellow" if report.overall_risk_score >= 30 else "green"
    header_text = (
        f"[bold cyan]Tenant:[/] {report.tenant_name} ([italic]{report.tenant_domain}[/])\n"
        f"[bold cyan]Mode:[/] {report.mode.upper()} (Read-Only Default)   |   "
        f"[bold cyan]Stale Threshold:[/] {report.stale_days_threshold} days\n"
        f"[bold cyan]Identity Protection:[/] {report.identity_protection_note}\n"
        f"[bold cyan]Overall Risk Score:[/] [{grade_color} bold]{report.overall_risk_score}/100 "
        f"(Posture Grade: {report.security_posture_grade})[/]   |   "
        f"[bold red]High: {len(report.high_findings)}[/]  "
        f"[bold yellow]Medium: {len(report.medium_findings)}[/]  "
        f"[bold blue]Low: {len(report.low_findings)}[/]  "
        f"(Total: {len(report.findings)})"
    )
    console.print(Panel(header_text, title="[bold]Sentinel ID — Entra ID Identity Security Auditor[/]", border_style="cyan"))

    if report.skipped_checks:
        for note in report.skipped_checks:
            console.print(f"[yellow]Notice:[/] {note}")

    table = Table(title="Identity Security Audit Findings (All 7 Checks)", show_lines=True)
    table.add_column("ID", style="bold", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Check Category", style="cyan", width=28)
    table.add_column("Finding & Principal", width=48)
    table.add_column("Approval-Gated Dry-Run Action", width=28)

    for f in report.findings:
        principal = f.affected_upn or f.affected_resource_id
        rem_str = (
            f"[green]{f.remediation.action_type.value}[/]\n`{f.remediation.http_method} {f.remediation.graph_endpoint}`"
            if f.remediation
            else "[dim]Read-Only / Policy Review[/]"
        )
        table.add_row(
            f.finding_id,
            _severity_badge(f.severity),
            f.category.value,
            f"[bold]{f.title}[/]\n[dim]Target:[/] {principal}",
            rem_str,
        )

    console.print(table)

    if show_redacted and report.redacted_payload_preview:
        sample = {
            "anonymized_tenant_token": report.redacted_payload_preview.get("anonymized_tenant_token"),
            "severity_summary": report.redacted_payload_preview.get("severity_summary"),
            "sample_redacted_findings": report.redacted_payload_preview.get("anonymized_findings", [])[:3],
        }
        console.print(
            Panel(
                json.dumps(sample, indent=2),
                title="[bold magenta]PII Redaction Gate Preview (Anonymized Payload Sent to Gemini)[/]",
                border_style="magenta",
            )
        )

    console.print(
        Panel(
            Markdown(report.ai_executive_summary),
            title=f"[bold green]AI Executive Summary — {report.ai_model_used}[/]",
            border_style="green",
        )
    )


def run_interactive_remediation(
    report: AuditReport,
    snapshot: TenantSnapshot,
    config: SentinelConfig,
    live_token: Optional[str] = None,
) -> None:
    """
    Run interactive approval-gated remediation in the CLI:
    1. Always runs a Dry-Run preview first
    2. Shows exact HTTP call, payload, pre/post state, and required write permission
    3. Requires typing `APPROVE <target_upn>` per action (or pressing Enter to skip)
    4. Logs every action to `logs/remediation_audit.log`
    """
    proposals = report.remediation_proposals
    if not proposals:
        console.print("[green]No actionable remediation proposals found.[/]")
        return

    engine = RemediationEngine(config=config)
    console.print(
        Panel(
            "[bold yellow]HUMAN-IN-THE-LOOP REMEDIATION GATE[/]\n"
            "Every proposed remediation runs as a [bold]DRY RUN FIRST[/].\n"
            "To execute an action, you must type the exact confirmation phrase shown.\n"
            "Press [bold]Enter[/] to skip an action, or type [bold]q[/] to quit remediation review.\n"
            f"All events are logged with UTC timestamps to: [cyan]{engine.audit_log_path}[/]",
            border_style="yellow",
        )
    )

    for idx, prop in enumerate(proposals, start=1):
        preview = engine.preview_dry_run(prop, mode=report.mode)
        dry_run_card = (
            f"[bold]Action {idx}/{len(proposals)}:[/] {preview.action_id} ({preview.action_type})\n"
            f"[bold]Related Finding:[/] {preview.finding_id} — {preview.summary}\n"
            f"[bold]Target Principal:[/] {preview.target_display_name} ([cyan]{preview.target_upn}[/])\n"
            f"[bold]Dry-Run Graph Call:[/] [bold magenta]{preview.http_method} {preview.graph_endpoint}[/]\n"
            f"[bold]Request Payload:[/] `{json.dumps(preview.request_body)}`\n"
            f"[bold]Pre-Change State:[/]  `{json.dumps(preview.pre_state)}`\n"
            f"[bold]Post-Change State:[/] `{json.dumps(preview.post_state)}`\n"
            f"[bold]Write Permission Required:[/] `{preview.required_write_permission}`\n\n"
            f"To approve, type exactly: [bold green]{preview.required_confirmation_phrase}[/]"
        )
        console.print(Panel(dry_run_card, title=f"[bold]DRY-RUN PREVIEW — {preview.action_id}[/]", border_style="magenta"))

        try:
            user_input = console.input("Confirmation (or Enter to skip, 'q' to exit): ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Exiting interactive remediation.[/]")
            break

        if user_input.lower() == "q":
            console.print("[yellow]Remediation review terminated by operator.[/]")
            break
        if not user_input:
            console.print(f"[dim]Skipped {preview.action_id} (remained in Dry-Run state).[/]\n")
            continue

        result = engine.execute_with_approval(
            proposal=prop,
            typed_confirmation=user_input,
            mode=report.mode,
            snapshot=snapshot,
            live_access_token=live_token,
        )
        if result.status.startswith("EXECUTED"):
            console.print(f"[bold green]✓ {result.message}[/] (Logged at {result.timestamp})\n")
        else:
            console.print(f"[bold red]✗ {result.message}[/] (Logged at {result.timestamp})\n")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = SentinelConfig()
    if args.live:
        config.mode = "live"
    elif args.demo:
        config.mode = "demo"

    if args.stale_days is not None:
        config.stale_days_threshold = args.stale_days

    live_token: Optional[str] = None
    if config.mode == "live":
        console.print(
            Panel(
                "[bold yellow]LIVE MODE SAFETY NOTICE[/]\n"
                "Connecting ONLY to your configured personal test Entra ID tenant in READ-ONLY mode.\n"
                f"Least-Privilege Read-Only Scopes: {', '.join(READ_ONLY_GRAPH_PERMISSIONS)}\n"
                f"Separate Write Scopes (Not requested by default): {', '.join(WRITE_GRAPH_PERMISSIONS_DOC)}",
                border_style="yellow",
            )
        )
        client = EntraGraphClient(config)
        try:
            live_token = client.authenticate()
            snapshot = client.fetch_tenant_snapshot()
        except GraphClientError as exc:
            console.print(f"[bold red]Live Mode Connection Error:[/] {exc}")
            return 1
    else:
        snapshot = generate_mock_tenant(
            supports_identity_protection=not args.no_p2_license
        )

    auditor = EntraAuditor(config=config)
    report = auditor.run_full_audit(snapshot)

    advisor = GeminiSecurityAdvisor(config=config)
    advisor.generate_executive_summary(report, snapshot=snapshot)

    render_cli_report(report, show_redacted=args.show_redacted)

    if args.export_md:
        md_path = ReportExporter.save_markdown(report, args.export_md)
        console.print(f"[bold green]✓ Exported Markdown report to:[/] {md_path}")

    if args.export_pdf:
        pdf_path = ReportExporter.save_pdf(report, args.export_pdf)
        console.print(f"[bold green]✓ Exported PDF report to:[/] {pdf_path}")

    if args.remediate:
        run_interactive_remediation(report, snapshot, config, live_token=live_token)

    return 0


if __name__ == "__main__":
    sys.exit(main())
