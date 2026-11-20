"""
Approval-Gated Remediation Engine & Audit Logger for Sentinel ID.

SECURITY GUARANTEES:
1. Remediation is OFF by default (Sentinel ID operates strictly Read-Only).
2. Every remediation action MUST run as a Dry Run first (`preview_dry_run`),
   showing the exact HTTP verb, Microsoft Graph endpoint, JSON payload,
   required write permission, and Pre-State -> Post-State diff.
3. Execution requires an explicit, exact typed confirmation string per action:
   `APPROVE <target_upn>`
4. Every dry-run, approval, rejection, and execution is immutably logged with
   an ISO-8601 UTC timestamp to `logs/remediation_audit.log` (JSON Lines format).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from sentinel_id.config import SentinelConfig
from sentinel_id.graph_client import GRAPH_BASE_URL
from sentinel_id.models import RemediationProposal, TenantSnapshot


@dataclass
class DryRunPreview:
    """Detailed dry-run impact preview presented to the human operator before approval."""

    action_id: str
    action_type: str
    finding_id: str
    target_upn: str
    target_display_name: str
    summary: str
    http_method: str
    graph_endpoint: str
    request_body: Dict[str, Any]
    pre_state: Dict[str, Any]
    post_state: Dict[str, Any]
    required_write_permission: str
    required_confirmation_phrase: str


@dataclass
class RemediationResult:
    """Result of an approval-gated remediation attempt."""

    action_id: str
    status: str  # "DRY_RUN", "EXECUTED_DEMO", "EXECUTED_LIVE", "REJECTED", "ERROR"
    message: str
    timestamp: str
    audit_log_entry: Dict[str, Any]


class RemediationEngine:
    """
    Human-in-the-loop remediation engine with mandatory dry-run preview,
    typed confirmation verification, and append-only audit trail logging.
    """

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        audit_log_path: Optional[Path] = None,
    ) -> None:
        self.config = config or SentinelConfig()
        self.audit_log_path = audit_log_path or self.config.audit_log_path

    @staticmethod
    def expected_confirmation_phrase(proposal: RemediationProposal) -> str:
        """Return the exact string the human operator must type to approve an action."""
        return f"APPROVE {proposal.target_upn}"

    def _write_audit_log(
        self,
        proposal: RemediationProposal,
        event_type: str,
        status: str,
        mode: str,
        operator_input: str,
        details: str,
    ) -> Dict[str, Any]:
        """Append a timestamped JSONL audit record to the remediation audit log file."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = {
            "timestamp_utc": now_str,
            "event_type": event_type,
            "status": status,
            "mode": mode,
            "action_id": proposal.action_id,
            "finding_id": proposal.finding_id,
            "action_type": proposal.action_type.value,
            "target_user_id": proposal.target_user_id,
            "target_upn": proposal.target_upn,
            "http_method": proposal.http_method,
            "graph_endpoint": proposal.graph_endpoint,
            "request_body": proposal.request_body,
            "pre_state": proposal.pre_state,
            "post_state": proposal.post_state,
            "required_write_permission": proposal.required_write_permission,
            "operator_confirmation_typed": operator_input,
            "details": details,
        }

        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def preview_dry_run(
        self, proposal: RemediationProposal, mode: str = "demo"
    ) -> DryRunPreview:
        """
        Execute a non-destructive Dry Run first and record the dry-run preview in the audit log.
        No changes are made to either demo state or Microsoft Graph.
        """
        phrase = self.expected_confirmation_phrase(proposal)
        self._write_audit_log(
            proposal=proposal,
            event_type="DRY_RUN_PREVIEW",
            status="DRY_RUN",
            mode=mode,
            operator_input="[DRY-RUN-ONLY]",
            details=f"Dry-run preview generated. Awaiting human typed confirmation: '{phrase}'.",
        )
        return DryRunPreview(
            action_id=proposal.action_id,
            action_type=proposal.action_type.value,
            finding_id=proposal.finding_id,
            target_upn=proposal.target_upn,
            target_display_name=proposal.target_display_name,
            summary=proposal.summary,
            http_method=proposal.http_method,
            graph_endpoint=proposal.graph_endpoint,
            request_body=proposal.request_body,
            pre_state=proposal.pre_state,
            post_state=proposal.post_state,
            required_write_permission=proposal.required_write_permission,
            required_confirmation_phrase=phrase,
        )

    def execute_with_approval(
        self,
        proposal: RemediationProposal,
        typed_confirmation: str,
        mode: str = "demo",
        snapshot: Optional[TenantSnapshot] = None,
        live_access_token: Optional[str] = None,
    ) -> RemediationResult:
        """
        Verify explicit human approval (`APPROVE <target_upn>`) and execute the action.
        If confirmation does not match exactly, reject and log the rejection.
        """
        expected = self.expected_confirmation_phrase(proposal)
        cleaned_input = (typed_confirmation or "").strip()

        if cleaned_input != expected:
            entry = self._write_audit_log(
                proposal=proposal,
                event_type="APPROVAL_GATE_REJECTED",
                status="REJECTED",
                mode=mode,
                operator_input=cleaned_input,
                details=(
                    f"Action blocked by human approval gate. Expected '{expected}', "
                    f"received '{cleaned_input}'."
                ),
            )
            return RemediationResult(
                action_id=proposal.action_id,
                status="REJECTED",
                message=f"Approval rejected: you must type `{expected}` exactly to authorize this change.",
                timestamp=entry["timestamp_utc"],
                audit_log_entry=entry,
            )

        # In Demo Mode, simulate the state transition on the in-memory snapshot if provided
        if mode.lower() == "demo":
            if snapshot is not None:
                self._apply_demo_state_change(proposal, snapshot)

            msg = (
                f"[DEMO MODE] Approved & simulated `{proposal.http_method} {proposal.graph_endpoint}` "
                f"for `{proposal.target_upn}`."
            )
            entry = self._write_audit_log(
                proposal=proposal,
                event_type="REMEDIATION_EXECUTED",
                status="EXECUTED_DEMO",
                mode="demo",
                operator_input=cleaned_input,
                details=msg,
            )
            return RemediationResult(
                action_id=proposal.action_id,
                status="EXECUTED_DEMO",
                message=msg,
                timestamp=entry["timestamp_utc"],
                audit_log_entry=entry,
            )

        # In Live Mode, require both allow_remediation flag and a valid access token
        if not self.config.allow_remediation:
            entry = self._write_audit_log(
                proposal=proposal,
                event_type="LIVE_REMEDIATION_BLOCKED_BY_CONFIG",
                status="REJECTED",
                mode="live",
                operator_input=cleaned_input,
                details="Live remediation blocked because SENTINEL_ALLOW_REMEDIATION is false.",
            )
            return RemediationResult(
                action_id=proposal.action_id,
                status="REJECTED",
                message=(
                    "Live remediation is disabled by default (`SENTINEL_ALLOW_REMEDIATION=false`). "
                    "Set `SENTINEL_ALLOW_REMEDIATION=true` in `.env` and grant the documented write "
                    f"permission (`{proposal.required_write_permission}`) on your test tenant app registration."
                ),
                timestamp=entry["timestamp_utc"],
                audit_log_entry=entry,
            )

        if not live_access_token:
            entry = self._write_audit_log(
                proposal=proposal,
                event_type="LIVE_REMEDIATION_ERROR",
                status="ERROR",
                mode="live",
                operator_input=cleaned_input,
                details="Missing Microsoft Graph access token for live remediation.",
            )
            return RemediationResult(
                action_id=proposal.action_id,
                status="ERROR",
                message="Cannot execute live remediation without an authenticated Graph access token.",
                timestamp=entry["timestamp_utc"],
                audit_log_entry=entry,
            )

        url = f"{GRAPH_BASE_URL}{proposal.graph_endpoint}"
        headers = {
            "Authorization": f"Bearer {live_access_token}",
            "Content-Type": "application/json",
        }
        try:
            resp = requests.request(
                method=proposal.http_method,
                url=url,
                headers=headers,
                json=proposal.request_body if proposal.request_body else None,
                timeout=30,
            )
            if resp.status_code in (200, 204):
                msg = (
                    f"[LIVE MODE] Successfully executed `{proposal.http_method} {proposal.graph_endpoint}` "
                    f"for `{proposal.target_upn}` (HTTP {resp.status_code})."
                )
                entry = self._write_audit_log(
                    proposal=proposal,
                    event_type="REMEDIATION_EXECUTED",
                    status="EXECUTED_LIVE",
                    mode="live",
                    operator_input=cleaned_input,
                    details=msg,
                )
                return RemediationResult(
                    action_id=proposal.action_id,
                    status="EXECUTED_LIVE",
                    message=msg,
                    timestamp=entry["timestamp_utc"],
                    audit_log_entry=entry,
                )

            err_msg = (
                f"Graph API returned HTTP {resp.status_code} for "
                f"`{proposal.http_method} {proposal.graph_endpoint}`: {resp.text[:250]}"
            )
            entry = self._write_audit_log(
                proposal=proposal,
                event_type="LIVE_REMEDIATION_ERROR",
                status="ERROR",
                mode="live",
                operator_input=cleaned_input,
                details=err_msg,
            )
            return RemediationResult(
                action_id=proposal.action_id,
                status="ERROR",
                message=err_msg,
                timestamp=entry["timestamp_utc"],
                audit_log_entry=entry,
            )
        except requests.RequestException as exc:
            err_msg = f"Network error calling Microsoft Graph: {exc}"
            entry = self._write_audit_log(
                proposal=proposal,
                event_type="LIVE_REMEDIATION_ERROR",
                status="ERROR",
                mode="live",
                operator_input=cleaned_input,
                details=err_msg,
            )
            return RemediationResult(
                action_id=proposal.action_id,
                status="ERROR",
                message=err_msg,
                timestamp=entry["timestamp_utc"],
                audit_log_entry=entry,
            )

    @staticmethod
    def _apply_demo_state_change(proposal: RemediationProposal, snapshot: TenantSnapshot) -> None:
        """Apply the approved remediation change to the in-memory mock tenant snapshot."""
        action_val = proposal.action_type.value
        if action_val == "disable_stale_account":
            for u in snapshot.users:
                if u.id == proposal.target_user_id:
                    u.account_enabled = False
        elif action_val == "remove_from_role":
            for u in snapshot.users:
                if u.id == proposal.target_user_id and proposal.role_name in u.assigned_roles:
                    u.assigned_roles.remove(proposal.role_name)
            for r in snapshot.roles:
                if r.role_id == proposal.role_id and proposal.target_user_id in r.member_user_ids:
                    r.member_user_ids.remove(proposal.target_user_id)

    def read_audit_log(self) -> List[Dict[str, Any]]:
        """Read all structured entries from the remediation audit log file."""
        if not self.audit_log_path.exists():
            return []
        entries: List[Dict[str, Any]] = []
        with self.audit_log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries
