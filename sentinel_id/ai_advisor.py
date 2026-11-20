"""
Gemini AI Executive Advisor for Sentinel ID.

Uses the current `google-genai` SDK (>= 3.2.0) and the `Interactions API`
(`client.interactions.create` with model `gemini-4-hydrogen`) to generate a
plain-English executive summary ("Top 5 things to fix and why") tailored for
a non-technical manager.

SECURITY INVARIANT:
Only the output of `PIIRedactor.build_redacted_ai_payload()` is ever passed to
the Gemini API. If `GEMINI_API_KEY` is not set (e.g., offline Demo Mode),
a deterministic plain-English executive summary is generated locally so the
application works seamlessly with zero cloud dependencies.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from google import genai

from sentinel_id.config import SentinelConfig
from sentinel_id.models import AuditReport, TenantSnapshot
from sentinel_id.redactor import PIIRedactor

SYSTEM_INSTRUCTION = (
    "You are a Principal Cloud Identity Security Advisor briefing a non-technical "
    "executive manager. You are given ANONYMIZED Microsoft Entra ID security audit "
    "findings (all names, emails, UPNs, and IPs have been redacted into tokens like "
    "[UPN_XXXXXXXX] for privacy). "
    "Write a clear, jargon-free executive brief in Markdown titled "
    "'### Executive Brief: Top 5 Priorities to Fix and Why'. "
    "For each of the Top 5 priorities:\n"
    "1. Give a plain-English headline.\n"
    "2. **What we found**: Summarize the count and scope of the issue without repeating raw hash tokens unless helpful for scale.\n"
    "3. **Why it matters to the business**: Explain the real-world business risk (e.g., ransomware, data breach, wasted software spend) in plain language a non-technical director understands.\n"
    "4. **Recommended action**: State the concrete, human-approved step to fix it.\n"
    "Keep the tone constructive, urgent where appropriate, and executive-ready."
)


class GeminiSecurityAdvisor:
    """Generates plain-English executive recommendations over redacted audit data."""

    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        self.config = config or SentinelConfig()
        self.redactor = PIIRedactor(salt=self.config.redaction_salt)

    def generate_executive_summary(
        self,
        report: AuditReport,
        snapshot: Optional[TenantSnapshot] = None,
        force_offline: bool = False,
    ) -> str:
        """
        Redact all PII from the report, populate `report.redacted_payload_preview`,
        and call Gemini (`gemini-4-hydrogen`) via `client.interactions.create`
        (or fall back to offline deterministic briefing if no API key is configured).
        """
        redacted_payload = self.redactor.build_redacted_ai_payload(report, snapshot=snapshot)
        report.redacted_payload_preview = redacted_payload

        if not force_offline and self.config.has_gemini_key():
            try:
                client = genai.Client(api_key=self.config.gemini_api_key)
                prompt = (
                    "Analyze the following PII-redacted Microsoft Entra ID security audit "
                    "report and produce the 'Top 5 Things to Fix and Why' for a non-technical "
                    "executive manager:\n\n"
                    f"```json\n{json.dumps(redacted_payload, indent=2)}\n```"
                )
                interaction = client.interactions.create(
                    model=self.config.gemini_model,
                    system_instruction=SYSTEM_INSTRUCTION,
                    input=prompt,
                )
                if interaction.output_text:
                    report.ai_executive_summary = interaction.output_text.strip()
                    report.ai_model_used = f"{self.config.gemini_model} (Live Gemini API — PII Redacted)"
                    return report.ai_executive_summary
            except Exception as exc:
                fallback = self._generate_offline_summary(redacted_payload)
                report.ai_executive_summary = (
                    f"> *Note: Gemini API call encountered an error ({exc}); displaying local "
                    "executive summary generated from PII-redacted findings.*\n\n" + fallback
                )
                report.ai_model_used = "Local Deterministic Advisor (Gemini Fallback — PII Redacted)"
                return report.ai_executive_summary

        # Offline / Zero-Cloud Demo Mode synthesis over the redacted payload
        report.ai_executive_summary = self._generate_offline_summary(redacted_payload)
        report.ai_model_used = (
            f"Offline Demo Synthesis (PII Redacted; set GEMINI_API_KEY for live {self.config.gemini_model})"
        )
        return report.ai_executive_summary

    @staticmethod
    def _generate_offline_summary(redacted_payload: Dict[str, Any]) -> str:
        """
        Generate a crisp, manager-friendly 'Top 5 things to fix and why' directly
        from the redacted payload when running without a live GEMINI_API_KEY.
        """
        score = redacted_payload.get("overall_risk_score", 0)
        grade = redacted_payload.get("security_posture_grade", "N/A")
        sev = redacted_payload.get("severity_summary", {})
        cat_counts = redacted_payload.get("findings_by_category", {})

        mfa_count = cat_counts.get("1. Users Without MFA Registered", 0)
        stale_count = cat_counts.get("2. Stale Accounts (Inactive 90+ Days)", 0)
        priv_count = cat_counts.get("3. Privileged Directory Roles & Excess Admins", 0)
        risk_count = cat_counts.get("4. Risky Sign-Ins & Risky Users (Identity Protection)", 0)
        guest_count = cat_counts.get("5. Old or Inactive Guest Accounts", 0)
        ca_count = cat_counts.get("6. Conditional Access Policy Gaps", 0)
        disabled_count = cat_counts.get(
            "7. Disabled Accounts with Licenses or Group Memberships", 0
        )

        lines = [
            "### Executive Brief: Top 5 Priorities to Fix and Why",
            "",
            f"**Overall Tenant Risk Score:** `{score}/100` (Posture Grade: **{grade}**) — "
            f"**{sev.get('High', 0)} High**, **{sev.get('Medium', 0)} Medium**, and "
            f"**{sev.get('Low', 0)} Low** severity findings identified across anonymized telemetry.",
            "",
            "---",
            "",
            "#### 1. Enforce Multi-Factor Authentication (MFA) for Every Admin and Employee",
            f"- **What we found:** **{mfa_count} active accounts** (including privileged administrators) do not have Multi-Factor Authentication registered, and **{ca_count} Conditional Access policy gaps** leave MFA enforcement in 'Report-Only' mode or allow legacy basic-authentication protocols.",
            "- **Why it matters to the business:** An account protected only by a password is like an office building with a single key and no alarm system. Over 99% of cloud account takeovers happen because attackers guess, phish, or buy a stolen password and walk right in without a phone or security key prompt.",
            "- **Recommended action:** Switch the Admin MFA Conditional Access policy from *Report-Only* to *Enabled*, enable the *Block Legacy Authentication* policy, and require all remaining users to register Microsoft Authenticator or a hardware security key immediately.",
            "",
            "#### 2. Contain Active Compromised & High-Risk Sign-Ins Immediately",
            f"- **What we found:** **{risk_count} high/medium-risk identity alerts** indicate employees signing in from anonymous proxy networks (Tor), impossible travel locations, or with leaked credentials.",
            "- **Why it matters to the business:** These are not theoretical vulnerabilities—they are smoke alarms signaling that an attacker may already be testing stolen employee passwords right now. Waiting allows an intruder to read sensitive emails or invoice clients fraudulently.",
            "- **Recommended action:** Use Sentinel ID's human-approved remediation workflow to revoke active sign-in sessions for flagged users and force an immediate password reset.",
            "",
            "#### 3. Reduce the Number of 'Global Administrators' (Master Key Holders)",
            f"- **What we found:** **{priv_count} privileged role findings** show the organization has too many permanent Global Administrators—including inactive former staff, external consultants, and executives who do not perform daily IT administration.",
            "- **Why it matters to the business:** A Global Administrator holds the 'master key' to every file, mailbox, and server in the company. The more people carrying a master key in their pocket every day, the higher the chance one gets lost or stolen.",
            "- **Recommended action:** Trim Global Administrators down to 2–4 dedicated accounts (including emergency break-glass accounts) and assign narrower, day-to-day roles for everyone else.",
            "",
            "#### 4. Lock Down Dormant & Abandoned Accounts (90+ Days Inactive)",
            f"- **What we found:** **{stale_count} internal accounts** and **{guest_count} external vendor guest accounts** remain enabled despite not logging in for over 90–140 days (or never logging in at all).",
            "- **Why it matters to the business:** Abandoned accounts are 'ghost badges' that still open your building doors. Because nobody is actively using them, an attacker who hijacks an old contractor or former employee account can operate for months without anyone noticing.",
            "- **Recommended action:** Approve the dry-run remediation to disable stale internal and guest accounts, and set up automated quarterly guest access reviews.",
            "",
            "#### 5. Reclaim Paid Licenses & Access Groups from Offboarded Staff",
            f"- **What we found:** **{disabled_count} disabled accounts** belonging to departed employees still hold active security group memberships and paid Microsoft 365 / Power BI licenses.",
            "- **Why it matters to the business:** First, the company is paying monthly subscription fees for software nobody is using. Second, if a disabled account is ever accidentally re-enabled, it immediately regains access to sensitive R&D and VPN groups.",
            "- **Recommended action:** Update the employee offboarding checklist to strip all group memberships and reclaim software licenses the moment an account is disabled.",
        ]
        return "\n".join(lines)
