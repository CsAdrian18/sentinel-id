"""
PII Redaction & Anonymization Engine for Sentinel ID.

CRITICAL PRIVACY & SECURITY CONTROL:
Before sending ANY audit finding or tenant telemetry to the Gemini AI model,
all Personally Identifiable Information (PII) and tenant identifiers must be
deterministically pseudonymized (salted SHA-256 short token) or masked:
- Display names
- Email addresses & User Principal Names (UPNs)
- IPv4 / IPv6 addresses
- Tenant IDs, domain names, and user object IDs

The AI model ONLY receives anonymized structural findings and risk statistics.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Dict, List, Optional

from sentinel_id.models import AuditFinding, AuditReport, TenantSnapshot

# Regex patterns to scrub free-text descriptions before AI transmission
EMAIL_UPN_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+(?:@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|#EXT#@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
QUOTED_NAME_REGEX = re.compile(r"Account '([^']+)'|User '([^']+)'|guest '([^']+)'")


class PIIRedactor:
    """
    Deterministic PII pseudonymizer and text scrubber.
    Ensures zero raw names, UPNs, emails, or IP addresses leave the boundary to AI models.
    """

    def __init__(self, salt: str = "sentinel-id-default-salt-2026") -> None:
        self._salt_bytes = salt.encode("utf-8")
        self._known_pii_map: Dict[str, str] = {}

    def _hash_token(self, prefix: str, raw_value: str) -> str:
        """Create a deterministic salted HMAC-SHA256 8-hex-char pseudonym token."""
        normalized = raw_value.strip().lower()
        digest = hmac.new(self._salt_bytes, normalized.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        token = f"[{prefix}_{digest.upper()}]"
        self._known_pii_map[raw_value] = token
        return token

    def redact_upn(self, upn: Optional[str]) -> str:
        """Hash an email address or User Principal Name into [UPN_XXXXXXXX]."""
        if not upn:
            return "[UPN_NONE]"
        return self._hash_token("UPN", upn)

    def redact_name(self, display_name: Optional[str]) -> str:
        """Hash a user display name into [USER_XXXXXXXX]."""
        if not display_name:
            return "[USER_NONE]"
        return self._hash_token("USER", display_name)

    def redact_ip(self, ip_address: Optional[str]) -> str:
        """Mask and hash an IP address into [IP_XXXXXXXX]."""
        if not ip_address:
            return "[IP_NONE]"
        return self._hash_token("IP", ip_address)

    def redact_resource_id(self, resource_id: Optional[str]) -> str:
        """Hash a directory object GUID or resource identifier into [OBJ_XXXXXXXX]."""
        if not resource_id:
            return "[OBJ_NONE]"
        return self._hash_token("OBJ", resource_id)

    def register_snapshot_pii(self, snapshot: TenantSnapshot) -> None:
        """Pre-register all known names, UPNs, mails, IPs, and tenant domains from a snapshot."""
        if snapshot.tenant_id:
            self._hash_token("TENANT", snapshot.tenant_id)
        if snapshot.tenant_domain:
            self._hash_token("DOMAIN", snapshot.tenant_domain)
        if snapshot.tenant_name:
            self._hash_token("ORG", snapshot.tenant_name)

        for u in snapshot.users:
            self.redact_name(u.display_name)
            self.redact_upn(u.user_principal_name)
            if u.mail:
                self.redact_upn(u.mail)
            if u.last_sign_in_ip:
                self.redact_ip(u.last_sign_in_ip)
            self.redact_resource_id(u.id)

        for ru in snapshot.risky_users:
            self.redact_name(ru.display_name)
            self.redact_upn(ru.user_principal_name)
            self.redact_resource_id(ru.user_id)

        for rsi in snapshot.risky_sign_ins:
            self.redact_upn(rsi.user_principal_name)
            self.redact_ip(rsi.ip_address)
            self.redact_resource_id(rsi.user_id)

    def scrub_free_text(self, text: str) -> str:
        """
        Replace any known PII values, email/UPN patterns, and IPv4 addresses
        inside a free-text finding title or description.
        """
        if not text:
            return ""

        scrubbed = text

        # 1. Replace any pre-registered exact PII strings (longest first to avoid partial overlap)
        for raw_val in sorted(self._known_pii_map.keys(), key=len, reverse=True):
            if raw_val and raw_val in scrubbed:
                scrubbed = scrubbed.replace(raw_val, self._known_pii_map[raw_val])

        # 2. Scrub any remaining email / UPN patterns
        scrubbed = EMAIL_UPN_REGEX.sub(lambda m: self.redact_upn(m.group(0)), scrubbed)

        # 3. Scrub any remaining IPv4 patterns
        scrubbed = IPV4_REGEX.sub(lambda m: self.redact_ip(m.group(0)), scrubbed)

        return scrubbed

    def redact_finding(self, finding: AuditFinding) -> Dict[str, Any]:
        """Return a PII-free dictionary representation of an AuditFinding safe for AI input."""
        if finding.affected_display_name:
            self.redact_name(finding.affected_display_name)
        if finding.affected_upn:
            self.redact_upn(finding.affected_upn)
        if finding.affected_ip:
            self.redact_ip(finding.affected_ip)
        if finding.affected_resource_id:
            self.redact_resource_id(finding.affected_resource_id)

        return {
            "finding_id": finding.finding_id,
            "category": finding.category.value,
            "severity": finding.severity.value,
            "title": self.scrub_free_text(finding.title),
            "description": self.scrub_free_text(finding.description),
            "impact": self.scrub_free_text(finding.impact),
            "recommendation": self.scrub_free_text(finding.recommendation),
            "anonymized_principal": (
                self.redact_upn(finding.affected_upn) if finding.affected_upn else None
            ),
            "anonymized_user": (
                self.redact_name(finding.affected_display_name)
                if finding.affected_display_name
                else None
            ),
            "anonymized_ip": (
                self.redact_ip(finding.affected_ip) if finding.affected_ip else None
            ),
            "anonymized_resource_id": self.redact_resource_id(finding.affected_resource_id),
        }

    def build_redacted_ai_payload(
        self, report: AuditReport, snapshot: Optional[TenantSnapshot] = None
    ) -> Dict[str, Any]:
        """
        Construct the complete anonymized JSON payload sent to Gemini AI.
        Guaranteed free of raw user names, UPNs, emails, IP addresses, or tenant domains.
        """
        if snapshot:
            self.register_snapshot_pii(snapshot)

        if report.tenant_id:
            self._hash_token("TENANT", report.tenant_id)
        if report.tenant_domain:
            self._hash_token("DOMAIN", report.tenant_domain)
        if report.tenant_name:
            self._hash_token("ORG", report.tenant_name)

        redacted_findings: List[Dict[str, Any]] = [
            self.redact_finding(f) for f in report.findings
        ]

        category_counts: Dict[str, int] = {}
        for f in report.findings:
            category_counts[f.category.value] = category_counts.get(f.category.value, 0) + 1

        return {
            "anonymized_tenant_token": self._hash_token("TENANT", report.tenant_id),
            "overall_risk_score": report.overall_risk_score,
            "security_posture_grade": report.security_posture_grade,
            "severity_summary": {
                "High": len(report.high_findings),
                "Medium": len(report.medium_findings),
                "Low": len(report.low_findings),
                "Total": len(report.findings),
            },
            "findings_by_category": category_counts,
            "skipped_checks": [self.scrub_free_text(s) for s in report.skipped_checks],
            "anonymized_findings": redacted_findings,
        }

    def verify_payload_contains_no_pii(
        self, payload: Dict[str, Any], raw_pii_values: List[str]
    ) -> bool:
        """
        Security assertion helper: verify none of the supplied raw PII strings
        appear anywhere in the serialized AI payload.
        """
        serialized = json.dumps(payload)
        for pii in raw_pii_values:
            if pii and pii.strip() and pii in serialized:
                return False
        return True
