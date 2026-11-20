"""
Unit tests for PII Redaction & Anonymization (`sentinel_id.redactor`).
Ensures zero names, emails, UPNs, IP addresses, or tenant domains are exposed to the AI model.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sentinel_id.auditor import EntraAuditor
from sentinel_id.mock_data import generate_mock_tenant
from sentinel_id.redactor import PIIRedactor


def test_pii_redactor_hashes_names_emails_upns_and_ips() -> None:
    redactor = PIIRedactor(salt="unit-test-salt")

    upn_token = redactor.redact_upn("marcus.vance@northwindlab.onmicrosoft.com")
    name_token = redactor.redact_name("Marcus Vance")
    ip_token = redactor.redact_ip("203.0.113.45")

    assert upn_token.startswith("[UPN_") and upn_token.endswith("]")
    assert name_token.startswith("[USER_") and name_token.endswith("]")
    assert ip_token.startswith("[IP_") and ip_token.endswith("]")

    # Deterministic hashing: same input with same salt produces identical token
    assert redactor.redact_upn("MARCUS.VANCE@northwindlab.onmicrosoft.com") == upn_token


def test_ai_payload_contains_zero_raw_pii() -> None:
    now = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
    snapshot = generate_mock_tenant(reference_now=now, supports_identity_protection=True)
    auditor = EntraAuditor(reference_now=now)
    report = auditor.run_full_audit(snapshot)

    redactor = PIIRedactor(salt="strict-privacy-test-salt")
    ai_payload = redactor.build_redacted_ai_payload(report, snapshot=snapshot)
    serialized = json.dumps(ai_payload)

    # Collect every raw PII value from the tenant snapshot
    forbidden_pii_values = [
        snapshot.tenant_id,
        snapshot.tenant_domain,
        snapshot.tenant_name,
    ]
    for u in snapshot.users:
        forbidden_pii_values.append(u.display_name)
        forbidden_pii_values.append(u.user_principal_name)
        forbidden_pii_values.append(u.mail)
        if u.last_sign_in_ip:
            forbidden_pii_values.append(u.last_sign_in_ip)
    for rsi in snapshot.risky_sign_ins:
        forbidden_pii_values.append(rsi.ip_address)
        forbidden_pii_values.append(rsi.user_principal_name)

    assert redactor.verify_payload_contains_no_pii(ai_payload, forbidden_pii_values)
    for raw_pii in forbidden_pii_values:
        assert raw_pii not in serialized, f"PII leak detected in AI payload: {raw_pii}"
