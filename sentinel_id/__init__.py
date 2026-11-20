"""
Sentinel ID — AI-Assisted Identity Security Auditor for Microsoft Entra ID.

Designed with secure-by-default principles:
- Demo Mode first (zero cloud access required)
- Strictly Read-Only Microsoft Graph permissions by default
- Deterministic PII Redaction (HMAC/SHA-256 + masking) before any AI call
- Dry-Run + Human-in-the-Loop Typed Approval for all optional remediations
"""

__version__ = "1.0.0"
__author__ = "Sentinel ID Security Engineering"
