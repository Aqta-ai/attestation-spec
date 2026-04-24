"""
aqta-verify-receipt
===================

Independent verifier for AqtaCore attestation receipts (ATTESTATION-v1).

Verifies the Ed25519 signature on an AI-enforcement attestation receipt using
only the issuer's published public key: no dependency on Aqta's servers.

Spec: https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md

Example
-------
    from aqta_verify_receipt import verify_receipt, fetch_published_public_key

    # Pin the issuer's public key once
    trusted = fetch_published_public_key()

    # Verify receipts
    result = verify_receipt(receipt, trusted_public_key=trusted)
    if not result.valid:
        raise ValueError(f"Receipt invalid: {result.reason}")
"""

from .verifier import (
    VerifyResult,
    fetch_published_public_key,
    verify_receipt,
)

__all__ = ["verify_receipt", "fetch_published_public_key", "VerifyResult"]
__version__ = "1.0.2"
