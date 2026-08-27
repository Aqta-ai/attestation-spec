"""
aqta-verify-receipt
===================

Independent verifier for Seal attestation receipts (ATTESTATION-v1) and
action authorisation records (ACTION-v1, via :func:`verify_action_record` or
the explicit ``profile`` option).

Verifies the Ed25519 signature on an AI-enforcement attestation receipt using
only the issuer's published public key: no dependency on Aqta's servers.

Spec: https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md
and spec/ACTION-v1.md in the same repository.

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
    verify_action_record,
    verify_receipt,
)

__all__ = [
    "verify_receipt",
    "verify_action_record",
    "fetch_published_public_key",
    "VerifyResult",
]
__version__ = "1.1.2"

from .transparency import (  # noqa: E402,F401
    ProofResult,
    leaf_hash,
    verify_consistency_proof,
    verify_inclusion_proof,
    verify_signed_tree_head,
)
