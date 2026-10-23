"""
aqta-verify-receipt
===================

Offline verifier for Seal attestation receipts (ATTESTATION-v1) and
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
__version__ = "1.4.0"

from .transparency import (  # noqa: E402,F401
    ProofResult,
    leaf_hash,
    verify_consistency_proof,
    verify_inclusion_proof,
    verify_signed_tree_head,
)

from .transparency import HistoryResult, assess_history  # noqa: E402,F401

# The chain profile (spec/USE-v1.md section 9; GRANT-v1 and USE-v1 are drafts).
# Explicit opt-in: call verify_chain, never inferred from a record's shape.
from .chain import (  # noqa: E402,F401
    ChainResult,
    check_grant_record,
    check_use_record,
    grant_hash,
    verify_chain,
)

# The complete and witnessed profiles (spec/CHECKPOINT-v1.md, spec/EXECUTION-v1.md,
# spec/WITNESS-v1.md; all drafts). Explicit opt-in: call verify_complete or
# verify_witnessed, never inferred from a bundle's shape.
from .complete import (  # noqa: E402,F401
    check_checkpoint_record,
    check_execution_record,
    checkpoint_hash,
    execution_hash,
    record_leaf,
    records_hash,
    verify_complete,
)
from .witnessed import check_witness_record, statement_hash, verify_witnessed  # noqa: E402,F401

# The policy profile (spec/POLICY-v1.md; draft). Explicit opt-in: call
# verify_policy, never inferred from a bundle's shape.
from .policy import (  # noqa: E402,F401
    check_policy_record,
    parse_binding,
    policy_body_hash,
    policy_leaf,
    verify_policy,
)
