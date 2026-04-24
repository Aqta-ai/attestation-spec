"""
Generate deterministic test vectors for ATTESTATION-v1 conformance testing.

Running this script produces a fixed set of receipts under the same seed,
so implementers can validate their verifier against known-good bytes.

All vectors use a deterministic Ed25519 key pair derived from the seed
`sha256("attestation-spec/test-vectors/v1")`. The resulting public key
is:
  alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E

A conformant verifier, given the receipts in `valid/`, MUST return
valid: true. Given the receipts in `invalid/`, it MUST return
valid: false. The `README.md` in each subdirectory documents the
specific failure mode for the invalid cases.

Re-run this script after any spec change that alters canonical
serialisation or signing; the resulting vectors are the canonical
source of truth for cross-implementation parity.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "ref", _REPO_ROOT / "examples" / "reference-issuer.py"
)
_ref = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_ref)  # type: ignore[union-attr]


SEED = hashlib.sha256(b"attestation-spec/test-vectors/v1").digest()
ISSUER = _ref.ReferenceIssuer.from_seed(SEED)

OUTPUT = Path(__file__).parent


def _write(relative_path: str, payload: dict) -> None:
    path = OUTPUT / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"  wrote {path.relative_to(OUTPUT.parent)}")


def _make(
    filename: str,
    *,
    outcome: str = "ALLOWED",
    trace_id: str = "trace-tv-001",
    org_id: str = "org-test-vectors",
    request_hash: str = "8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
    model: str = "gpt-4o",
    policy_applied: list | None = None,
    cost_prevented_eur: float = 0.0,
    attestation_id: str = "00000000-0000-0000-0000-000000000001",
    timestamp: str = "2026-04-23T10:15:30.000000+00:00",
) -> dict:
    return ISSUER.sign(
        trace_id=trace_id,
        org_id=org_id,
        request_hash=request_hash,
        model=model,
        outcome=outcome,
        policy_applied=policy_applied or ["budget_guard"],
        cost_prevented_eur=cost_prevented_eur,
        attestation_id=attestation_id,
        timestamp=timestamp,
    )


def main() -> None:
    print("Public key (pin this to verify vectors):")
    print(f"  {ISSUER.public_key_b64}")
    print()

    # Valid vectors, one per spec-allowed outcome
    print("Valid vectors:")
    _write(
        "valid/001-allowed.json",
        _make("001", outcome="ALLOWED", attestation_id="00000000-0000-0000-0000-000000000001"),
    )
    _write(
        "valid/002-blocked.json",
        _make("002", outcome="BLOCKED", attestation_id="00000000-0000-0000-0000-000000000002",
              policy_applied=["pii_scan", "loop_guard"], cost_prevented_eur=0.0),
    )
    _write(
        "valid/003-suppressed.json",
        _make("003", outcome="SUPPRESSED", attestation_id="00000000-0000-0000-0000-000000000003",
              policy_applied=["loop_guard"]),
    )
    _write(
        "valid/004-passed.json",
        _make("004", outcome="PASSED", attestation_id="00000000-0000-0000-0000-000000000004"),
    )
    _write(
        "valid/005-multi-policy.json",
        _make(
            "005",
            outcome="ALLOWED",
            attestation_id="00000000-0000-0000-0000-000000000005",
            policy_applied=[
                "budget_guard",
                "loop_guard",
                "pii_scan",
                "prompt_injection_guard",
                "rate_limit",
            ],
        ),
    )
    _write(
        "valid/006-cost-prevented-nonzero.json",
        _make(
            "006",
            outcome="BLOCKED",
            attestation_id="00000000-0000-0000-0000-000000000006",
            cost_prevented_eur=2.5,
        ),
    )
    print()

    # Invalid vectors: each should be rejected by a conformant verifier for
    # a specific reason. The filename encodes the failure mode.
    print("Invalid vectors (verifier MUST reject):")

    # Valid receipt to base tampering on
    base = _make(
        "tamper-base",
        attestation_id="00000000-0000-0000-0000-00000000ffff",
    )

    tampered_signature = dict(base)
    tampered_signature["signature"] = (
        ("A" if base["signature"][0] != "A" else "B") + base["signature"][1:]
    )
    _write("invalid/001-tampered-signature.json", tampered_signature)

    tampered_field = dict(base)
    tampered_field["outcome"] = "BLOCKED"
    _write("invalid/002-tampered-outcome.json", tampered_field)

    tampered_public_key = dict(base)
    tampered_public_key["public_key"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    _write("invalid/003-tampered-public-key.json", tampered_public_key)

    missing_field = dict(base)
    del missing_field["outcome"]
    _write("invalid/004-missing-field.json", missing_field)

    unknown_field = dict(base)
    unknown_field["extra_metadata"] = "should not be here"
    _write("invalid/005-unknown-field.json", unknown_field)

    wrong_version = dict(base)
    wrong_version["v"] = 2
    _write("invalid/006-wrong-version.json", wrong_version)

    bad_request_hash = dict(base)
    bad_request_hash["request_hash"] = "not-a-hash"
    _write("invalid/007-bad-request-hash.json", bad_request_hash)

    invalid_outcome = dict(base)
    invalid_outcome["outcome"] = "MAYBE"
    _write("invalid/008-invalid-outcome.json", invalid_outcome)

    print()
    print("All vectors written to test-vectors/.")
    print("Run your verifier against valid/*.json (MUST return valid)")
    print("and invalid/*.json (MUST reject) to claim conformance.")


if __name__ == "__main__":
    main()
