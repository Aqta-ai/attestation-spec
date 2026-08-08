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


def _sign_raw(payload: dict) -> dict:
    """Sign an arbitrary payload, bypassing the issuer's own validation.

    Needed because the invalid vectors must carry a VALID signature over their
    defect. Signing a clean receipt and mutating it afterwards, which is what
    this generator used to do, breaks the signature, so every invalid vector
    failed on the signature before the defect it is named for was ever
    reached. A verifier that checked nothing but the signature scored 15/15 on
    the published suite, which means the suite could not distinguish a
    conformant verifier from a signature-only one. Reported by Michael
    Msebenzi, 2026-08-05, and reproduced.

    The issuer's sign() rejects invalid outcomes and malformed hashes by
    design, so it cannot mint these. This signs the exact bytes given.
    """
    payload = {**payload, "public_key": ISSUER.public_key_b64}
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    signature = ISSUER.private_key.sign(canonical)
    return {**payload, "signature": _ref._b64url_encode(signature)}


def _base_payload(**overrides) -> dict:
    """The twelve-field payload a valid receipt carries, before signing."""
    payload = {
        "v": 1,
        "attestation_id": "00000000-0000-0000-0000-00000000ffff",
        "trace_id": "trace-tv-001",
        "org_id": "org-test-vectors",
        "request_hash": (
            "8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c"
            "3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a"
        ),
        "model": "gpt-4o",
        "outcome": "ALLOWED",
        "policy_applied": ["budget_guard"],
        "cost_prevented_eur": 0,
        "timestamp": "2026-04-23T10:15:30.000000+00:00",
    }
    payload.update(overrides)
    return payload


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
    # Pins spec §6.1. An issuer or verifier that escapes non-ASCII to \uXXXX
    # (Python's json.dumps default) produces different canonical bytes than
    # JSON.stringify, so this vector verifies in one language and fails in the
    # other. Any implementation that passes 001-006 but fails this one has the
    # escaping bug.
    _write(
        "valid/007-non-ascii-policy.json",
        _make(
            "007",
            outcome="BLOCKED",
            attestation_id="00000000-0000-0000-0000-000000000007",
            model="mistral-large-latest",
            policy_applied=["Größe-Limit", "contrôle-des-coûts", "個人情報スキャン"],
            cost_prevented_eur=1.25,
        ),
    )
    # Pins the number grammar in §6. Python's default float repr switches to
    # exponent notation below 1e-4 and zero-pads the exponent (1e-05) where
    # JavaScript writes 0.00001, so every value in 0 < |x| < 1e-4 canonicalised
    # to different bytes in the two reference verifiers: the reference issuer
    # minted receipts that verified in Python and failed in JavaScript with
    # "signature check failed". §4 allows six digits of precision, so the whole
    # divergent band is reachable by a conforming issuer. No vector exercised
    # it, because every cost in the suite was 0, 1.0, 1.25, 2.5 or -5.
    # An implementation that passes 001-007 and fails these has that bug.
    _write(
        "valid/008-cost-sub-milli.json",
        _make(
            "008",
            outcome="BLOCKED",
            attestation_id="00000000-0000-0000-0000-000000000008",
            cost_prevented_eur=0.000015,
        ),
    )
    _write(
        "valid/009-cost-smallest-precision.json",
        _make(
            "009",
            outcome="BLOCKED",
            attestation_id="00000000-0000-0000-0000-000000000009",
            cost_prevented_eur=0.000001,
        ),
    )
    # A leap second is legal RFC 3339. A verifier that defers timestamp
    # well-formedness to a date parser rejects this one.
    _write(
        "valid/010-timestamp-leap-second.json",
        _make(
            "010",
            outcome="ALLOWED",
            attestation_id="00000000-0000-0000-0000-000000000010",
            timestamp="2016-12-31T23:59:60Z",
        ),
    )
    print()

    # Invalid vectors: each should be rejected by a conformant verifier for
    # a specific reason. The filename encodes the failure mode.
    print("Invalid vectors (verifier MUST reject):")

    # 001 to 003 are signature-integrity vectors: the defect IS the broken
    # signature, so these are correctly produced by tampering after signing.
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

    # 004 onwards are STRUCTURAL vectors. Each carries a VALID signature over
    # its own defect, so a verifier must reject it on the named rule rather
    # than on the signature. Before 2026-08-05 these were also produced by
    # mutating after signing, which meant they failed on the signature first
    # and the named rule was never exercised.
    missing_field = _base_payload()
    del missing_field["outcome"]
    _write("invalid/004-missing-field.json", _sign_raw(missing_field))

    _write(
        "invalid/005-unknown-field.json",
        _sign_raw(_base_payload(extra_metadata="should not be here")),
    )

    _write("invalid/006-wrong-version.json", _sign_raw(_base_payload(v=2)))

    _write(
        "invalid/007-bad-request-hash.json",
        _sign_raw(_base_payload(request_hash="not-a-hash")),
    )

    _write(
        "invalid/008-invalid-outcome.json",
        _sign_raw(_base_payload(outcome="MAYBE")),
    )

    # New structural vectors for the rules draft 6 step 1 specifies but no
    # verifier was checking, because nothing in the suite exercised them.
    _write(
        "invalid/009-policy-not-sorted.json",
        _sign_raw(_base_payload(policy_applied=["z_guard", "a_guard"])),
    )
    _write(
        "invalid/010-policy-not-strings.json",
        _sign_raw(_base_payload(policy_applied=[1])),
    )
    _write(
        "invalid/011-timestamp-no-offset.json",
        _sign_raw(_base_payload(timestamp="2026-08-05T10:00:00")),
    )
    _write(
        "invalid/012-timestamp-not-datetime.json",
        _sign_raw(_base_payload(timestamp="whenever")),
    )
    _write(
        "invalid/013-negative-cost.json",
        _sign_raw(_base_payload(cost_prevented_eur=-5)),
    )
    _write(
        "invalid/014-boolean-version.json",
        _sign_raw(_base_payload(v=True)),
    )
    _write(
        "invalid/015-uncoerced-integer-float.json",
        _sign_raw(_base_payload(cost_prevented_eur=1.0)),
    )

    print()
    print("All vectors written to test-vectors/.")
    print("Run your verifier against valid/*.json (MUST return valid)")
    print("and invalid/*.json (MUST reject) to claim conformance.")


if __name__ == "__main__":
    main()
