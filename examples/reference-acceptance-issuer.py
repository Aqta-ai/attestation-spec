"""
Reference issuer for ACCEPT-v1 records (spec/ACCEPT-v1.md).

The third profile in the family, and the same rule as the second: the
canonicalisation is imported from reference-issuer.py rather than restated,
so the profiles cannot drift at the byte level.

The one function worth reading here is subject_hash_of(). An acceptance
record binds to the SIGNED BYTES of the record it responds to, not to its
identifier, which is what makes "this was accepted" mean something a holder
can check. Apache-2.0.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_spec = importlib.util.spec_from_file_location(
    "attestation_ref", Path(__file__).resolve().parent / "reference-issuer.py"
)
_ref = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_ref)  # type: ignore[union-attr]

canonical_payload = _ref.canonical_payload

SPEC_VERSION = "accept-1"
DECISIONS = {"ACCEPTED", "OVERRIDDEN", "ESCALATED"}
SUBJECT_VERSIONS = {"1", "action-1"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def subject_hash_of(subject: Mapping[str, object]) -> str:
    """
    SHA-256 of the subject record's canonical signed bytes, signature excluded
    (spec section 6.1). Pass the subject record exactly as it was issued.
    """
    return hashlib.sha256(canonical_payload(subject)).hexdigest()


def reason_hash_of(reason: str) -> str:
    """SHA-256 of the reviewer's stated reason. The text never enters the record."""
    return hashlib.sha256(reason.encode("utf-8")).hexdigest() if reason else ""


class ReferenceAcceptanceIssuer:
    """Minimal ACCEPT-v1 issuer, deterministic when keyed via from_seed."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key

    @classmethod
    def new(cls) -> "ReferenceAcceptanceIssuer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed_bytes: bytes) -> "ReferenceAcceptanceIssuer":
        if len(seed_bytes) != 32:
            raise ValueError("seed_bytes must be exactly 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed_bytes))

    @property
    def public_key_b64(self) -> str:
        raw = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return _b64url_encode(raw)

    def sign(
        self,
        *,
        org_id: str,
        subject_v: str,
        subject_id: str,
        subject_hash: str,
        decision: str,
        reviewer_ref: str,
        policy_applied: List[str],
        reviewer_authority: str = "",
        reason_hash: str = "",
        acceptance_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Mapping[str, object]:
        """
        Produce a signed ACCEPT-v1 record. Validation mirrors the spec's
        semantic checks so the reference issuer cannot mint a record the
        reference verifiers would reject.

        reviewer_ref and reviewer_authority are recorded exactly as given and
        are never verified (spec section 8). An issuer that accepts any value
        here will produce records naming any reviewer, which is the
        deployment's problem to solve and not the format's.
        """
        if decision not in DECISIONS:
            raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
        if subject_v not in SUBJECT_VERSIONS:
            raise ValueError(f"subject_v must be one of {sorted(SUBJECT_VERSIONS)}")
        if not subject_id:
            raise ValueError("subject_id must be non-empty")
        if not _HEX64.match(subject_hash):
            raise ValueError("subject_hash must be 64 lowercase hex characters")
        if reason_hash and not _HEX64.match(reason_hash):
            raise ValueError("reason_hash must be '' or 64 lowercase hex characters")
        if not reviewer_ref:
            raise ValueError("reviewer_ref must be non-empty")

        payload = {
            "v": SPEC_VERSION,
            "acceptance_id": acceptance_id or str(uuid.uuid4()),
            "org_id": org_id,
            "subject_v": subject_v,
            "subject_id": subject_id,
            "subject_hash": subject_hash,
            "decision": decision,
            "reason_hash": reason_hash or "",
            "reviewer_ref": reviewer_ref,
            "reviewer_authority": reviewer_authority or "",
            "policy_applied": sorted(policy_applied),
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "public_key": self.public_key_b64,
        }
        signature = self.private_key.sign(canonical_payload(payload))
        return {**payload, "signature": _b64url_encode(signature)}


if __name__ == "__main__":
    issuer = ReferenceAcceptanceIssuer.from_seed(
        hashlib.sha256(b"attestation-spec/examples/accept").digest()
    )
    # A subject receipt, as the ATTESTATION reference issuer would produce it.
    subject = _ref.ReferenceIssuer.from_seed(
        hashlib.sha256(b"attestation-spec/examples").digest()
    ).sign(
        trace_id="trace-example-0001",
        org_id="org-example",
        request_hash="8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
        model="gpt-4o",
        outcome="BLOCKED",
        policy_applied=["affordability_v3"],
        cost_prevented_eur=0.0,
        attestation_id="00000000-0000-0000-0000-000000000001",
        timestamp="2026-04-23T10:15:30.000000+00:00",
    )
    record = issuer.sign(
        org_id="org-example",
        subject_v="1",
        subject_id=str(subject["attestation_id"]),
        subject_hash=subject_hash_of(subject),
        decision="OVERRIDDEN",
        reason_hash=reason_hash_of(
            "Post-period management accounts show recovery above the floor."
        ),
        reviewer_ref="credit-officer c-1f8e",
        reviewer_authority="SME credit, limit EUR 150000",
        policy_applied=["adverse_action", "affordability_v3"],
        acceptance_id="00000000-0000-0000-0000-0000000000a1",
        timestamp="2026-08-23T09:12:44.108231+00:00",
    )
    print(json.dumps(record, indent=2, sort_keys=True))
