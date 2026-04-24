"""
Reference issuer for ATTESTATION-v1 receipts.

A minimal, stand-alone implementation of the issuer side of the spec.
Useful for:
  - Understanding exactly how a conforming issuer should build a canonical
    payload and sign it with Ed25519.
  - Generating test vectors for third-party verifiers.
  - Running the cross-implementation interop script without any dependency
    on a production gateway.

This code is *not* a production issuer. A real issuer (like the AqtaCore
managed service at https://aqta.ai) additionally:
  - Manages the private signing key in a secure enclave or KMS;
  - Enforces policy, budget, and loop-detection before signing;
  - Persists signed receipts to a tamper-evident audit log;
  - Integrates with LLM providers and returns receipts inline with API
    responses.

This file only demonstrates the *format* side. Apache-2.0.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import List, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


SPEC_VERSION = 1
ALLOWED_OUTCOMES = {"ALLOWED", "BLOCKED", "SUPPRESSED", "PASSED"}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class ReferenceIssuer:
    """
    Minimal ATTESTATION-v1 issuer. Generates an ephemeral Ed25519 key at
    construction unless an existing key is supplied via ``from_seed``.
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key

    @classmethod
    def new(cls) -> "ReferenceIssuer":
        """Create an issuer with a fresh random key."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed_bytes: bytes) -> "ReferenceIssuer":
        """
        Create a deterministic issuer keyed from a 32-byte seed.
        Useful for reproducible test vectors.
        """
        if len(seed_bytes) != 32:
            raise ValueError("seed_bytes must be exactly 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed_bytes))

    @property
    def public_key_b64(self) -> str:
        """Base64url-encoded raw 32-byte Ed25519 public key (no padding)."""
        raw = self.private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        return _b64url_encode(raw)

    def sign(
        self,
        *,
        trace_id: str,
        org_id: str,
        request_hash: str,
        model: str,
        outcome: str,
        policy_applied: List[str],
        cost_prevented_eur: float = 0.0,
        attestation_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Mapping[str, object]:
        """
        Produce a signed ATTESTATION-v1 receipt.

        Parameters match the spec fields of the same name. ``attestation_id``
        and ``timestamp`` are generated if omitted; pass explicit values to
        produce reproducible receipts.

        Canonicalization rule (spec §6): integer-valued floats are coerced
        to int before JSON serialisation so the canonical bytes match across
        Python and JavaScript verifiers.
        """
        if outcome not in ALLOWED_OUTCOMES:
            raise ValueError(f"outcome must be one of {ALLOWED_OUTCOMES}")
        if len(request_hash) != 64 or not all(
            c in "0123456789abcdef" for c in request_hash
        ):
            raise ValueError("request_hash must be 64 lowercase hex chars")

        cost = round(cost_prevented_eur, 6)
        if cost == int(cost):
            cost = int(cost)

        payload = {
            "v": SPEC_VERSION,
            "attestation_id": attestation_id or str(uuid.uuid4()),
            "trace_id": trace_id,
            "org_id": org_id,
            "request_hash": request_hash,
            "model": model,
            "outcome": outcome,
            "policy_applied": sorted(policy_applied),
            "cost_prevented_eur": cost,
            "timestamp": timestamp
            or datetime.now(timezone.utc).isoformat(),
            "public_key": self.public_key_b64,
        }

        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        signature = self.private_key.sign(canonical)

        return {**payload, "signature": _b64url_encode(signature)}


def canonical_payload(receipt: Mapping[str, object]) -> bytes:
    """
    Return the canonical signing bytes for a receipt, per spec §6.
    Provided as a utility so third-party verifiers can validate their own
    canonicalisation against this reference.
    """
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


if __name__ == "__main__":
    # Example: mint a sample receipt with a deterministic key and print it.
    issuer = ReferenceIssuer.from_seed(hashlib.sha256(b"attestation-spec/examples").digest())
    receipt = issuer.sign(
        trace_id="trace-example-0001",
        org_id="org-example",
        request_hash="8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
        model="gpt-4o",
        outcome="ALLOWED",
        policy_applied=["budget_guard", "loop_guard"],
        cost_prevented_eur=0.0,
        attestation_id="00000000-0000-0000-0000-000000000001",
        timestamp="2026-04-23T10:15:30.000000+00:00",
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
