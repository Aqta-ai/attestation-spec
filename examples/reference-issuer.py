"""
Reference issuer for ATTESTATION-v1 receipts.

A minimal, stand-alone implementation of the issuer side of the spec.
Useful for:
  - Understanding exactly how a conforming issuer should build a canonical
    payload and sign it with Ed25519.
  - Generating test vectors for third-party verifiers.
  - Running the cross-implementation interop script without any dependency
    on a production gateway.

This code is *not* a production issuer. A real issuer (like the Seal
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
import math
import re
import uuid
from datetime import datetime, timezone
from decimal import Decimal
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

        canonical = canonical_payload(payload)
        signature = self.private_key.sign(canonical)

        return {**payload, "signature": _b64url_encode(signature)}


def _js_number(x: float) -> str:
    """ECMA-262 Number::toString, the number grammar RFC 8785 (JCS) 3.2.2.3 sets.

    Python's default float repr disagrees with JavaScript's below 1e-4, so an
    issuer using json.dumps minted receipts that verified in Python and failed
    in JavaScript. spec 4 allows six digits of precision, which puts the whole
    divergent band inside what a conforming issuer may emit.
    """
    if not math.isfinite(x):
        raise ValueError("non-finite number")
    if x == 0:
        return "0"
    sign, digits, exp = Decimal(repr(x)).as_tuple()
    ds = "".join(map(str, digits))
    n = len(ds) + exp
    ds = ds.rstrip("0") or "0"
    if -6 < n <= 21:
        if n <= 0:
            s = "0." + "0" * -n + ds
        elif n >= len(ds):
            s = ds + "0" * (n - len(ds))
        else:
            s = ds[:n] + "." + ds[n:]
    else:
        mant = ds[0] + ("." + ds[1:] if len(ds) > 1 else "")
        s = f'{mant}e{"+" if n - 1 >= 0 else "-"}{abs(n - 1)}'
    return ("-" if sign else "") + s


def _canonical(value) -> str:
    """Canonical JSON per spec 6. Mirrors both reference verifiers exactly."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if -(2**53) <= value <= 2**53:
            return str(value)
        return _js_number(float(value))
    if isinstance(value, float):
        return _js_number(value)
    if isinstance(value, str):
        if re.search(r"[\ud800-\udfff]", value):
            raise ValueError("string contains an unpaired surrogate")
        # ensure_ascii=False per spec 6.1: the default escapes non-ASCII to
        # \uXXXX and the signature would not verify in JavaScript.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, Mapping):
        return (
            "{"
            + ",".join(
                f"{_canonical(str(k))}:{_canonical(value[k])}"
                for k in sorted(value.keys())
            )
            + "}"
        )
    raise ValueError(f"not canonicalisable: {type(value).__name__}")


def canonical_payload(receipt: Mapping[str, object]) -> bytes:
    """
    Return the canonical signing bytes for a receipt, per spec §6.
    Provided as a utility so third-party verifiers can validate their own
    canonicalisation against this reference.
    """
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    return _canonical(payload).encode("utf-8")


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
