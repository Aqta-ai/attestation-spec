"""
Reference issuer for ACTION-v1 records (spec/ACTION-v1.md).

The sibling of reference-issuer.py: same key handling, same canonical
serialisation, a different record type. It deliberately imports the
canonicalisation from reference-issuer.py rather than restating it; the two
profiles must share bytes-level behaviour, and one implementation of the
rules is how that stays true.

This code is *not* a production issuer. A real issuer additionally enforces
policy before signing, persists records to a tamper-evident log, and holds
the private key in a secret manager. This file demonstrates the format side
only. Apache-2.0.
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

# Shared canonicalisation: import from the sibling reference issuer so the
# two profiles can never drift at the byte level.
_spec = importlib.util.spec_from_file_location(
    "attestation_ref", Path(__file__).resolve().parent / "reference-issuer.py"
)
_ref = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_ref)  # type: ignore[union-attr]

canonical_payload = _ref.canonical_payload  # re-exported utility

SPEC_VERSION = "action-1"
ALLOWED_OUTCOMES = {"ALLOWED", "BLOCKED"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def args_hash_of(args: Mapping[str, object]) -> str:
    """
    SHA-256 hex of the canonical byte serialisation of an argument object,
    per spec ACTION-v1 §6. Both sides of a check MUST hash the canonical
    form, never raw request bytes.
    """
    return hashlib.sha256(_ref._canonical(args).encode("utf-8")).hexdigest()


class ReferenceActionIssuer:
    """Minimal ACTION-v1 issuer, deterministic when keyed via from_seed."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key

    @classmethod
    def new(cls) -> "ReferenceActionIssuer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed_bytes: bytes) -> "ReferenceActionIssuer":
        if len(seed_bytes) != 32:
            raise ValueError("seed_bytes must be exactly 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed_bytes))

    @property
    def public_key_b64(self) -> str:
        raw = self.private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        return _b64url_encode(raw)

    def sign(
        self,
        *,
        org_id: str,
        agent: str,
        tool: str,
        args_hash: str,
        outcome: str,
        policy_applied: List[str],
        session_id: str = "",
        intent_hash: str = "",
        action_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Mapping[str, object]:
        """
        Produce a signed ACTION-v1 record. Validation mirrors the spec's
        semantic checks (§7) so the reference issuer cannot emit a record the
        reference verifiers would reject.
        """
        if outcome not in ALLOWED_OUTCOMES:
            raise ValueError(f"outcome must be one of {ALLOWED_OUTCOMES}")
        if not tool:
            raise ValueError("tool must be non-empty")
        if not _HEX64.match(args_hash):
            raise ValueError("args_hash must be 64 lowercase hex chars")
        if intent_hash and not _HEX64.match(intent_hash):
            raise ValueError("intent_hash must be '' or 64 lowercase hex chars")
        if intent_hash and not session_id:
            raise ValueError("intent_hash requires a session_id (spec §7)")

        payload = {
            "v": SPEC_VERSION,
            "action_id": action_id or str(uuid.uuid4()),
            "org_id": org_id,
            "session_id": session_id,
            "intent_hash": intent_hash,
            "agent": agent,
            "tool": tool,
            "args_hash": args_hash,
            "outcome": outcome,
            "policy_applied": sorted(policy_applied),
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "public_key": self.public_key_b64,
        }

        canonical = canonical_payload(payload)
        signature = self.private_key.sign(canonical)
        return {**payload, "signature": _b64url_encode(signature)}


if __name__ == "__main__":
    issuer = ReferenceActionIssuer.from_seed(
        hashlib.sha256(b"attestation-spec/examples/action").digest()
    )
    record = issuer.sign(
        org_id="org-example",
        session_id="sess-example-0001",
        intent_hash=hashlib.sha256(b"fix the failing auth test").hexdigest(),
        agent="claude-code/2.1",
        tool="github.merge_pull_request",
        args_hash=args_hash_of({"repo": "example/api", "pr": 41}),
        outcome="BLOCKED",
        policy_applied=["production_change_review", "require_intent"],
        action_id="00000000-0000-0000-0000-00000000a001",
        timestamp="2026-08-22T14:03:11.412903+00:00",
    )
    print(json.dumps(record, indent=2, sort_keys=True))
