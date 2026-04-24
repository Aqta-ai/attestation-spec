"""
Reference verifier for ATTESTATION-v1 receipts.

Matches the canonical-payload + Ed25519 rules in the spec §6. Never raises;
returns a :class:`VerifyResult` with a human-readable reason string when a
check fails.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from urllib.request import urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


REQUIRED_FIELDS = frozenset(
    {
        "v",
        "attestation_id",
        "trace_id",
        "org_id",
        "request_hash",
        "model",
        "outcome",
        "policy_applied",
        "cost_prevented_eur",
        "timestamp",
        "public_key",
        "signature",
    }
)

ALLOWED_OUTCOMES = frozenset({"ALLOWED", "BLOCKED", "SUPPRESSED", "PASSED"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_PUBKEY_URL = "https://app.aqta.ai/security/pubkey.txt"


@dataclass
class VerifyResult:
    """Outcome of :func:`verify_receipt`."""

    valid: bool
    reason: Optional[str] = None


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def verify_receipt(
    receipt: Mapping[str, Any],
    *,
    trusted_public_key: Optional[str] = None,
    strict_fields: bool = True,
) -> VerifyResult:
    """
    Verify an AqtaCore attestation receipt.

    Parameters
    ----------
    receipt
        The full receipt dict including the ``signature`` field.
    trusted_public_key
        Optional base64url public key (no padding). If supplied, the receipt's
        ``public_key`` field must match byte-for-byte. Strongly recommended.
    strict_fields
        If True (default), unknown top-level fields cause rejection, per spec §4.

    Returns
    -------
    VerifyResult
        ``valid=True`` iff the Ed25519 signature is valid under the declared
        (and optionally pinned) public key. Never raises.
    """
    if not isinstance(receipt, Mapping):
        return VerifyResult(False, "receipt is not a mapping")

    # Structural checks
    for field in REQUIRED_FIELDS:
        if field not in receipt:
            return VerifyResult(False, f"missing required field: {field}")
    if strict_fields:
        unknown = set(receipt.keys()) - REQUIRED_FIELDS
        if unknown:
            return VerifyResult(
                False, f"unknown top-level field: {sorted(unknown)[0]}"
            )

    # Semantic sanity
    if receipt["v"] != 1:
        return VerifyResult(False, f"unsupported version: {receipt['v']!r}")
    if receipt["outcome"] not in ALLOWED_OUTCOMES:
        return VerifyResult(False, f"invalid outcome: {receipt['outcome']!r}")
    if not isinstance(receipt["policy_applied"], list):
        return VerifyResult(False, "policy_applied must be an array")
    rh = receipt["request_hash"]
    if not isinstance(rh, str) or not _HEX64.match(rh):
        return VerifyResult(False, "request_hash must be 64 lowercase hex chars")

    # Pinning
    if trusted_public_key is not None and trusted_public_key != receipt["public_key"]:
        return VerifyResult(False, "public_key does not match trusted key")

    # Canonical payload per spec §6
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )

    # Signature verification (constant-time via cryptography library)
    try:
        sig = _b64url_decode(receipt["signature"])
        pub = _b64url_decode(receipt["public_key"])
    except Exception as e:
        return VerifyResult(False, f"signature decode error: {e}")

    if len(sig) != 64:
        return VerifyResult(False, "signature length != 64 bytes")
    if len(pub) != 32:
        return VerifyResult(False, "public key length != 32 bytes")

    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, canonical)
    except InvalidSignature:
        return VerifyResult(False, "signature check failed")
    except Exception as e:
        return VerifyResult(False, f"verification error: {e}")

    return VerifyResult(True)


def fetch_published_public_key(
    url: str = _DEFAULT_PUBKEY_URL, *, timeout: float = 10.0
) -> str:
    """
    Fetch the issuer's published public key and return a trimmed base64url
    string ready to pass as ``trusted_public_key`` to :func:`verify_receipt`.

    Callers SHOULD pin this value once retrieved rather than re-fetching
    on every verification.
    """
    with urlopen(url, timeout=timeout) as resp:  # nosec B310 (HTTPS URL)
        if resp.status != 200:
            raise RuntimeError(f"failed to fetch public key: HTTP {resp.status}")
        return resp.read().decode("utf-8").strip()
