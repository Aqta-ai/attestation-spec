"""
Reference verifier for ATTESTATION-v1 receipts.

Matches the canonical-payload + Ed25519 rules in the spec §6. Never raises;
returns a :class:`VerifyResult` with a human-readable reason string when a
check fails.

Pinning is required by default. A self-signed receipt must not return
``valid=True`` unless ``allow_untrusted_embedded_key`` is set.
"""

from __future__ import annotations

import base64
import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal, Mapping, Optional
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

# ACTION-v1 (spec/ACTION-v1.md). A separate record type, not a widening of
# ATTESTATION-v1: its own required set, its own outcome set. Presence is
# checked in this exact order in both reference implementations, so the two
# emit the same reason for the same multiply-defective record.
ACTION_REQUIRED_FIELDS = (
    "v",
    "action_id",
    "org_id",
    "session_id",
    "intent_hash",
    "agent",
    "tool",
    "args_hash",
    "outcome",
    "policy_applied",
    "timestamp",
    "public_key",
    "signature",
)
_ACTION_REQUIRED_SET = frozenset(ACTION_REQUIRED_FIELDS)
ACTION_ALLOWED_OUTCOMES = frozenset({"ALLOWED", "BLOCKED"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Range-checks the calendar without parsing, and permits a leap second (:60),
# which is legal RFC 3339. Character-for-character identical to the regex in
# the TypeScript verifier: the two must agree on what a timestamp is.
_RFC3339_OFFSET = re.compile(
    r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])"
    r"[Tt ]([01]\d|2[0-3]):[0-5]\d:([0-5]\d|60)(\.\d+)?"
    r"([Zz]|[+-]([01]\d|2[0-3]):[0-5]\d)$"
)
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_LONE_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _js_number(x: float) -> str:
    """ECMA-262 Number::toString, which is what RFC 8785 (JCS) 3.2.2.3 requires.

    Python and JavaScript disagree about how to render a float. Python switches
    to exponent notation below 1e-4 and zero-pads the exponent (1e-05);
    JavaScript switches below 1e-6 and does not (0.00001). Every value in
    0 < |x| < 1e-4 therefore canonicalised to different bytes in the two
    reference verifiers, so a correctly signed receipt from the reference issuer
    verified in Python and failed in JavaScript with "signature check failed".
    spec 4 permits six digits of precision, so the whole divergent band is
    reachable by a conforming issuer.

    JavaScript is the side that matches RFC 8785, so Python moves to it.
    """
    if not math.isfinite(x):
        raise ValueError("non-finite number")
    if x == 0:
        return "0"  # ECMA-262 renders both +0 and -0 as "0"
    sign, digits, exp = Decimal(repr(x)).as_tuple()  # repr is shortest round-trip
    ds = "".join(map(str, digits))
    # n is the position of the decimal point relative to the leading digit, so
    # it is fixed before trailing zeros are dropped. Dropping them is what makes
    # 1.0 render as "1" and 1.2345678901234568e20 render as the shortest
    # round-tripping form rather than the exact binary value.
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
    """Canonical JSON for one value, mirroring the TypeScript canonicalValue.

    Written out rather than delegated to json.dumps because the float rule
    above has to apply at every depth, and because both implementations must
    be the same algorithm rather than two languages' defaults that happen to
    agree on the values anyone happened to test.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        # JSON numbers are IEEE 754 binary64 (spec 6). Python keeps large
        # integer literals exact where JavaScript's JSON.parse rounds them, so
        # anything outside the exactly-representable range goes through the
        # double model to keep the two implementations on one numeric model.
        if -(2**53) <= value <= 2**53:
            return str(value)
        return _js_number(float(value))
    if isinstance(value, float):
        return _js_number(value)
    if isinstance(value, str):
        if _LONE_SURROGATE.search(value):
            # Not encodable as UTF-8, so there is no canonical payload to sign.
            raise ValueError("string contains an unpaired surrogate")
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, Mapping):
        return (
            "{"
            + ",".join(
                f"{_canonical(str(k))}:{_canonical(value[k])}"
                # RFC 8785 3.2.3: member names sort by UTF-16 code units, the
                # order JavaScript's default string sort produces. Plain
                # sorted() compares code points, which reverses astral-plane
                # names against U+E000..U+FFFF. surrogatepass keeps the sort
                # key total; lone surrogates still fail inside _canonical.
                for k in sorted(
                    value.keys(),
                    key=lambda k: str(k).encode("utf-16-be", "surrogatepass"),
                )
            )
            + "}"
        )
    raise ValueError(f"not canonicalisable: {type(value).__name__}")


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return _canonical(payload).encode("utf-8")


_DEFAULT_PUBKEY_URL = "https://app.aqta.ai/security/pubkey.txt"

KeySource = Literal["pinned", "untrusted"]


@dataclass
class VerifyResult:
    """Outcome of :func:`verify_receipt`."""

    valid: bool
    reason: Optional[str] = None
    key_source: Optional[KeySource] = None
    #: Which envelope format was recognised, when one was.
    envelope: Optional[str] = None


def _b64url_decode(s: str) -> bytes:
    """Strict base64url, no padding, per spec 4.

    base64.urlsafe_b64decode defaults to validate=False, which silently
    discards every character outside the alphabet and stops at the first "=".
    Since `signature` is the one field the signature cannot cover, that made it
    an unauthenticated write channel: arbitrary text could be appended to a
    genuine signature and the receipt still passed a pinned check here while
    failing in JavaScript.
    """
    if not isinstance(s, str) or not _B64URL.match(s):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64_any_decode(s: str) -> bytes:
    """Lenient decoder for foreign envelopes, which use standard base64.

    Kept separate so ATTESTATION-v1 stays strict. Only the alphabet is
    relaxed here; anything outside it is still rejected.
    """
    if not isinstance(s, str) or not re.match(r"^[A-Za-z0-9_+/-]+=*$", s):
        raise ValueError("not base64")
    t = s.rstrip("=").replace("+", "-").replace("/", "_")
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))


ENVELOPE_FIELDS = {
    "ATTESTATION-v1": ("signature", "public_key"),
    "anchor-v1": ("signature_b64", "public_key_b64"),
}


def detect_envelope(receipt: object) -> Optional[str]:
    """Identify an envelope by the field names it carries, else None.

    An auditor should install one verifier, not one per issuer. The formats
    differ only in which fields hold the signature and the signer's key, and in
    base64 versus base64url, which ``_b64url_decode`` already normalises. The
    canonicalisation rule is identical in both.
    """
    if not isinstance(receipt, dict):
        return None
    if isinstance(receipt.get("signature"), str) and isinstance(
        receipt.get("public_key"), str
    ):
        return "ATTESTATION-v1"
    if isinstance(receipt.get("signature_b64"), str) and isinstance(
        receipt.get("public_key_b64"), str
    ):
        return "anchor-v1"
    return None


def _verify_signed_envelope(
    receipt: dict,
    envelope: str,
    trusted_public_key: Optional[str],
    allow_untrusted_embedded_key: bool,
) -> "VerifyResult":
    """Signature check shared by every envelope.

    Answers only "were these bytes signed by this key". Format-specific
    structural rules, such as ATTESTATION-v1's twelve-field requirement, are
    applied by the caller before this runs.
    """
    sig_field, key_field = ENVELOPE_FIELDS[envelope]

    if trusted_public_key is None and not allow_untrusted_embedded_key:
        return VerifyResult(
            False,
            "trusted_public_key required "
            "(pass allow_untrusted_embedded_key for integrity-only)",
        )

    embedded = receipt[key_field]
    if trusted_public_key is not None and trusted_public_key != embedded:
        return VerifyResult(False, "public key does not match trusted key")

    payload = {k: v for k, v in receipt.items() if k != sig_field}
    try:
        canonical = _canonical_bytes(payload)
    except (ValueError, TypeError, OverflowError, UnicodeEncodeError) as e:
        return VerifyResult(False, f"receipt is not canonicalisable: {e}")

    try:
        sig = _b64_any_decode(receipt[sig_field])
        pub = _b64_any_decode(embedded)
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

    return VerifyResult(
        True,
        key_source="pinned" if trusted_public_key is not None else "untrusted",
        envelope=envelope,
    )


def _verify_action_record(
    record: Mapping[str, Any],
    trusted_public_key: Optional[str],
    allow_untrusted_embedded_key: bool,
    strict_fields: bool,
) -> "VerifyResult":
    """ACTION-v1 profile verification (spec/ACTION-v1.md sections 4-7).

    The check order is a cross-implementation contract: both reference
    verifiers run this exact sequence and the first failure wins, so the two
    emit identical reasons for identical bytes. The signature path is the
    strict one: the strict base64url decoder, never the lenient foreign
    envelope decoder.
    """
    # 2. Required-field presence, in the contract's order.
    for field in ACTION_REQUIRED_FIELDS:
        if field not in record:
            return VerifyResult(False, f"missing required field: {field}")
    # 3. Unknown top-level fields, spec section 4.
    if strict_fields:
        unknown = set(record.keys()) - _ACTION_REQUIRED_SET
        if unknown:
            return VerifyResult(
                False, f"unknown top-level field: {sorted(unknown)[0]}"
            )
    # 4. Version tag. ATTESTATION-v1 uses the integer 1; this profile uses
    # the string "action-1". The type is part of the discrimination.
    if not isinstance(record["v"], str) or record["v"] != "action-1":
        return VerifyResult(False, "v must be the string 'action-1'")
    # 5. Types: every field except policy_applied is a string (there are no
    # numeric fields in this profile, by design); policy_applied is an array.
    for field in ACTION_REQUIRED_FIELDS:
        if field == "policy_applied":
            if not isinstance(record[field], list):
                return VerifyResult(False, "policy_applied must be an array")
        elif not isinstance(record[field], str):
            return VerifyResult(False, f"{field} must be a string")
    # 6-12. Semantic checks, spec section 7.
    if record["outcome"] not in ACTION_ALLOWED_OUTCOMES:
        return VerifyResult(False, "outcome must be ALLOWED or BLOCKED")
    if record["tool"] == "":
        return VerifyResult(False, "tool must be a non-empty string")
    if not _HEX64.match(record["args_hash"]):
        return VerifyResult(
            False, "args_hash must be 64 lowercase hex characters"
        )
    if record["intent_hash"] != "" and not _HEX64.match(record["intent_hash"]):
        return VerifyResult(
            False, "intent_hash must be '' or 64 lowercase hex characters"
        )
    if record["intent_hash"] != "" and record["session_id"] == "":
        return VerifyResult(
            False, "intent_hash requires a non-empty session_id"
        )
    if not all(isinstance(p, str) for p in record["policy_applied"]):
        return VerifyResult(False, "policy_applied must contain only strings")
    if list(record["policy_applied"]) != sorted(record["policy_applied"]):
        return VerifyResult(
            False, "policy_applied must be in lexicographic order"
        )
    if not _RFC3339_OFFSET.match(record["timestamp"]):
        return VerifyResult(
            False,
            "timestamp must be an RFC 3339 datetime with an explicit offset",
        )

    # 13. Key pinning, same rules and wording as ATTESTATION-v1.
    if trusted_public_key is None and not allow_untrusted_embedded_key:
        return VerifyResult(
            False,
            "trusted_public_key required "
            "(pass allow_untrusted_embedded_key for integrity-only)",
        )
    if (
        trusted_public_key is not None
        and trusted_public_key != record["public_key"]
    ):
        return VerifyResult(False, "public_key does not match trusted key")

    # Canonical payload, spec section 6: same shared canonicalisation as
    # ATTESTATION-v1. No numeric fields exist to canonicalise, but the code
    # path must be the shared one, not a profile-local reimplementation.
    payload = {k: v for k, v in record.items() if k != "signature"}
    try:
        canonical = _canonical_bytes(payload)
    except (ValueError, TypeError, OverflowError, UnicodeEncodeError) as e:
        return VerifyResult(False, f"receipt is not canonicalisable: {e}")

    # 14. Signature: strict base64url only.
    try:
        sig = _b64url_decode(record["signature"])
        pub = _b64url_decode(record["public_key"])
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

    return VerifyResult(
        True,
        key_source="pinned" if trusted_public_key is not None else "untrusted",
        envelope="ACTION-v1",
    )


def verify_receipt(
    receipt: Mapping[str, Any],
    *,
    trusted_public_key: Optional[str] = None,
    allow_untrusted_embedded_key: bool = False,
    strict_fields: bool = True,
    envelope: Optional[str] = None,
    profile: Optional[str] = None,
) -> VerifyResult:
    """
    Verify a Seal attestation receipt.

    Parameters
    ----------
    receipt
        The full receipt dict including the ``signature`` field.
    trusted_public_key
        Base64url public key (no padding). Required for a counsel-grade check:
        the receipt must carry this key and verify under it.
    allow_untrusted_embedded_key
        If True, verify against the embedded ``public_key`` without pinning.
        Result includes ``key_source="untrusted"``. Default False.
    strict_fields
        If True (default), unknown top-level fields cause rejection, per spec §4.
    envelope
        Name of a non-ATTESTATION-v1 envelope the caller is deliberately
        verifying. Foreign envelopes carry their own field sets, so none of
        ATTESTATION-v1's structural or semantic rules apply to them; naming one
        here is how a caller says it understands that.
    profile
        Explicit verification profile. The only accepted value is
        ``"ACTION-v1"`` (spec/ACTION-v1.md), and it must be requested by the
        caller: profiles are never auto-detected from the input's field shape
        (spec section 7). Mutually exclusive with ``envelope``. See also
        :func:`verify_action_record`.

    Returns
    -------
    VerifyResult
        ``valid=True`` iff the Ed25519 signature is valid under the pinned
        (or explicitly allowed embedded) public key. Never raises.
    """
    expect_envelope = envelope
    # Profile selection runs before envelope detection: a profile is an
    # explicit caller decision, never an inference from the input.
    if profile is not None and expect_envelope is not None:
        return VerifyResult(False, "profile and envelope are mutually exclusive")
    if expect_envelope == "ACTION-v1":
        # The foreign-envelope path is signature-only and uses the lenient
        # decoder. Routing an ACTION record through it would skip every
        # structural and semantic rule, so the misuse is named rather than
        # silently honoured.
        return VerifyResult(
            False,
            "ACTION-v1 is a profile, not a foreign envelope; "
            "use the profile option",
        )
    if not isinstance(receipt, Mapping):
        return VerifyResult(False, "receipt is not a mapping")
    if profile is not None:
        if profile != "ACTION-v1":
            return VerifyResult(False, f"unknown profile: {profile}")
        return _verify_action_record(
            receipt,
            trusted_public_key,
            allow_untrusted_embedded_key,
            strict_fields,
        )

    envelope = detect_envelope(receipt)
    if envelope is None:
        return VerifyResult(
            False,
            "unrecognised envelope: expected signature/public_key "
            "or signature_b64/public_key_b64",
        )
    # Other issuers' envelopes carry their own field sets, so only the
    # signature is checked. The rules below are ATTESTATION-v1's alone.
    #
    # That has to be opted into. Detecting a foreign envelope by field name
    # meant any object naming its fields signature_b64/public_key_b64 skipped
    # every structural and semantic rule: a payload carrying v:99,
    # outcome:"MAYBE" and request_hash:"nope" verified, and so did an object
    # that was not a receipt at all. Exit 0 then meant "these bytes were signed
    # by that key" rather than "this is a conformant ATTESTATION-v1 receipt",
    # which is not the question the tool is asked.
    if envelope != "ATTESTATION-v1":
        if expect_envelope != envelope:
            return VerifyResult(
                False,
                f"envelope {envelope} requires explicit opt-in "
                f"(pass envelope={envelope!r}); "
                "ATTESTATION-v1 rules do not apply to it",
            )
        return _verify_signed_envelope(
            receipt, envelope, trusted_public_key, allow_untrusted_embedded_key
        )

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
    # isinstance excluding bool is required, not stylistic: bool subclasses
    # int in Python, so True == 1 and a receipt carrying "v": true passed this
    # gate while the TypeScript verifier's strict !== rejected it. Reported by
    # Michael Msebenzi, 2026-08-05.
    if not isinstance(receipt["v"], int) or isinstance(receipt["v"], bool) or receipt["v"] != 1:
        return VerifyResult(False, f"unsupported version: {receipt['v']!r}")
    if receipt["outcome"] not in ALLOWED_OUTCOMES:
        return VerifyResult(False, f"invalid outcome: {receipt['outcome']!r}")
    if not isinstance(receipt["policy_applied"], list):
        return VerifyResult(False, "policy_applied must be an array")
    # Draft 6 step 1 specifies three further checks that neither verifier
    # implemented, because no test vector exercised them: the conformance
    # suite derived its invalid vectors by mutating a signed receipt, so
    # every one failed on the signature first. Reported by Michael Msebenzi
    # 2026-08-05; vectors 009-013 now cover these.
    if not all(isinstance(p, str) for p in receipt["policy_applied"]):
        return VerifyResult(False, "policy_applied must contain only strings")
    if list(receipt["policy_applied"]) != sorted(receipt["policy_applied"]):
        return VerifyResult(
            False, "policy_applied must be in lexicographic order"
        )
    cost = receipt["cost_prevented_eur"]
    # isfinite matters: 1e999 is ordinary RFC 8259 JSON, so it never reaches
    # the parse_constant guard that rejects the NaN and Infinity literals. It
    # arrives here as inf, passes an isinstance check, and used to reach
    # int(value) in the coercion path, which raises OverflowError. Parity with
    # the TypeScript Number.isFinite check.
    if (
        isinstance(cost, bool)
        or not isinstance(cost, (int, float))
        or (isinstance(cost, float) and not math.isfinite(cost))
    ):
        return VerifyResult(False, "cost_prevented_eur must be a number")
    if cost < 0:
        return VerifyResult(False, "cost_prevented_eur must be non-negative")
    ts = receipt["timestamp"]
    if not isinstance(ts, str) or not _RFC3339_OFFSET.match(ts):
        return VerifyResult(
            False,
            "timestamp must be an RFC 3339 datetime with an explicit offset",
        )
    rh = receipt["request_hash"]
    if not isinstance(rh, str) or not _HEX64.match(rh):
        return VerifyResult(False, "request_hash must be 64 lowercase hex chars")

    if trusted_public_key is None and not allow_untrusted_embedded_key:
        return VerifyResult(
            False,
            "trusted_public_key required "
            "(pass allow_untrusted_embedded_key for integrity-only)",
        )

    # Pinning
    if (
        trusted_public_key is not None
        and trusted_public_key != receipt["public_key"]
    ):
        return VerifyResult(False, "public_key does not match trusted key")

    # Canonical payload per spec §6.
    # ensure_ascii=False is required, not stylistic: the default escapes
    # non-ASCII to \uXXXX, so a policy name like "Größe-Limit" would canonicalise
    # to different bytes here than under JSON.stringify, and a receipt valid in
    # Python would fail in JavaScript. The spec mandates raw UTF-8.
    # Integer-valued floats are coerced to int before serialisation, per
    # spec 6(3) and draft 5 step 4. The TypeScript verifier already did
    # this; Python did not, so a receipt signed by a non-conforming issuer
    # over "1.0" verified here and failed there. Coercing means such a
    # receipt now fails in BOTH, which is the intended behaviour: it is a
    # non-conforming issuer and the mismatch should surface.
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        canonical = _canonical_bytes(payload)
    except (ValueError, TypeError, OverflowError, UnicodeEncodeError) as e:
        # The contract is that this never raises. Any value that has no
        # canonical form, an unpaired surrogate for instance, is a malformed
        # receipt and must be reported as one rather than escape as a traceback.
        return VerifyResult(False, f"receipt is not canonicalisable: {e}")

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

    return VerifyResult(
        True,
        key_source="pinned" if trusted_public_key is not None else "untrusted",
        envelope="ATTESTATION-v1",
    )


def verify_action_record(
    record: Mapping[str, Any],
    *,
    trusted_public_key: Optional[str] = None,
    allow_untrusted_embedded_key: bool = False,
    strict_fields: bool = True,
) -> VerifyResult:
    """
    Verify a Seal ACTION-v1 action authorisation record.

    Convenience wrapper for :func:`verify_receipt` with
    ``profile="ACTION-v1"``. Same pinning rules: a trusted public key is
    required unless ``allow_untrusted_embedded_key`` is set, in which case the
    result is labelled ``key_source="untrusted"``. Never raises.
    """
    return verify_receipt(
        record,
        trusted_public_key=trusted_public_key,
        allow_untrusted_embedded_key=allow_untrusted_embedded_key,
        strict_fields=strict_fields,
        profile="ACTION-v1",
    )


def fetch_published_public_key(
    url: str = _DEFAULT_PUBKEY_URL, *, timeout: float = 10.0
) -> str:
    """
    Fetch the issuer's published public key and return a trimmed base64url
    string ready to pass as ``trusted_public_key`` to :func:`verify_receipt`.

    .. warning::
        PIN THE RESULT. This helper performs a live HTTPS fetch. Calling it
        on every verification collapses the trust model back to "trust the
        issuer's server right now", which is exactly what the attestation
        format is designed to avoid.

        The correct pattern is:

        1. Call this function once on first use.
        2. Persist the returned string (configuration file, database, KMS,
           environment variable, secret manager).
        3. Pass the persisted value as ``trusted_public_key`` to
           :func:`verify_receipt` on every subsequent verification.
        4. Rotate only when you receive a documented key-rotation notice
           via a channel you already trust.

        Using this helper in a verification loop without pinning the first
        result is a misuse.
    """
    with urlopen(url, timeout=timeout) as resp:  # nosec B310 (HTTPS URL)
        if resp.status != 200:
            raise RuntimeError(f"failed to fetch public key: HTTP {resp.status}")
        return resp.read().decode("utf-8").strip()
