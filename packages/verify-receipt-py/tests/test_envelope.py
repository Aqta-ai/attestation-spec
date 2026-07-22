"""Multi-envelope tests.

The claim being defended: an auditor installs one verifier, not one per issuer.
These cover envelope detection and the shared signature path for anchor-v1
receipts, which the ATTESTATION-v1 tests do not reach. They mirror
``packages/verify-receipt/src/envelope.test.ts`` case for case, because two
reference implementations that disagree are worse than one.
"""

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aqta_verify_receipt.verifier import detect_envelope, verify_receipt


def _canonical(payload: dict) -> bytes:
    """The canonical form both envelopes share: sorted keys, no whitespace."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def make_anchor(**overrides):
    """Mint a signed anchor-v1 receipt with a throwaway key."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    signed = {
        "checked_at": "2026-07-22T21:00:00Z",
        "transcript_sha256": "a" * 64,
        "summary_sha256": "b" * 64,
        "bound": 7,
        "gaps": 1,
        "public_key_b64": base64.b64encode(pub).decode(),
        **overrides,
    }
    sig = key.sign(_canonical(signed))
    receipt = {**signed, "signature_b64": base64.b64encode(sig).decode()}
    return receipt, signed["public_key_b64"]


def test_detect_attestation_v1():
    assert detect_envelope({"signature": "x", "public_key": "y"}) == "ATTESTATION-v1"


def test_detect_anchor_v1():
    assert detect_envelope({"signature_b64": "x", "public_key_b64": "y"}) == "anchor-v1"


@pytest.mark.parametrize(
    "value",
    [
        {"hello": "world"},
        None,
        "a string",
        {"signature": 1, "public_key": 2},  # present but wrong type
    ],
)
def test_detect_returns_none_rather_than_guessing(value):
    assert detect_envelope(value) is None


def test_genuine_anchor_receipt_verifies():
    receipt, key = make_anchor()
    result = verify_receipt(receipt, trusted_public_key=key)
    assert result.valid is True
    assert result.envelope == "anchor-v1"
    assert result.key_source == "pinned"


def test_altering_a_signed_field_breaks_it():
    receipt, key = make_anchor()
    result = verify_receipt({**receipt, "bound": 99}, trusted_public_key=key)
    assert result.valid is False
    assert result.reason == "signature check failed"


def test_will_not_verify_against_a_different_key():
    receipt, _ = make_anchor()
    _, other = make_anchor()
    result = verify_receipt(receipt, trusted_public_key=other)
    assert result.valid is False
    assert result.reason == "public key does not match trusted key"


def test_refuses_to_run_without_a_pinned_key():
    receipt, _ = make_anchor()
    result = verify_receipt(receipt)
    assert result.valid is False
    assert "trusted_public_key required" in (result.reason or "")


def test_integrity_only_reports_key_as_untrusted():
    receipt, _ = make_anchor()
    result = verify_receipt(receipt, allow_untrusted_embedded_key=True)
    assert result.valid is True
    assert result.key_source == "untrusted"


def test_non_ascii_still_verifies():
    receipt, key = make_anchor(note="Größe · héllo · 世界")
    assert verify_receipt(receipt, trusted_public_key=key).valid is True


def test_unrecognised_envelope_is_rejected_not_assumed():
    result = verify_receipt({"some": "object"}, trusted_public_key="k")
    assert result.valid is False
    assert "unrecognised envelope" in (result.reason or "")
