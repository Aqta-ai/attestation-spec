"""
Tests for the Python reference verifier.

Uses the standalone reference issuer (examples/reference-issuer.py) to
produce real signed receipts, then verifies them through the public
`aqta_verify_receipt.verify_receipt` API. This proves the spec's
canonical-payload rules and Ed25519 signing are consistent end to end.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

_issuer_path = _REPO_ROOT / "examples" / "reference-issuer.py"
_spec = importlib.util.spec_from_file_location("reference_issuer", _issuer_path)
_ref = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
assert _spec and _spec.loader, "failed to load reference-issuer module"
_spec.loader.exec_module(_ref)  # type: ignore[union-attr]

from aqta_verify_receipt import verify_receipt  # noqa: E402


@pytest.fixture(scope="module")
def issuer():
    return _ref.ReferenceIssuer.new()


@pytest.fixture
def receipt(issuer) -> dict:
    return dict(
        issuer.sign(
            trace_id="trace-fixture-v1",
            org_id="org-test",
            request_hash="8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
            model="gpt-4o",
            outcome="ALLOWED",
            policy_applied=["budget_guard", "loop_guard"],
            cost_prevented_eur=0.0,
        )
    )


def test_requires_pin_by_default(receipt):
    res = verify_receipt(receipt)
    assert res.valid is False
    assert "trusted_public_key required" in (res.reason or "")


def test_real_receipt_verifies_with_pin(receipt):
    res = verify_receipt(receipt, trusted_public_key=receipt["public_key"])
    assert res.valid is True, res.reason
    assert res.key_source == "pinned"


def test_integrity_only_marks_untrusted(receipt):
    res = verify_receipt(receipt, allow_untrusted_embedded_key=True)
    assert res.valid is True, res.reason
    assert res.key_source == "untrusted"


def test_pinned_public_key_mismatch_rejects(receipt):
    res = verify_receipt(
        receipt, trusted_public_key="some_other_base64url_public_key_here"
    )
    assert res.valid is False
    assert "trusted key" in (res.reason or "")


def test_tampered_signature_rejects(receipt):
    bad = dict(receipt)
    sig = bad["signature"]
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    bad["signature"] = flipped
    res = verify_receipt(bad, trusted_public_key=receipt["public_key"])
    assert res.valid is False


def test_tampered_field_rejects(receipt):
    bad = dict(receipt)
    bad["outcome"] = "BLOCKED"  # valid value, but not the signed one
    res = verify_receipt(bad, trusted_public_key=receipt["public_key"])
    assert res.valid is False
    assert "signature check" in (res.reason or "")


def test_unknown_field_strict_rejects(receipt):
    bad = dict(receipt)
    bad["extra"] = "surprise"
    res = verify_receipt(bad, trusted_public_key=receipt["public_key"])
    assert res.valid is False
    assert "unknown top-level field" in (res.reason or "")


def test_missing_field_rejects(receipt):
    bad = dict(receipt)
    del bad["outcome"]
    res = verify_receipt(bad, trusted_public_key=receipt["public_key"])
    assert res.valid is False
    assert "missing required field" in (res.reason or "")


def test_wrong_version_rejects(receipt):
    bad = dict(receipt)
    bad["v"] = 2
    res = verify_receipt(bad, trusted_public_key=receipt["public_key"])
    assert res.valid is False
    assert "unsupported version" in (res.reason or "")


def test_never_raises_on_garbage():
    assert verify_receipt({}).valid is False
    assert verify_receipt({"v": 1}).valid is False
    assert verify_receipt("not a mapping").valid is False  # type: ignore[arg-type]


# Conformance against the published test vectors.
#
# The same files are checked by the TypeScript suite. Running them in both
# languages is what catches a canonicalisation change that one accepts and
# the other rejects; a fixture built locally by this language alone cannot.
_VECTOR_KEY = "alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E"
_VECTOR_DIR = _REPO_ROOT / "test-vectors"


def _vectors(kind: str) -> list:
    paths = sorted((_VECTOR_DIR / kind).glob("*.json"))
    assert paths, f"no {kind} vectors found"
    return [pytest.param(p, id=p.name) for p in paths]


@pytest.mark.parametrize("path", _vectors("valid"))
def test_valid_vector_verifies(path: Path) -> None:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    result = verify_receipt(receipt, trusted_public_key=_VECTOR_KEY)
    assert result.valid, f"{path.name} must verify: {result.reason}"


@pytest.mark.parametrize("path", _vectors("invalid"))
def test_invalid_vector_rejected(path: Path) -> None:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    result = verify_receipt(receipt, trusted_public_key=_VECTOR_KEY)
    assert not result.valid, f"{path.name} must be rejected"
