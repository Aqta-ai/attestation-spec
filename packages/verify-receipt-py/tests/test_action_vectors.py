"""
ACTION-v1 profile conformance tests.

Runs the published action vectors (test-vectors/action/) through the explicit
ACTION-v1 profile with the vector issuer key pinned. The same files are
checked by the TypeScript suite; two implementations disagreeing on any one of
them is a release blocker, per the interop rule in spec/ACTION-v1.md section 6.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aqta_verify_receipt import verify_action_record, verify_receipt  # noqa: E402

# Vector issuer key from test-vectors/action/README.md.
_ACTION_KEY = "pOaccW6Csyo1POtxjixPH80oux9--YC1tzzaENT4vQ0"
_ACTION_DIR = _REPO_ROOT / "test-vectors" / "action"


def _vectors(kind: str) -> list:
    paths = sorted((_ACTION_DIR / kind).glob("*.json"))
    assert paths, f"no action {kind} vectors found"
    return [pytest.param(p, id=p.name) for p in paths]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", _vectors("valid"))
def test_valid_action_vector_verifies(path: Path) -> None:
    record = _load(path)
    result = verify_action_record(record, trusted_public_key=_ACTION_KEY)
    assert result.valid, f"{path.name} must verify: {result.reason}"
    assert result.envelope == "ACTION-v1"
    assert result.key_source == "pinned"


@pytest.mark.parametrize("path", _vectors("invalid"))
def test_invalid_action_vector_rejected(path: Path) -> None:
    record = _load(path)
    result = verify_action_record(record, trusted_public_key=_ACTION_KEY)
    assert not result.valid, f"{path.name} must be rejected"
    assert result.reason, f"{path.name} must carry a reason"


def test_profile_option_on_verify_receipt_matches_wrapper() -> None:
    record = _load(_ACTION_DIR / "valid" / "001-allowed.json")
    via_option = verify_receipt(
        record, trusted_public_key=_ACTION_KEY, profile="ACTION-v1"
    )
    via_wrapper = verify_action_record(record, trusted_public_key=_ACTION_KEY)
    assert via_option == via_wrapper
    assert via_option.valid is True


def test_profile_requires_pin_by_default() -> None:
    record = _load(_ACTION_DIR / "valid" / "001-allowed.json")
    result = verify_action_record(record)
    assert result.valid is False
    assert "trusted_public_key required" in (result.reason or "")


def test_profile_integrity_only_marks_untrusted() -> None:
    record = _load(_ACTION_DIR / "valid" / "001-allowed.json")
    result = verify_action_record(record, allow_untrusted_embedded_key=True)
    assert result.valid is True
    assert result.key_source == "untrusted"


def test_profile_and_envelope_are_mutually_exclusive() -> None:
    record = _load(_ACTION_DIR / "valid" / "001-allowed.json")
    result = verify_receipt(
        record,
        trusted_public_key=_ACTION_KEY,
        profile="ACTION-v1",
        envelope="anchor-v1",
    )
    assert result.valid is False
    assert result.reason == "profile and envelope are mutually exclusive"


def test_action_v1_rejected_as_foreign_envelope() -> None:
    """The signature-only envelope path must never accept an ACTION record.

    Routing envelope='ACTION-v1' through _verify_signed_envelope would skip
    every structural and semantic rule and use the lenient base64 decoder.
    """
    record = _load(_ACTION_DIR / "valid" / "001-allowed.json")
    result = verify_receipt(
        record, trusted_public_key=_ACTION_KEY, envelope="ACTION-v1"
    )
    assert result.valid is False
    assert result.reason == (
        "ACTION-v1 is a profile, not a foreign envelope; use the profile option"
    )


def test_verify_action_record_is_exported() -> None:
    import aqta_verify_receipt as pkg

    assert "verify_action_record" in pkg.__all__
    assert callable(pkg.verify_action_record)


def test_detect_envelope_never_returns_action_v1() -> None:
    from aqta_verify_receipt.verifier import detect_envelope

    record = _load(_ACTION_DIR / "valid" / "001-allowed.json")
    # An action record carries signature/public_key, so field-shape detection
    # sees the ATTESTATION-v1 envelope; the profile is never auto-detected.
    assert detect_envelope(record) == "ATTESTATION-v1"


# Cross-profile discrimination, spec/ACTION-v1.md section 4. Vector
# invalid/007 is a complete, correctly signed ATTESTATION-v1 receipt: it must
# fail the ACTION profile on structure alone, and the same bytes must still
# verify as ATTESTATION-v1 when no profile is requested.
def test_attestation_receipt_fails_action_profile() -> None:
    receipt = _load(_ACTION_DIR / "invalid" / "007-attestation-v1-receipt.json")
    result = verify_action_record(receipt, trusted_public_key=_ACTION_KEY)
    assert result.valid is False
    assert result.reason == "missing required field: action_id"


def test_same_attestation_receipt_verifies_without_profile() -> None:
    receipt = _load(_ACTION_DIR / "invalid" / "007-attestation-v1-receipt.json")
    result = verify_receipt(
        receipt, trusted_public_key=receipt["public_key"]
    )
    assert result.valid is True, result.reason
    assert result.envelope == "ATTESTATION-v1"


# CLI: --profile action-1 per the cross-implementation contract.
def test_cli_action_profile_json_output(tmp_path: Path, capsys) -> None:
    from aqta_verify_receipt.__main__ import main

    src = _ACTION_DIR / "valid" / "001-allowed.json"
    code = main([str(src), "--key", _ACTION_KEY, "--profile", "action-1", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out == {
        "valid": True,
        "outcome": "ALLOWED",
        "action_id": "00000000-0000-0000-0000-000000000001",
        "key_source": "pinned",
        "profile": "ACTION-v1",
        "reason": None,
    }
    assert list(out.keys()) == [
        "valid",
        "outcome",
        "action_id",
        "key_source",
        "profile",
        "reason",
    ]


def test_cli_rejects_unknown_profile_value(capsys) -> None:
    from aqta_verify_receipt.__main__ import main

    src = _ACTION_DIR / "valid" / "001-allowed.json"
    assert main([str(src), "--key", _ACTION_KEY, "--profile", "ACTION-v1"]) == 2
    assert "unknown profile" in capsys.readouterr().err


def test_cli_rejects_profile_with_envelope(capsys) -> None:
    from aqta_verify_receipt.__main__ import main

    src = _ACTION_DIR / "valid" / "001-allowed.json"
    code = main(
        [
            str(src),
            "--key",
            _ACTION_KEY,
            "--profile",
            "action-1",
            "--envelope",
            "anchor-v1",
        ]
    )
    assert code == 2
    assert "not both" in capsys.readouterr().err


def test_cli_invalid_action_vector_exits_1(capsys) -> None:
    from aqta_verify_receipt.__main__ import main

    src = _ACTION_DIR / "invalid" / "012-suppressed-outcome.json"
    code = main([str(src), "--key", _ACTION_KEY, "--profile", "action-1", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 1
    assert out["valid"] is False
    assert out["profile"] == "ACTION-v1"
    assert out["reason"] == "outcome must be ALLOWED or BLOCKED"
