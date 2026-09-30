"""Whole-string, ASCII-only matching and the string edge cases (1.2.7).

Python's `$` also matches just before a final line feed and its `\\d` matches
any Unicode decimal digit; JavaScript's do neither. Each vector below must be
refused with exactly the reason the TypeScript verifier gives, which
packages/verify-receipt/src/string-checks.test.ts asserts from its side and
the interop sweeps compare directly.
"""
import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aqta_verify_receipt import verify_receipt
from aqta_verify_receipt.transparency import verify_signed_tree_head

V = Path(__file__).resolve().parents[3] / "test-vectors"
ATT_KEY = "alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E"
ACT_KEY = "pOaccW6Csyo1POtxjixPH80oux9--YC1tzzaENT4vQ0"
TS_REASON = "timestamp must be an RFC 3339 datetime with an explicit offset"

EXPECTED = {
    "invalid/018-request-hash-trailing-newline.json": "request_hash must be 64 lowercase hex chars",
    "invalid/019-timestamp-trailing-newline.json": TS_REASON,
    "invalid/020-signature-trailing-newline.json": "signature decode error: not base64url",
    "invalid/021-timestamp-non-ascii-digits.json": TS_REASON,
    "invalid/022-outcome-not-a-string.json": "outcome must be a string",
    "invalid/023-policy-lone-surrogate.json": "policy_applied must be in lexicographic order",
    "action/invalid/017-args-hash-trailing-newline.json": "args_hash must be 64 lowercase hex characters",
    "action/invalid/018-intent-hash-trailing-newline.json": "intent_hash must be '' or 64 lowercase hex characters",
    "action/invalid/019-timestamp-trailing-newline.json": TS_REASON,
    "action/invalid/020-signature-trailing-newline.json": "signature decode error: not base64url",
    "action/invalid/021-timestamp-non-ascii-digits.json": TS_REASON,
    "action/invalid/022-outcome-not-a-string.json": "outcome must be a string",
    "action/invalid/023-policy-lone-surrogate.json": "policy_applied must be in lexicographic order",
}


def _load(rel):
    return json.loads((V / rel).read_text(encoding="utf-8"))


@pytest.mark.parametrize("rel", sorted(EXPECTED))
def test_vector_is_refused_with_the_shared_reason(rel):
    if rel.startswith("action/"):
        r = verify_receipt(_load(rel), trusted_public_key=ACT_KEY, profile="ACTION-v1")
    else:
        r = verify_receipt(_load(rel), trusted_public_key=ATT_KEY)
    assert (r.valid, r.reason) == (False, EXPECTED[rel])


@pytest.mark.parametrize("outcome", [["ALLOWED"], {"a": 1}, 1, None])
def test_non_string_outcome_is_a_verdict_not_an_exception(outcome):
    r = verify_receipt({**_load("valid/001-allowed.json"), "outcome": outcome}, trusted_public_key=ATT_KEY)
    assert (r.valid, r.reason) == (False, "outcome must be a string")


def test_sorted_lone_surrogate_reaches_canonicalisation_without_raising():
    r = verify_receipt({**_load("valid/001-allowed.json"), "policy_applied": ["\ud800"]}, trusted_public_key=ATT_KEY)
    assert (r.valid, r.reason) == (False, "receipt is not canonicalisable: string contains an unpaired surrogate")


def test_anchor_signature_with_a_trailing_line_feed_is_refused():
    key = Ed25519PrivateKey.generate()
    signed = {"n": 1, "public_key_b64": base64.b64encode(key.public_key().public_bytes_raw()).decode()}
    sig = base64.b64encode(key.sign(json.dumps(signed, separators=(",", ":")).encode())).decode()
    opts = {"allow_untrusted_embedded_key": True, "envelope": "anchor-v1"}
    assert verify_receipt({**signed, "signature_b64": sig}, **opts).valid is True
    r = verify_receipt({**signed, "signature_b64": sig + "\n"}, **opts)
    assert (r.valid, r.reason) == (False, "signature decode error: not base64")


def test_signed_tree_head_refuses_a_trailing_line_feed_in_signature_or_key():
    head = _load("transparency/valid/sth-public-live.json")
    key = head["_trusted_public_key"]
    assert verify_signed_tree_head(head, key).valid is True
    reason = "signature and key must be base64url without padding"
    assert verify_signed_tree_head({**head, "signature": head["signature"] + "\n"}, key).reason == reason
    assert verify_signed_tree_head(head, key + "\n").reason == reason


@pytest.mark.parametrize("name", ["sth-org-id-lone-surrogate.json", "sth-public-timestamp-lone-surrogate.json"])
def test_signed_tree_head_with_a_lone_surrogate_is_refused(name):
    head = _load(f"transparency/invalid/{name}")
    r = verify_signed_tree_head(head, head["_trusted_public_key"])
    assert (r.valid, r.reason) == (False, "head contains an unpaired surrogate")


@pytest.mark.parametrize("body", [b'{"audit_path": [], "x": NaN}', b'{"audit_path": [\x80]}'])
def test_proof_cli_exits_2_on_non_json_and_invalid_utf8(tmp_path, body):
    from aqta_verify_receipt.verify_proof import main

    f = tmp_path / "proof.json"
    f.write_bytes(body)
    with pytest.raises(SystemExit) as exit_info:
        main([str(f), "--json"])
    assert exit_info.value.code == 2
