"""
Generate deterministic test vectors for ACCEPT-v1 conformance testing.

Sibling of ../generate.py and ../action/generate.py. Same seeded-key
discipline, same rule: every vector participates in the interop sweep.

The invalid set carries one vector per sibling profile (007, 008). A verifier
that accepts either is inferring the format from field shape, which the
specs forbid, and the shapes are close enough that this is a real mistake to
make rather than a theoretical one.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, _REPO_ROOT / rel)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


_acc = _load("acc_ref", "examples/reference-acceptance-issuer.py")
_att = _load("att_ref", "examples/reference-issuer.py")
_act = _load("act_ref", "examples/reference-action-issuer.py")

SEED = hashlib.sha256(b"attestation-spec/test-vectors/accept-1").digest()
ISSUER = _acc.ReferenceAcceptanceIssuer.from_seed(SEED)
ATT_ISSUER = _att.ReferenceIssuer.from_seed(SEED)
ACT_ISSUER = _act.ReferenceActionIssuer.from_seed(SEED)

HERE = Path(__file__).resolve().parent
VALID = HERE / "valid"
INVALID = HERE / "invalid"

TS = "2026-08-23T09:12:44.108231+00:00"

# A subject receipt and a subject action record, fixed so the hashes are stable.
SUBJECT_RECEIPT = dict(ATT_ISSUER.sign(
    trace_id="trace-vector-accept", org_id="org-vector",
    request_hash="8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
    model="gpt-4o", outcome="BLOCKED", policy_applied=["affordability_v3"],
    cost_prevented_eur=0.0,
    attestation_id="00000000-0000-0000-0000-0000000000s1", timestamp=TS,
))
SUBJECT_ACTION = dict(ACT_ISSUER.sign(
    org_id="org-vector", agent="claude-code/2.1", tool="github.merge_pull_request",
    args_hash=_act.args_hash_of({"repo": "example/api", "pr": 41}),
    outcome="BLOCKED", policy_applied=["production_change_review"],
    action_id="00000000-0000-0000-0000-0000000000s2", timestamp=TS,
))
RECEIPT_HASH = _acc.subject_hash_of(SUBJECT_RECEIPT)
ACTION_HASH = _acc.subject_hash_of(SUBJECT_ACTION)
REASON = _acc.reason_hash_of("Post-period accounts show recovery above the floor.")


def _write(directory: Path, name: str, record) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"  {directory.name}/{name}")


def _sign(n: int, **kw):
    kw.setdefault("org_id", "org-vector")
    kw.setdefault("subject_v", "1")
    kw.setdefault("subject_id", "00000000-0000-0000-0000-0000000000s1")
    kw.setdefault("subject_hash", RECEIPT_HASH)
    kw.setdefault("reviewer_ref", "credit-officer c-1f8e")
    kw.setdefault("reviewer_authority", "SME credit, limit EUR 150000")
    kw.setdefault("policy_applied", ["adverse_action", "affordability_v3"])
    kw.setdefault("timestamp", TS)
    kw.setdefault("acceptance_id", f"00000000-0000-0000-0000-0000000000{n:02x}")
    return dict(ISSUER.sign(**kw))


def generate_valid() -> None:
    print("valid/")
    _write(VALID, "001-accepted.json", _sign(1, decision="ACCEPTED"))
    _write(VALID, "002-overridden-with-reason.json",
           _sign(2, decision="OVERRIDDEN", reason_hash=REASON))
    _write(VALID, "003-escalated.json", _sign(3, decision="ESCALATED"))
    _write(VALID, "004-subject-is-an-action.json", _sign(
        4, decision="ACCEPTED", subject_v="action-1",
        subject_id="00000000-0000-0000-0000-0000000000s2", subject_hash=ACTION_HASH))
    _write(VALID, "005-no-reason.json", _sign(5, decision="ACCEPTED", reason_hash=""))
    _write(VALID, "006-no-authority-stated.json",
           _sign(6, decision="ACCEPTED", reviewer_authority=""))
    _write(VALID, "007-empty-policy.json", _sign(7, decision="ACCEPTED", policy_applied=[]))
    _write(VALID, "008-non-ascii-reviewer.json",
           _sign(8, decision="OVERRIDDEN", reviewer_ref="prüfer m-90a2",
                 reviewer_authority="Kreditprüfung, Größenlimit"))


def generate_invalid() -> None:
    print("invalid/")
    base = lambda n, **kw: _sign(n, decision="ACCEPTED", **kw)  # noqa: E731

    r = base(0x11)
    r["signature"] = r["signature"][:-2] + ("AA" if not r["signature"].endswith("AA") else "BB")
    _write(INVALID, "001-tampered-signature.json", r)

    r = base(0x12); r["decision"] = "OVERRIDDEN"
    _write(INVALID, "002-tampered-decision.json", r)

    r = base(0x13)
    other = _acc.ReferenceAcceptanceIssuer.from_seed(
        hashlib.sha256(b"attestation-spec/test-vectors/accept-1/other").digest())
    r["public_key"] = other.public_key_b64
    _write(INVALID, "003-tampered-public-key.json", r)

    r = base(0x14); del r["reviewer_authority"]
    _write(INVALID, "004-missing-field.json", r)

    r = base(0x15); r["reviewer_name"] = "A. Person"
    _write(INVALID, "005-unknown-field.json", r)

    r = base(0x16); r["v"] = 1
    _write(INVALID, "006-integer-version.json", r)

    # One vector per sibling profile. Both are correctly signed and must still
    # be rejected: accepting either means the verifier guessed the format.
    _write(INVALID, "007-attestation-v1-receipt.json", SUBJECT_RECEIPT)
    _write(INVALID, "008-action-v1-record.json", SUBJECT_ACTION)

    # DECLINED is a reviewer's verdict on an evidence pack, a different act
    # with a different subject. Plausible enough to be worth pinning.
    r = base(0x19); r["decision"] = "DECLINED"
    _write(INVALID, "009-pack-verdict-as-decision.json", r)

    r = base(0x1A); r["subject_v"] = "2"
    _write(INVALID, "010-unknown-subject-version.json", r)

    r = base(0x1B); r["subject_hash"] = RECEIPT_HASH.upper()
    _write(INVALID, "011-uppercase-subject-hash.json", r)

    r = base(0x1C); r["reviewer_ref"] = ""
    _write(INVALID, "012-empty-reviewer.json", r)

    r = base(0x1D); r["policy_applied"] = ["z_last", "a_first"]
    _write(INVALID, "013-policy-not-sorted.json", r)

    r = base(0x1E); r["timestamp"] = "2026-08-23T09:12:44"
    _write(INVALID, "014-timestamp-no-offset.json", r)

    # Signed over \uXXXX-escaped bytes: the cross-language escaping trap,
    # pinned here as it is in the other two suites.
    payload = {k: v for k, v in base(0x1F, reviewer_ref="prüfer m-90a2").items()
               if k != "signature"}
    escaped = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
    import base64 as _b64
    sig = ISSUER.private_key.sign(escaped)
    payload["signature"] = _b64.urlsafe_b64encode(sig).decode().rstrip("=")
    _write(INVALID, "015-escaped-unicode-signing.json", payload)


if __name__ == "__main__":
    print(f"ACCEPT-v1 vector key: {ISSUER.public_key_b64}")
    generate_valid()
    generate_invalid()
    print("done", file=sys.stderr)
