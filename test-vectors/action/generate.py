"""
Generate deterministic test vectors for ACTION-v1 conformance testing.

The sibling of ../generate.py (ATTESTATION-v1 vectors). Running this script
produces a fixed set of action records under the same seed, so implementers
can validate their verifier against known-good bytes.

All vectors use a deterministic Ed25519 key pair derived from the seed
`sha256("attestation-spec/test-vectors/action-1")`.

A conformant ACTION-v1 verifier, given the records in `valid/`, MUST return
valid: true. Given the records in `invalid/`, it MUST return valid: false.
`README.md` documents the failure mode of each invalid case.

Two lessons from the ATTESTATION-v1 conformance history are enforced here:
  - every vector participates in the cross-implementation interop sweep,
    never a single hardcoded fixture;
  - the invalid set includes a complete, correctly signed ATTESTATION-v1
    receipt (007), because a verifier that profile-sniffs by field shape
    instead of requiring explicit opt-in would otherwise pass it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

_action_spec = importlib.util.spec_from_file_location(
    "action_ref", _REPO_ROOT / "examples" / "reference-action-issuer.py"
)
_action_ref = importlib.util.module_from_spec(_action_spec)  # type: ignore[arg-type]
_action_spec.loader.exec_module(_action_ref)  # type: ignore[union-attr]

_att_spec = importlib.util.spec_from_file_location(
    "att_ref", _REPO_ROOT / "examples" / "reference-issuer.py"
)
_att_ref = importlib.util.module_from_spec(_att_spec)  # type: ignore[arg-type]
_att_spec.loader.exec_module(_att_ref)  # type: ignore[union-attr]


SEED = hashlib.sha256(b"attestation-spec/test-vectors/action-1").digest()
ISSUER = _action_ref.ReferenceActionIssuer.from_seed(SEED)
ATT_ISSUER = _att_ref.ReferenceIssuer.from_seed(SEED)

HERE = Path(__file__).resolve().parent
VALID = HERE / "valid"
INVALID = HERE / "invalid"

TS = "2026-08-22T14:03:11.412903+00:00"
INTENT = hashlib.sha256(b"fix the failing auth test in repo example/api").hexdigest()
ARGS = _action_ref.args_hash_of({"repo": "example/api", "pr": 41})


def _write(directory: Path, name: str, record) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"  {path.relative_to(HERE)}")


def _sign(n: int, **kw):
    kw.setdefault("org_id", "org-vector")
    kw.setdefault("agent", "claude-code/2.1")
    kw.setdefault("tool", "github.merge_pull_request")
    kw.setdefault("args_hash", ARGS)
    kw.setdefault("timestamp", TS)
    kw.setdefault("action_id", f"00000000-0000-0000-0000-0000000000{n:02x}")
    return dict(ISSUER.sign(**kw))


def generate_valid() -> None:
    print("valid/")
    _write(VALID, "001-allowed.json", _sign(
        1, outcome="ALLOWED",
        policy_applied=["production_change_review", "require_intent"],
        session_id="sess-vector-0001", intent_hash=INTENT,
    ))
    _write(VALID, "002-blocked.json", _sign(
        2, outcome="BLOCKED",
        policy_applied=["production_change_review", "require_intent"],
        session_id="sess-vector-0001", intent_hash=INTENT,
    ))
    _write(VALID, "003-no-session.json", _sign(
        3, outcome="ALLOWED", policy_applied=["tool_allowlist"],
        session_id="", intent_hash="",
    ))
    _write(VALID, "004-session-no-intent.json", _sign(
        4, outcome="ALLOWED", policy_applied=["tool_allowlist"],
        session_id="sess-vector-0004", intent_hash="",
    ))
    _write(VALID, "005-empty-policy.json", _sign(
        5, outcome="ALLOWED", policy_applied=[],
        session_id="", intent_hash="",
    ))
    _write(VALID, "006-multi-policy.json", _sign(
        6, outcome="BLOCKED",
        policy_applied=["a_first", "m_middle", "z_last"],
        session_id="sess-vector-0006", intent_hash=INTENT,
    ))
    _write(VALID, "007-non-ascii-tool.json", _sign(
        7, outcome="BLOCKED", tool="dateien.löschen",
        args_hash=_action_ref.args_hash_of({"pfad": "/tmp/größe"}),
        policy_applied=["require_intent"],
        session_id="sess-vector-0007", intent_hash=INTENT,
    ))
    _write(VALID, "008-non-utc-offset.json", _sign(
        8, outcome="ALLOWED", policy_applied=["tool_allowlist"],
        session_id="", intent_hash="",
        timestamp="2026-08-22T16:03:11.412903+02:00",
    ))
    _write(VALID, "009-agent-empty.json", _sign(
        # `agent` is caller-asserted and MAY be empty; the record remains
        # valid, it simply records that no identity was claimed.
        9, outcome="ALLOWED", agent="", policy_applied=["tool_allowlist"],
        session_id="", intent_hash="",
    ))
    _write(VALID, "010-deep-namespace.json", _sign(
        10, outcome="ALLOWED",
        tool="cloud.eu-west-1.kubernetes.deployments.scale",
        policy_applied=["change_window"],
        session_id="sess-vector-0010", intent_hash="",
    ))


def generate_invalid() -> None:
    print("invalid/")
    base = lambda n, **kw: _sign(n, outcome="BLOCKED",  # noqa: E731
        policy_applied=["require_intent"],
        session_id="sess-vector-bad", intent_hash=INTENT, **kw)

    r = base(0x11)
    r["signature"] = r["signature"][:-2] + ("AA" if not r["signature"].endswith("AA") else "BB")
    _write(INVALID, "001-tampered-signature.json", r)

    r = base(0x12)
    r["outcome"] = "ALLOWED"  # flipped after signing
    _write(INVALID, "002-tampered-outcome.json", r)

    r = base(0x13)
    other = _action_ref.ReferenceActionIssuer.from_seed(
        hashlib.sha256(b"attestation-spec/test-vectors/action-1/other").digest()
    )
    r["public_key"] = other.public_key_b64  # signed by SEED key, claims another
    _write(INVALID, "003-tampered-public-key.json", r)

    r = base(0x14)
    del r["agent"]  # missing required field
    _write(INVALID, "004-missing-field.json", r)

    r = base(0x15)
    r["cost_prevented_eur"] = 0  # an ATTESTATION-v1 field is unknown here
    _write(INVALID, "005-unknown-field.json", r)

    r = base(0x16)
    r["v"] = 1  # integer version: ATTESTATION-style tag on an action shape
    _write(INVALID, "006-integer-version.json", r)

    # A complete, correctly signed ATTESTATION-v1 receipt. An ACTION-v1
    # verifier MUST reject it; accepting it means the verifier is
    # profile-sniffing instead of enforcing the ACTION-v1 structure.
    att = dict(ATT_ISSUER.sign(
        trace_id="trace-vector-cross", org_id="org-vector",
        request_hash="8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
        model="gpt-4o", outcome="ALLOWED",
        policy_applied=["budget_guard"], cost_prevented_eur=0.0,
        attestation_id="00000000-0000-0000-0000-0000000000c7", timestamp=TS,
    ))
    _write(INVALID, "007-attestation-v1-receipt.json", att)

    r = base(0x18, args_hash=ARGS)
    r["args_hash"] = ARGS.upper()  # uppercase hex breaks the format rule
    _write(INVALID, "008-uppercase-args-hash.json", r)

    r = base(0x19)
    r["policy_applied"] = ["z_last", "a_first"]  # unsorted after signing
    _write(INVALID, "009-policy-not-sorted.json", r)

    r = base(0x1A)
    r["policy_applied"] = ["require_intent", 7]  # non-string member
    _write(INVALID, "010-policy-not-strings.json", r)

    r = base(0x1B)
    r["timestamp"] = "2026-08-22T14:03:11"  # no timezone offset
    _write(INVALID, "011-timestamp-no-offset.json", r)

    r = base(0x1C)
    r["outcome"] = "SUPPRESSED"  # a valid ATTESTATION outcome, not here
    _write(INVALID, "012-suppressed-outcome.json", r)

    r = base(0x1D)
    r["tool"] = ""  # tool MUST be non-empty
    _write(INVALID, "013-empty-tool.json", r)

    r = _sign(0x1E, outcome="ALLOWED", policy_applied=["tool_allowlist"],
              session_id="", intent_hash="")
    r["intent_hash"] = INTENT  # intent without a session violates §7
    _write(INVALID, "014-intent-without-session.json", r)

    # Signed over \uXXXX-escaped bytes: an issuer that escaped non-ASCII
    # produced different canonical bytes than a §6-conformant verifier
    # reconstructs, so the signature MUST fail.
    payload = {k: v for k, v in base(0x1F, tool="dateien.löschen").items()
               if k != "signature"}
    escaped = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
    sig = ISSUER.private_key.sign(escaped)
    import base64 as _b64
    payload["signature"] = _b64.urlsafe_b64encode(sig).decode().rstrip("=")
    _write(INVALID, "015-escaped-unicode-signing.json", payload)


if __name__ == "__main__":
    print(f"ACTION-v1 vector key: {ISSUER.public_key_b64}")
    generate_valid()
    generate_invalid()
    print("done", file=sys.stderr)
