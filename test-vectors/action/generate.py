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


_acc_spec = importlib.util.spec_from_file_location(
    "acc_ref", _REPO_ROOT / "examples" / "reference-acceptance-issuer.py"
)
_acc_ref = importlib.util.module_from_spec(_acc_spec)  # type: ignore[arg-type]
_acc_spec.loader.exec_module(_acc_ref)  # type: ignore[union-attr]


SEED = hashlib.sha256(b"attestation-spec/test-vectors/action-1").digest()
ISSUER = _action_ref.ReferenceActionIssuer.from_seed(SEED)
ATT_ISSUER = _att_ref.ReferenceIssuer.from_seed(SEED)
ACC_ISSUER = _acc_ref.ReferenceAcceptanceIssuer.from_seed(SEED)

HERE = Path(__file__).resolve().parent
VALID = HERE / "valid"
INVALID = HERE / "invalid"
ARGS_DIR = HERE / "args"

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

    # Non-BMP policy identifiers, in UTF-16 code-unit order. Python's sorted()
    # would place these the other way round because it compares code points:
    # U+E000 < U+1F600 by code point, but the emoji begins with the surrogate
    # 0xD83D so it comes FIRST by code unit. The two reference verifiers split
    # on exactly this until 10 Sep 2026. Every earlier multi-policy vector was
    # ASCII, where both orderings agree, which is why nothing caught it.
    # Reported through the forgery bounty, 9 September 2026.
    _write(VALID, "006-policy-non-bmp-sorted.json", _sign(
        6, outcome="ALLOWED", policy_applied=["\U0001F600", "\uE000"],
        session_id="sess-vector-0001", intent_hash=INTENT,
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


    # The same identifiers in code-point order, which is what Python's default
    # sorted() produces. A conformant verifier MUST reject it: order is by
    # UTF-16 code unit. This is the vector for the divergence class itself, so
    # both implementations are pinned to the same answer on the same bytes.
    # Built by signing directly rather than through ISSUER.sign(), because the
    # reference issuer now sorts by code unit and would silently correct the
    # very order this vector exists to test. The signature is VALID: only the
    # semantic ordering check may reject it, which is exactly the shape of the
    # reported divergence.
    import base64 as _b64x
    payload = {k: v for k, v in _sign(
        0x20, outcome="ALLOWED", policy_applied=["\U0001F600"],
        session_id="sess-vector-0001", intent_hash=INTENT,
    ).items() if k != "signature"}
    payload["policy_applied"] = ["\uE000", "\U0001F600"]  # code-point order
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    payload["signature"] = _b64x.urlsafe_b64encode(
        ISSUER.private_key.sign(canonical)).decode().rstrip("=")
    _write(INVALID, "016-policy-code-point-order.json", payload)

    # 017 to 023, added 29 September 2026 after internal adversarial review:
    # the classes behind ATTESTATION-v1 invalid 018 to 023, under this profile.
    # Python's `$` also matches just before a final line feed and its `\d`
    # matches any Unicode decimal digit; JavaScript's do neither, and until
    # 1.2.7 the Python verifier accepted 017, 018, 019 and 021. Signed directly
    # over the defect, as 016 is, because the reference issuer now refuses
    # these hashes.
    def _resigned(n, **fields):
        p = {k: v for k, v in base(n).items() if k != "signature"}
        p.update(fields)
        c = json.dumps(p, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")
        p["signature"] = _b64x.urlsafe_b64encode(
            ISSUER.private_key.sign(c)).decode().rstrip("=")
        return p

    _write(INVALID, "017-args-hash-trailing-newline.json", _resigned(0x21, args_hash=ARGS + "\n"))
    _write(INVALID, "018-intent-hash-trailing-newline.json", _resigned(0x22, intent_hash=INTENT + "\n"))
    _write(INVALID, "019-timestamp-trailing-newline.json", _resigned(0x23, timestamp=TS + "\n"))
    r = base(0x24)
    r["signature"] = r["signature"] + "\n"  # outside what is signed: anyone can append it
    _write(INVALID, "020-signature-trailing-newline.json", r)
    _write(INVALID, "021-timestamp-non-ascii-digits.json", _resigned(
        0x25, timestamp="2026-08-22T14:03:11.\u0664\u0661\u0662\u0669\u0660\u0663+00:00"))
    _write(INVALID, "022-outcome-not-a-string.json", _resigned(0x26, outcome=["BLOCKED"]))
    # No canonical bytes exist for a lone surrogate, so the genuine signature
    # stays and the ordering rule refuses the record first. The 1.2.6 Python
    # verifier raised UnicodeEncodeError building that order.
    r = base(0x27)
    r["policy_applied"] = ["\ud800", "require_intent"]
    _write(INVALID, "023-policy-lone-surrogate.json", r)

    # 024 to 026: record-type confusion. 024 and 025 are ACTION-v1 records whose
    # only change is the declared version tag, re-signed so the signature is
    # valid and only the version check can refuse them. 026 is a complete,
    # correctly signed ACCEPT-v1 record under this suite's key, the sibling of
    # 007 for the third profile.
    _write(INVALID, "024-attestation-version-tag.json", _resigned(0x28, v=1))
    _write(INVALID, "025-accept-version-tag.json", _resigned(0x29, v="accept-1"))
    _write(INVALID, "026-accept-v1-record.json", dict(ACC_ISSUER.sign(
        org_id="org-vector", subject_v="action-1",
        subject_id="00000000-0000-0000-0000-000000000001",
        subject_hash=_acc_ref.subject_hash_of(_sign(
            1, outcome="ALLOWED",
            policy_applied=["production_change_review", "require_intent"],
            session_id="sess-vector-0001", intent_hash=INTENT,
        )),
        decision="ACCEPTED", reviewer_ref="reviewer r-0001",
        policy_applied=["require_intent"],
        acceptance_id="00000000-0000-0000-0000-0000000000ca", timestamp=TS,
    )))


# Argument objects whose member names order differently by UTF-16 code unit
# (spec section 6, RFC 8785 section 3.2.3) and by Unicode code point. Each file
# carries the canonical bytes and args_hash a conformant issuer produces, the
# code-point-order bytes for contrast, and two anchor-v1 envelopes over the same
# object: one signed over the code-unit bytes (verifies) and one signed over
# the code-point bytes (does not). The envelope path is the one public verifier
# entry point that canonicalises arbitrary member names, so it is how a
# verifier's key ordering is checked end to end. Member names are not
# normalised: section 6 defines the bytes, and NFC and NFD spellings are
# different names with different bytes.
ARGS_CASES = [
    ("001-non-bmp-vs-fullwidth",
     "ASCII, a supplementary-plane name (U+1F4C1) and a name in U+E000 to "
     "U+FFFF (U+FF21). By code unit U+1F4C1 (0xD83D 0xDCC1) sorts before "
     "U+FF21; by code point it sorts after.",
     {"repo": "example/api", "\uff21": "fullwidth A", "\U0001F4C1": "folder"}),
    ("002-cjk-extension-b",
     "CJK: U+4E00, U+F900 (compatibility ideograph) and U+20000 (Extension B). "
     "By code unit U+20000 (0xD840 0xDC00) sorts between U+4E00 and U+F900; by "
     "code point it sorts last.",
     {"path": "/tmp/x", "\u4e00": "one", "\uf900": "compat", "\U00020000": "ext-b"}),
    ("003-common-prefix",
     "Names sharing a prefix and differing in one character: U+E000 against "
     "U+1F600.",
     {"name": "plain", "name\ue000": "private use", "name\U0001F600": "emoji"}),
    ("004-nfc-nfd-distinct-names",
     "U+00E9 (NFC) and U+0065 U+0301 (NFD) are distinct member names with "
     "distinct bytes; neither is normalised. Combining U+0301 sorts by its own "
     "code unit. Both orders agree here; the vector pins that no normalisation "
     "is applied.",
     {"e": "base", "\u00e9": "nfc", "e\u0301": "nfd", "f": "next"}),
    ("005-nested",
     "Non-BMP and U+E000 to U+FFFF names inside a nested object and inside an "
     "object within an array. Ordering applies at every depth.",
     {"options": {"\U0001F600": True, "\ue000": False},
      "items": [{"\uff21": 1, "\U00010000": 2}], "count": 2}),
    ("006-ascii-only",
     "ASCII names only, the argument object used by the other vectors. Both "
     "orders agree: the fix changes no hash for ASCII names.",
     {"repo": "example/api", "pr": 41}),
]


def _code_point_canonical(value) -> bytes:
    # The bytes an issuer sorting by code point produces. Valid for these
    # cases only: they carry no floats.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _anchor_envelope(args, canonical_of) -> dict:
    p = {**args, "public_key_b64": ISSUER.public_key_b64}
    sig = ISSUER.private_key.sign(canonical_of(p))
    return {**p, "signature_b64": _b64url(sig)}


def _b64url(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def generate_args() -> None:
    print("args/")
    ARGS_DIR.mkdir(parents=True, exist_ok=True)
    for name, description, args in ARGS_CASES:
        unit = _action_ref.canonical_payload(args)
        point = _code_point_canonical(args)
        assert _action_ref.args_hash_of(args) == hashlib.sha256(unit).hexdigest()
        vector = {
            "description": description,
            "args": args,
            "canonical_hex": unit.hex(),
            "args_hash": hashlib.sha256(unit).hexdigest(),
            "orders_differ": unit != point,
            "code_point_order_hex": point.hex(),
            "code_point_order_args_hash": hashlib.sha256(point).hexdigest(),
            "envelope": _anchor_envelope(args, _action_ref.canonical_payload),
            "envelope_code_point_order": _anchor_envelope(args, _code_point_canonical),
        }
        _write(ARGS_DIR, f"{name}.json", vector)

if __name__ == "__main__":
    print(f"ACTION-v1 vector key: {ISSUER.public_key_b64}")
    generate_valid()
    generate_invalid()
    generate_args()
    print("done", file=sys.stderr)
