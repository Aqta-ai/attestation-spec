"""
Generate deterministic conformance vectors for the `policy` profile and POLICY-v1
(spec/POLICY-v1.md). DRAFT: the format is a draft and these vectors move with it
until it is frozen.

    test-vectors/policy/{pass,fail,incomplete}/*.json
        {"bundle": {...}}

The directory is the verdict a conformant verifier MUST return with the vector
issuer key below pinned. Every key is a throwaway derived from a public seed.
None is a production key.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("action_ref", ROOT / "examples" / "reference-action-issuer.py")
_action_ref = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_action_ref)  # type: ignore[union-attr]
_canonical = _action_ref._ref._canonical
_b64 = _action_ref._b64url_encode

_lib = importlib.util.spec_from_file_location("tlib", ROOT / "scripts" / "make_transparency_vectors_lib.py")
tlib = importlib.util.module_from_spec(_lib)  # type: ignore[arg-type]
_lib.loader.exec_module(tlib)  # type: ignore[union-attr]


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"attestation-spec/test-vectors/policy-1/" + label.encode()).digest())


def _pub(sk) -> str:
    return _b64(sk.public_key().public_bytes_raw())


ISSUER_SK = _key("issuer")
ISSUER = _action_ref.ReferenceActionIssuer(ISSUER_SK)
PIN = _pub(ISSUER_SK)
FORGER = _key("forger")
ORG = "org-vector"
APPROVER_KEY = _pub(_key("approver"))


def T(hms: str) -> str:
    return f"2026-10-20T{hms}.000000+00:00"


def sign_with(sk, payload: dict) -> dict:
    return {**payload, "signature": _b64(sk.sign(_canonical(payload).encode("utf-8")))}


def resign(rec: dict, sk, **changes) -> dict:
    payload = {k: v for k, v in rec.items() if k != "signature"}
    payload.update(changes)
    return sign_with(sk, payload)


def body_hash(org_id: str, name: str, rules: str) -> str:
    return hashlib.sha256(_canonical({"v": "policy-body-1", "org_id": org_id, "policy_name": name,
                                      "rules": rules}).encode("utf-8")).hexdigest()


def rules_of(*rules) -> str:
    """The rule array as RFC 8785 canonical JSON text, as the issuer writes it."""
    return _canonical(list(rules))


def policy(name: str, version: int, rules: str, created: str, prev: dict | None = None, *, org_id=ORG, sk=ISSUER_SK,
           policy_hash: str | None = None, **over) -> dict:
    payload = {"v": "policy-1", "org_id": org_id, "policy_name": name, "version": str(version),
               "prev_policy_hash": prev["policy_hash"] if prev else "", "rules": rules,
               "policy_hash": policy_hash or body_hash(org_id, name, rules), "created_at": created,
               "public_key": _pub(sk)}
    payload.update(over)
    return sign_with(sk, payload)


def bound(st: dict) -> str:
    return f"{st['policy_name']}@sha256:{st['policy_hash']}"


def action(n: int, ts: str, outcome: str, applied: list, *, tool="payments.transfer", org_id=ORG, raw_order=False) -> dict:
    rec = dict(ISSUER.sign(org_id=org_id, agent="agent", tool=tool,
                           args_hash=hashlib.sha256(f"args-{n}".encode()).hexdigest(), outcome=outcome,
                           policy_applied=applied, action_id=f"00000000-0000-4000-8000-0000000000{n:02x}",
                           timestamp=ts))
    if raw_order:  # the list exactly as given, never sorted: for the vectors that pin the ordering rule
        rec = resign(rec, ISSUER_SK, policy_applied=list(applied))
    return rec


TAGS = {"action": b"\x02", "policy": b"\x05"}


def leaf(kind: str, rec: dict) -> bytes:
    payload = _canonical({k: v for k, v in rec.items() if k != "signature"}).encode("utf-8")
    return tlib.leaf_hash(TAGS[kind] + len(payload).to_bytes(8, "big") + payload + rec["signature"].encode("utf-8"))


def other_leaf(i: int) -> bytes:
    return tlib.leaf_hash(b"\x02" + f"another-organisation-{i}".encode())


def sth(leaves, stamp: str, sk=ISSUER_SK) -> dict:
    root = tlib.merkle_root(leaves)
    signed = b"aqta-sth-public-v1|" + str(len(leaves)).encode() + b"|" + root + b"|" + stamp.encode()
    return {"v": 1, "log": "public", "tree_size": len(leaves), "root_hash": root.hex(), "timestamp": stamp,
            "signature": _b64(sk.sign(signed))}


# --- The world --------------------------------------------------------------------------------------------------

GRANT_RULE = {"type": "require_grant", "value": f"payments.*:{APPROVER_KEY}"}
P1 = policy("policy_payments_guard", 1, rules_of(GRANT_RULE), T("09:00:00"))
P1v2 = policy("policy_payments_guard", 2, rules_of(GRANT_RULE, {"type": "require_args",
                                                                    "value": "payments.*:approval_ticket"}),
              T("11:00:00"), P1)
P2 = policy("policy_deploy_gate", 1, rules_of({"type": "require_args",
                                               "value": "deploy.*:eval_report_sha256,approved_by"}), T("09:30:00"))
# Non-BMP and high-BMP names: U+1F600 sorts first by UTF-16 code unit (0xD83D < 0xFF5E), last by code point.
P_EMOJI = policy("policy_\U0001F600", 1, rules_of({"type": "block_phrase", "value": "wire everything"}), T("09:40:00"))
P_TILDE = policy("policy_～", 1, rules_of({"type": "block_phrase", "value": "skip review"}), T("09:41:00"))

A1 = action(1, T("10:00:00"), "ALLOWED", [bound(P1), bound(P2)])
A2 = action(2, T("10:30:00"), "BLOCKED", [bound(P2)], tool="deploy.production")
A3 = action(3, T("12:00:00"), "ALLOWED", [bound(P1v2), bound(P2)])
A4 = action(4, T("10:45:00"), "BLOCKED", [bound(P_EMOJI), bound(P_TILDE)])


class World:
    """A shared public log: other organisations' leaves and ours, in log order, under one signed head."""

    def __init__(self, events, head_at="2026-10-20T13:00:00Z", head_sk=ISSUER_SK):
        # events: (log time, kind, record)
        ev = [("08:00:00", None, None), ("08:30:00", None, None)] + list(events) + [("12:30:00", None, None)]
        ev.sort(key=lambda e: e[0])
        self.ev = ev
        self.leaves = [leaf(k, r) if k else other_leaf(i) for i, (_, k, r) in enumerate(ev)]
        self.head = sth(self.leaves, head_at, head_sk)

    def proof(self, rec) -> dict:
        i = next(i for i, e in enumerate(self.ev) if e[2] is rec)
        return {"leaf_index": i, "tree_size": len(self.leaves), "leaf_hash": self.leaves[i].hex(),
                "root_hash": tlib.merkle_root(self.leaves).hex(),
                "audit_path": [h.hex() for h in tlib.inclusion_path(self.leaves, i)]}

    def bundle(self, policies, decisions, *, head="world", proofs=True) -> dict:
        return {"v": "policy-1", "head": self.head if head == "world" else head,
                "policies": [{"statement": p, "proof": self.proof(p) if proofs else None} for p in policies],
                "decisions": [{"record": d, "proof": self.proof(d) if proofs else None} for d in decisions]}


BASE_EVENTS = [("09:00:01", "policy", P1), ("09:30:01", "policy", P2), ("09:40:01", "policy", P_EMOJI),
               ("09:41:01", "policy", P_TILDE), ("10:00:01", "action", A1), ("10:30:01", "action", A2),
               ("10:45:01", "action", A4), ("11:00:01", "policy", P1v2), ("12:00:01", "action", A3)]

VECTORS: dict = {"pass": [], "fail": [], "incomplete": []}


def add(kind, name, why, bundle):
    VECTORS[kind].append((name, why, {"bundle": bundle}))


def build() -> None:
    w = World(BASE_EVENTS)
    # ---- PASS
    add("pass", "001-bound-history", "Every decision binds every policy it names to a signed version, created and "
        "logged before it.", w.bundle([P1, P2, P_EMOJI, P_TILDE, P1v2], [A1, A2, A4, A3]))
    add("pass", "002-refusal-bound", "A BLOCKED decision binds the policy that refused it.", w.bundle([P2], [A2]))
    add("pass", "003-non-bmp-names-in-utf16-order", "Two bindings whose names sort differently by code point and by "
        "UTF-16 code unit, in UTF-16 order.", w.bundle([P_EMOJI, P_TILDE], [A4]))
    add("pass", "004-version-chain", "Two versions of one policy; each decision binds the version in force when it "
        "was made, and version 2 names version 1.", w.bundle([P1, P1v2, P2], [A1, A3]))
    a5 = action(5, T("10:50:00"), "ALLOWED", [])
    w5 = World(BASE_EVENTS + [("10:50:01", "action", a5)])
    add("pass", "005-no-policy-applied", "A decision that names no policy has nothing to bind.", w5.bundle([], [a5]))
    p_edge = policy("policy_edge", 1, rules_of({"type": "require_intent"}), T("10:20:00"))
    a_edge = action(6, T("10:20:00"), "ALLOWED", [bound(p_edge)])
    we = World(BASE_EVENTS + [("10:20:00.1", "policy", p_edge), ("10:20:00.2", "action", a_edge)])
    add("pass", "006-created-at-the-decision-instant", "The version is created at the decision's own instant: at or "
        "before is allowed.", we.bundle([p_edge], [a_edge]))
    p_off = policy("policy_offset", 1, rules_of({"type": "require_intent"}), "2026-10-20T11:15:00+01:00")
    a_off = action(7, T("10:16:00"), "ALLOWED", [bound(p_off)])
    wo = World(BASE_EVENTS + [("10:15:01", "policy", p_off), ("10:16:01", "action", a_off)])
    add("pass", "007-created-at-in-another-offset", "created_at written in +01:00 (10:15Z), compared as an instant.",
        wo.bundle([p_off], [a_off]))

    # ---- FAIL
    edited = policy("policy_payments_guard", 1, rules_of({"type": "require_grant", "value": "payments.*:anyone"}),
                    T("09:00:00"), policy_hash=P1["policy_hash"])
    add("fail", "001-rules-edited-keeping-the-hash", "The operator presents edited rules under the hash the decision "
        "names (the silent edit after the fact).", w.bundle([edited, P2], [A1], proofs=False) | {"head": None})
    forged = policy("policy_payments_guard", 1, P1["rules"], T("09:00:00"), sk=FORGER)
    add("fail", "002-statement-signed-by-another-key", "A statement signed by a key other than the pinned issuer key.",
        w.bundle([forged, P2], [A1], proofs=False) | {"head": None})
    p_late = policy("policy_late", 1, rules_of({"type": "require_intent"}), T("10:10:00"))
    a_late = action(8, T("10:05:00"), "ALLOWED", [bound(p_late)])
    wl = World(BASE_EVENTS + [("10:05:01", "action", a_late), ("10:10:01", "policy", p_late)])
    add("fail", "003-policy-created-after-the-decision", "The version is created five minutes after the decision.",
        wl.bundle([p_late], [a_late]))
    p_back = policy("policy_backdated", 1, rules_of({"type": "block_phrase", "value": "refund"}), T("09:15:00"))
    a_back = action(9, T("10:05:00"), "ALLOWED", [bound(p_back)])
    wb = World(BASE_EVENTS + [("10:05:01", "action", a_back), ("10:50:00", "policy", p_back)])
    add("fail", "004-policy-backdated-logged-after-the-decision", "created_at says 09:15, before the decision, but "
        "the statement entered the log after it: the issuer wrote it later and backdated it.",
        wb.bundle([p_back], [a_back]))
    upper = f"{P1['policy_name']}@sha256:{P1['policy_hash'].upper()}"
    a_up = action(10, T("10:06:00"), "ALLOWED", [upper])
    wu = World(BASE_EVENTS + [("10:06:01", "action", a_up)])
    add("fail", "005-binding-hash-uppercase", "A binding whose hash is upper-case hex.", wu.bundle([P1], [a_up]))
    a_other_name = action(11, T("10:07:00"), "ALLOWED", [f"policy_other@sha256:{P1['policy_hash']}"])
    wn = World(BASE_EVENTS + [("10:07:01", "action", a_other_name)])
    add("fail", "006-binding-under-another-name", "A binding names policy_other with policy_payments_guard's hash.",
        wn.bundle([P1], [a_other_name]))
    p_org = policy("policy_payments_guard", 1, P1["rules"], T("09:00:00"), org_id="org-elsewhere")
    a_org = action(12, T("10:08:00"), "ALLOWED", [bound(p_org)])
    wg = World(BASE_EVENTS + [("09:00:02", "policy", p_org), ("10:08:01", "action", a_org)])
    add("fail", "007-policy-of-another-organisation", "The bound version belongs to another organisation.",
        wg.bundle([p_org], [a_org]))
    a_trunc = action(13, T("10:09:00"), "ALLOWED", [f"{P1['policy_name']}@sha256:{P1['policy_hash'][:16]}"])
    wt = World(BASE_EVENTS + [("10:09:01", "action", a_trunc)])
    add("fail", "008-binding-hash-truncated", "A binding carrying 16 hex characters, not 64.", wt.bundle([P1], [a_trunc]))
    fork = policy("policy_payments_guard", 2, rules_of({"type": "block_phrase", "value": "x"}), T("11:00:00"), P1)
    wf = World(BASE_EVENTS + [("11:00:02", "policy", fork)])
    add("fail", "009-forked-version-history", "Two different statements both numbered version 2 of one policy.",
        wf.bundle([P1, P1v2, fork], [A1]))
    skip = policy("policy_payments_guard", 3, P1v2["rules"], T("11:00:00"), P1)
    ws = World(BASE_EVENTS + [("11:00:02", "policy", skip)])
    add("fail", "010-version-does-not-follow", "Version 3 names version 1 as its predecessor.",
        ws.bundle([P1, skip], [A1]))
    at_name = policy("policy@payments", 1, P1["rules"], T("09:00:00"))
    add("fail", "011-policy-name-contains-at", "A statement whose policy_name contains '@', which would make a "
        "binding ambiguous.", w.bundle([], [A2], proofs=False) | {"head": None, "policies": [{"statement": at_name,
                                                                                            "proof": None}]})
    unk = policy("policy_payments_guard", 1, P1["rules"], T("09:00:00"), note="extra")
    add("fail", "012-statement-unknown-field", "A signed statement carrying a member the format does not define.",
        {"v": "policy-1", "head": None, "policies": [{"statement": unk, "proof": None}],
         "decisions": [{"record": A1, "proof": None}]})
    vtag = policy("policy_payments_guard", 1, P1["rules"], T("09:00:00"), v="policy-2")
    add("fail", "013-statement-version-tag", "v is policy-2.",
        {"v": "policy-1", "head": None, "policies": [{"statement": vtag, "proof": None}],
         "decisions": [{"record": A1, "proof": None}]})
    a_edit = dict(A1)
    a_edit["outcome"] = "BLOCKED"
    add("fail", "014-decision-edited", "A decision record altered after signing.",
        {"v": "policy-1", "head": None, "policies": [{"statement": P1, "proof": None}],
         "decisions": [{"record": a_edit, "proof": None}]})
    a_cp = action(14, T("10:46:00"), "BLOCKED", [bound(P_TILDE), bound(P_EMOJI)], raw_order=True)
    wc = World(BASE_EVENTS + [("10:46:01", "action", a_cp)])
    add("fail", "015-non-bmp-names-in-code-point-order", "The same two bindings as pass/003 in code-point order, "
        "which is not UTF-16 code unit order.", wc.bundle([P_EMOJI, P_TILDE], [a_cp]))
    b16 = w.bundle([P1, P2], [A1])
    b16["policies"][0]["proof"] = w.proof(P2)
    add("fail", "016-proof-for-another-leaf", "A statement presented with another statement's inclusion proof.", b16)
    b17 = w.bundle([P1, P2], [A1])
    b17["head"] = None
    add("fail", "017-proof-without-head", "Inclusion proofs with no head to check them against.", b17)
    b18 = w.bundle([P1, P2], [A1])
    b18["head"] = sth(w.leaves, "2026-10-20T13:00:00Z", FORGER)
    add("fail", "018-head-not-signed-by-the-issuer", "A head signed by another key.", b18)
    a_mix_late = action(15, T("10:09:00"), "ALLOWED", ["require_intent", bound(p_late)])
    wm2 = World(BASE_EVENTS + [("10:09:01", "action", a_mix_late), ("10:10:01", "policy", p_late)])
    add("fail", "019-fail-outranks-incomplete", "One plain name (INCOMPLETE) beside a version created after the "
        "decision (FAIL): FAIL wins.", wm2.bundle([p_late], [a_mix_late]))
    v2_early = policy("policy_payments_guard", 2, P1v2["rules"], T("08:59:00"), P1)
    wv = World(BASE_EVENTS + [("09:00:02", "policy", v2_early)])
    add("fail", "020-version-created-before-its-predecessor", "Version 2 says it was created before version 1.",
        wv.bundle([P1, v2_early], [A1]))
    v_lead = resign(P1, ISSUER_SK, version="01")
    add("fail", "021-version-not-canonical", "version is '01'.",
        {"v": "policy-1", "head": None, "policies": [{"statement": v_lead, "proof": None}],
         "decisions": [{"record": A1, "proof": None}]})
    add("fail", "022-statement-repeated", "One statement presented twice.", w.bundle([P1, P1, P2], [A1]))
    b23 = w.bundle([P1, P2], [A1])
    b23["note"] = "x"
    add("fail", "023-bundle-unknown-member", "A bundle member the profile does not define.", b23)

    # ---- INCOMPLETE
    a_plain = action(16, T("10:12:00"), "ALLOWED", ["policy_payments_guard"])
    wp = World(BASE_EVENTS + [("10:12:01", "action", a_plain)])
    add("incomplete", "001-unbound-name", "A plain name without @sha256: the record does not say which version.",
        wp.bundle([P1], [a_plain]))
    add("incomplete", "002-statement-missing", "The decision binds policy_deploy_gate, whose statement is withheld.",
        w.bundle([P1], [A1]))
    add("incomplete", "003-no-head", "Statements and decisions without a head or proofs: created_at is the issuer's "
        "own clock, so log order is not shown.", w.bundle([P1, P2], [A1], head=None, proofs=False))
    b4 = w.bundle([P1, P2], [A1])
    b4["decisions"][0]["proof"] = None
    add("incomplete", "004-decision-proof-missing", "The decision has no inclusion proof.", b4)
    add("incomplete", "005-no-decision", "Nothing to check.", w.bundle([P1, P2], []))
    a_err = action(17, T("10:13:00"), "BLOCKED", ["org_policies_unreadable"])
    wr = World(BASE_EVENTS + [("10:13:01", "action", a_err)])
    add("incomplete", "006-reserved-marker-unbound", "A refusal naming the reserved marker org_policies_unreadable: "
        "no policy version was evaluated, so nothing is bound.", wr.bundle([], [a_err]))


def write() -> None:
    base = ROOT / "test-vectors" / "policy"
    for kind, items in VECTORS.items():
        d = base / kind
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        for name, _why, body in items:
            (d / f"{name}.json").write_text(json.dumps(body, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    rows = [f"| {kind}/{name} | {why} |" for kind, items in VECTORS.items() for name, why, _ in items]
    (base / "INDEX.md").write_text(
        "# policy vectors: generated index\n\nGenerated by `scripts/make-policy-vectors.py`; do not edit by hand.\n\n"
        f"Vector issuer key (pin it): `{PIN}`\n\n| Vector | What it pins |\n|---|---|\n" + "\n".join(rows) + "\n")


def main() -> None:
    build()
    write()
    print("policy", {k: len(v) for k, v in VECTORS.items()}, "issuer", PIN)


if __name__ == "__main__":
    main()
