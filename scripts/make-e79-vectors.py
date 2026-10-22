"""
Generate deterministic conformance vectors for the `complete` profile
(spec/CHECKPOINT-v1.md, spec/EXECUTION-v1.md) and the `witnessed` profile
(spec/WITNESS-v1.md). DRAFT: the formats are drafts and these vectors move with
them until they are frozen.

    test-vectors/complete/{pass,fail,incomplete}/*.json
        {"review_from": ..., "review_to": ..., "executor_keys": [...] | null, "bundle": {...}}
    test-vectors/witnessed/{pass,fail,incomplete}/*.json
        {"witness_keys": [...] | null, "tolerance_seconds": <int>, "bundle": {...}}

The directory is the verdict a conformant verifier MUST return with the vector
issuer key below pinned and the parameters in the file. Every key is a
throwaway derived from a public seed. None is a production key.
"""

from __future__ import annotations

import copy
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
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"attestation-spec/test-vectors/e79-1/" + label.encode()).digest())


def _pub(sk) -> str:
    return _b64(sk.public_key().public_bytes_raw())


ISSUER_SK = _key("issuer")
ISSUER = _action_ref.ReferenceActionIssuer(ISSUER_SK)
PIN = _pub(ISSUER_SK)
APPROVER = _key("approver")
EXECUTOR = _key("executor")
EXECUTOR2 = _key("executor-other")
TIME = _key("time-authority")
FORGER = _key("forger")
ORG = "org-vector"
EXECUTOR_ID = "payments-executor-1"
WITNESS_ID = "seal-log-witness (vector)"


def sign_with(sk, payload: dict) -> dict:
    return {**payload, "signature": _b64(sk.sign(_canonical(payload).encode("utf-8")))}


def resign(rec: dict, sk, **changes) -> dict:
    payload = {k: v for k, v in rec.items() if k != "signature"}
    payload.update(changes)
    return sign_with(sk, payload)


def unsigned_hash(rec: dict) -> str:
    return hashlib.sha256(_canonical({k: v for k, v in rec.items() if k != "signature"}).encode("utf-8")).hexdigest()


TAGS = {"action": b"\x02", "use": b"\x03", "checkpoint": b"\x04"}


def leaf(kind: str, rec: dict) -> bytes:
    payload = _canonical({k: v for k, v in rec.items() if k != "signature"}).encode("utf-8")
    return tlib.leaf_hash(TAGS[kind] + len(payload).to_bytes(8, "big") + payload + rec["signature"].encode("utf-8"))


def other_leaf(i: int) -> bytes:
    return tlib.leaf_hash(b"\x02" + f"another-organisation-{i}".encode())


# --- Records --------------------------------------------------------------------------------------------------

def action(n: int, ts: str, outcome: str, *, tool="payments.transfer", org_id=ORG, signer=None) -> dict:
    iss = signer or ISSUER
    return dict(iss.sign(org_id=org_id, agent="agent", tool=tool, args_hash=hashlib.sha256(f"args-{n}".encode()).hexdigest(),
                         outcome=outcome, policy_applied=["require_grant"],
                         action_id=f"00000000-0000-4000-8000-0000000000{n:02x}", timestamp=ts))


def use(n: int, act: dict, ts: str) -> dict:
    return sign_with(ISSUER_SK, {
        "v": "use-1", "use_id": f"00000000-0000-4000-9000-0000000000{n:02x}", "org_id": ORG,
        "action_id": act["action_id"], "args_hash": act["args_hash"], "grant_id": f"g-{n}",
        "grant_hash": hashlib.sha256(f"grant-{n}".encode()).hexdigest(), "approver_public_key": _pub(APPROVER),
        "consumption_key": f"org:{ORG}|grant:g-{n}", "use_index": "1", "max_uses": "1", "timestamp": ts,
        "public_key": PIN})


def records_hash(leaves) -> str:
    return hashlib.sha256(b"".join(sorted(leaves))).hexdigest()


def checkpoint(seq: int, prev: dict | None, start: str, end: str, members: list, issued: str, *, org_id=ORG,
               sk=ISSUER_SK, rh: str | None = None, total: str | None = None, **over) -> dict:
    leaves = [leaf(k, r) for k, r in members]
    prev_total = int(prev["total_count"]) if prev else 0
    payload = {"v": "checkpoint-1", "org_id": org_id, "checkpoint_seq": str(seq),
               "prev_checkpoint_hash": unsigned_hash(prev) if prev else "", "period_start": start, "period_end": end,
               "record_count": str(len(leaves)), "total_count": total or str(prev_total + len(leaves)),
               "records_hash": rh or records_hash(leaves), "timestamp": issued, "public_key": _pub(sk)}
    payload.update(over)
    return sign_with(sk, payload)


def execution(seq: int, prev: dict | None, result: str, ts: str, act: dict | None = None, u: dict | None = None, *,
              sk=EXECUTOR, executor_id=EXECUTOR_ID, **over) -> dict:
    payload = {"v": "execution-1", "executor_id": executor_id, "entry_seq": str(seq),
               "prev_entry_hash": unsigned_hash(prev) if prev else "", "org_id": ORG, "result": result,
               "action_id": act["action_id"] if act else "", "action_leaf_hash": leaf("action", act).hex() if act else "",
               "use_id": u["use_id"] if u else "", "use_leaf_hash": leaf("use", u).hex() if u else "",
               "args_hash": act["args_hash"] if act else "", "timestamp": ts, "public_key": _pub(sk)}
    payload.update(over)
    return sign_with(sk, payload)


def T(hms: str) -> str:
    return f"2026-10-20T{hms}.000000+00:00"


# The world: one organisation, three hours, a quiet hour in the middle.
A1 = action(1, T("10:05:10"), "ALLOWED")
U1 = use(1, A1, "2026-10-20T10:05:09.950000+00:00")
A2 = action(2, T("10:07:40"), "BLOCKED")
A3 = action(3, T("10:41:30"), "BLOCKED", tool="deploy.production")
A4 = action(4, T("12:24:15"), "ALLOWED", tool="deploy.production")
U4 = use(4, A4, "2026-10-20T12:24:14.950000+00:00")
H10 = [("use", U1), ("action", A1), ("action", A2), ("action", A3)]
H12 = [("use", U4), ("action", A4)]
CP1 = checkpoint(1, None, T("10:00:00"), T("11:00:00"), H10, T("11:02:00"))
CP2 = checkpoint(2, CP1, T("11:00:00"), T("12:00:00"), [], T("12:02:00"))
CP3 = checkpoint(3, CP2, T("12:00:00"), T("13:00:00"), H12, T("13:02:00"))
E1 = execution(1, None, "EXECUTED", T("10:05:12"), A1, U1)
E2 = execution(2, E1, "REFUSED", T("10:08:00"), A2)
E3 = execution(3, E2, "EXECUTED", T("12:24:17"), A4, U4)

ALL = H10 + H12
FROM, TO = T("10:00:00"), T("13:00:00")


def recs(pairs) -> list:
    return [{"kind": k, "record": r} for k, r in pairs]


def cbundle(cps, pairs, execs=(), **extra) -> dict:
    b = {"v": "complete-1", "org_id": ORG, "checkpoints": list(cps), "records": recs(pairs), "executions": list(execs)}
    b.update(extra)
    return b


COMPLETE: dict = {"pass": [], "fail": [], "incomplete": []}


def addc(kind, name, why, b, *, frm=FROM, to=TO, keys="default"):
    COMPLETE[kind].append((name, why, {"review_from": frm, "review_to": to,
                                       "executor_keys": [_pub(EXECUTOR)] if keys == "default" else keys,
                                       "bundle": b}))


def without(pairs, *drop):
    ids = [id(r) for r in drop]
    return [(k, r) for k, r in pairs if id(r) not in ids]


def build_complete() -> None:
    honest = cbundle([CP1, CP2, CP3], ALL, [E1, E2, E3])
    # ---- PASS
    addc("pass", "001-complete-with-executor-log", "Three hourly checkpoints (one empty), every record they count, "
         "and the executor's log: two executions and one refusal, each naming a record in the bundle.", honest)
    addc("pass", "002-no-executor-log", "The same records and checkpoints, no executor log, no executor key set.",
         cbundle([CP1, CP2, CP3], ALL), keys=None)
    addc("pass", "003-quiet-hour-only", "A window covering only the empty hour: one checkpoint counting nothing.",
         cbundle([CP2], []), frm=T("11:00:00"), to=T("12:00:00"))
    addc("pass", "004-window-inside-an-hour", "A window inside one hour is covered by that hour's checkpoint; "
         "every record of the hour must still be presented.", cbundle([CP3], H12), frm=T("12:15:00"), to=T("12:45:00"))
    a5 = action(5, "2026-10-20T13:59:59.999999+01:00", "BLOCKED")
    cp5 = checkpoint(1, None, T("12:00:00"), T("13:00:00"), [("action", a5)], T("13:02:00"))
    addc("pass", "005-offset-timestamp-assigned-by-instant", "A record stamped 13:59:59.999999+01:00 is "
         "12:59:59.999999Z and belongs to the 12:00Z to 13:00Z checkpoint; compared as instants, not strings.",
         cbundle([cp5], [("action", a5)]), frm=T("12:00:00"), to=T("13:00:00"))
    e_norec = execution(4, E3, "REFUSED", T("12:40:00"))
    addc("pass", "006-refusal-without-a-seal-record", "The executor refused a request that carried no Seal record; "
         "the entry names none, so nothing needs reconciling.", cbundle([CP1, CP2, CP3], ALL, [E1, E2, E3, e_norec]))

    # ---- FAIL
    addc("fail", "001-edited-record-count", "A2 withheld and the hour's checkpoint edited to count 3: the "
         "checkpoint's signature fails.", cbundle([{**CP1, "record_count": "3", "total_count": "3"}, CP2, CP3], without(ALL, A2)))
    addc("fail", "002-checkpoint-chain-gap", "The empty hour's checkpoint withheld: checkpoint 3 does not follow "
         "checkpoint 1.", cbundle([CP1, CP3], ALL))
    other = checkpoint(1, None, T("10:00:00"), T("11:00:00"), [], T("11:02:00"), org_id="org-other")
    addc("fail", "003-another-organisations-checkpoint", "A checkpoint the issuer signed for another organisation.",
         cbundle([other, CP2, CP3], ALL))
    addc("fail", "004-record-repeated", "A2 presented twice.", cbundle([CP1, CP2, CP3], ALL + [("action", A2)]))
    a6 = action(6, T("10:30:00"), "BLOCKED")
    addc("fail", "005-more-records-than-counted", "A record the hour's checkpoint does not count.",
         cbundle([CP1, CP2, CP3], ALL + [("action", a6)]))
    addc("fail", "006-substituted-record", "Same count, one record swapped for another of the same hour: the "
         "records_hash does not match.", cbundle([CP1, CP2, CP3], without(ALL, A2) + [("action", a6)]))
    bad_prev = checkpoint(2, CP1, T("11:00:00"), T("12:00:00"), [], T("12:02:00"), prev_checkpoint_hash="0" * 64)
    addc("fail", "007-previous-hash-wrong", "Checkpoint 2 names a previous hash that is not checkpoint 1's.",
         cbundle([CP1, bad_prev, checkpoint(3, bad_prev, T("12:00:00"), T("13:00:00"), H12, T("13:02:00"))], ALL))
    bad_total = checkpoint(2, CP1, T("11:00:00"), T("12:00:00"), [], T("12:02:00"), total="5")
    addc("fail", "008-total-wrong", "Checkpoint 2's total_count is not checkpoint 1's plus its own count.",
         cbundle([CP1, bad_total], H10), to=T("12:00:00"))
    forged = checkpoint(1, None, T("10:00:00"), T("11:00:00"), H10, T("11:02:00"), sk=FORGER)
    addc("fail", "009-checkpoint-not-under-pinned-key", "A checkpoint signed by a key other than the pinned issuer "
         "key.", cbundle([forged], H10), to=T("11:00:00"))
    early = checkpoint(1, None, T("10:00:00"), T("11:00:00"), H10, "2026-10-20T10:59:59.999999+00:00")
    addc("fail", "010-checkpoint-issued-before-its-period-ends", "timestamp one microsecond before period_end.",
         cbundle([early], H10), to=T("11:00:00"))
    inverted = checkpoint(1, None, T("11:00:00"), T("11:00:00"), [], T("11:02:00"))
    addc("fail", "011-empty-period", "period_end equal to period_start.", cbundle([inverted], []),
         frm=T("11:00:00"), to=T("11:00:01"))
    first_prev = checkpoint(1, None, T("10:00:00"), T("11:00:00"), H10, T("11:02:00"), prev_checkpoint_hash="a" * 64)
    addc("fail", "012-first-checkpoint-with-previous-hash", "checkpoint_seq 1 naming a previous checkpoint.",
         cbundle([first_prev], H10), to=T("11:00:00"))
    empty_wrong = checkpoint(1, None, T("11:00:00"), T("12:00:00"), [], T("12:02:00"), rh="0" * 64)
    addc("fail", "013-empty-hour-wrong-hash", "An empty period whose records_hash is not the hash of nothing.",
         cbundle([empty_wrong], []), frm=T("11:00:00"), to=T("12:00:00"))
    addc("fail", "014-checkpoint-unknown-field", "A checkpoint carrying an extra signed member.",
         cbundle([resign(CP1, ISSUER_SK, note="x")], H10), to=T("11:00:00"))
    addc("fail", "015-checkpoint-version-tag", "checkpoint-2.",
         cbundle([resign(CP1, ISSUER_SK, v="checkpoint-2")], H10), to=T("11:00:00"))
    cp1_noa1 = checkpoint(1, None, T("10:00:00"), T("11:00:00"), [("action", A2), ("action", A3)], T("11:02:00"))
    addc("fail", "016-executed-action-never-recorded", "The issuer never logged or counted A1 and its USE; the "
         "executor executed A1 under them. (A2 omission made visible, given the executor's cooperation.)",
         cbundle([cp1_noa1], [("action", A2), ("action", A3)], [E1]), to=T("11:00:00"))
    cp1_nou1 = checkpoint(1, None, T("10:00:00"), T("11:00:00"), [("action", A1), ("action", A2), ("action", A3)], T("11:02:00"))
    addc("fail", "017-executed-use-never-recorded", "The issuer counted A1 but never logged its USE.",
         cbundle([cp1_nou1], [("action", A1), ("action", A2), ("action", A3)], [E1]), to=T("11:00:00"))
    cp1_noa2 = checkpoint(1, None, T("10:00:00"), T("11:00:00"), [("use", U1), ("action", A1), ("action", A3)], T("11:02:00"))
    addc("fail", "018-refused-record-never-recorded", "The issuer never logged A2, a refusal the agent took to the "
         "executor anyway; the executor's REFUSED entry names A2's record.",
         cbundle([cp1_noa2], [("use", U1), ("action", A1), ("action", A3)], [E1, E2]), to=T("11:00:00"))
    addc("fail", "019-executor-not-designated", "The executor log is signed by a key the reviewer did not "
         "designate.", honest, keys=[_pub(EXECUTOR2)])
    e3_gap = execution(4, E2, "EXECUTED", T("12:24:17"), A4, U4)
    addc("fail", "020-executor-log-gap", "Entry 3 is missing from the executor log.",
         cbundle([CP1, CP2, CP3], ALL, [E1, E2, e3_gap]))
    e2_other = execution(2, E1, "REFUSED", T("10:08:00"), A2, sk=EXECUTOR2, executor_id="other-executor")
    addc("fail", "021-two-executors-in-one-log", "One log, two executors.",
         cbundle([CP1, CP2, CP3], ALL, [E1, e2_other]), keys=[_pub(EXECUTOR), _pub(EXECUTOR2)])
    e2_exec = execution(2, E1, "EXECUTED", T("10:08:00"), A2, U1)
    addc("fail", "022-executed-a-refused-action", "The executor log says it executed A2, which Seal refused.",
         cbundle([CP1, CP2, CP3], ALL, [E1, e2_exec]))
    e2_twice = execution(2, E1, "EXECUTED", T("10:08:00"), A1, U1)
    addc("fail", "023-executed-twice", "One action executed twice.", cbundle([CP1, CP2, CP3], ALL, [E1, e2_twice]))
    e1_args = execution(1, None, "EXECUTED", T("10:05:12"), A1, U1, args_hash="1" * 64)
    addc("fail", "024-execution-args-differ", "The executor executed other arguments than the record's.",
         cbundle([CP1, CP2, CP3], ALL, [e1_args]))
    e1_id = execution(1, None, "EXECUTED", T("10:05:12"), A1, U1, action_id="00000000-0000-4000-8000-0000000000ff")
    addc("fail", "025-execution-action-id-differs", "The entry's action_id is not the record's.",
         cbundle([CP1, CP2, CP3], ALL, [e1_id]))
    e1_wrong_use = execution(1, None, "EXECUTED", T("10:05:12"), A1, U4)
    addc("fail", "026-use-for-another-action", "The entry pairs A1 with A4's USE.",
         cbundle([CP1, CP2, CP3], ALL, [e1_wrong_use]))
    a_other = action(7, T("10:20:00"), "BLOCKED", org_id="org-other")
    addc("fail", "027-record-of-another-organisation", "A record of another organisation in the bundle.",
         cbundle([CP1, CP2, CP3], ALL + [("action", a_other)]))
    b = cbundle([CP1, CP2, CP3], ALL)
    b["records"][0] = {"kind": "receipt", "record": U1}
    addc("fail", "028-unknown-record-kind", "A record kind this profile does not count.", b)
    addc("fail", "029-bundle-unknown-member", "The bundle carries an unrecognised member.", {**honest, "notes": []})
    unsorted = hashlib.sha256(b"".join(leaf(k, r) for k, r in H10)).hexdigest()
    sorted_h = records_hash([leaf(k, r) for k, r in H10])
    assert unsorted != sorted_h, "pick an order that differs from the sorted one"
    cp_uns = checkpoint(1, None, T("10:00:00"), T("11:00:00"), H10, T("11:02:00"), rh=unsorted)
    addc("fail", "030-records-hash-not-sorted", "records_hash computed over the leaves in log order instead of "
         "sorted order.", cbundle([cp_uns], H10), to=T("11:00:00"))
    addc("fail", "031-count-not-canonical-decimal", "record_count \"04\".",
         cbundle([resign(CP1, ISSUER_SK, record_count="04")], H10), to=T("11:00:00"))
    addc("fail", "032-review-window-inverted", "review_from after review_to.", honest, frm=TO, to=FROM)
    addc("fail", "033-signature-trailing-line-feed", "A checkpoint signature with a trailing line feed.",
         cbundle([{**CP1, "signature": CP1["signature"] + "\n"}], H10), to=T("11:00:00"))
    addc("fail", "034-fail-outranks-incomplete", "No executor key set (INCOMPLETE on its own) and an executed "
         "action missing from the bundle (FAIL): FAIL wins.",
         cbundle([cp1_noa1], [("action", A2), ("action", A3)], [E1]), to=T("11:00:00"), keys=None)

    # ---- INCOMPLETE
    addc("incomplete", "001-record-withheld", "The operator withheld A2: the hour counts 4, the bundle carries 3.",
         cbundle([CP1, CP2, CP3], without(ALL, A2)))
    addc("incomplete", "002-window-not-covered", "The last hour's checkpoint and records are absent.",
         cbundle([CP1, CP2], H10))
    addc("incomplete", "003-no-checkpoint", "Records with no checkpoint at all.", cbundle([], ALL))
    addc("incomplete", "004-no-executor-key-set", "An executor log with no executor key set supplied.", honest,
         keys=None)
    addc("incomplete", "005-record-outside-every-checkpoint", "A record stamped after the last checkpoint's "
         "period: 14:00:00+01:00 is 13:00:00Z, the first instant outside 12:00Z to 13:00Z.",
         cbundle([cp5], [("action", a5), ("action", action(8, "2026-10-20T14:00:00+01:00", "BLOCKED"))]),
         frm=T("12:00:00"), to=T("13:00:00"))
    e_late = execution(4, E3, "REFUSED", T("13:30:00"))
    addc("incomplete", "006-execution-outside-the-checkpointed-span", "An executor entry after the last "
         "checkpoint's period.", cbundle([CP1, CP2, CP3], ALL, [E1, E2, E3, e_late]))
    addc("incomplete", "007-use-withheld", "The operator withheld U1.", cbundle([CP1, CP2, CP3], without(ALL, U1)))


# --- witnessed -------------------------------------------------------------------------------------------------

def sth(leaves, stamp: str) -> dict:
    root = tlib.merkle_root(leaves)
    signed = b"aqta-sth-public-v1|" + str(len(leaves)).encode() + b"|" + root + b"|" + stamp.encode()
    return {"v": 1, "log": "public", "tree_size": len(leaves), "root_hash": root.hex(), "timestamp": stamp,
            "signature": _b64(ISSUER_SK.sign(signed))}


def statement(seq: int, prev: dict | None, head: dict, at: str, *, sk=TIME, **over) -> dict:
    payload = {"v": "witness-1", "witness_id": WITNESS_ID, "statement_seq": str(seq),
               "prev_statement_hash": unsigned_hash(prev) if prev else "", "log_public_key": PIN,
               "tree_size": str(head["tree_size"]), "root_hash": head["root_hash"], "head_timestamp": head["timestamp"],
               "head_signature": head["signature"], "witnessed_at": at, "public_key": _pub(sk)}
    payload.update(over)
    return sign_with(sk, payload)


class World:
    """A shared public log: other organisations' leaves, ours, witnessed hourly at :17, a head at 13:20."""

    def __init__(self, late=None):
        # (time, leaf, (kind, record) or None)
        ev = [("09:00:00", other_leaf(i), None) for i in range(3)]
        ev += [("10:05:09.95", leaf("use", U1), ("use", U1)), ("10:05:10", leaf("action", A1), ("action", A1)),
               ("10:06:00", other_leaf(10), None), ("10:07:40", leaf("action", A2), ("action", A2)),
               ("10:41:30", leaf("action", A3), ("action", A3)), ("11:02:00", leaf("checkpoint", CP1), ("checkpoint", CP1)),
               ("12:02:00", leaf("checkpoint", CP2), ("checkpoint", CP2)), ("12:24:14.95", leaf("use", U4), ("use", U4)),
               ("12:24:15", leaf("action", A4), ("action", A4)), ("12:30:00", other_leaf(11), None),
               ("13:40:00", other_leaf(12), None)]
        for t, kr in (late or []):
            ev.append((t, leaf(*kr), kr))
        ev.sort(key=lambda e: e[0])
        self.ev = ev
        self.leaves = [e[1] for e in ev]
        self.heads = {}
        self.stmts = []
        prev = None
        for i, hh in enumerate(("10", "11", "12", "13")):
            n = sum(1 for e in ev if e[0] < f"{hh}:17:00")
            h = sth(self.leaves[:n], f"2026-10-20T{hh}:17:00Z")
            s = statement(i + 1, prev, h, f"2026-10-20T{hh}:17:42.000000+00:00")
            self.stmts.append(s)
            prev = s
        self.target_n = sum(1 for e in ev if e[0] < "13:20:00")
        self.head = sth(self.leaves[:self.target_n], "2026-10-20T13:20:00Z")

    def index(self, rec) -> int:
        return next(i for i, e in enumerate(self.ev) if e[2] is not None and e[2][1] is rec)

    def proof(self, rec, leaves=None, n=None) -> dict:
        leaves = leaves or self.leaves[:self.target_n]
        i = self.index(rec)
        return {"leaf_index": i, "tree_size": len(leaves), "leaf_hash": leaves[i].hex(),
                "root_hash": tlib.merkle_root(leaves).hex(),
                "audit_path": [h.hex() for h in tlib.inclusion_path(leaves, i)]}

    def cons(self, stmts=None, leaves=None) -> list:
        leaves = leaves or self.leaves[:self.target_n]
        out, seen = [], set()
        for s in (stmts or self.stmts):
            old = int(s["tree_size"])
            if old == len(leaves) or old in seen:
                continue
            seen.add(old)
            out.append({"old_size": old, "new_size": len(leaves), "old_root": tlib.merkle_root(leaves[:old]).hex(),
                        "new_root": tlib.merkle_root(leaves).hex(),
                        "consistency_path": [h.hex() for h in tlib.consistency_path(leaves, old, len(leaves))]})
        return out

    def bundle(self, pairs, stmts=None, head=None, cons=None) -> dict:
        stmts = self.stmts if stmts is None else stmts
        return {"v": "witnessed-1", "head": head or self.head, "witnessed": list(stmts),
                "consistency": self.cons(stmts) if cons is None else cons,
                "records": [{"kind": k, "record": r, "proof": self.proof(r)} for k, r in pairs]}


WITNESSED: dict = {"pass": [], "fail": [], "incomplete": []}


def addw(kind, name, why, b, *, keys="default", tol=3600):
    WITNESSED[kind].append((name, why, {"witness_keys": [_pub(TIME)] if keys == "default" else keys,
                                        "tolerance_seconds": tol, "bundle": b}))


OURS = [("use", U1), ("action", A1), ("action", A2), ("action", A3), ("checkpoint", CP1), ("checkpoint", CP2),
        ("use", U4), ("action", A4)]


def build_witnessed() -> None:
    w = World()
    honest = w.bundle(OURS)
    # ---- PASS
    addw("pass", "001-honest-history", "Every record of the organisation, each in a witnessed head within the "
         "hour after its claimed time.", honest)
    edge = action(20, "2026-10-20T10:17:42.000000+00:00", "BLOCKED")
    we = World(late=[("11:30:00", ("action", edge))])
    addw("pass", "002-exactly-at-the-tolerance", "Claims 10:17:42, first in the head witnessed at 12:17:42; the "
         "11:17:42 head does not contain it: exactly 3600 seconds late, which the tolerance allows.",
         we.bundle([("action", edge)]))
    chain, prev = [], None
    for i, s in enumerate(w.stmts):
        at = s["witnessed_at"].replace("+00:00", "+01:00")
        hh = int(at[11:13]) + 1
        at = f"{at[:11]}{hh:02d}{at[13:]}"
        prev = statement(i + 1, prev, {"tree_size": int(s["tree_size"]), "root_hash": s["root_hash"],
                                       "timestamp": s["head_timestamp"], "signature": s["head_signature"]}, at)
        chain.append(prev)
    addw("pass", "003-witnessed-at-in-another-offset", "Every witnessed_at written in +01:00; compared as "
         "instants.", w.bundle(OURS, stmts=chain))
    target_is_last = World()
    last = target_is_last.stmts[-1]
    head13 = sth(target_is_last.leaves[:int(last["tree_size"])], last["head_timestamp"])
    target_is_last.target_n = int(last["tree_size"])
    target_is_last.head = head13
    addw("pass", "004-head-is-the-last-witnessed-head", "The proofs target the last witnessed head itself; no "
         "consistency proof is needed for it.", target_is_last.bundle([("action", A4)]))
    addw("pass", "005-one-record", "One record alone.", w.bundle([("action", A3)]))

    # ---- FAIL
    back = action(21, "2026-10-20T10:06:00.000000+00:00", "BLOCKED")
    wb = World(late=[("12:31:50", ("action", back))])
    addw("fail", "001-backdated", "Claims 10:06:00, first logged at 12:31:50: the head witnessed at 12:17:42 does not "
         "contain it.", wb.bundle([("action", back)]))
    edge2 = action(22, "2026-10-20T10:17:41.999999+00:00", "BLOCKED")
    we2 = World(late=[("11:30:00", ("action", edge2))])
    addw("fail", "002-one-microsecond-past-the-tolerance", "As pass/002 but claiming one microsecond earlier.",
         we2.bundle([("action", edge2)]))
    fwd = action(23, "2026-10-20T12:17:42.000001+00:00", "BLOCKED")
    wf = World(late=[("12:10:00", ("action", fwd))])
    addw("fail", "003-forward-dated", "Claims a time after the witnessed head that already contains it.",
         wf.bundle([("action", fwd)]))
    s2 = resign(wb.stmts[2], ISSUER_SK, public_key=PIN)
    forged_chain = wb.stmts[:2] + [s2] + [statement(4, s2, {"tree_size": int(wb.stmts[3]["tree_size"]),
                                                              "root_hash": wb.stmts[3]["root_hash"],
                                                              "timestamp": wb.stmts[3]["head_timestamp"],
                                                              "signature": wb.stmts[3]["head_signature"]},
                                                         wb.stmts[3]["witnessed_at"])]
    addw("fail", "004-statement-signed-by-the-issuer", "The 12:17 statement replaced by one the issuer signed.",
         wb.bundle([("action", back)], stmts=forged_chain))
    addw("fail", "005-statements-removed", "The 11:17 and 12:17 statements removed: the chain breaks.",
         wb.bundle([("action", back)], stmts=[wb.stmts[0], wb.stmts[3]]))
    other_log = _pub(FORGER)
    addw("fail", "006-statement-for-another-log", "A statement witnessing another log's key.",
         w.bundle(OURS, stmts=[resign(w.stmts[0], TIME, log_public_key=other_log)] + w.stmts[1:]))
    s_badhead = resign(w.stmts[0], TIME, head_signature=w.stmts[1]["head_signature"])
    addw("fail", "007-statement-names-an-unsigned-head", "A statement whose head signature belongs to another head.",
         w.bundle(OURS, stmts=[s_badhead]))
    s_back = statement(2, w.stmts[0], {"tree_size": int(w.stmts[1]["tree_size"]), "root_hash": w.stmts[1]["root_hash"],
                                       "timestamp": w.stmts[1]["head_timestamp"], "signature": w.stmts[1]["head_signature"]},
                       "2026-10-20T10:17:41.000000+00:00")
    addw("fail", "008-witnessed-time-goes-backwards", "Statement 2 is witnessed before statement 1.",
         w.bundle([("action", A1)], stmts=[w.stmts[0], s_back]))
    shrink = statement(3, w.stmts[1], {"tree_size": int(w.stmts[0]["tree_size"]), "root_hash": w.stmts[0]["root_hash"],
                                       "timestamp": w.stmts[0]["head_timestamp"], "signature": w.stmts[0]["head_signature"]},
                       "2026-10-20T12:17:42.000000+00:00")
    addw("fail", "009-tree-shrinks", "A later statement names a smaller tree.",
         w.bundle([("action", A1)], stmts=[w.stmts[0], w.stmts[1], shrink]))
    alt_leaves = list(w.leaves)
    n1 = int(w.stmts[1]["tree_size"])
    alt_leaves[n1 - 1] = other_leaf(99)
    alt_head = sth(alt_leaves[:n1], "2026-10-20T11:30:00Z")
    s_eq = statement(3, w.stmts[1], alt_head, "2026-10-20T11:30:42.000000+00:00")
    addw("fail", "010-two-roots-one-size", "Two consecutive statements name one size with different roots.",
         w.bundle([("action", A1)], stmts=w.stmts[:2] + [s_eq]))
    big = statement(5, w.stmts[3], sth(w.leaves, "2026-10-20T14:17:00Z"), "2026-10-20T14:17:42.000000+00:00")
    if int(big["tree_size"]) <= w.target_n:
        raise SystemExit("world too small for the larger-than-head vector")
    addw("fail", "011-statement-larger-than-head", "A statement names a tree larger than the head the proofs "
         "target.", w.bundle(OURS, stmts=w.stmts + [big]))
    # A rewritten history: the backdated record inside the 10:17 head. The proofs are computed over the rewrite.
    rw_ev = [e for e in wb.ev if not (e[2] and e[2][1] is back)]
    pos = next(i for i, e in enumerate(rw_ev) if e[0] > "10:06:00")
    rw_ev.insert(pos, ("10:06:00", leaf("action", back), ("action", back)))
    rw_leaves = [e[1] for e in rw_ev][:wb.target_n]
    rw_head = sth(rw_leaves, "2026-10-20T13:20:00Z")
    rw_cons = []
    for s in wb.stmts:
        old = int(s["tree_size"])
        rw_cons.append({"old_size": old, "new_size": len(rw_leaves), "old_root": tlib.merkle_root(rw_leaves[:old]).hex(),
                        "new_root": rw_head["root_hash"],
                        "consistency_path": [h.hex() for h in tlib.consistency_path(rw_leaves, old, len(rw_leaves))]})
    i_rw = pos
    rw_bundle = {"v": "witnessed-1", "head": rw_head, "witnessed": wb.stmts, "consistency": rw_cons,
                 "records": [{"kind": "action", "record": back,
                              "proof": {"leaf_index": i_rw, "tree_size": len(rw_leaves), "leaf_hash": rw_leaves[i_rw].hex(),
                                        "root_hash": rw_head["root_hash"],
                                        "audit_path": [h.hex() for h in tlib.inclusion_path(rw_leaves, i_rw)]}}]}
    addw("fail", "012-history-rewritten", "The issuer rewrites history so the backdated record sits inside the "
         "10:17 head, signs a new head over the rewrite and computes consistency proofs over it: the proofs do not "
         "start at the witnessed roots.", rw_bundle)
    tampered = copy.deepcopy(honest)
    tampered["consistency"][0]["consistency_path"][0] = "00" * 32
    addw("fail", "013-consistency-path-tampered", "A consistency proof whose path does not verify.", tampered)
    stray = copy.deepcopy(honest)
    stray["consistency"].append({**stray["consistency"][0], "old_size": 1})
    addw("fail", "014-consistency-from-an-unwitnessed-size", "A consistency proof that starts at no witnessed head.",
         stray)
    other_head = copy.deepcopy(honest)
    other_head["records"][0]["proof"]["tree_size"] = int(w.stmts[2]["tree_size"])
    assert int(w.stmts[2]["tree_size"]) != w.target_n
    addw("fail", "015-proof-targets-another-head", "A record proof that targets a different tree.", other_head)
    wrong_leaf = copy.deepcopy(honest)
    wrong_leaf["records"][1]["proof"] = copy.deepcopy(honest["records"][2]["proof"])
    addw("fail", "016-proof-for-another-leaf", "A record carrying another record's proof.", wrong_leaf)
    bad_path = copy.deepcopy(honest)
    bad_path["records"][0]["proof"]["audit_path"][0] = "11" * 32
    addw("fail", "017-proof-path-tampered", "An inclusion proof whose path does not verify.", bad_path)
    edited = copy.deepcopy(honest)
    edited["records"][1]["record"]["outcome"] = "BLOCKED"
    addw("fail", "018-record-edited", "A record edited after signing.", edited)
    forged_head = copy.deepcopy(honest)
    forged_head["head"]["timestamp"] = "2026-10-20T13:21:00Z"
    addw("fail", "019-head-not-signed", "The target head's signature does not cover its timestamp.", forged_head)
    perorg = copy.deepcopy(honest)
    perorg["head"] = {k: v for k, v in perorg["head"].items() if k != "log"}
    addw("fail", "020-head-not-public", "The target head is not a public head.", perorg)
    addw("fail", "021-statement-unknown-field", "A statement with an extra signed member.",
         w.bundle(OURS, stmts=[resign(w.stmts[0], TIME, note="x")]))
    addw("fail", "022-statement-version-tag", "witness-2.", w.bundle(OURS, stmts=[resign(w.stmts[0], TIME, v="witness-2")]))
    addw("fail", "023-tree-size-not-canonical", "tree_size \"0" + w.stmts[0]["tree_size"] + "\".",
         w.bundle(OURS, stmts=[resign(w.stmts[0], TIME, tree_size="0" + w.stmts[0]["tree_size"])]))
    addw("fail", "024-witnessed-at-without-offset", "witnessed_at with no offset.",
         w.bundle(OURS, stmts=[resign(w.stmts[0], TIME, witnessed_at="2026-10-20T10:17:42")]))
    addw("fail", "025-bundle-unknown-member", "The bundle carries an unrecognised member.", {**honest, "notes": []})
    addw("fail", "026-tolerance-negative", "A negative tolerance.", honest, tol=-1)
    addw("fail", "027-head-timestamp-fractional", "head_timestamp with fractional seconds.",
         w.bundle(OURS, stmts=[resign(w.stmts[0], TIME, head_timestamp="2026-10-20T10:17:00.5Z")]))
    addw("fail", "028-fail-outranks-incomplete", "No witness key set (INCOMPLETE on its own) and a backdated "
         "record (FAIL): FAIL wins.", wb.bundle([("action", back)]), keys=None)

    # ---- INCOMPLETE
    addw("incomplete", "001-no-witness-key-set", "The honest history with no witness key set supplied.", honest,
         keys=None)
    late = action(24, "2026-10-20T13:18:00.000000+00:00", "BLOCKED")
    wl = World(late=[("13:18:00", ("action", late))])
    addw("incomplete", "002-not-yet-witnessed", "A record logged after the last witnessed head.",
         wl.bundle([("action", late)]))
    addw("incomplete", "003-chain-starts-too-late", "Every statement before 13:17 withheld: the first statement "
         "that contains the backdated record is hours after its claimed time, and nothing earlier bounds it.",
         wb.bundle([("action", back)], stmts=wb.stmts[3:]))
    no_cons = copy.deepcopy(honest)
    no_cons["consistency"] = no_cons["consistency"][1:]
    addw("incomplete", "004-consistency-proof-missing", "One witnessed head has no consistency proof to the head.",
         no_cons)
    addw("incomplete", "005-no-record", "Nothing to check.", w.bundle([]))


def write(dirname: str, vectors: dict, title: str, params: str) -> None:
    base = ROOT / "test-vectors" / dirname
    for kind, items in vectors.items():
        d = base / kind
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        for name, _why, body in items:
            (d / f"{name}.json").write_text(json.dumps(body, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    rows = [f"| {kind}/{name} | {why} |" for kind, items in vectors.items() for name, why, _ in items]
    (base / "INDEX.md").write_text(
        f"# {title} vectors: generated index\n\nGenerated by `scripts/make-e79-vectors.py`; do not edit by hand.\n\n"
        f"Vector issuer key (pin it): `{PIN}`\n\n{params}\n\n| Vector | What it pins |\n|---|---|\n" + "\n".join(rows) + "\n")


def main() -> None:
    build_complete()
    build_witnessed()
    write("complete", COMPLETE, "complete",
          f"Designated executor key (the default `executor_keys`): `{_pub(EXECUTOR)}`")
    write("witnessed", WITNESSED, "witnessed",
          f"Designated time-authority key (the default `witness_keys`): `{_pub(TIME)}`; tolerance 3600 seconds "
          "unless the file says otherwise")
    print("complete", {k: len(v) for k, v in COMPLETE.items()}, "witnessed", {k: len(v) for k, v in WITNESSED.items()},
          "issuer", PIN)


if __name__ == "__main__":
    main()
