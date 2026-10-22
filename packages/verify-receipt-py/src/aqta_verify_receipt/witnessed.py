"""
The `witnessed` profile (spec/WITNESS-v1.md section 7) and WITNESS-v1
(spec/WITNESS-v1.md). DRAFT: not frozen.

Backdating (ISSUER-ADVERSARY A3) needs a clock the issuer does not control.
A witness fetches the public log head every hour and a time authority stamps
it; a record whose claimed time is more than the stated tolerance before the
witnessed time of a head that does not contain it was logged late by more
than the tolerance, so its claimed time is not believable. Absence from an
unwitnessed head proves nothing (vector a3-lag-is-not-backdating still holds
for assess_history); absence from a witnessed head, beyond the tolerance, does.

Three verdicts, never two: PASS, FAIL, INCOMPLETE. The check order and every
reason string are a cross-implementation contract with the TypeScript verifier
(src/witnessed.ts): first FAIL wins, and the two must return the same verdict
and reason on the same bytes.

Explicit opt-in only. Nothing here is reached by inspecting the input's shape.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, List, Mapping, Optional, Sequence

from .chain import (
    _DECIMAL_POSITIVE,
    FAIL,
    INCOMPLETE,
    PASS,
    ChainResult,
    _cmp_instant,
    _Fail,
    _first_unknown,
    _instant,
    _is_key,
    _signature_ok,
)
from .complete import check_record_of_kind, record_leaf
from .transparency import (
    _MAX_SAFE_SIZE,
    verify_consistency_proof,
    verify_inclusion_proof,
    verify_signed_tree_head,
)
from .verifier import _HEX64, _RFC3339_OFFSET, _canonical_bytes

WITNESS_FIELDS = (
    "v", "witness_id", "statement_seq", "prev_statement_hash", "log_public_key", "tree_size", "root_hash",
    "head_timestamp", "head_signature", "witnessed_at", "public_key", "signature",
)
BUNDLE_MEMBERS = ("v", "head", "witnessed", "consistency", "records")
DEFAULT_TOLERANCE_SECONDS = 3600

_HEAD_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", re.ASCII)
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)


def statement_hash(w: Mapping) -> str:
    return hashlib.sha256(_canonical_bytes({k: v for k, v in w.items() if k != "signature"})).hexdigest()


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _later_than(w: str, claimed: str, tolerance: int) -> bool:
    """w > claimed + tolerance seconds, exactly, to every fractional digit."""
    (sw, fw), (sc, fc) = _instant(w), _instant(claimed)
    sc += tolerance
    if sw != sc:
        return sw > sc
    n = max(len(fw), len(fc))
    return fw.ljust(n, "0") > fc.ljust(n, "0")


# --- WITNESS-v1 (spec/WITNESS-v1.md section 6) ------------------------------------------------------------------


def check_witness_record(w: Any) -> Optional[str]:
    """Integrity of one witness statement under its own embedded key. Says nothing about whether that key is a
    designated time authority's, or about the head it names."""
    if not isinstance(w, Mapping):
        return "statement must be an object"
    for f in WITNESS_FIELDS:
        if f not in w:
            return f"missing required field: {f}"
    unknown = _first_unknown(w, set(WITNESS_FIELDS))
    if unknown is not None:
        return f"unknown top-level field: {unknown}"
    if not isinstance(w["v"], str) or w["v"] != "witness-1":
        return "v must be the string 'witness-1'"
    for f in WITNESS_FIELDS:
        if not isinstance(w[f], str):
            return f"{f} must be a string"
    if w["witness_id"] == "":
        return "witness_id must be a non-empty string"
    if not _DECIMAL_POSITIVE.fullmatch(w["statement_seq"]):
        return "statement_seq must be a canonical decimal string of at least 1"
    if w["statement_seq"] == "1":
        if w["prev_statement_hash"] != "":
            return "prev_statement_hash must be empty for statement_seq 1"
    elif not _HEX64.fullmatch(w["prev_statement_hash"]):
        return "prev_statement_hash must be 64 lowercase hex characters"
    if not _is_key(w["log_public_key"]):
        return "log_public_key must be a base64url Ed25519 key"
    if not _DECIMAL_POSITIVE.fullmatch(w["tree_size"]):
        return "tree_size must be a canonical decimal string of at least 1"
    if len(w["tree_size"]) > 16 or int(w["tree_size"]) > _MAX_SAFE_SIZE:
        return "tree_size is too large"
    if not _HEX64.fullmatch(w["root_hash"]):
        return "root_hash must be 64 lowercase hex characters"
    if not _HEAD_TS.fullmatch(w["head_timestamp"]):
        return "head_timestamp must be YYYY-MM-DDTHH:MM:SSZ"
    if not _B64URL.fullmatch(w["head_signature"]):
        return "head_signature must be base64url"
    if not _RFC3339_OFFSET.fullmatch(w["witnessed_at"]):
        return "witnessed_at must be an RFC 3339 datetime with an explicit offset"
    if not _is_key(w["public_key"]):
        return "public_key must be a base64url Ed25519 key"
    return _signature_ok({k: v for k, v in w.items() if k != "signature"}, w["signature"], w["public_key"])


def witnessed_head(w: Mapping) -> dict:
    """The public tree head a statement names, in the shape verify_signed_tree_head reads."""
    return {"v": 1, "log": "public", "tree_size": int(w["tree_size"]), "root_hash": w["root_hash"],
            "timestamp": w["head_timestamp"], "signature": w["head_signature"]}


# --- The profile (spec/WITNESS-v1.md section 7) -----------------------------------------------------------------


def verify_witnessed(
    bundle: Any,
    *,
    trusted_public_key: Optional[str] = None,
    witness_keys: Optional[Sequence[str]] = None,
    tolerance_seconds: Any = DEFAULT_TOLERANCE_SECONDS,
) -> ChainResult:
    """Verify a witnessed-time bundle. Never raises. Returns PASS, FAIL or INCOMPLETE with a reason."""
    try:
        return _verify_witnessed(bundle, trusted_public_key, witness_keys, tolerance_seconds)
    except _Fail as e:
        return ChainResult(FAIL, str(e))
    except Exception:  # never raise: an unexpected input is a failed check, reported
        return ChainResult(FAIL, "verification error")


def _verify_witnessed(bundle, pinned, witness_keys, tol) -> ChainResult:
    incomplete: List[str] = []

    def fail(reason: str):
        raise _Fail(reason)

    # 1. Inputs.
    if not isinstance(pinned, str) or not _is_key(pinned):
        fail("a pinned issuer key is required")
    if witness_keys is not None:
        if not isinstance(witness_keys, (list, tuple)) or not all(_is_key(k) for k in witness_keys):
            fail("witness_keys must be base64url Ed25519 keys")
        trusted = set(witness_keys)
    else:
        trusted = None
    if not _is_int(tol) or tol < 0 or tol > _MAX_SAFE_SIZE:
        fail("tolerance_seconds must be a non-negative integer")

    # 2. Bundle.
    if not isinstance(bundle, Mapping):
        fail("bundle must be an object")
    for m in BUNDLE_MEMBERS:
        if m not in bundle:
            fail(f"bundle missing member: {m}")
    unknown = _first_unknown(bundle, set(BUNDLE_MEMBERS))
    if unknown is not None:
        fail(f"bundle has unknown member: {unknown}")
    if not isinstance(bundle["v"], str) or bundle["v"] != "witnessed-1":
        fail("bundle v must be the string 'witnessed-1'")
    for m in ("witnessed", "consistency", "records"):
        if not isinstance(bundle[m], list):
            fail(f"bundle {m} must be an array")

    # 3. The head the record proofs target: a public head the pinned issuer key signed.
    head = bundle["head"]
    if not isinstance(head, Mapping) or head.get("log") != "public":
        fail("head must be a public tree head")
    if not verify_signed_tree_head(head, pinned).valid:
        fail("head does not verify under the pinned key")
    size, root = head["tree_size"], head["root_hash"]

    # 4. Witness statements: each one, then the chain.
    ws = bundle["witnessed"]
    for i, w in enumerate(ws):
        why = check_witness_record(w)
        if why is not None:
            fail(f"witnessed[{i}]: {why}")
        if w["log_public_key"] != pinned:
            fail(f"witnessed[{i}] witnesses a different log key")
        if not verify_signed_tree_head(witnessed_head(w), pinned).valid:
            fail(f"witnessed[{i}] names a head the pinned issuer key did not sign")
        if trusted is None:
            if "no witness key set was supplied" not in incomplete:
                incomplete.append("no witness key set was supplied")
        elif w["public_key"] not in trusted:
            fail(f"witnessed[{i}] is not signed by a designated witness key")
        if i > 0:
            prev = ws[i - 1]
            if (w["witness_id"] != prev["witness_id"]
                    or int(w["statement_seq"]) != int(prev["statement_seq"]) + 1
                    or w["prev_statement_hash"] != statement_hash(prev)):
                fail(f"witnessed[{i}] does not follow witnessed[{i - 1}]")
            if _cmp_instant(w["witnessed_at"], prev["witnessed_at"]) < 0:
                fail(f"witnessed[{i}] is witnessed before witnessed[{i - 1}]")
            if int(w["tree_size"]) < int(prev["tree_size"]):
                fail(f"witnessed[{i}] has a smaller tree than witnessed[{i - 1}]")
            if w["tree_size"] == prev["tree_size"] and w["root_hash"] != prev["root_hash"]:
                fail(f"witnessed[{i}] and witnessed[{i - 1}] name one size with different roots")
        if int(w["tree_size"]) > size:
            fail(f"witnessed[{i}] is larger than the head")

    # 5. Each witnessed head is a prefix of the head.
    sizes = {int(w["tree_size"]) for w in ws}
    cons = bundle["consistency"]
    for j, c in enumerate(cons):
        if not isinstance(c, Mapping) or not _is_int(c.get("old_size")) or c["old_size"] not in sizes:
            fail(f"consistency[{j}] does not start at a witnessed head")
    for i, w in enumerate(ws):
        ws_size = int(w["tree_size"])
        if ws_size == size:
            if w["root_hash"] != root:
                fail(f"witnessed[{i}] and the head name one size with different roots")
            continue
        c = next((c for c in cons if c["old_size"] == ws_size), None)
        if c is None:
            incomplete.append(f"no consistency proof from witnessed[{i}] to the head")
            continue
        if c.get("old_root") != w["root_hash"] or not _is_int(c.get("new_size")) or c["new_size"] != size \
                or c.get("new_root") != root:
            fail(f"the consistency proof for witnessed[{i}] does not join it to the head")
        if not verify_consistency_proof(c).valid:
            fail(f"the consistency proof for witnessed[{i}] does not verify")

    # 6. Records: each verifies, is in the head, and its claimed time agrees with the witnessed heads.
    recs = bundle["records"]
    for i, item in enumerate(recs):
        if not isinstance(item, Mapping) or set(item.keys()) != {"kind", "record", "proof"}:
            fail(f"records[{i}] must be an object with kind, record and proof")
        kind = item["kind"]
        if not isinstance(kind, str) or kind not in ("action", "use", "checkpoint"):
            fail(f"records[{i}].kind must be action, use or checkpoint")
        rec = item["record"]
        why = check_record_of_kind(kind, rec, pinned)
        if why is not None:
            fail(f"records[{i}]: {why}")
        p = item["proof"]
        if (not isinstance(p, Mapping) or not _is_int(p.get("tree_size")) or p["tree_size"] != size
                or p.get("root_hash") != root):
            fail(f"records[{i}].proof does not target the head")
        if p.get("leaf_hash") != record_leaf(kind, rec).hex():
            fail(f"records[{i}].proof is for a different leaf")
        if not verify_inclusion_proof(p).valid:
            fail(f"records[{i}].proof does not verify")
        index = p["leaf_index"]
        claimed = rec["timestamp"]
        k = next((k for k, w in enumerate(ws) if int(w["tree_size"]) > index), None)
        if k is None:
            incomplete.append(f"records[{i}] is not yet in a witnessed head")
            continue
        w_inc = ws[k]
        if _cmp_instant(claimed, w_inc["witnessed_at"]) > 0:
            fail(f"records[{i}] claims a time after a witnessed head that already contains it")
        if k > 0:
            w_prev = ws[k - 1]
            if _later_than(w_prev["witnessed_at"], claimed, tol):
                fail(f"records[{i}] claims {claimed}, and the head witnessed at {w_prev['witnessed_at']} "
                     f"does not contain it: logged more than {tol} seconds late")
        elif _later_than(w_inc["witnessed_at"], claimed, tol):
            incomplete.append(f"records[{i}]: the first witnessed head is more than {tol} seconds after its "
                              "claimed time, so how late it was logged cannot be bounded")

    # 7. Empty.
    if not recs:
        incomplete.append("the bundle carries no record")

    if incomplete:
        return ChainResult(INCOMPLETE, incomplete[0])
    return ChainResult(PASS, None)
