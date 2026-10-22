"""
The `complete` profile (spec/CHECKPOINT-v1.md section 8), CHECKPOINT-v1
(spec/CHECKPOINT-v1.md) and EXECUTION-v1 (spec/EXECUTION-v1.md). DRAFT: both
record formats are drafts, not frozen.

A reviewer holding an organisation's signed hourly checkpoints can tell when
records are missing from a bundle (a count or hash mismatch); a reviewer also
holding an executor's signed log can tell when the executor acted on a Seal
record the bundle does not carry. The second needs the executor's cooperation,
and catches only what reached the executor.

Three verdicts, never two: PASS, FAIL, INCOMPLETE. The check order and every
reason string are a cross-implementation contract with the TypeScript verifier
(src/complete.ts): first FAIL wins, and the two must return the same verdict
and reason on the same bytes.

Explicit opt-in only. Nothing here is reached by inspecting the input's shape.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .chain import (
    _DECIMAL,
    _DECIMAL_POSITIVE,
    FAIL,
    INCOMPLETE,
    PASS,
    ChainResult,
    _cmp_instant,
    _Fail,
    _first_unknown,
    _is_key,
    _signature_ok,
    check_use_record,
)
from .transparency import leaf_hash
from .verifier import _HEX64, _RFC3339_OFFSET, _canonical_bytes, verify_action_record

CHECKPOINT_FIELDS = (
    "v", "org_id", "checkpoint_seq", "prev_checkpoint_hash", "period_start", "period_end", "record_count",
    "total_count", "records_hash", "timestamp", "public_key", "signature",
)
EXECUTION_FIELDS = (
    "v", "executor_id", "entry_seq", "prev_entry_hash", "org_id", "result", "action_id", "action_leaf_hash",
    "use_id", "use_leaf_hash", "args_hash", "timestamp", "public_key", "signature",
)
BUNDLE_MEMBERS = ("v", "org_id", "checkpoints", "records", "executions")

# Log entry tags (spec/CHECKPOINT-v1.md section 6): receipts 0x00, anchors
# 0x01, ACTION-v1 0x02, USE-v1 0x03, CHECKPOINT-v1 0x04.
ENTRY_TAGS = {"action": b"\x02", "use": b"\x03", "checkpoint": b"\x04"}
EMPTY_RECORDS_HASH = hashlib.sha256(b"").hexdigest()


# --- Shared: verifying a record of a named kind, and its log leaf -----------------------------------------------


def check_record_of_kind(kind: str, record: Any, pinned: str) -> Optional[str]:
    """None when the record is a well-formed record of `kind` under the pinned issuer key, else the reason."""
    # One wording for a non-object in both languages: the published ACTION-v1
    # paths say "not a mapping" here and "not an object" in TypeScript.
    if not isinstance(record, Mapping):
        return "record must be an object"
    if kind == "action":
        r = verify_action_record(record, trusted_public_key=pinned)
        if r.valid:
            return None
        reason = r.reason or ""
        # The published ACTION-v1 paths word a canonicalisation failure
        # differently in each language (same verdict). Here it is one string.
        if reason.startswith("receipt is not canonicalisable"):
            reason = "record is not canonicalisable"
        return reason
    if kind == "use":
        return check_use_record(record, pinned)
    if kind == "checkpoint":
        return check_checkpoint_record(record, pinned)
    return "unknown record kind"


def record_leaf(kind: str, record: Mapping) -> bytes:
    """RFC 6962 leaf hash of a verified record's log entry:
    tag || uint64be(len(payload)) || payload || signature, payload = the canonical signed bytes."""
    payload = _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    sig = record["signature"].encode("utf-8")
    return leaf_hash(ENTRY_TAGS[kind] + len(payload).to_bytes(8, "big") + payload + sig)


def records_hash(leaves: Sequence[bytes]) -> str:
    """SHA-256 over the 32-byte leaf hashes, sorted ascending bytewise and concatenated."""
    return hashlib.sha256(b"".join(sorted(leaves))).hexdigest()


def _hash_unsigned(record: Mapping) -> str:
    return hashlib.sha256(_canonical_bytes({k: v for k, v in record.items() if k != "signature"})).hexdigest()


def checkpoint_hash(cp: Mapping) -> str:
    return _hash_unsigned(cp)


def execution_hash(entry: Mapping) -> str:
    return _hash_unsigned(entry)


def _strings(obj: Mapping, fields) -> Optional[str]:
    for f in fields:
        if not isinstance(obj[f], str):
            return f"{f} must be a string"
    return None


# --- CHECKPOINT-v1 (spec/CHECKPOINT-v1.md section 7) ------------------------------------------------------------


def check_checkpoint_record(cp: Any, trusted_public_key: Optional[str]) -> Optional[str]:
    if not isinstance(cp, Mapping):
        return "checkpoint must be an object"
    for f in CHECKPOINT_FIELDS:
        if f not in cp:
            return f"missing required field: {f}"
    unknown = _first_unknown(cp, set(CHECKPOINT_FIELDS))
    if unknown is not None:
        return f"unknown top-level field: {unknown}"
    if not isinstance(cp["v"], str) or cp["v"] != "checkpoint-1":
        return "v must be the string 'checkpoint-1'"
    why = _strings(cp, CHECKPOINT_FIELDS)
    if why:
        return why
    if cp["org_id"] == "":
        return "org_id must be a non-empty string"
    if not _DECIMAL_POSITIVE.fullmatch(cp["checkpoint_seq"]):
        return "checkpoint_seq must be a canonical decimal string of at least 1"
    if cp["checkpoint_seq"] == "1":
        if cp["prev_checkpoint_hash"] != "":
            return "prev_checkpoint_hash must be empty for checkpoint_seq 1"
    elif not _HEX64.fullmatch(cp["prev_checkpoint_hash"]):
        return "prev_checkpoint_hash must be 64 lowercase hex characters"
    for f in ("period_start", "period_end", "timestamp"):
        if not _RFC3339_OFFSET.fullmatch(cp[f]):
            return f"{f} must be an RFC 3339 datetime with an explicit offset"
    if _cmp_instant(cp["period_start"], cp["period_end"]) >= 0:
        return "period_end must be after period_start"
    if _cmp_instant(cp["timestamp"], cp["period_end"]) < 0:
        return "timestamp must not be before period_end"
    for f in ("record_count", "total_count"):
        if not _DECIMAL.fullmatch(cp[f]):
            return f"{f} must be a canonical decimal string"
    if int(cp["total_count"]) < int(cp["record_count"]):
        return "total_count must be at least record_count"
    if cp["checkpoint_seq"] == "1" and cp["total_count"] != cp["record_count"]:
        return "total_count must equal record_count for checkpoint_seq 1"
    if not _HEX64.fullmatch(cp["records_hash"]):
        return "records_hash must be 64 lowercase hex characters"
    if cp["record_count"] == "0" and cp["records_hash"] != EMPTY_RECORDS_HASH:
        return "records_hash of an empty period must be the hash of nothing"
    if trusted_public_key is None:
        return "trusted_public_key required"
    if cp["public_key"] != trusted_public_key:
        return "public_key does not match trusted key"
    return _signature_ok({k: v for k, v in cp.items() if k != "signature"}, cp["signature"], cp["public_key"])


# --- EXECUTION-v1 (spec/EXECUTION-v1.md section 6) --------------------------------------------------------------

_LINK_FIELDS = ("action_leaf_hash", "use_leaf_hash", "args_hash")


def check_execution_record(entry: Any) -> Optional[str]:
    """Integrity of one executor log entry under its own embedded key. Says nothing about whether that key is
    a designated executor's."""
    if not isinstance(entry, Mapping):
        return "entry must be an object"
    for f in EXECUTION_FIELDS:
        if f not in entry:
            return f"missing required field: {f}"
    unknown = _first_unknown(entry, set(EXECUTION_FIELDS))
    if unknown is not None:
        return f"unknown top-level field: {unknown}"
    if not isinstance(entry["v"], str) or entry["v"] != "execution-1":
        return "v must be the string 'execution-1'"
    why = _strings(entry, EXECUTION_FIELDS)
    if why:
        return why
    for f in ("executor_id", "org_id"):
        if entry[f] == "":
            return f"{f} must be a non-empty string"
    if not _DECIMAL_POSITIVE.fullmatch(entry["entry_seq"]):
        return "entry_seq must be a canonical decimal string of at least 1"
    if entry["entry_seq"] == "1":
        if entry["prev_entry_hash"] != "":
            return "prev_entry_hash must be empty for entry_seq 1"
    elif not _HEX64.fullmatch(entry["prev_entry_hash"]):
        return "prev_entry_hash must be 64 lowercase hex characters"
    if entry["result"] not in ("EXECUTED", "REFUSED"):
        return "result must be EXECUTED or REFUSED"
    if entry["result"] == "EXECUTED":
        for f in ("action_id", "use_id"):
            if entry[f] == "":
                return f"{f} must be a non-empty string for an EXECUTED entry"
        for f in _LINK_FIELDS:
            if not _HEX64.fullmatch(entry[f]):
                return f"{f} must be 64 lowercase hex characters"
    else:
        for f in _LINK_FIELDS:
            if entry[f] != "" and not _HEX64.fullmatch(entry[f]):
                return f"{f} must be empty or 64 lowercase hex characters"
        if entry["action_leaf_hash"] == "" and entry["action_id"] != "":
            return "action_id must be empty when action_leaf_hash is"
        if entry["use_leaf_hash"] == "" and entry["use_id"] != "":
            return "use_id must be empty when use_leaf_hash is"
    if not _RFC3339_OFFSET.fullmatch(entry["timestamp"]):
        return "timestamp must be an RFC 3339 datetime with an explicit offset"
    if not _is_key(entry["public_key"]):
        return "public_key must be a base64url Ed25519 key"
    return _signature_ok({k: v for k, v in entry.items() if k != "signature"}, entry["signature"], entry["public_key"])


# --- The profile (spec/CHECKPOINT-v1.md section 8) --------------------------------------------------------------


def verify_complete(
    bundle: Any,
    *,
    trusted_public_key: Optional[str] = None,
    review_from: Optional[str] = None,
    review_to: Optional[str] = None,
    executor_keys: Optional[Sequence[str]] = None,
) -> ChainResult:
    """Verify a completeness bundle. Never raises. Returns PASS, FAIL or INCOMPLETE with a reason."""
    try:
        return _verify_complete(bundle, trusted_public_key, review_from, review_to, executor_keys)
    except _Fail as e:
        return ChainResult(FAIL, str(e))
    except Exception:  # never raise: an unexpected input is a failed check, reported
        return ChainResult(FAIL, "verification error")


def _verify_complete(bundle, pinned, review_from, review_to, executor_keys) -> ChainResult:
    incomplete: List[str] = []

    def fail(reason: str):
        raise _Fail(reason)

    # 1. Inputs.
    if not isinstance(pinned, str) or not _is_key(pinned):
        fail("a pinned issuer key is required")
    for w in (review_from, review_to):
        if not isinstance(w, str) or not _RFC3339_OFFSET.fullmatch(w):
            fail("a review window (review_from and review_to, RFC 3339 with an offset) is required")
    if _cmp_instant(review_from, review_to) >= 0:
        fail("review_from must be before review_to")
    if executor_keys is not None:
        if not isinstance(executor_keys, (list, tuple)) or not all(_is_key(k) for k in executor_keys):
            fail("executor_keys must be base64url Ed25519 keys")
        trusted_exec = set(executor_keys)
    else:
        trusted_exec = None

    # 2. Bundle.
    if not isinstance(bundle, Mapping):
        fail("bundle must be an object")
    for m in BUNDLE_MEMBERS:
        if m not in bundle:
            fail(f"bundle missing member: {m}")
    unknown = _first_unknown(bundle, set(BUNDLE_MEMBERS))
    if unknown is not None:
        fail(f"bundle has unknown member: {unknown}")
    if not isinstance(bundle["v"], str) or bundle["v"] != "complete-1":
        fail("bundle v must be the string 'complete-1'")
    org = bundle["org_id"]
    if not isinstance(org, str) or org == "":
        fail("bundle org_id must be a non-empty string")
    for m in ("checkpoints", "records", "executions"):
        if not isinstance(bundle[m], list):
            fail(f"bundle {m} must be an array")

    # 3. Checkpoints: each one, then the chain.
    cps = bundle["checkpoints"]
    for i, cp in enumerate(cps):
        why = check_checkpoint_record(cp, pinned)
        if why is not None:
            fail(f"checkpoints[{i}]: {why}")
        if cp["org_id"] != org:
            fail(f"checkpoints[{i}] is for a different organisation")
        if i > 0:
            prev = cps[i - 1]
            if int(cp["checkpoint_seq"]) != int(prev["checkpoint_seq"]) + 1:
                fail(f"checkpoints[{i}] does not follow checkpoints[{i - 1}] (sequence)")
            if cp["prev_checkpoint_hash"] != checkpoint_hash(prev):
                fail(f"checkpoints[{i}] does not follow checkpoints[{i - 1}] (previous hash)")
            if _cmp_instant(cp["period_start"], prev["period_end"]) != 0:
                fail(f"checkpoints[{i}] does not follow checkpoints[{i - 1}] (period)")
            if int(cp["total_count"]) != int(prev["total_count"]) + int(cp["record_count"]):
                fail(f"checkpoints[{i}] does not follow checkpoints[{i - 1}] (total)")

    # 4. Coverage of the review window.
    if not cps:
        incomplete.append("the bundle carries no checkpoint")
    elif _cmp_instant(cps[0]["period_start"], review_from) > 0 or _cmp_instant(cps[-1]["period_end"], review_to) < 0:
        incomplete.append("the checkpoints do not cover the review window")

    # 5. Records: each verifies, belongs to the organisation, appears once, and falls in a checkpoint's period.
    by_leaf: Dict[bytes, Tuple[str, Mapping]] = {}
    per_cp: List[List[bytes]] = [[] for _ in cps]
    for i, item in enumerate(bundle["records"]):
        if not isinstance(item, Mapping) or set(item.keys()) != {"kind", "record"}:
            fail(f"records[{i}] must be an object with kind and record")
        kind = item["kind"]
        if not isinstance(kind, str) or kind not in ("action", "use"):
            fail(f"records[{i}].kind must be action or use")
        rec = item["record"]
        why = check_record_of_kind(kind, rec, pinned)
        if why is not None:
            fail(f"records[{i}]: {why}")
        if rec["org_id"] != org:
            fail(f"records[{i}] is for a different organisation")
        leaf = record_leaf(kind, rec)
        if leaf in by_leaf:
            fail(f"records[{i}] repeats a record")
        by_leaf[leaf] = (kind, rec)
        slot = None
        for j, cp in enumerate(cps):
            if _cmp_instant(cp["period_start"], rec["timestamp"]) <= 0 and _cmp_instant(rec["timestamp"], cp["period_end"]) < 0:
                slot = j
                break
        if slot is None:
            if cps:
                incomplete.append(f"records[{i}] lies outside every checkpoint in the bundle")
            continue
        per_cp[slot].append(leaf)

    # 6. Each checkpoint against the records the bundle carries for its period.
    for j, cp in enumerate(cps):
        n = len(per_cp[j])
        counted = int(cp["record_count"])
        if n > counted:
            fail(f"checkpoints[{j}] counts {cp['record_count']} records in its period and the bundle carries {n}")
        if n < counted:
            incomplete.append(f"checkpoints[{j}] counts {cp['record_count']} records in its period and the bundle carries {n}")
            continue
        if records_hash(per_cp[j]) != cp["records_hash"]:
            fail(f"the records the bundle carries for checkpoints[{j}] do not match its records_hash")

    # 7. The executor's log, reconciled against the records.
    execs = bundle["executions"]
    executed = set()
    for i, e in enumerate(execs):
        why = check_execution_record(e)
        if why is not None:
            fail(f"executions[{i}]: {why}")
        if e["org_id"] != org:
            fail(f"executions[{i}] is for a different organisation")
        if i > 0:
            first, prev = execs[0], execs[i - 1]
            if e["executor_id"] != first["executor_id"] or e["public_key"] != first["public_key"]:
                fail(f"executions[{i}] is from a different executor")
            if int(e["entry_seq"]) != int(prev["entry_seq"]) + 1 or e["prev_entry_hash"] != execution_hash(prev):
                fail(f"executions[{i}] does not follow executions[{i - 1}]")
        if trusted_exec is None:
            if "no executor key set was supplied" not in incomplete:
                incomplete.append("no executor key set was supplied")
        elif e["public_key"] not in trusted_exec:
            fail(f"executions[{i}] is not signed by a designated executor key")
        if cps and (_cmp_instant(e["timestamp"], cps[0]["period_start"]) < 0
                    or _cmp_instant(e["timestamp"], cps[-1]["period_end"]) >= 0):
            incomplete.append(f"executions[{i}] lies outside the checkpointed span")
        if e["action_leaf_hash"] != "":
            found = by_leaf.get(bytes.fromhex(e["action_leaf_hash"]))
            if found is None:
                fail(f"executions[{i}] names an action record that is not in the bundle")
            kind, rec = found
            if kind != "action":
                fail(f"executions[{i}].action_leaf_hash names a record that is not an action")
            if rec["action_id"] != e["action_id"]:
                fail(f"executions[{i}].action_id differs from the record's")
            if e["args_hash"] != "" and e["args_hash"] != rec["args_hash"]:
                fail(f"executions[{i}].args_hash differs from the record's")
            if e["result"] == "EXECUTED" and rec["outcome"] != "ALLOWED":
                fail(f"executions[{i}] executed an action that was not ALLOWED")
        if e["use_leaf_hash"] != "":
            found = by_leaf.get(bytes.fromhex(e["use_leaf_hash"]))
            if found is None:
                fail(f"executions[{i}] names a USE record that is not in the bundle")
            kind, use = found
            if kind != "use":
                fail(f"executions[{i}].use_leaf_hash names a record that is not a USE")
            if use["use_id"] != e["use_id"]:
                fail(f"executions[{i}].use_id differs from the record's")
            if use["action_id"] != e["action_id"]:
                fail(f"executions[{i}] names a USE record for a different action")
        if e["result"] == "EXECUTED":
            if e["action_id"] in executed:
                fail(f"executions[{i}] executes an action already executed")
            executed.add(e["action_id"])

    if incomplete:
        return ChainResult(INCOMPLETE, incomplete[0])
    return ChainResult(PASS, None)
