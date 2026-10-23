"""
The `policy` profile and POLICY-v1 (spec/POLICY-v1.md). DRAFT: not frozen.

A decision record names the policies it was evaluated under in
`policy_applied`. With policy binding, each entry is `<name>@sha256:<hash>`,
and the hash is the content address of one signed POLICY-v1 statement: which
exact version of the policy the issuer says it evaluated. ACTION-v1 is frozen
and gains no field for this; the binding rides inside the string list it
already signs.

Three verdicts, never two: PASS, FAIL, INCOMPLETE. The check order and every
reason string are a cross-implementation contract with the TypeScript verifier
(src/policy.ts): first FAIL wins, and the two must return the same verdict and
reason on the same bytes.

Explicit opt-in only. Nothing here is reached by inspecting the input's shape.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .chain import (
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
)
from .complete import check_record_of_kind, record_leaf
from .transparency import _MAX_SAFE_SIZE, leaf_hash, verify_inclusion_proof, verify_signed_tree_head
from .verifier import _HEX64, _RFC3339_OFFSET, _canonical_bytes

POLICY_FIELDS = (
    "v", "org_id", "policy_name", "version", "prev_policy_hash", "rules", "policy_hash", "created_at",
    "public_key", "signature",
)
BUNDLE_MEMBERS = ("v", "head", "policies", "decisions")
BODY_TAG = "policy-body-1"
# Log entry tag (spec/POLICY-v1.md section 6): receipts 0x00, anchors 0x01,
# ACTION-v1 0x02, USE-v1 0x03, CHECKPOINT-v1 0x04, POLICY-v1 0x05.
ENTRY_TAG = b"\x05"

_BINDING = re.compile(r"([^@]+)@sha256:([0-9a-f]{64})", re.ASCII)


def policy_body_hash(org_id: str, policy_name: str, rules: str) -> str:
    """The content address of one policy version: SHA-256 over the canonical body (section 5)."""
    return hashlib.sha256(
        _canonical_bytes({"v": BODY_TAG, "org_id": org_id, "policy_name": policy_name, "rules": rules})
    ).hexdigest()


def policy_leaf(statement: Mapping) -> bytes:
    """RFC 6962 leaf hash of a POLICY-v1 log entry: 0x05 || uint64be(len(payload)) || payload || signature."""
    payload = _canonical_bytes({k: v for k, v in statement.items() if k != "signature"})
    sig = statement["signature"].encode("utf-8")
    return leaf_hash(ENTRY_TAG + len(payload).to_bytes(8, "big") + payload + sig)


def parse_binding(entry: str) -> Optional[Tuple[str, str]]:
    """(name, policy_hash) for a well-formed `name@sha256:hash` entry, else None."""
    m = _BINDING.fullmatch(entry)
    return (m.group(1), m.group(2)) if m else None


# --- POLICY-v1 (spec/POLICY-v1.md section 7) --------------------------------------------------------------------


def check_policy_record(st: Any, trusted_public_key: Optional[str]) -> Optional[str]:
    """None when the statement is a well-formed POLICY-v1 statement under the pinned issuer key, else the reason."""
    if not isinstance(st, Mapping):
        return "policy statement must be an object"
    for f in POLICY_FIELDS:
        if f not in st:
            return f"missing required field: {f}"
    unknown = _first_unknown(st, set(POLICY_FIELDS))
    if unknown is not None:
        return f"unknown top-level field: {unknown}"
    if not isinstance(st["v"], str) or st["v"] != "policy-1":
        return "v must be the string 'policy-1'"
    for f in POLICY_FIELDS:
        if not isinstance(st[f], str):
            return f"{f} must be a string"
    for f in ("org_id", "policy_name", "rules"):
        if st[f] == "":
            return f"{f} must be a non-empty string"
    if "@" in st["policy_name"]:
        return "policy_name must not contain '@'"
    if not _DECIMAL_POSITIVE.fullmatch(st["version"]):
        return "version must be a canonical decimal string of at least 1"
    if len(st["version"]) > 16 or int(st["version"]) > _MAX_SAFE_SIZE:
        return "version is too large"
    if st["version"] == "1":
        if st["prev_policy_hash"] != "":
            return "prev_policy_hash must be empty for version 1"
    elif not _HEX64.fullmatch(st["prev_policy_hash"]):
        return "prev_policy_hash must be 64 lowercase hex characters"
    if not _HEX64.fullmatch(st["policy_hash"]):
        return "policy_hash must be 64 lowercase hex characters"
    if not _RFC3339_OFFSET.fullmatch(st["created_at"]):
        return "created_at must be an RFC 3339 datetime with an explicit offset"
    if trusted_public_key is None:
        return "trusted_public_key required"
    if st["public_key"] != trusted_public_key:
        return "public_key does not match trusted key"
    why = _signature_ok({k: v for k, v in st.items() if k != "signature"}, st["signature"], st["public_key"])
    if why is not None:
        return why
    if st["policy_hash"] != policy_body_hash(st["org_id"], st["policy_name"], st["rules"]):
        return "policy_hash does not match the policy body"
    return None


# --- The profile (spec/POLICY-v1.md section 8) ------------------------------------------------------------------


def verify_policy(bundle: Any, *, trusted_public_key: Optional[str] = None) -> ChainResult:
    """Verify a policy-binding bundle. Never raises. Returns PASS, FAIL or INCOMPLETE with a reason."""
    try:
        return _verify_policy(bundle, trusted_public_key)
    except _Fail as e:
        return ChainResult(FAIL, str(e))
    except Exception:  # never raise: an unexpected input is a failed check, reported
        return ChainResult(FAIL, "verification error")


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _verify_policy(bundle, pinned) -> ChainResult:
    incomplete: List[str] = []

    def fail(reason: str):
        raise _Fail(reason)

    # 1. Inputs.
    if not isinstance(pinned, str) or not _is_key(pinned):
        fail("a pinned issuer key is required")

    # 2. Bundle.
    if not isinstance(bundle, Mapping):
        fail("bundle must be an object")
    for m in BUNDLE_MEMBERS:
        if m not in bundle:
            fail(f"bundle missing member: {m}")
    unknown = _first_unknown(bundle, set(BUNDLE_MEMBERS))
    if unknown is not None:
        fail(f"bundle has unknown member: {unknown}")
    if not isinstance(bundle["v"], str) or bundle["v"] != "policy-1":
        fail("bundle v must be the string 'policy-1'")
    for m in ("policies", "decisions"):
        if not isinstance(bundle[m], list):
            fail(f"bundle {m} must be an array")

    # 3. The head, when one is given: a public head the pinned issuer key signed.
    head = bundle["head"]
    if head is not None:
        if not isinstance(head, Mapping) or head.get("log") != "public":
            fail("head must be null or a public tree head")
        if not verify_signed_tree_head(head, pinned).valid:
            fail("head does not verify under the pinned key")

    def check_proof(where: str, proof: Any, leaf: bytes) -> Optional[int]:
        """The leaf index of a verified proof against the head, or None when no proof is given."""
        if proof is None:
            return None
        if head is None:
            fail(f"{where}.proof is given without a head")
        if (not isinstance(proof, Mapping) or not _is_int(proof.get("tree_size"))
                or proof["tree_size"] != head["tree_size"] or proof.get("root_hash") != head["root_hash"]):
            fail(f"{where}.proof does not target the head")
        if proof.get("leaf_hash") != leaf.hex():
            fail(f"{where}.proof is for a different leaf")
        if not verify_inclusion_proof(proof).valid:
            fail(f"{where}.proof does not verify")
        return proof["leaf_index"]

    # 4. Policy statements.
    by_hash: Dict[str, Tuple[Mapping, Optional[int]]] = {}
    versions: Dict[Tuple[str, str, str], str] = {}
    policies = bundle["policies"]
    for i, item in enumerate(policies):
        if not isinstance(item, Mapping) or set(item.keys()) != {"statement", "proof"}:
            fail(f"policies[{i}] must be an object with statement and proof")
        st = item["statement"]
        why = check_policy_record(st, pinned)
        if why is not None:
            fail(f"policies[{i}]: {why}")
        if st["policy_hash"] in by_hash:
            fail(f"policies[{i}] repeats an earlier policy version")
        lineage = (st["org_id"], st["policy_name"], st["version"])
        if lineage in versions:
            fail(f"policies[{i}] forks the version history of its policy")
        versions[lineage] = st["policy_hash"]
        by_hash[st["policy_hash"]] = (st, check_proof(f"policies[{i}]", item["proof"], policy_leaf(st)))
    for i, item in enumerate(policies):
        st = item["statement"]
        prev = by_hash.get(st["prev_policy_hash"])
        if prev is None:
            continue
        p = prev[0]
        if (p["org_id"] != st["org_id"] or p["policy_name"] != st["policy_name"]
                or int(p["version"]) + 1 != int(st["version"])):
            fail(f"policies[{i}] does not follow the version its prev_policy_hash names")
        if _cmp_instant(p["created_at"], st["created_at"]) > 0:
            fail(f"policies[{i}] is created before the version it follows")

    # 5. Decisions.
    decisions = bundle["decisions"]
    seen = set()
    indexed: List[Optional[int]] = []
    for i, item in enumerate(decisions):
        if not isinstance(item, Mapping) or set(item.keys()) != {"record", "proof"}:
            fail(f"decisions[{i}] must be an object with record and proof")
        rec = item["record"]
        why = check_record_of_kind("action", rec, pinned)
        if why is not None:
            fail(f"decisions[{i}]: {why}")
        if rec["action_id"] in seen:
            fail(f"decisions[{i}] repeats an action_id")
        seen.add(rec["action_id"])
        indexed.append(check_proof(f"decisions[{i}]", item["proof"], record_leaf("action", rec)))

    # 6. Each binding.
    for i, item in enumerate(decisions):
        rec = item["record"]
        for j, entry in enumerate(rec["policy_applied"]):
            where = f"decisions[{i}].policy_applied[{j}]"
            if "@" not in entry:
                incomplete.append(f"{where} is not bound to a policy version")
                continue
            parsed = parse_binding(entry)
            if parsed is None:
                fail(f"{where} is not a well-formed binding")
            name, h = parsed
            found = by_hash.get(h)
            if found is None:
                incomplete.append(f"{where} names a policy version that is not in the bundle")
                continue
            st, st_index = found
            if st["policy_name"] != name:
                fail(f"{where} names the version under a different policy name")
            if st["org_id"] != rec["org_id"]:
                fail(f"{where} names a policy version of another organisation")
            if _cmp_instant(st["created_at"], rec["timestamp"]) > 0:
                fail(f"{where} names a policy version created after the decision")
            if st_index is None or indexed[i] is None:
                incomplete.append(f"{where} is not shown to be logged before the decision")
                continue
            if st_index >= indexed[i]:
                fail(f"{where} names a policy version logged after the decision")

    # 7. Empty.
    if not decisions:
        incomplete.append("the bundle carries no decision")

    if incomplete:
        return ChainResult(INCOMPLETE, incomplete[0])
    return ChainResult(PASS, None)
