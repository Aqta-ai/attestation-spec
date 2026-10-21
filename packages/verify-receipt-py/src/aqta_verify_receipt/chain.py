"""
The `chain` profile (spec/USE-v1.md section 9), GRANT-v1 (spec/GRANT-v1.md) and
USE-v1 (spec/USE-v1.md). DRAFT: both record formats are drafts, not frozen.

Three verdicts, never two: PASS, FAIL, INCOMPLETE. Missing evidence is never a
pass. The check order and every reason string are a cross-implementation
contract with the TypeScript verifier (src/chain.ts): first FAIL wins, and the
two must return the same verdict and reason on the same bytes.

Explicit opt-in only. Nothing here is reached by inspecting the input's shape.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .verifier import (
    _HEX64,
    _RFC3339_OFFSET,
    _b64url_decode,
    _canonical,
    _canonical_bytes,
    _utf16_order,
    verify_action_record,
)

PASS, FAIL, INCOMPLETE = "PASS", "FAIL", "INCOMPLETE"

GRANT_FIELDS = (
    "v", "grant_id", "intent_ref", "org_id", "approver", "signing_mode", "scope_tool", "scope_resource",
    "scope_environment", "max_uses", "not_before", "not_after", "require_args", "public_key", "signature",
)
GRANT_OPTIONAL = ("scope_args", "agent_key_id")
USE_FIELDS = (
    "v", "use_id", "org_id", "action_id", "args_hash", "grant_id", "grant_hash", "approver_public_key",
    "consumption_key", "use_index", "max_uses", "timestamp", "public_key", "signature",
)
BUNDLE_MEMBERS = ("v", "grants", "uses", "actions")

_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$", re.ASCII)
_DECIMAL_POSITIVE = re.compile(r"^[1-9][0-9]*$", re.ASCII)
_ARG_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$", re.ASCII)
_KEY_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$", re.ASCII)
_UNBINDABLE = frozenset({"aqta_grant", "aqta_grant_id", "aqta_grant_hash"})
_TS = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:[Zz]|([+-])(\d{2}):(\d{2}))$", re.ASCII
)


@dataclass
class ChainResult:
    verdict: str
    reason: Optional[str] = None


class _Fail(Exception):
    pass


def _first_unknown(obj: Mapping, allowed) -> Optional[str]:
    unknown = [str(k) for k in obj.keys() if k not in allowed]
    return _utf16_order(unknown)[0] if unknown else None


def _signature_ok(payload: Mapping, signature: Any, public_key: Any) -> Optional[str]:
    """None when the Ed25519 signature verifies; otherwise the reason."""
    try:
        canonical = _canonical_bytes(payload)
    except (ValueError, TypeError, OverflowError, UnicodeEncodeError):
        return "record is not canonicalisable"
    try:
        sig = _b64url_decode(signature)
        pub = _b64url_decode(public_key)
    except Exception:
        return "signature decode error: not base64url"
    if len(sig) != 64:
        return "signature length != 64 bytes"
    if len(pub) != 32:
        return "public key length != 32 bytes"
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, canonical)
    except InvalidSignature:
        return "signature check failed"
    except Exception:
        return "signature check failed"
    return None


def _is_key(value: Any) -> bool:
    try:
        return len(_b64url_decode(value)) == 32
    except Exception:
        return False


# --- Times: exact instants without a date library (spec/GRANT-v1.md section 6.1) -----------------------------


def _days_from_civil(y: int, m: int, d: int) -> int:
    y -= 1 if m <= 2 else 0
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _instant(ts: str):
    m = _TS.fullmatch(ts)
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    secs = _days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s
    if m.group(8):
        off = int(m.group(9)) * 3600 + int(m.group(10)) * 60
        secs -= off if m.group(8) == "+" else -off
    return secs, (m.group(7) or "")


def _cmp_instant(a: str, b: str) -> int:
    (sa, fa), (sb, fb) = _instant(a), _instant(b)
    if sa != sb:
        return -1 if sa < sb else 1
    n = max(len(fa), len(fb))
    fa, fb = fa.ljust(n, "0"), fb.ljust(n, "0")
    return 0 if fa == fb else (-1 if fa < fb else 1)


def _dec_le(a: str, b: str) -> bool:
    """a <= b for canonical decimal strings, compared without integer parsing."""
    if len(a) != len(b):
        return len(a) < len(b)
    return a <= b


# --- GRANT-v1 (spec/GRANT-v1.md section 7.1) -------------------------------------------------------------------


def check_grant_record(grant: Any) -> Optional[str]:
    """Integrity of one grant. None when it holds, else the reason. Says nothing about authority."""
    if not isinstance(grant, Mapping):
        return "grant must be an object"
    for f in GRANT_FIELDS:
        if f not in grant:
            return f"missing required field: {f}"
    unknown = _first_unknown(grant, set(GRANT_FIELDS) | set(GRANT_OPTIONAL))
    if unknown is not None:
        return f"unknown top-level field: {unknown}"
    if not isinstance(grant["v"], str) or grant["v"] != "grant-1":
        return "v must be the string 'grant-1'"
    for f in GRANT_FIELDS + GRANT_OPTIONAL:
        if f not in grant:
            continue
        if f in ("require_args", "scope_args"):
            if not isinstance(grant[f], list):
                return f"{f} must be an array"
        elif not isinstance(grant[f], str):
            return f"{f} must be a string"
    if grant["signing_mode"] != "approver-signed":
        return "signing_mode must be 'approver-signed'"
    for f in ("grant_id", "org_id", "approver", "scope_tool"):
        if grant[f] == "":
            return f"{f} must be a non-empty string"
    if grant["max_uses"] != "" and not _DECIMAL.fullmatch(grant["max_uses"]):
        return "max_uses must be '' or a canonical decimal string"
    if grant["not_before"] != "" and not _RFC3339_OFFSET.fullmatch(grant["not_before"]):
        return "not_before must be '' or an RFC 3339 datetime with an explicit offset"
    if not _RFC3339_OFFSET.fullmatch(grant["not_after"]):
        return "not_after must be an RFC 3339 datetime with an explicit offset"
    if not all(isinstance(x, str) for x in grant["require_args"]):
        return "require_args must contain only strings"
    if list(grant["require_args"]) != _utf16_order(grant["require_args"]):
        return "require_args must be in lexicographic order"
    if "scope_args" in grant:
        entries = grant["scope_args"]
        if not entries:
            return "scope_args must be a non-empty list of name=value strings"
        names = set()
        for e in entries:
            if not isinstance(e, str) or "=" not in e:
                return "scope_args entries must be name=value strings"
            name, _, value = e.partition("=")
            if not _ARG_NAME.fullmatch(name) or name in _UNBINDABLE or value == "":
                return "scope_args entry has an invalid name or an empty value"
            if name in names:
                return f"scope_args names {name} twice"
            names.add(name)
        if list(entries) != _utf16_order(entries):
            return "scope_args must be sorted"
    if "agent_key_id" in grant and not _KEY_ID.fullmatch(grant["agent_key_id"]):
        return "agent_key_id must be an API key id"
    why = _signature_ok({k: v for k, v in grant.items() if k != "signature"}, grant["signature"], grant["public_key"])
    return why


def grant_hash(grant: Mapping) -> str:
    return hashlib.sha256(_canonical_bytes({k: v for k, v in grant.items() if k != "signature"})).hexdigest()


# --- USE-v1 (spec/USE-v1.md section 7) -------------------------------------------------------------------------


def check_use_record(use: Any, trusted_public_key: Optional[str]) -> Optional[str]:
    if not isinstance(use, Mapping):
        return "use must be an object"
    for f in USE_FIELDS:
        if f not in use:
            return f"missing required field: {f}"
    unknown = _first_unknown(use, set(USE_FIELDS))
    if unknown is not None:
        return f"unknown top-level field: {unknown}"
    if not isinstance(use["v"], str) or use["v"] != "use-1":
        return "v must be the string 'use-1'"
    for f in USE_FIELDS:
        if not isinstance(use[f], str):
            return f"{f} must be a string"
    for f in ("use_id", "org_id", "action_id", "grant_id", "consumption_key"):
        if use[f] == "":
            return f"{f} must be a non-empty string"
    for f in ("args_hash", "grant_hash"):
        if not _HEX64.fullmatch(use[f]):
            return f"{f} must be 64 lowercase hex characters"
    if not _is_key(use["approver_public_key"]):
        return "approver_public_key must be a base64url Ed25519 key"
    if not _DECIMAL_POSITIVE.fullmatch(use["use_index"]):
        return "use_index must be a canonical decimal string of at least 1"
    if not _DECIMAL.fullmatch(use["max_uses"]):
        return "max_uses must be a canonical decimal string"
    if not _RFC3339_OFFSET.fullmatch(use["timestamp"]):
        return "timestamp must be an RFC 3339 datetime with an explicit offset"
    if trusted_public_key is None:
        return "trusted_public_key required"
    if use["public_key"] != trusted_public_key:
        return "public_key does not match trusted key"
    return _signature_ok({k: v for k, v in use.items() if k != "signature"}, use["signature"], use["public_key"])


# --- Scope (spec/GRANT-v1.md section 6) ------------------------------------------------------------------------


def _matches(pattern: str, value: str) -> bool:
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def _scope_reason(grant: Mapping, record: Mapping, args: Mapping) -> Optional[str]:
    if grant["org_id"] != record["org_id"]:
        return "the grant was issued for a different organisation"
    if not _matches(grant["scope_tool"], record["tool"]):
        return "the tool is outside the grant's scope_tool"
    res = grant["scope_resource"]
    if res != "":
        declared = [k for k in ("device_id", "resource") if k in args and args[k] is not None and args[k] != ""]
        if not declared:
            return "the action declares no resource and the grant names one"
        for k in declared:
            if not isinstance(args[k], str) or args[k] != res:
                return f"the action's {k} is not the grant's resource"
    env = grant["scope_environment"]
    if env != "":
        if not isinstance(args.get("environment"), str) or args.get("environment") != env:
            return "the action's environment is not the grant's"
    for entry in grant.get("scope_args", []):
        name, _, value = entry.partition("=")
        if not isinstance(args.get(name), str) or args.get(name) != value:
            return f"the action does not match the value the grant fixes for {name}"
    for name in grant["require_args"]:
        v = args.get(name)
        if name not in args or v is None or v == "" or v == [] or v == {}:
            return f"the action lacks evidence the grant requires: {name}"
    return None


def _in_window(grant: Mapping, ts: str) -> bool:
    if grant["not_before"] != "" and _cmp_instant(ts, grant["not_before"]) < 0:
        return False
    return _cmp_instant(ts, grant["not_after"]) <= 0


def _ckey(grant: Mapping, org_id: str) -> str:
    if grant["intent_ref"] != "":
        return f"org:{org_id}|intent:{grant['intent_ref']}"
    return f"org:{org_id}|grant:{grant['grant_id']}"


# --- The chain (spec/USE-v1.md section 9.3) --------------------------------------------------------------------


def verify_chain(
    bundle: Any,
    *,
    trusted_public_key: Optional[str] = None,
    approver_keys: Optional[Sequence[str]] = None,
) -> ChainResult:
    """Verify a chain bundle. Never raises. Returns PASS, FAIL or INCOMPLETE with a reason."""
    try:
        return _verify_chain(bundle, trusted_public_key, approver_keys)
    except _Fail as e:
        return ChainResult(FAIL, str(e))
    except Exception:  # never raise: an unexpected input is a failed check, reported
        return ChainResult(FAIL, "verification error")


def _verify_chain(bundle, pinned, approver_keys) -> ChainResult:
    incomplete: List[str] = []

    def fail(reason: str):
        raise _Fail(reason)

    # 1. Inputs.
    if not isinstance(pinned, str) or not _is_key(pinned):
        fail("a pinned issuer key is required")
    if approver_keys is not None:
        if not isinstance(approver_keys, (list, tuple)) or not all(_is_key(k) for k in approver_keys):
            fail("approver_keys must be base64url Ed25519 keys")
        trusted = set(approver_keys)
    else:
        trusted = None

    # 2. Bundle.
    if not isinstance(bundle, Mapping):
        fail("bundle must be an object")
    for m in BUNDLE_MEMBERS:
        if m not in bundle:
            fail(f"bundle missing member: {m}")
    unknown = _first_unknown(bundle, set(BUNDLE_MEMBERS))
    if unknown is not None:
        fail(f"bundle has unknown member: {unknown}")
    if not isinstance(bundle["v"], str) or bundle["v"] != "chain-1":
        fail("bundle v must be the string 'chain-1'")
    for m in ("grants", "uses", "actions"):
        if not isinstance(bundle[m], list):
            fail(f"bundle {m} must be an array")

    # 3. Actions.
    actions = bundle["actions"]
    by_action = {}
    for i, a in enumerate(actions):
        if not isinstance(a, Mapping) or set(a.keys()) != {"record", "args"}:
            fail(f"actions[{i}] must be an object with record and args")
        if not isinstance(a["args"], Mapping):
            fail(f"actions[{i}].args must be an object")
        r = verify_action_record(a["record"], trusted_public_key=pinned)
        if not r.valid:
            # The published ACTION-v1 paths word a canonicalisation failure
            # differently in each language (same verdict). The chain reason is
            # one string in both.
            reason = r.reason or ""
            if reason.startswith("receipt is not canonicalisable"):
                reason = "record is not canonicalisable"
            fail(f"actions[{i}]: {reason}")
        try:
            h = hashlib.sha256(_canonical_bytes(a["args"])).hexdigest()
        except (ValueError, TypeError, OverflowError, UnicodeEncodeError):
            fail(f"actions[{i}].args is not canonicalisable")
        if h != a["record"]["args_hash"]:
            fail(f"actions[{i}].args do not match the record's args_hash")
        aid = a["record"]["action_id"]
        if aid in by_action:
            fail(f"actions[{i}] repeats an action_id")
        by_action[aid] = a

    # 4. Grants.
    by_hash = {}
    for i, g in enumerate(bundle["grants"]):
        why = check_grant_record(g)
        if why is not None:
            fail(f"grants[{i}]: {why}")
        h = grant_hash(g)
        if h in by_hash:
            fail(f"grants[{i}] repeats an earlier grant")
        by_hash[h] = g
    ids = {g["grant_id"] for g in by_hash.values()}

    # 5. Uses.
    uses = bundle["uses"]
    seen_use_ids = set()
    for i, u in enumerate(uses):
        why = check_use_record(u, pinned)
        if why is not None:
            fail(f"uses[{i}]: {why}")
        if u["use_id"] in seen_use_ids:
            fail(f"uses[{i}] repeats a use_id")
        seen_use_ids.add(u["use_id"])

    # 6. Conflicts.
    claims, named = set(), set()
    for i, u in enumerate(uses):
        c = (u["consumption_key"], u["use_index"])
        if c in claims:
            fail(f"uses[{i}] claims a use another USE record already claims")
        claims.add(c)
        if u["action_id"] in named:
            fail(f"uses[{i}] names an action another USE record already names")
        named.add(u["action_id"])

    # 7. Each USE.
    for i, u in enumerate(uses):
        g = by_hash.get(u["grant_hash"])
        if g is None:
            if u["grant_id"] in ids:
                fail(f"uses[{i}].grant_hash does not match the grant presented")
            incomplete.append(f"uses[{i}] names a grant that is not in the bundle")
            continue
        if u["grant_id"] != g["grant_id"]:
            fail(f"uses[{i}].grant_id differs from the grant's")
        if u["org_id"] != g["org_id"]:
            fail(f"uses[{i}].org_id differs from the grant's")
        if u["approver_public_key"] != g["public_key"]:
            fail(f"uses[{i}].approver_public_key differs from the grant's key")
        if u["max_uses"] != g["max_uses"]:
            fail(f"uses[{i}].max_uses differs from the grant's")
        if g["max_uses"] == "":
            fail(f"uses[{i}] consumes a grant with no use limit")
        if not _dec_le(u["use_index"], g["max_uses"]):
            fail(f"uses[{i}] is use {u['use_index']} of {g['max_uses']}")
        if u["consumption_key"] != _ckey(g, u["org_id"]):
            fail(f"uses[{i}].consumption_key is not the key the grant is counted against")
        if not _in_window(g, u["timestamp"]):
            fail(f"uses[{i}] was recorded outside the grant's validity window")
        a = by_action.get(u["action_id"])
        if a is None:
            incomplete.append(f"uses[{i}] names an action that is not in the bundle")
            continue
        rec = a["record"]
        if rec["outcome"] != "ALLOWED":
            fail(f"uses[{i}] names an action that was not ALLOWED")
        if rec["org_id"] != u["org_id"]:
            fail(f"uses[{i}].org_id differs from the action's")
        if rec["args_hash"] != u["args_hash"]:
            fail(f"uses[{i}].args_hash differs from the action's")
        if a["args"].get("aqta_grant_hash") != u["grant_hash"]:
            fail(f"uses[{i}] names an action whose arguments do not reference its grant")

    # 8. Each action that references a grant.
    for i, a in enumerate(actions):
        args, rec = a["args"], a["record"]
        if "aqta_grant_id" not in args and "aqta_grant_hash" not in args:
            continue
        gid, gh = args.get("aqta_grant_id"), args.get("aqta_grant_hash")
        if not isinstance(gid, str) or not isinstance(gh, str):
            fail(f"actions[{i}].args carry a partial grant reference")
        g = by_hash.get(gh)
        if g is None:
            if gid in ids:
                fail(f"actions[{i}] names a grant whose content differs from the grant presented")
            if rec["outcome"] == "ALLOWED":
                incomplete.append(f"actions[{i}] names a grant that is not in the bundle")
            continue
        if gid != g["grant_id"]:
            fail(f"actions[{i}].aqta_grant_id differs from the grant's")
        if rec["outcome"] != "ALLOWED":
            continue
        why = _scope_reason(g, rec, args)
        if why is not None:
            fail(f"actions[{i}] is outside its grant: {why}")
        if trusted is None:
            incomplete.append("no approver key set was supplied")
        elif g["public_key"] not in trusted:
            fail(f"actions[{i}] was authorised by a grant whose key is not a designated approver")
        if g["max_uses"] != "":
            if not any(u["action_id"] == rec["action_id"] for u in uses):
                incomplete.append(f"actions[{i}] consumed a counted grant and its USE record is not in the bundle")
        elif not _in_window(g, rec["timestamp"]):
            fail(f"actions[{i}] is outside its grant's validity window")

    # 9. Empty.
    if not actions:
        incomplete.append("the bundle carries no action")

    if incomplete:
        return ChainResult(INCOMPLETE, incomplete[0])
    return ChainResult(PASS, None)
