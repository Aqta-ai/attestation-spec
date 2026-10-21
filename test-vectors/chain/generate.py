"""
Generate deterministic conformance vectors for the `chain` profile: a GRANT-v1
approval, the USE-v1 records that consumed it, and the ACTION-v1 records they
authorised, checked together (spec/USE-v1.md section 9).

DRAFT. GRANT-v1 and USE-v1 are drafts and not frozen; these vectors move with
them until they are.

Each vector is one JSON file:

    {"approver_keys": [<base64url key>, ...] | null, "bundle": {...}}

and the directory it sits in is the verdict a conformant verifier MUST return
with the vector issuer key below pinned and `approver_keys` supplied as the
relying party's designated approver set (null means none was supplied):

    pass/        PASS
    fail/        FAIL
    incomplete/  INCOMPLETE

Every key here is a throwaway derived from a public seed. Nothing is a
production key.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_spec = importlib.util.spec_from_file_location("action_ref", _REPO_ROOT / "examples" / "reference-action-issuer.py")
_action_ref = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_action_ref)  # type: ignore[union-attr]
_ref = _action_ref._ref
_canonical = _ref._canonical
_b64 = _action_ref._b64url_encode


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"attestation-spec/test-vectors/chain-1/" + label.encode()).digest())


def _pub(sk: Ed25519PrivateKey) -> str:
    return _b64(sk.public_key().public_bytes_raw())


ISSUER = _action_ref.ReferenceActionIssuer(_key("issuer"))
ISSUER_SK = _key("issuer")
FINANCE = _key("approver-finance")
RELEASE = _key("approver-release")
AGENT = _key("agent-own-key")
FORGER = _key("forger")
APPROVERS = [_pub(FINANCE), _pub(RELEASE)]
ORG = "org-vector"

HERE = Path(__file__).resolve().parent


def utf16(values):
    return sorted(values, key=lambda v: v.encode("utf-16-be", "surrogatepass"))


def sign_with(sk: Ed25519PrivateKey, payload: dict, raw: bytes | None = None) -> dict:
    data = raw if raw is not None else _canonical(payload).encode("utf-8")
    return {**payload, "signature": _b64(sk.sign(data))}


# --- GRANT-v1, field for field as the gateway's sign_grant emits it ----------------------------------------------

def grant(sk=FINANCE, *, grant_id="g-pay-1", intent_ref="", org_id=ORG, approver="finance-controller",
          scope_tool="payments.transfer", scope_resource="INV-2291", scope_environment="", max_uses="1",
          not_before="", not_after="2026-10-20T10:17:00+00:00", require_args=(), scope_args=None, agent_key_id="",
          v="grant-1", extra=None, sort=True) -> dict:
    payload = {
        "v": v, "grant_id": grant_id, "intent_ref": intent_ref, "org_id": org_id, "approver": approver,
        "signing_mode": "approver-signed", "scope_tool": scope_tool, "scope_resource": scope_resource,
        "scope_environment": scope_environment, "max_uses": max_uses, "not_before": not_before,
        "not_after": not_after, "require_args": utf16(require_args) if sort else list(require_args),
        "public_key": _pub(sk),
    }
    if scope_args:
        payload["scope_args"] = sorted(f"{k}={v}" for k, v in scope_args.items())
    if agent_key_id:
        payload["agent_key_id"] = agent_key_id
    payload.update(extra or {})
    return sign_with(sk, payload)


def grant_hash(g: dict) -> str:
    return hashlib.sha256(_canonical({k: v for k, v in g.items() if k != "signature"}).encode("utf-8")).hexdigest()


# --- ACTION-v1, with the argument object its args_hash commits to ------------------------------------------------

INVOICE = {"invoice_id": "INV-2291", "amount_minor": "480000", "currency": "EUR", "payee": "Harbour Print Ltd",
           "payee_iban": "IE29AIBK93115212345678", "resource": "INV-2291"}
FIXED = {k: INVOICE[k] for k in ("amount_minor", "currency", "payee_iban")}


def action(n: int, args: dict, g: dict | None, outcome="ALLOWED", *, tool="payments.transfer",
           ts="2026-10-20T10:05:10.000000+00:00", org_id=ORG, signer=None) -> dict:
    bound = dict(args)
    if g is not None:
        bound["aqta_grant_id"] = g["grant_id"]
        bound["aqta_grant_hash"] = grant_hash(g)
    iss = signer or ISSUER
    rec = dict(iss.sign(org_id=org_id, agent="agent", tool=tool, args_hash=_action_ref.args_hash_of(bound),
                        outcome=outcome, policy_applied=["require_grant"], action_id=f"00000000-0000-4000-8000-0000000000{n:02x}",
                        timestamp=ts))
    return {"record": rec, "args": bound}


# --- USE-v1, signed by the boundary in the claim transaction ----------------------------------------------------

def ckey(g: dict, org_id=ORG) -> str:
    return f"org:{org_id}|intent:{g['intent_ref']}" if g["intent_ref"] else f"org:{org_id}|grant:{g['grant_id']}"


def use(n: int, g: dict, act: dict, index: str = "1", *, ts="2026-10-20T10:05:09.950000+00:00", sk=ISSUER_SK,
        **over) -> dict:
    payload = {
        "v": "use-1", "use_id": f"00000000-0000-4000-9000-0000000000{n:02x}", "org_id": ORG,
        "action_id": act["record"]["action_id"], "args_hash": act["record"]["args_hash"],
        "grant_id": g["grant_id"], "grant_hash": grant_hash(g), "approver_public_key": g["public_key"],
        "consumption_key": ckey(g), "use_index": index, "max_uses": g["max_uses"], "timestamp": ts,
        "public_key": _pub(sk),
    }
    payload.update(over)
    return sign_with(sk, payload)


def bundle(grants, uses, actions, **extra) -> dict:
    b = {"v": "chain-1", "grants": list(grants), "uses": list(uses), "actions": list(actions)}
    b.update(extra)
    return b


def resign(rec: dict, sk, **changes) -> dict:
    payload = {k: v for k, v in rec.items() if k != "signature"}
    payload.update(changes)
    return sign_with(sk, payload)


VECTORS: dict[str, list] = {"pass": [], "fail": [], "incomplete": []}


def add(kind: str, name: str, why: str, b: dict, approver_keys=APPROVERS) -> None:
    VECTORS[kind].append((name, why, {"approver_keys": approver_keys, "bundle": b}))


def build() -> None:
    G1 = grant(scope_args=FIXED, intent_ref="pay-INV-2291")
    A1 = action(1, INVOICE, G1)
    U1 = use(1, G1, A1)
    honest = bundle([G1], [U1], [A1])

    # ---- PASS ---------------------------------------------------------------------------------------------------
    add("pass", "001-single-use", "V1: a single-use grant, one USE, one ALLOWED action.", honest)

    G3 = grant(grant_id="g-batch-3", max_uses="3", scope_resource="", scope_tool="reports.send",
               not_after="2026-10-20T18:00:00+00:00")
    acts3 = [action(10 + i, {"report": f"R-{i}"}, G3, tool="reports.send", ts=f"2026-10-20T11:0{i}:00+00:00")
             for i in (1, 2, 3)]
    uses3 = [use(10 + i, G3, a, str(i), ts=f"2026-10-20T11:0{i - 1}:59+00:00") for i, a in zip((1, 2, 3), acts3)]
    add("pass", "002-three-uses", "V2: max_uses \"3\", uses 1, 2 and 3, each bound to its own action.",
        bundle([G3], uses3, acts3))

    Ga = grant(grant_id="g-pay-1a", intent_ref="pay-INV-2291", scope_args=FIXED)
    Gb = grant(grant_id="g-pay-1b", intent_ref="pay-INV-2291", scope_args=FIXED)
    Aa = action(20, INVOICE, Ga, "BLOCKED", ts="2026-10-20T10:04:00+00:00")
    Ab = action(21, INVOICE, Gb)
    Ub = use(21, Gb, Ab)
    add("pass", "003-intent-reissue", "V3: two grants for one intent_ref (a reissue); the first is refused, the "
        "second consumes the one use. The consumption key names the intent, not either grant.",
        bundle([Ga, Gb], [Ub], [Aa, Ab]))

    A_over = action(2, {**INVOICE, "amount_minor": "750000"}, G1, "BLOCKED", ts="2026-10-20T10:07:40+00:00")
    A_replay = action(3, INVOICE, G1, "BLOCKED", ts="2026-10-20T10:09:05+00:00")
    A_none = action(4, {"version": "2026.09.27-rc1"}, None, "BLOCKED", tool="deploy.production",
                    ts="2026-10-20T10:41:30+00:00")
    add("pass", "004-refusals-carry-no-use", "Refused actions, with and without a grant reference, carry no USE "
        "record and need none.", bundle([G1], [U1], [A1, A_over, A_replay, A_none]))

    Gu = grant(grant_id="g-read", max_uses="", scope_tool="ledger.read", scope_resource="")
    Au = action(5, {"ledger": "L-1"}, Gu, tool="ledger.read")
    add("pass", "005-unlimited-grant", "max_uses \"\" (unlimited within the window): an ALLOWED action needs the "
        "grant but no USE, because nothing is counted.", bundle([Gu], [], [Au]))

    Gk = grant(grant_id="g-pay-key", scope_args=FIXED, agent_key_id="key_7f3a", require_args=["approval_ticket"])
    Ak = action(6, {**INVOICE, "approval_ticket": "CHG-1234"}, Gk)
    add("pass", "006-live-grant-shape", "A grant carrying the optional scope_args and agent_key_id members and a "
        "require_args list, as the boundary's sign_grant emits them.", bundle([Gk], [use(6, Gk, Ak)], [Ak]))

    Gn = grant(grant_id="g-pay-nonbmp", intent_ref="pay-\U0001F4B6-INV-2291", scope_args=FIXED)
    An = action(7, INVOICE, Gn)
    add("pass", "007-non-bmp-consumption-key", "intent_ref, and so consumption_key, carries a non-BMP character, "
        "signed as literal UTF-8.", bundle([Gn], [use(7, Gn, An)], [An]))

    Gr = grant(grant_id="g-pay-req", scope_args=FIXED, require_args=["\U0001F600note", "mark"])
    Ar = action(8, {**INVOICE, "\U0001F600note": "x", "mark": "y"}, Gr)
    add("pass", "008-require-args-utf16-order", "require_args holds a non-BMP and a private-use name in UTF-16 "
        "code-unit order, the order a code-point sort reverses.", bundle([Gr], [use(8, Gr, Ar)], [Ar]))

    add("pass", "009-blocked-only-no-approver-set", "Only refusals: nothing was authorised, so no approver set is "
        "needed.", bundle([], [], [A_none]), approver_keys=None)

    # ---- FAIL ---------------------------------------------------------------------------------------------------
    def changed_args(**kv):
        a = copy.deepcopy(A1)
        a["args"].update(kv)
        return a

    add("fail", "001-action-amount-changed", "A1: the disclosed amount differs from what the action record's "
        "args_hash commits to.", bundle([G1], [U1], [changed_args(amount_minor="750000")]))
    add("fail", "002-action-payee-changed", "A1: the disclosed payee IBAN differs.",
        bundle([G1], [U1], [changed_args(payee_iban="IE29AIBK93115299999999")]))
    add("fail", "003-grant-key-swapped", "A2: the grant's public_key is swapped for another designated approver's "
        "key; the signature no longer verifies.", bundle([{**G1, "public_key": _pub(RELEASE)}], [U1], [A1]))
    Gs = grant(AGENT, scope_args=FIXED, intent_ref="pay-INV-2291", grant_id="g-self")
    As = action(9, INVOICE, Gs)
    add("fail", "004-approver-not-designated", "A3: a well-signed grant from a key outside the relying party's "
        "approver set (the agent's own key) authorised an ALLOWED action.", bundle([Gs], [use(9, Gs, As)], [As]))
    G1_2 = {**G1, "max_uses": "2"}
    add("fail", "005-grant-max-uses-edited", "A5: max_uses edited from \"1\" to \"2\" after the approver signed.",
        bundle([G1_2], [U1], [A1]))
    add("fail", "006-use-max-uses-disagrees", "A6: the USE copies max_uses \"2\" against a grant of \"1\".",
        bundle([G1], [use(1, G1, A1, max_uses="2")], [A1]))
    A2nd = action(30, INVOICE, G1, ts="2026-10-20T10:09:05+00:00")
    add("fail", "007-use-index-over-limit", "A7: a second ALLOWED action under a single-use grant, recorded as use "
        "2 of 1.", bundle([G1], [U1, use(30, G1, A2nd, "2", ts="2026-10-20T10:09:04+00:00")], [A1, A2nd]))
    add("fail", "008-duplicate-use-index", "A8: two USE records under one consumption key, both index 1, for "
        "different actions.", bundle([G1], [U1, use(30, G1, A2nd, "1", ts="2026-10-20T10:09:04+00:00")], [A1, A2nd]))
    add("fail", "009-use-version-unknown", "A11: a USE carrying version tag use-2.",
        bundle([G1], [resign(U1, ISSUER_SK, v="use-2")], [A1]))
    G_v2 = grant(scope_args=FIXED, intent_ref="pay-INV-2291", v="grant-2")
    add("fail", "010-grant-version-unknown", "A11: a grant carrying version tag grant-2.",
        bundle([G_v2], [], []))
    add("fail", "011-bundle-version-unknown", "A11: the bundle carries version tag chain-2.",
        {**honest, "v": "chain-2"})
    add("fail", "012-use-field-edited", "A12: the USE's timestamp edited after signing.",
        bundle([G1], [{**U1, "timestamp": "2026-10-20T10:05:08.950000+00:00"}], [A1]))
    add("fail", "013-use-substituted-key", "A13: the USE re-signed by a forger's key that it also embeds; the "
        "relying party pins the published issuer key.", bundle([G1], [use(1, G1, A1, sk=FORGER)], [A1]))
    add("fail", "014-use-args-hash-differs", "A14: the USE's args_hash differs from the action's.",
        bundle([G1], [use(1, G1, A1, args_hash="0" * 64)], [A1]))
    add("fail", "015-use-grant-hash-differs", "A15: the USE's grant_hash is not the canonical hash of the grant "
        "presented.", bundle([G1], [use(1, G1, A1, grant_hash="f" * 64)], [A1]))
    A_over_ok = action(31, {**INVOICE, "amount_minor": "750000"}, G1, ts="2026-10-20T10:07:40+00:00")
    add("fail", "016-value-outside-scope-args", "The issuer recorded ALLOWED for an amount the grant's scope_args "
        "do not fix.", bundle([G1], [use(31, G1, A_over_ok, ts="2026-10-20T10:07:39+00:00")], [A_over_ok]))
    A_res = action(32, {**INVOICE, "invoice_id": "INV-3000", "resource": "INV-3000"}, G1)
    add("fail", "017-resource-outside-scope", "ALLOWED on a resource the grant does not name.",
        bundle([G1], [use(32, G1, A_res)], [A_res]))
    A_tool = action(33, INVOICE, G1, tool="payments.refund")
    add("fail", "018-tool-outside-scope", "ALLOWED for a tool outside the grant's scope_tool.",
        bundle([G1], [use(33, G1, A_tool)], [A_tool]))
    A_late = action(34, INVOICE, G1, ts="2026-10-20T10:17:00.000001+00:00")
    add("fail", "019-use-after-not-after", "The use is recorded one microsecond after not_after. A verifier that "
        "parses timestamps to milliseconds accepts it.",
        bundle([G1], [use(34, G1, A_late, ts="2026-10-20T10:17:00.000001+00:00")], [A_late]))
    add("fail", "020-use-index-zero", "use_index \"0\".", bundle([G1], [use(1, G1, A1, "0")], [A1]))
    add("fail", "021-use-index-leading-zero", "use_index \"01\": number-like but not canonical decimal.",
        bundle([G1], [use(1, G1, A1, "01")], [A1]))
    add("fail", "022-use-index-non-ascii-digit", "use_index in an Arabic-Indic digit, which Python's isdigit and "
        "int() accept.", bundle([G1], [use(1, G1, A1, "١")], [A1]))
    add("fail", "023-use-for-blocked-action", "A USE names a refused action: a refusal consumes nothing.",
        bundle([G1], [use(2, G1, A_over)], [A_over]))
    add("fail", "024-use-approver-key-differs", "The USE's approver_public_key differs from the grant's key.",
        bundle([G1], [use(1, G1, A1, approver_public_key=_pub(RELEASE))], [A1]))
    add("fail", "025-consumption-key-wrong", "The USE counts against the grant id although the grant names an "
        "intent_ref, which would escape the shared budget.",
        bundle([G1], [use(1, G1, A1, consumption_key=f"org:{ORG}|grant:g-pay-1")], [A1]))
    add("fail", "026-use-unknown-field", "A USE carrying one extra signed field.",
        bundle([G1], [use(1, G1, A1, note="x")], [A1]))
    add("fail", "027-use-index-number", "use_index as the JSON number 1, signed. No numeric field exists.",
        bundle([G1], [use(1, G1, A1, 1)], [A1]))
    add("fail", "028-grant-unknown-field", "A grant carrying an unrecognised signed member.",
        bundle([grant(scope_args=FIXED, intent_ref="pay-INV-2291", extra={"scope_amount_max": "500000"})], [], []))
    add("fail", "029-require-args-code-point-order", "require_args sorted by code point, not UTF-16 code unit. "
        "The signature is valid; only the order check rejects it.",
        bundle([grant(require_args=["mark", "\U0001F600note"], sort=False)], [], []))
    U_pad = {**U1, "signature": U1["signature"] + "=="}
    add("fail", "030-use-signature-padded", "Genuine USE signature with base64 padding appended.",
        bundle([G1], [U_pad], [A1]))
    add("fail", "031-use-signature-trailing-newline", "Genuine USE signature with a line feed appended.",
        bundle([G1], [{**U1, "signature": U1["signature"] + "\n"}], [A1]))
    add("fail", "032-grant-signature-trailing-newline", "Genuine grant signature with a line feed appended.",
        bundle([{**G1, "signature": G1["signature"] + "\n"}], [U1], [A1]))
    add("fail", "033-two-uses-one-action", "Two USE records name one action.",
        bundle([G3], [use(40, G3, acts3[0], "1", ts="2026-10-20T11:00:59+00:00"),
                      use(41, G3, acts3[0], "2", ts="2026-10-20T11:00:59+00:00")], [acts3[0]]))
    bad_args = {**INVOICE, "aqta_grant_id": G1["grant_id"], "aqta_grant_hash": "e" * 64}
    A_bad_ref = {"record": dict(ISSUER.sign(org_id=ORG, agent="agent", tool="payments.transfer",
                                            args_hash=_action_ref.args_hash_of(bad_args), outcome="ALLOWED",
                                            policy_applied=["require_grant"],
                                            action_id="00000000-0000-4000-8000-000000000035",
                                            timestamp="2026-10-20T10:05:10.000000+00:00")),
                 "args": bad_args}
    add("fail", "034-action-grant-hash-mismatch", "The action's bound aqta_grant_hash names a grant whose content "
        "differs from the grant presented under that id.", bundle([G1], [], [A_bad_ref]))
    raw = json.dumps({k: v for k, v in use(36, Gn, An).items() if k != "signature"}, sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True).encode()
    U_esc = sign_with(ISSUER_SK, {k: v for k, v in use(36, Gn, An).items() if k != "signature"}, raw=raw)
    add("fail", "035-use-escaped-unicode-signing", "A USE signed over \\uXXXX-escaped bytes; the canonical form is "
        "literal UTF-8, so the signature fails.", bundle([Gn], [U_esc], [An]))
    G_org = grant(scope_args=FIXED, intent_ref="pay-INV-2291", org_id="org-other")
    A_org = action(37, INVOICE, G_org)
    add("fail", "036-grant-for-another-org", "A grant issued for another organisation authorised this "
        "organisation's action.", bundle([G_org], [use(37, G_org, A_org, consumption_key=ckey(G_org))], [A_org]))
    add("fail", "037-use-for-unlimited-grant", "A USE consumes a grant with no use limit.",
        bundle([Gu], [use(38, Gu, Au, "1", max_uses="")], [Au]))
    add("fail", "038-use-timestamp-no-offset", "USE timestamp without an explicit offset.",
        bundle([G1], [use(1, G1, A1, ts="2026-10-20T10:05:09.950000")], [A1]))
    add("fail", "039-grant-not-after-no-offset", "Grant not_after without an explicit offset.",
        bundle([grant(not_after="2026-10-20T10:17:00")], [], []))
    Ge = grant(RELEASE, grant_id="g-dep", scope_tool="deploy.production", scope_resource="2026.09.27-rc1",
               scope_environment="production", approver="release-manager", not_after="2026-10-20T12:35:00+00:00")
    Ae = action(39, {"version": "2026.09.27-rc1", "resource": "2026.09.27-rc1", "environment": "staging"}, Ge,
                tool="deploy.production", ts="2026-10-20T12:24:15+00:00")
    add("fail", "040-environment-outside-scope", "ALLOWED in an environment the grant does not name.",
        bundle([Ge], [use(39, Ge, Ae, ts="2026-10-20T12:24:14+00:00")], [Ae]))
    Aq = action(41, dict(INVOICE), Gk)
    add("fail", "041-required-evidence-missing", "ALLOWED without an argument the grant's require_args demands.",
        bundle([Gk], [use(41, Gk, Aq)], [Aq]))
    add("fail", "042-use-org-differs", "The USE names another organisation.",
        bundle([G1], [use(1, G1, A1, org_id="org-other")], [A1]))
    A_forged = action(42, INVOICE, G1, signer=_action_ref.ReferenceActionIssuer(FORGER))
    add("fail", "043-action-not-under-pinned-key", "The ACTION record is signed by a key other than the pinned "
        "issuer key.", bundle([G1], [use(42, G1, A_forged)], [A_forged]))
    add("fail", "044-bundle-unknown-member", "The bundle carries an unrecognised member.",
        {**honest, "notes": []})
    add("fail", "045-fail-outranks-incomplete", "No approver set is supplied (INCOMPLETE on its own) and a USE "
        "conflicts (FAIL): FAIL wins.", bundle([G1], [U1, use(30, G1, A2nd, "1", ts="2026-10-20T10:09:04+00:00")],
                                                [A1, A2nd]), approver_keys=None)
    U_noref = use(43, G1, action(43, INVOICE, None))
    A_noref = action(43, INVOICE, None)
    add("fail", "046-use-for-action-without-grant-reference", "A USE names an action whose arguments do not "
        "reference the grant.", bundle([G1], [U_noref], [A_noref]))

    # ---- INCOMPLETE ---------------------------------------------------------------------------------------------
    add("incomplete", "001-no-approver-set", "A4: the honest bundle, with no approver set supplied by the relying "
        "party.", honest, approver_keys=None)
    add("incomplete", "002-grant-missing", "A9: the grant is not in the bundle.", bundle([], [U1], [A1]))
    add("incomplete", "003-use-missing", "A10: an ALLOWED action consumed a counted grant and its USE is not in "
        "the bundle.", bundle([G1], [], [A1]))
    add("incomplete", "004-action-missing", "A USE names an action that is not in the bundle.",
        bundle([G1], [U1], []))
    add("incomplete", "005-empty-bundle", "Nothing to check.", bundle([], [], []))
    add("incomplete", "006-use-presented-again", "d1's USE presented again for a second ALLOWED action under the "
        "same grant, with no USE of its own.", bundle([G1], [U1], [A1, A2nd]))


def main() -> None:
    build()
    for kind, items in VECTORS.items():
        d = HERE / kind
        if d.exists():
            shutil.rmtree(d)
        d.mkdir()
        for name, _why, body in items:
            (d / f"{name}.json").write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    rows = []
    for kind, items in VECTORS.items():
        for name, why, _ in items:
            rows.append(f"| {kind}/{name} | {why} |")
    (HERE / "INDEX.md").write_text(
        "# chain vectors: generated index\n\nGenerated by `generate.py`; do not edit by hand.\n\n"
        f"Vector issuer key: `{ISSUER.public_key_b64}`\n\nDesignated approver keys (the default `approver_keys`): "
        f"`{APPROVERS[0]}`, `{APPROVERS[1]}`\n\n| Vector | What it pins |\n|---|---|\n" + "\n".join(rows) + "\n")
    print({k: len(v) for k, v in VECTORS.items()}, "issuer", ISSUER.public_key_b64)


if __name__ == "__main__":
    main()
