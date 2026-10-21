# Seal Use Record Format, Version 1, and the `chain` Profile

**Status:** DRAFT. Not frozen. The wire format may change before it is frozen; a frozen version will say so here.
**Version:** 1.0-draft
**Last updated:** 2026-10-21
**Sibling specifications:** [ACTION-v1](./ACTION-v1.md) (frozen; unchanged by this document), [GRANT-v1](./GRANT-v1.md) (draft).
**Conformance vectors:** [test-vectors/chain/](../test-vectors/chain/)

---

## 1. Purpose

A USE-v1 record says: **action A consumed use *i* of *N* of grant G (content hash H), under consumption key K.**
The boundary signs it with the issuer key in the same database transaction in which it claims that use, and only
when the claim succeeds.

Without it, a single-use approval's consumption is enforced but not evidenced: the boundary refuses a second use,
and nothing signed says which action took the first. With it, a relying party holding a grant, its USE records
and the ACTION-v1 records they name can check, offline and without trusting the boundary's database, that the
approval, the use and the decision bind one action, that the use stayed within the approver's limit, and that no
two records claim the same use.

## 2. Scope

This document covers the USE-v1 record (sections 4 to 8) and the `chain` profile (section 9), which checks a
bundle of GRANT-v1, USE-v1 and ACTION-v1 records together and returns one of three verdicts: `PASS`, `FAIL` or
`INCOMPLETE`. **Missing evidence is never `PASS`.**

It does not cover records that were never issued. A boundary that is bypassed, or an issuer that never records a
decision, leaves nothing to check; that is omission, and it is out of scope here as it is for ACTION-v1.

## 3. Terminology

- **Consumption key**: the budget a use is counted against: `org:<org_id>|intent:<intent_ref>` when the grant
  names an `intent_ref`, else `org:<org_id>|grant:<grant_id>`.
- **Counted grant**: a grant whose `max_uses` is not `""`. Only counted grants have USE records.
- **Bundle**: the evidence a relying party is handed (section 9.1).

## 4. Record Structure

A flat JSON object of exactly fourteen members, every one a string. There are no numeric members: `use_index`
and `max_uses` are canonical decimal strings.

| Member | Meaning |
|---|---|
| `v` | the string `"use-1"` |
| `use_id` | non-empty identifier of this record (a UUID in the reference boundary) |
| `org_id` | non-empty; the organisation, as in the ACTION-v1 record |
| `action_id` | non-empty; the ACTION-v1 record this use authorised |
| `args_hash` | 64 lowercase hex; equal to that record's `args_hash` |
| `grant_id` | non-empty; the grant's `grant_id` |
| `grant_hash` | 64 lowercase hex; the grant's hash (GRANT-v1 section 5) |
| `approver_public_key` | the grant's `public_key`, copied so the chain is checkable without a lookup; strict base64url, 32 bytes |
| `consumption_key` | non-empty; the key the use was counted against, as enforced (section 3) |
| `use_index` | canonical decimal of at least 1: a non-zero ASCII digit followed by ASCII digits |
| `max_uses` | canonical decimal (`0`, or a non-zero ASCII digit followed by ASCII digits), copied from the grant |
| `timestamp` | RFC 3339 with an explicit offset (the ACTION-v1 grammar); the boundary's clock at the claim |
| `public_key` | the issuer key, strict base64url |
| `signature` | Ed25519 over the canonical payload, strict base64url |

Any other member is refused.

## 5. Issuance (normative for a boundary)

1. Policy is evaluated first. A refused action claims nothing and has no USE record.
2. For a counted grant, the boundary claims the next `use_index` under the consumption key with an atomic insert
   under a uniqueness constraint on (consumption key, use index), and in the same transaction writes the signed
   USE record. Either both commit or neither does. A claim that loses a race is retried with the next index and a
   newly signed record, or refused.
3. The `action_id` of the decision is fixed before the claim, so the USE can name it; the ACTION-v1 record is
   signed afterwards under that id.
4. A crash between the claim and the decision leaves a USE for an action whose record may never be signed. The use
   is spent, which is the safe direction; a relying party sees `INCOMPLETE` for that USE (section 9.4), not a pass.
5. The USE record is entered into the public transparency log under its own entry tag, numbered from the same
   sequence as receipts and action records, append-only.

## 6. Canonical Payload and Signing

Exactly as ACTION-v1 section 6: payload without `signature`, RFC 8785 member order by UTF-16 code unit, no
whitespace, literal UTF-8, Ed25519 over those bytes, base64url without padding.

## 7. Verification of One USE Record

In this order; the first failure is the result:

1. Each member of section 4 is present, in table order.
2. No other member.
3. `v` is the string `"use-1"`.
4. Every member is a string.
5. `use_id`, `org_id`, `action_id`, `grant_id`, `consumption_key` are not `""`.
6. `args_hash` and `grant_hash` are 64 lowercase hex.
7. `approver_public_key` is strict base64url decoding to 32 bytes.
8. `use_index` is canonical decimal of at least 1; `max_uses` is canonical decimal.
9. `timestamp` is RFC 3339 with an offset.
10. A pinned issuer key is supplied and `public_key` equals it. There is no embedded-key mode for this profile.
11. The payload canonicalises; `signature` and `public_key` are strict base64url of 64 and 32 bytes; the signature
    verifies.

Patterns are matched against the whole string with ASCII semantics: a trailing line feed or a non-ASCII digit
fails. Decimal strings are compared as numbers by length, then character by character; they are never parsed by
a language's integer conversion, which accepts `"01"`, `" 1"` or non-ASCII digits.

## 8. Assertion Provenance (normative)

| Member | Provenance | What the signature establishes |
|---|---|---|
| `use_index`, `consumption_key` | **Issuer-attested** | The boundary claimed this use under this key, atomically. It does not prove that no other boundary counted the same grant elsewhere. |
| `action_id`, `args_hash` | **Issuer-attested binding** | The use authorised the action with this id and this argument digest. |
| `grant_id`, `grant_hash`, `approver_public_key`, `max_uses` | **Issuer-copied** | Copied from the grant the boundary checked. The grant itself is the approver's evidence; a relying party checks the copy against it (section 9). |
| `timestamp` | **Issuer-attested (self-clock)** | The boundary's clock at the claim. |
| `org_id`, `use_id` | **Issuer-assigned** | Identifiers the boundary controls. |

A compromised issuer key can sign a false USE. The transparency log makes that visible to a monitor; it does not
make it impossible.

## 9. The `chain` Profile

The `chain` profile is explicit opt-in. A verifier MUST NOT select it by inspecting the input. It takes a bundle,
a pinned issuer key (required), and the relying party's designated approver key set (optional).

### 9.1 Bundle

```json
{"v": "chain-1", "grants": [GRANT-v1, ...], "uses": [USE-v1, ...],
 "actions": [{"record": ACTION-v1, "args": {argument object}}, ...]}
```

`args` is the object the ACTION record's `args_hash` commits to, with the grant reference bound in
(`aqta_grant_id`, `aqta_grant_hash`). ACTION-v1 records carry only the hash, so a bundle without the argument
object cannot be checked.

### 9.2 Verdicts

- **PASS**: every check below holds and nothing is missing.
- **FAIL**: any check fails. FAIL outranks INCOMPLETE.
- **INCOMPLETE**: no check failed, but a record the chain needs is absent, or no approver set was supplied for an
  action that a grant authorised. INCOMPLETE is never a pass.

### 9.3 Checks, in order

The first FAIL is the result. INCOMPLETE reasons are collected; if no FAIL occurs, the first one collected is the
result. Indices refer to array positions.

1. **Inputs.** A pinned issuer key is supplied. The approver set, if supplied, is an array of strict base64url
   keys of 32 bytes.
2. **Bundle.** An object with members `v`, `grants`, `uses`, `actions` (checked present in that order) and no
   other; `v` is the string `"chain-1"`; the other three are arrays.
3. **Actions**, each: an object with exactly `record` and `args`; `args` is an object; `record` verifies under
   ACTION-v1 with the pinned issuer key; `args` canonicalises and its SHA-256 equals `record.args_hash`. No two
   actions share an `action_id`.
4. **Grants**, each: verifies under GRANT-v1 section 7.1. No two grants have the same grant hash.
5. **Uses**, each: verifies under section 7 with the pinned issuer key. No two share a `use_id`.
6. **Conflicts.** No two USE records share (`consumption_key`, `use_index`). No two USE records name one
   `action_id`.
7. **Each USE**:
   1. Find the grant whose hash equals `grant_hash`. If none: FAIL if a grant with the same `grant_id` is present
      (its content differs), else INCOMPLETE and skip the rest of this USE.
   2. `grant_id`, `org_id`, `approver_public_key` and `max_uses` equal the grant's `grant_id`, `org_id`,
      `public_key` and `max_uses`. The grant is counted (`max_uses` not `""`). `use_index` is at most `max_uses`.
      `consumption_key` is the one section 3 derives from the grant and `org_id`. `timestamp` lies in the grant's
      window (GRANT-v1 section 6, rule 7).
   3. Find the action named by `action_id`. If none: INCOMPLETE and skip the rest of this USE.
   4. The action's outcome is `ALLOWED`; its `org_id` and `args_hash` equal the USE's; its `args.aqta_grant_hash`
      equals the USE's `grant_hash`.
8. **Each action whose `args` carry `aqta_grant_id` or `aqta_grant_hash`**:
   1. Both are present and are strings.
   2. Find the grant whose hash equals `aqta_grant_hash`. If none: FAIL if a grant with that `grant_id` is present;
      otherwise INCOMPLETE for an `ALLOWED` action, and nothing for a `BLOCKED` one (a refusal needs no grant).
      Skip the rest for this action.
   3. `aqta_grant_id` equals the grant's `grant_id`.
   4. A `BLOCKED` action stops here: a refusal consumed nothing.
   5. The grant authorises the action (GRANT-v1 section 6, rules 1 to 6).
   6. Approver trust: with no approver set supplied, INCOMPLETE; with one supplied, the grant's `public_key` is in
      it.
   7. A counted grant has a USE naming this action, else INCOMPLETE. An uncounted grant's window is checked
      against the action's `timestamp`.
9. **Empty.** A bundle with no actions is INCOMPLETE.

### 9.4 What the verdicts establish

PASS establishes: each authorised action was within a grant signed by a key the relying party designated; the
grant's limit was not exceeded by any USE in the bundle; no two USE records claim one use; and the arguments
disclosed are the ones the decision committed to. It does not establish that the bundle holds every record the
boundary issued: a USE and its ACTION withheld together leave a bundle that is internally complete. That is
omission, and it is not detected by this profile.

## 10. Reference Implementations

`aqta-verify-receipt` (TypeScript and Python), `--profile chain` with `--key` and `--approver-keys`. CLI exit
codes for this profile: 0 PASS, 1 FAIL, 3 INCOMPLETE, 2 usage or input error. The two implementations must return
the same verdict and the same reason on every vector; `scripts/chain-interop-sweep.mjs` enforces it.

## 11. Change Log

- 2026-10-21: first draft.
