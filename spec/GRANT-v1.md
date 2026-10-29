# Seal Grant Record Format, Version 1

**Status:** DRAFT. Not frozen. The wire format may change before it is frozen; a frozen version will say so here.
**Version:** 1.0-draft
**Last updated:** 2026-10-29
**Sibling specifications:** [ACTION-v1](./ACTION-v1.md) (what the boundary allowed or refused), [USE-v1](./USE-v1.md) (which use of a grant an action consumed, and the `chain` profile that checks all three together).
**Conformance vectors:** [test-vectors/chain/](../test-vectors/chain/)

---

## 1. Purpose

A GRANT-v1 record is an approval: a scope that the holder of an approver key permits an agent to act within,
signed by that approver's own key rather than by the boundary that enforces it.

Three records, three assertors:

| Record | Claim | Who signs it |
|---|---|---|
| GRANT-v1 | a scope an authority holder permits | the approver |
| USE-v1 | this action consumed use *i* of *N* of that grant | the boundary (Seal issuer key) |
| ACTION-v1 | this action was ALLOWED or BLOCKED under these policies | the boundary (Seal issuer key) |

The separation is the point. If an approval travelled inside the requester's own declaration, the party
requesting the action would also be asserting its own authority to perform it.

## 2. Scope

This document covers the record structure, canonical bytes, signature, verification of one grant, and the
provenance of each field (section 8, normative). How a grant is matched against an action is in USE-v1 section 9.

It does not cover: how an approver's key is designated as an approver (that is the relying party's trust
policy, section 7.2), revocation (not supported: a signed grant cannot be unsigned; keep `not_after` short), or
a mode where the boundary signs on behalf of an authenticated approver (not defined in this version).

## 3. Terminology

- **Approver**: the holder of the private key that signs the grant.
- **Boundary**: the enforcement point that checks a grant before an action and records the decision.
- **Relying party**: whoever later checks the evidence. It decides which approver keys it trusts.

## 4. Record Structure

A GRANT-v1 record is a flat JSON object. Every member is a string except `require_args` and `scope_args`,
which are arrays of strings. There are no numeric members, by design: numbers are where two languages disagree
about canonical bytes, so `max_uses` is a decimal string.

| Member | Required | Meaning |
|---|---|---|
| `v` | yes | the string `"grant-1"` |
| `grant_id` | yes | non-empty identifier chosen by the signer |
| `intent_ref` | yes | `""`, or a reference naming one authorisation; grants sharing it share one use budget (USE-v1 section 5) |
| `org_id` | yes | non-empty; the organisation the grant is issued for |
| `approver` | yes | non-empty name of the approver. A label only: authority comes from the key (section 8) |
| `signing_mode` | yes | the string `"approver-signed"`. No other mode is defined in this version |
| `scope_tool` | yes | non-empty tool pattern: an exact name, or a prefix ending in a single `*` |
| `scope_resource` | yes | `""` (any), or the resource every resource argument of the action must name (section 6.2) |
| `scope_environment` | yes | `""` (any), or the value the action's `environment` argument must have |
| `max_uses` | yes | `""` (no use limit within the window) or a canonical decimal string: `0`, or a non-zero ASCII digit followed by ASCII digits |
| `not_before` | yes | `""` or an RFC 3339 datetime with an explicit offset |
| `not_after` | yes | an RFC 3339 datetime with an explicit offset. Required: a grant without an expiry is not a grant |
| `require_args` | yes | array of argument names the action must carry with a non-empty value. Sorted by UTF-16 code unit |
| `public_key` | yes | the approver's Ed25519 public key, base64url without padding |
| `signature` | yes | Ed25519 signature over the canonical bytes, base64url without padding |
| `scope_args` | no | non-empty array of `"name=value"` strings fixing exact argument values. Names match `^[A-Za-z0-9_.-]{1,64}$`, are distinct, and are not `aqta_grant`, `aqta_grant_id` or `aqta_grant_hash`; values are non-empty. Sorted. Absent means no values are fixed |
| `agent_key_id` | no | the id of the one API key the grant is issued to, matching `^[A-Za-z0-9_.:-]{1,128}$`. Absent means any key of the organisation |
| `approver_policy_sha256` | no | lowercase hex SHA-256 (64 characters) of the canonical bytes (RFC 8785) of the approver trust policy under which the signer acts as an approver (section 7.2). Absent means the grant names no policy |

Any other member is refused. A boundary that ignored a member it did not recognise would enforce less than the
approver signed.

`scope_args` names are ASCII and distinct, so code-point order and UTF-16 order agree on every valid list.
`require_args` has no such restriction, and its order is UTF-16 code unit, as everywhere in this family.

## 5. Canonical Payload and Signing

As ACTION-v1 section 6: the payload is the record without `signature`; it is serialised as canonical JSON (RFC
8785 member order by UTF-16 code unit, no insignificant whitespace, strings as literal UTF-8, `\uXXXX` only where
JSON requires an escape) and signed with Ed25519. `public_key` is inside the payload.

**Grant hash.** `grant_hash` is the lowercase hex SHA-256 of the same canonical payload (the record without
`signature`). An action binds a grant through its argument object, which carries `aqta_grant_id` and
`aqta_grant_hash`; ACTION-v1's `args_hash` commits to them. ACTION-v1 is frozen and gains no field for this.

## 6. Scope Semantics

A grant authorises an action with tool `t` and argument object `a` (the bound arguments, without the reserved
grant keys mattering) when every one of the following holds, in this order:

1. `org_id` equals the action's `org_id`.
2. `scope_tool` matches `t`: equal, or `scope_tool` ends in `*` and `t` starts with the part before it.
3. **Resource.** If `scope_resource` is not `""`: at least one of `a.device_id`, `a.resource` is present and not
   `""`, and every one of them that is present and not `""` is a string equal to `scope_resource`.
4. **Environment.** If `scope_environment` is not `""`: `a.environment` is a string equal to it.
5. **Fixed values.** For each `name=value` in `scope_args`: `a[name]` is a string equal to `value`, byte for byte.
   A number never matches a fixed string.
6. **Required evidence.** For each name in `require_args`: `a[name]` is present and is not `null`, `""`, `[]` or
   `{}`.
7. **Window.** The time of use `u` satisfies `not_before <= u` (when `not_before` is not `""`) and `u <= not_after`.
   Times are compared as instants, exactly, to every fractional digit written (section 6.1).

`agent_key_id` is enforced by the boundary against the API key the request authenticated with. That key id is
not in any signed record, so a relying party cannot recheck it (section 8).

### 6.1 Comparing times

Both reference verifiers compare RFC 3339 times without a date library: the instant is the whole seconds since
1970-01-01T00:00:00Z, computed from the calendar fields and the offset with integer arithmetic, plus the
fractional digits compared as a decimal fraction. A date library that keeps milliseconds would accept a use one
microsecond after `not_after` (vector `fail/019`).

## 7. Verification

### 7.1 One grant

A verifier checks, in this order, and the first failure is the result:

1. Each required member is present, in the order of the table in section 4.
2. No member outside section 4.
3. `v` is the string `"grant-1"`.
4. `require_args` is an array; `scope_args`, if present, is an array; every other member is a string.
5. `signing_mode` is `"approver-signed"`.
6. `grant_id`, `org_id`, `approver` and `scope_tool` are not `""`.
7. `max_uses` is `""` or canonical decimal.
8. `not_before` is `""` or RFC 3339 with an offset; `not_after` is RFC 3339 with an offset (the ACTION-v1
   timestamp grammar).
9. `require_args` holds only strings, in UTF-16 code-unit order.
10. `scope_args`, if present, is well formed (section 4).
11. `agent_key_id`, if present, is well formed; `approver_policy_sha256`, if present, matches `^[0-9a-f]{64}$`.
12. The payload canonicalises; `signature` and `public_key` are strict base64url (`^[A-Za-z0-9_-]+$`, no padding,
    no line feed); they decode to 64 and 32 bytes; the signature verifies under `public_key`.

Passing 7.1 means only **integrity**: the holder of `public_key` signed these bytes. It says nothing about
authority. Anyone can sign a grant for themselves.

### 7.2 Approver trust policy

Authority is a decision of the relying party, not of the record. In this version the relying party supplies the
set of approver keys it designates, exactly as it pins the issuer key. A grant whose `public_key` is in that set
was "signed by a key you designated". A grant outside it was not. Without a supplied set, a verifier cannot say
which, and the `chain` profile returns `INCOMPLETE` rather than guess (USE-v1 section 9).

A signed, published approver set rooted in an organisation key, with rotation and revocation, is future work and
is not defined here.

**Binding the policy.** When a grant carries `approver_policy_sha256`, the approver has signed which trust policy
it claims to act under. A relying party that holds a policy document computes the SHA-256 of its canonical bytes
and compares. Equal: the grant was signed under the policy the relying party holds. Different: the approver
claims a different policy, and the grant is not treated as designated by the relying party's policy, even if
the key appears in it. The digest does not make a key an approver; only the relying party's own policy does.

## 8. Assertion Provenance (normative)

| Member | Provenance | What the signature establishes |
|---|---|---|
| `scope_tool`, `scope_resource`, `scope_environment`, `scope_args`, `require_args`, `max_uses`, `not_before`, `not_after`, `intent_ref` | **Approver-attested** | The holder of `public_key` permitted this scope, this many uses, in this window. |
| `public_key` | **Key-bound** | Which key signed. Whether that key is an approver is the relying party's trust policy (7.2), never the record's say. |
| `approver` | **Approver-asserted label** | The signer called itself this. It is not verified and confers nothing. |
| `signing_mode` | **Approver-attested** | Which signing mode produced the grant. Only `approver-signed` exists; a grant without it is refused, never downgraded. |
| `grant_id`, `org_id` | **Approver-assigned** | Identifiers the signer chose. |
| `agent_key_id` | **Approver-attested, boundary-enforced** | The approver bound the grant to one API key. Only the boundary can check that binding; a relying party cannot, because no signed record carries the key a request used. |
| `approver_policy_sha256` | **Approver-attested** | The approver signed which trust policy it acts under. A relying party compares it with the policy it holds (7.2); the record cannot make a key an approver. |

## 9. Example

```json
{
  "agent_key_id": "key_7f3a",
  "approver": "finance-controller",
  "grant_id": "g-pay-key",
  "intent_ref": "",
  "max_uses": "1",
  "not_after": "2026-10-20T10:17:00+00:00",
  "not_before": "",
  "org_id": "org-vector",
  "public_key": "<approver key>",
  "require_args": ["approval_ticket"],
  "scope_args": ["amount_minor=480000", "currency=EUR", "payee_iban=IE29AIBK93115212345678"],
  "scope_environment": "",
  "scope_resource": "INV-2291",
  "scope_tool": "payments.transfer",
  "signature": "<signature>",
  "signing_mode": "approver-signed",
  "v": "grant-1"
}
```

The full signed form is `test-vectors/chain/pass/006-live-grant-shape.json`.

## 10. Security Considerations

- **Revocation is not supported.** A short `not_after` is the only bound. A grant leaked before expiry can be
  presented until it expires, subject to `max_uses`.
- **A key in the trust set is trusted completely.** A coerced approver or a stolen approver key produces valid
  grants. The signature names the key holder, not their intent.
- **`intent_ref` is asserted by the approver.** Two genuinely separate authorisations given the same reference
  share one budget. That fails closed.

## 11. Change Log

- 2026-10-21: first draft, matching the boundary's GRANT-v1 records field for field (`grants.py`, including the
  optional `scope_args` and `agent_key_id`).
- 2026-10-29: optional `approver_policy_sha256`, so an approval can name, inside the signed payload, the trust
  policy that designated its approver. Prompted by the approval-record interoperability example built against
  ACTION-v1 section 8.3. Not yet issued by the boundary; aqta-verify-receipt 1.4.0 refuses the member until the
  next release adds it, with conformance vectors for a matching, a mismatching and a malformed digest.
