# Executor Log Entry Format, Version 1

**Status:** DRAFT. Not frozen. The wire format may change before it is frozen; a frozen version will say so here.
**Version:** 1.0-draft
**Last updated:** 2026-10-22
**Sibling specifications:** [ACTION-v1](./ACTION-v1.md), [USE-v1](./USE-v1.md), [CHECKPOINT-v1](./CHECKPOINT-v1.md)
(whose `complete` profile reconciles these entries).
**Conformance vectors:** [test-vectors/complete/](../test-vectors/complete/)

---

## 1. Purpose

An EXECUTION-v1 entry is written and signed by **the system that carries out an action** (a payment rail, a deploy
system), not by Seal. It says: **I executed (or refused) this request, and the Seal records it carried have these leaf
hashes.** Entries are numbered and chained, so the executor's log is append-only in the reviewer's hands.

The issuer that signs a decision record is also the party whose decisions are recorded; it can leave a decision out.
A second log, kept by the party that acted, makes an omission visible when the action reached that party: an entry
naming a Seal record that the issuer's checkpoints do not count. The idea of a receiving service countersigning what
it observed is not new (Sello / Notarized Agents, arXiv 2606.04193, June 2026, among others); this is one concrete
format for it.

## 2. The condition (normative, and the first thing a claim built on this must say)

This works only if the executor cooperates:

1. it refuses any action that lacks a verifying Seal ALLOWED ACTION-v1 record and a USE-v1 record for that action;
2. it writes one entry for every request it executes or refuses, and signs it with its own key;
3. it hands the reviewer its log in full for the period under review.

A real deployment needs the customer's executor to adopt this. A refusal that never reaches the executor leaves no
entry, so an issuer that omits such a refusal is not detected. ISSUER-ADVERSARY A2 is narrowed, not closed.

## 3. Record structure

A flat JSON object with exactly these fourteen members, every one a string:

| Member | Meaning |
|---|---|
| `v` | `"execution-1"` |
| `executor_id` | the executor's name for itself; non-empty |
| `entry_seq` | canonical ASCII decimal from `"1"`, one more than the previous entry's |
| `prev_entry_hash` | `""` for entry 1; otherwise SHA-256 (64 lowercase hex) of the previous entry's canonical bytes without `signature` |
| `org_id` | the organisation the request came from; non-empty |
| `result` | `"EXECUTED"` or `"REFUSED"` |
| `action_id` | the ACTION-v1 record's `action_id`; `""` only for a REFUSED request that carried no record |
| `action_leaf_hash` | 64 lowercase hex: the leaf hash of that ACTION-v1 record (CHECKPOINT-v1 section 6); `""` only when `action_id` is |
| `use_id`, `use_leaf_hash` | the USE-v1 record, likewise; required for EXECUTED |
| `args_hash` | the arguments digest the executor acted on, equal to the record's; `""` permitted only for REFUSED |
| `timestamp` | RFC 3339 with an explicit offset |
| `public_key` | the executor's Ed25519 key, base64url without padding |
| `signature` | Ed25519 over the canonical payload (ACTION-v1 section 5) |

## 4. What the executor checks before acting

The ACTION-v1 record verifies under the pinned Seal issuer key and is ALLOWED; the USE-v1 record verifies under the
same key and names that action and its `args_hash`; the arguments it is asked to apply hash to that `args_hash`; it
has not executed that `action_id` before. Otherwise it refuses, and logs the refusal.

## 5. Canonical payload and signing

As ACTION-v1 section 5: canonical JSON, UTF-8, Ed25519, strict base64url.

## 6. Verification of one entry

In order: an object with exactly the members of section 3; `v` is `"execution-1"`; every member a string;
`executor_id` and `org_id` non-empty; `entry_seq` canonical decimal of at least 1, with `prev_entry_hash` empty
exactly for entry 1 and 64 lowercase hex otherwise; `result` is EXECUTED or REFUSED; for EXECUTED, `action_id` and
`use_id` non-empty and the three hashes 64 lowercase hex; for REFUSED, each hash empty or 64 lowercase hex, and an
identifier empty when its leaf hash is; `timestamp` RFC 3339 with an offset; `public_key` a 32-byte key; the
signature verifies under it. Whether that key is the executor's is the reviewer's designation, checked by the profile.

## 7. Reconciliation

See CHECKPOINT-v1 section 8.3, step 7.

## 8. Change log

- 2026-10-22: first draft.
