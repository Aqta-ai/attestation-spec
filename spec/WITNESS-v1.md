# Witness Statement Format, Version 1, and the `witnessed` Profile

**Status:** DRAFT. Not frozen. The wire format may change before it is frozen; a frozen version will say so here.
**Version:** 1.0-draft
**Last updated:** 2026-10-22
**Sibling specifications:** [ACTION-v1](./ACTION-v1.md), [USE-v1](./USE-v1.md), [CHECKPOINT-v1](./CHECKPOINT-v1.md).
**Conformance vectors:** [test-vectors/witnessed/](../test-vectors/witnessed/)

---

## 1. Purpose

A record's `timestamp` is the issuer's own claim. ISSUER-ADVERSARY A3 (backdating) needs a clock the issuer does not
control. A witness fetches the public log's signed head on a schedule (hourly), and a time authority the issuer does
not operate stamps what the witness saw. A WITNESS-v1 statement says: **at `witnessed_at`, the public log signed by
this key had this size and this root.**

From such statements a reviewer can bound how late a record entered the log: if a head witnessed at time W does not
contain a record that claims time T, the record entered the log after W. When W is more than a stated tolerance
after T, the claim is not believable. That is the `witnessed` profile (section 7).

Absence from an *unwitnessed* head still proves nothing: the issuer signs its own heads, and log order is submission
order. The vector `a3-lag-is-not-backdating` (test-vectors/transparency/adversary/) keeps its verdict for
`assess_history`; this profile is a separate, opt-in check that needs witnessed heads.

## 2. Relationship to the production witness, stated plainly

The production witness (seal-log-witness, hourly at :17) records each head and countersigns the head file into
Sigstore with keyless cosign: a Fulcio certificate naming the witness workflow, and Rekor's integrated time. Rekor
signs with ECDSA P-256. This draft defines an Ed25519 statement as a stand-in so both reference verifiers can check
it with what they already carry. **It does not verify real Sigstore bundles.** Binding real Rekor entries (or a
second, Ed25519 statement from a time authority the issuer does not control) is required before any claim about the
production log rests on this profile. The witness's own operator is Aqta; independence comes from the time
authority's log, and from anyone running the witness themselves.

## 3. Terminology

- **Time authority**: the party whose key signs a statement and whose clock `witnessed_at` reads.
- **Witness chain**: statements with one `witness_id`, consecutive `statement_seq`, each naming the previous one's hash.
- **W_inc** for a record: the first statement in the chain whose tree contains the record's leaf. **W_prev**: the
  statement before it.
- **Tolerance**: how late, in whole seconds, an honest record may enter the log after its claimed time. Chosen by
  the reviewer. The reference default is 3600.

## 4. Record structure

A flat JSON object with exactly these twelve members, every one a string:

| Member | Meaning |
|---|---|
| `v` | `"witness-1"` |
| `witness_id` | the witness's name; non-empty |
| `statement_seq` | canonical ASCII decimal from `"1"` |
| `prev_statement_hash` | `""` for statement 1; otherwise SHA-256 (64 lowercase hex) of the previous statement's canonical bytes without `signature` |
| `log_public_key` | the issuer key that signs the witnessed log's heads |
| `tree_size` | canonical ASCII decimal, at least 1, at most 2^53 - 1 |
| `root_hash` | 64 lowercase hex |
| `head_timestamp` | the head's own timestamp, `YYYY-MM-DDTHH:MM:SSZ` |
| `head_signature` | the issuer's signature over the public head (`aqta-sth-public-v1|size|root|timestamp`), base64url |
| `witnessed_at` | the time authority's time, RFC 3339 with an explicit offset |
| `public_key` | the time authority's key |
| `signature` | Ed25519 over the canonical payload (ACTION-v1 section 5) |

## 5. Producing statements (normative for a witness)

Fetch the public head; check its signature under the pinned issuer key and its consistency with the last witnessed
head; then have the time authority stamp it, and publish the statement in sequence. A missed run is a gap in time,
not in the chain: the next statement still follows the last one, and the bound it gives is weaker.

## 6. Verification of one statement

In order: an object with exactly the members of section 4; `v` is `"witness-1"`; every member a string; `witness_id`
non-empty; `statement_seq` canonical decimal of at least 1 with `prev_statement_hash` empty exactly for statement 1;
`log_public_key` a 32-byte key; `tree_size` canonical decimal of at least 1 and at most 2^53 - 1; `root_hash` 64
lowercase hex; `head_timestamp` in the fixed grammar; `head_signature` base64url; `witnessed_at` RFC 3339 with an
offset; `public_key` a 32-byte key; the signature verifies under it.

## 7. The `witnessed` Profile

Explicit opt-in only (`--profile witnessed`, or a direct call).

### 7.1 Inputs

The pinned issuer key (required); the time-authority keys the reviewer designates (absent: INCOMPLETE); the tolerance
in whole seconds (a non-negative integer; default 3600).

### 7.2 Bundle

    {"v": "witnessed-1", "head": <public head>, "witnessed": [<statements in chain order>],
     "consistency": [<RFC 6962 consistency proofs>], "records": [{"kind": "action"|"use"|"checkpoint",
     "record": {...}, "proof": <inclusion proof against head>}]}

### 7.3 Checks, in order

First FAIL wins; INCOMPLETE reasons are collected.

1. Inputs, else FAIL. 2. Bundle shape, else FAIL.
3. `head` is a public head that verifies under the pinned key, else FAIL.
4. Each statement verifies (section 6); witnesses the pinned key; names a head the pinned key signed; is signed by a
   designated key (no set: INCOMPLETE; outside it: FAIL). Each after the first follows its predecessor (same
   `witness_id`, sequence plus one, previous hash), is not witnessed earlier, does not shrink the tree, and does not
   name a different root at the same size. No statement is larger than `head`. Else FAIL.
5. Every consistency proof starts at a witnessed size (else FAIL). For each statement smaller than `head`: no proof
   from its size is INCOMPLETE; a proof that does not join its root to `head`'s, or does not verify, is FAIL. A
   statement at `head`'s size must name `head`'s root.
6. Each record verifies under the pinned key as its kind; its proof targets `head`, is for its leaf, and verifies
   (else FAIL). Then, with T its `timestamp`:
   - no statement contains it: INCOMPLETE;
   - T after W_inc's `witnessed_at`: FAIL (it was in the log before the time it claims);
   - W_prev exists and W_prev's `witnessed_at` is more than the tolerance after T: FAIL (logged too late);
   - W_inc is the first statement and its `witnessed_at` is more than the tolerance after T: INCOMPLETE (nothing
     bounds how late it was logged).
7. No record: INCOMPLETE.

Times are compared as exact instants, to every fractional digit (GRANT-v1 section 6.1); the tolerance is added in
whole seconds.

### 7.4 What the verdicts establish

`PASS`: every record entered the log no more than the tolerance after the last witnessed head before it, by a clock
the issuer does not control. With hourly statements, a record logged more than the tolerance plus one interval after
its claimed time is always caught; one logged within the tolerance never is. It says nothing about records that were
never logged (CHECKPOINT-v1, EXECUTION-v1).

## 8. Reference implementations

`packages/verify-receipt-py/src/aqta_verify_receipt/witnessed.py` and `packages/verify-receipt/src/witnessed.ts`;
`scripts/e79-interop-sweep.mjs` holds them to one verdict and reason.

## 9. Change log

- 2026-10-22: first draft.
