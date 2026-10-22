# Seal Checkpoint Format, Version 1, and the `complete` Profile

**Status:** DRAFT. Not frozen. The wire format may change before it is frozen; a frozen version will say so here.
**Version:** 1.0-draft
**Last updated:** 2026-10-22
**Sibling specifications:** [ACTION-v1](./ACTION-v1.md) (frozen; unchanged), [USE-v1](./USE-v1.md) (draft),
[EXECUTION-v1](./EXECUTION-v1.md) (draft), [WITNESS-v1](./WITNESS-v1.md) (draft).
**Conformance vectors:** [test-vectors/complete/](../test-vectors/complete/)

---

## 1. Purpose

A CHECKPOINT-v1 record says: **in this hour, organisation X has exactly N ACTION-v1 and USE-v1 records, and these
are their leaf hashes (as one digest); the chain of checkpoints before this one is the one whose hash I name.** The
issuer signs one per organisation per period, empty periods included, and enters each into the public transparency
log.

A bundle of records handed to a reviewer says nothing about what was left out of it. Checkpoints change that for the
party who hands the bundle over: an operator who withholds a record from a reviewer holding the checkpoints leaves a
count that does not add up. This is ISSUER-ADVERSARY class A6 (selective disclosure) closed for that party, not A2.

## 2. Scope and limits

This document covers CHECKPOINT-v1 (sections 4 to 7) and the `complete` profile (section 8), which checks a bundle of
records, the checkpoints covering a review window and, optionally, an executor's log ([EXECUTION-v1](./EXECUTION-v1.md)),
and returns `PASS`, `FAIL` or `INCOMPLETE`. **Missing evidence is never `PASS`.**

What checkpoints do not do, stated plainly:

- **They do not stop the issuer omitting a record.** An issuer that never signs a decision also never counts it. The
  executor log (section 8, step 7) narrows this to: an action that reached a cooperating executor, and that the
  issuer then left out, is visible. A refusal that never reached the executor is not. ISSUER-ADVERSARY A2 stays open.
- **They count ACTION-v1 and USE-v1 records only.** ATTESTATION-v1 receipts are not counted by this version.
- **A chain starts when checkpoints are switched on.** Records before the first checkpoint are not covered.
- **The issuer's time.** A checkpoint's `timestamp` is the issuer's; [WITNESS-v1](./WITNESS-v1.md) is how a reviewer
  holds the issuer to it (a checkpoint is a log leaf like any record, so a late checkpoint is detectable as one).

## 3. Terminology

- **Period**: the half-open interval [`period_start`, `period_end`). A record is in the period when its own
  `timestamp`, compared as an exact instant (GRANT-v1 section 6.1), is at or after `period_start` and before
  `period_end`.
- **Counted record**: an ACTION-v1 or USE-v1 record of the organisation whose `timestamp` is in the period.
- **Leaf hash**: the RFC 6962 leaf hash of a record's log entry (section 6).

## 4. Record Structure

A flat JSON object with exactly these twelve members, every one a string:

| Member | Meaning |
|---|---|
| `v` | `"checkpoint-1"` |
| `org_id` | the organisation, as in its ACTION-v1 records; non-empty |
| `checkpoint_seq` | canonical ASCII decimal, from `"1"`, one more than the previous checkpoint's |
| `prev_checkpoint_hash` | `""` when `checkpoint_seq` is `"1"`; otherwise 64 lowercase hex: SHA-256 of the previous checkpoint's canonical bytes without `signature` |
| `period_start`, `period_end` | RFC 3339 with an explicit offset; `period_start` before `period_end`; a checkpoint's `period_start` equals the previous one's `period_end` as an instant |
| `record_count` | canonical ASCII decimal: the number of counted records |
| `total_count` | canonical ASCII decimal: the previous checkpoint's `total_count` plus `record_count`; equal to `record_count` for sequence 1 |
| `records_hash` | 64 lowercase hex: SHA-256 over the 32-byte leaf hashes of the counted records, sorted ascending bytewise and concatenated. For no records, SHA-256 of the empty string |
| `timestamp` | when the checkpoint was issued; RFC 3339 with an explicit offset; not before `period_end` |
| `public_key` | the issuer key, base64url without padding |
| `signature` | Ed25519 over the canonical payload, base64url without padding |

The digest is over a sorted set, not over log order, so it does not depend on the order in which records committed.

## 5. Issuance (normative for an issuer)

1. One chain per organisation. Every period after the first is issued, including periods with no record.
2. A checkpoint is issued only after its period has closed, and after a settle interval long enough for every record
   stamped inside the period to have committed (the reference gateway waits two minutes). A record stamped in a
   period that commits after the period's checkpoint is a defect: it will never be counted, and an honest bundle
   containing it does not verify.
3. Issuance is idempotent and safe under concurrency: the pair (`org_id`, `checkpoint_seq`) is unique.
4. Each checkpoint is entered into the public log (section 6) from the same sequence as every other leaf.

## 6. Canonical payload, signing and log entry

The canonical payload and signature are those of ACTION-v1 section 5 (sorted member names by UTF-16 code unit, no
insignificant whitespace, UTF-8, Ed25519 over those bytes, strict base64url).

Public log entry, under entry tag `0x04` (receipts `0x00`, anchors `0x01`, ACTION-v1 `0x02`, USE-v1 `0x03`):

    0x04 || uint64be(len(payload)) || payload || utf8(signature)

where `payload` is the canonical payload. ACTION-v1 and USE-v1 entries have the same shape under `0x02` and `0x03`.
The leaf hash is `SHA-256(0x00 || entry)`.

## 7. Verification of one CHECKPOINT-v1 record

In this order; the first failure is the reason:

1. An object; every member of section 4 present; no other member (the first unknown one by UTF-16 order is named).
2. `v` is `"checkpoint-1"`; every member a string; `org_id` non-empty.
3. `checkpoint_seq` canonical decimal of at least 1; `prev_checkpoint_hash` empty exactly for sequence 1, else 64
   lowercase hex.
4. `period_start`, `period_end`, `timestamp` RFC 3339 with an offset; `period_end` after `period_start`;
   `timestamp` not before `period_end`.
5. `record_count`, `total_count` canonical decimal; `total_count` at least `record_count`, and equal to it for
   sequence 1; `records_hash` 64 lowercase hex, and the hash of nothing when `record_count` is `"0"`.
6. `public_key` equals the pinned issuer key; the signature verifies.

## 8. The `complete` Profile

Explicit opt-in only (`--profile complete`, or a direct call). Never inferred from a bundle's shape.

### 8.1 Inputs

- the pinned issuer key (required);
- the review window `review_from`, `review_to`, RFC 3339 with an offset, `review_from` before `review_to`, chosen by
  the reviewer, never by the party handing over the bundle;
- optionally, the executor keys the reviewer designates.

### 8.2 Bundle

    {"v": "complete-1", "org_id": "...", "checkpoints": [...], "records": [{"kind": "action"|"use", "record": {...}}],
     "executions": [...]}

No other member. Checkpoints in chain order; executor entries in log order.

### 8.3 Checks, in order

First FAIL wins; INCOMPLETE reasons are collected and the first is reported only if nothing fails.

1. Inputs as in 8.1, else FAIL.
2. The bundle's shape, else FAIL.
3. Each checkpoint verifies (section 7) and names the bundle's organisation; each after the first follows its
   predecessor: sequence plus one, previous hash, contiguous period, running total. Else FAIL.
4. Coverage: no checkpoint, or checkpoints that do not reach from `review_from` to `review_to`: INCOMPLETE.
5. Each record verifies under the pinned key as its kind (ACTION-v1 or USE-v1), names the organisation, and appears
   once (else FAIL). A record in no checkpoint's period: INCOMPLETE.
6. Per checkpoint: more records in its period than it counts: FAIL. Fewer: INCOMPLETE (records withheld). Equal, and
   the sorted digest differs: FAIL.
7. Executor entries ([EXECUTION-v1](./EXECUTION-v1.md)): each verifies under its own key, names the organisation,
   comes from one executor, and follows its predecessor (sequence, previous hash), else FAIL. No executor key set:
   INCOMPLETE; a key outside the set: FAIL. An entry outside the checkpointed span: INCOMPLETE. Every entry that
   names an action or USE leaf must find that record in the bundle, with the same `action_id`, `use_id` and
   `args_hash`, else FAIL. An EXECUTED entry must name an ALLOWED action and a USE for that action, and no action may
   be executed twice, else FAIL.

### 8.4 What the verdicts establish

`PASS`: every record the issuer counted in the window is in the bundle, none is added, and every Seal record the
designated executor acted on or refused is among them. It does not establish that the issuer recorded every decision
(section 2).

## 9. Reference implementations

`packages/verify-receipt-py/src/aqta_verify_receipt/complete.py` and `packages/verify-receipt/src/complete.ts`. The
two must return the same verdict and reason on the same bytes; `scripts/e79-interop-sweep.mjs` runs every vector and
a mutation set through both.

## 10. Change log

- 2026-10-22: first draft.
