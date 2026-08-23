# Seal Acceptance Record Format, Version 1

**Status:** Draft wire format v1.0-draft. Not frozen; bytes may change until the first published verifier release that supports it.
**Version:** 1.0-draft
**Last updated:** 2026-08-23
**Sibling specifications:** [ATTESTATION-v1](./ATTESTATION-v1.md) (model-call decisions) and [ACTION-v1](./ACTION-v1.md) (agent tool actions). This document defines a third record type in the same family: same key, same canonicalisation, same verification model, different subject.
**Reference issuer:** [examples/reference-acceptance-issuer.py](../examples/reference-acceptance-issuer.py)
**Reference verifiers:** `aqta-verify-receipt` (planned v1.2.0; explicit profile opt-in required).

---

## 1. Purpose

ATTESTATION-v1 records what a gateway decided about a model call. ACTION-v1
records what an agent was permitted to do. Both describe a machine.

This document specifies the record for the other half of an accountable
decision: **the moment a person takes responsibility for it.** A responsible
human accepts a machine's recommendation, overrides it, or escalates it, and
that act is bound to the exact machine record it responds to and signed.

A decision is not complete when the model answers. It is complete when
someone accepts, overrides or escalates the answer. Until that act is
evidenced, an evidence pack can show what a system produced and not who
stood behind it.

## 2. Scope

This specification covers:

1. The canonical JSON structure of an acceptance record.
2. Its binding to the subject record it responds to.
3. The canonical byte serialisation used for signing.
4. The Ed25519 signature construction and base64url encoding.
5. Record-level verification by a third party.
6. The provenance of each field (§8). **This section is normative and is the
   most important part of this document,** because an acceptance record is
   the one place where a signature is most likely to be read as proving more
   than it does.

It does not cover:

- **Who the reviewer is.** The record carries the reviewer identifier and
  authority that the caller supplied. It does not establish either. See §8
  and §10.
- Reviewer credentials issued by a third party. A countersignature carrying
  a verifiable credential is a separate mechanism; see §10.
- Whether the accepted decision was correct.

## 3. Terminology

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174).

- **Issuer.** The gateway that produces the record.
- **Subject record.** The ATTESTATION-v1 or ACTION-v1 record being accepted,
  overridden or escalated.
- **Reviewer.** The person the caller says took the decision. A claimant, not
  a verified party.

## 4. Record Structure

A record is a single JSON object with exactly the following top-level fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `v` | string | yes | MUST be the exact string `"accept-1"`. |
| `acceptance_id` | string | yes | UUID v4, unique per record. |
| `org_id` | string | yes | Identifier of the subject organisation. |
| `subject_v` | string | yes | Version tag of the record being responded to: `"1"` for ATTESTATION-v1, `"action-1"` for ACTION-v1. |
| `subject_id` | string | yes | The `attestation_id` or `action_id` of the subject record. |
| `subject_hash` | string | yes | SHA-256 hex digest (64 lowercase hex chars) of the subject record's canonical signed bytes, signature excluded. See §6.1. |
| `decision` | string | yes | One of the values listed in §5. |
| `reason_hash` | string | yes | SHA-256 hex digest of the reviewer's stated reason, UTF-8 encoded. MUST be `""` when no reason was given. The reason text is never in the record. |
| `reviewer_ref` | string | yes | Caller-supplied identifier for the reviewer. Recorded, never verified (§8). |
| `reviewer_authority` | string | yes | Caller-supplied statement of the authority under which the reviewer acted, e.g. `"SME credit, limit EUR 150000"`. Recorded, never verified (§8). MAY be `""`. |
| `policy_applied` | array | yes | Sorted JSON array of policy identifier strings. MAY be empty. |
| `timestamp` | string | yes | ISO 8601 datetime with explicit timezone offset. |
| `public_key` | string | yes | Base64url-encoded raw 32-byte Ed25519 public key of the issuer (no padding). |
| `signature` | string | yes | Base64url-encoded 64-byte Ed25519 signature (no padding). Omitted from the canonical payload (§6). |

Records MUST NOT contain any additional top-level fields in v1. Verifiers
MUST reject records containing unknown top-level fields.

**No numeric fields.** As in ACTION-v1, every field is a string or an array
of strings, which removes the cross-language number-serialisation divergence
class by construction.

**Cross-profile discrimination.** The three profiles are distinguished by the
signed `v` field: integer `1`, string `"action-1"`, string `"accept-1"`. A
conformant verifier for one profile MUST reject a record of another, and MUST
require explicit profile selection rather than inferring one from field shape
(§7).

## 5. Decision Values

`decision` MUST be one of:

| Value | Meaning |
|---|---|
| `ACCEPTED` | The reviewer adopted the machine's outcome as the decision. |
| `OVERRIDDEN` | The reviewer set the decision aside and substituted their own. |
| `ESCALATED` | The reviewer declined to decide and referred it onward. |

A reviewer's verdict on an **evidence pack** (accepted, declined, not enough
to answer) is a different act with a different subject and is not this
record.

## 6. Canonical Payload and Signing

The canonical payload is produced exactly as in ATTESTATION-v1 §6 and
ACTION-v1 §6: remove `signature`, serialise with lexicographically sorted
keys, no whitespace between tokens, UTF-8, and non-ASCII emitted literally
rather than as `\uXXXX` escapes. There is no number-canonicalisation step
because the profile contains no numeric fields.

The signature is the Ed25519 signature (RFC 8032) of the canonical bytes,
base64url-encoded without padding.

### 6.1 Subject binding

`subject_hash` MUST be the SHA-256 of the subject record's **canonical signed
bytes with the `signature` field removed**, that is, exactly the bytes the
issuer signed when it produced the subject record.

Binding by hash and not by identifier alone is the point of this record. An
identifier says which record was nominally accepted; the hash says which
bytes were. A holder given both records can recompute the hash and confirm
that the reviewer accepted the record they now hold, and not a different
version of it.

A verifier that holds the subject record MUST offer to check this binding,
and MUST report it separately from the signature result: a record may carry a
valid signature and a subject hash that does not match the subject supplied,
and those are different failures with different meanings.

## 7. Verification

A verifier performing ACCEPT-v1 verification MUST:

1. Be explicitly invoked for this profile. A verifier MUST NOT select a
   profile by inspecting field shape.
2. Obtain the issuer's public key out of band and pin it, as in
   ATTESTATION-v1 §7.
3. Confirm the record's `public_key` matches the pinned key byte for byte.
4. Decode `signature` from base64url to 64 bytes.
5. Compute the canonical payload bytes (§6).
6. Verify the Ed25519 signature with a constant-time routine.
7. Reject on any failure.

Verifiers SHOULD also check:

- `v` equals `"accept-1"`.
- `decision` is one of the values in §5.
- `subject_v` is `"1"` or `"action-1"`.
- `subject_hash` is 64 lowercase hex characters.
- `reason_hash` is `""` or 64 lowercase hex characters.
- `subject_id` and `reviewer_ref` are non-empty.
- `policy_applied` is sorted and contains only strings.
- `timestamp` is a well-formed ISO 8601 datetime with explicit offset.

## 8. Assertion Provenance (normative)

A signature on this record proves that the issuer produced these exact bytes.
It does not make the reviewer real.

| Field | Provenance | What the signature establishes |
|---|---|---|
| `decision`, `timestamp`, `policy_applied` | **Issuer-attested** | The issuer recorded this decision, against these policies, at this time. |
| `subject_v`, `subject_id`, `subject_hash` | **Issuer-attested binding** | The decision was recorded against a subject record with these exact signed bytes. |
| `reason_hash` | **Issuer-attested commitment** | A reason with this digest was supplied. The text is not in the record and the issuer does not assert the reason is honest or adequate. |
| `reviewer_ref`, `reviewer_authority` | **Caller-asserted, recorded only** | The caller stated that this reviewer, under this authority, took the decision. **The issuer does not verify the reviewer's identity, their existence, their authority, or that a human was involved at all.** |

The last row is the one that matters. An acceptance record establishes that
an acceptance **was recorded**, bound to a specific machine record. It does
not establish **who accepted**. A deployment that needs verified reviewer
identity must add a mechanism that carries it, and must not present this
record as though it already did.

Consumers MUST take this distinction from this table and not from the
presence of a valid signature.

## 9. Example

```json
{
  "v": "accept-1",
  "acceptance_id": "3f1c8a02-64d1-4a77-9b0e-2b7d1f4e5a63",
  "org_id": "org-example",
  "subject_v": "1",
  "subject_id": "a3f2b1c4-9d87-4e6f-b012-34567890abcd",
  "subject_hash": "8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
  "decision": "OVERRIDDEN",
  "reason_hash": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
  "reviewer_ref": "credit-officer c-1f8e",
  "reviewer_authority": "SME credit, limit EUR 150000",
  "policy_applied": ["adverse_action", "affordability_v3"],
  "timestamp": "2026-08-23T09:12:44.108231+00:00",
  "public_key": "9Y3Eiq6V8QjRDUM5nPqSwKIOPQaoEU4SbagfYFdvWa4"
}
```

Read against §8: an issuer holding the key recorded that a decline was
overridden, against a receipt with those exact signed bytes, under the named
policies, with a reason whose digest is committed. It records, without
verifying, that the person who did so was `credit-officer c-1f8e`.

## 10. Non-Goals and Future Extensions

- **Verified reviewer identity.** The natural extension is a
  countersignature from a credential the issuer did not issue, carrying
  attributes the reviewer's own wallet or certificate can prove. That is a
  separate mechanism and a separate document; `reviewer_ref` stays
  caller-asserted regardless of what is added beside it.
- **Reviewer verdicts on evidence packs.** A different act, different
  subject, out of scope (§5).
- **Whether the decision was correct.** Never in scope for any record in this
  family.
- **Omission.** As elsewhere: a record proves what was recorded. It cannot
  prove that no acceptance went unrecorded.

## 11. Security Considerations

ATTESTATION-v1 §10 applies unchanged (key storage, clock skew, replay and
deduplication on `acceptance_id`). Additionally:

- **Reviewer impersonation is not addressed by this record.** An issuer that
  lets a caller name any reviewer will produce records naming any reviewer.
  Authentication of the person is the deployment's responsibility, and the
  record must not be read as evidence that it was performed.
- **Subject substitution.** Checking the signature alone does not confirm the
  record refers to the subject a holder has in hand; the `subject_hash` check
  of §6.1 is what does that, and it MUST be reported separately.

## 12. Change Log

- **1.0-draft (2026-08-23).** Initial draft: 14-field record (thirteen
  canonical fields plus signature), string version tag `"accept-1"`, no
  numeric fields, hash-bound subject, normative assertion-provenance table
  (§8) stating that the reviewer is recorded and never verified.
