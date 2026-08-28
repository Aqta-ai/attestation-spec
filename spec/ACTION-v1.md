# Seal Action Record Format, Version 1

**Status:** Stable wire format v1.0. Frozen with the publication of verifier 1.1.0 (2026-08-22); editorial revisions do not change on-the-wire bytes.
**Version:** 1.0
**Last updated:** 2026-08-22
**Sibling specification:** [ATTESTATION-v1](./ATTESTATION-v1.md) (model-call enforcement receipts). This document defines a second record type in the same family: same key, same canonicalisation discipline, same verification model, different subject.
**Reference issuer:** [examples/reference-action-issuer.py](../examples/reference-action-issuer.py)
**Reference verifiers:** [`aqta-verify-receipt`](https://pypi.org/project/aqta-verify-receipt/) on PyPI and npm (**v1.1.0+**; explicit profile opt-in required).

---

## 1. Purpose

This document specifies the on-the-wire format of **action authorisation
records** produced by an enforcement gateway when an AI agent proposes an
action, a tool call, a workflow step, or any operation that changes external
state, and the gateway decides whether that action is permitted under the
subject organisation's policy. A record binds the authorisation decision to a
specific proposed action under a published public key. Any third party holding
the public key can verify a record **without trusting the issuing gateway's
servers**.

ATTESTATION-v1 answers "what did the gateway decide about this model call?".
ACTION-v1 answers "what did the gateway decide this agent was allowed to do?".
As agents move from generating text to taking actions, the second question is
the one a reviewer asks.

## 2. Scope

This specification covers:

1. The canonical JSON structure of an action record.
2. The canonical byte serialisation used for signing.
3. The Ed25519 signature construction.
4. The base64url encoding of the signature and public key.
5. Record-level verification by a third-party verifier.
6. The provenance of each field: which fields the issuer attests and which it
   merely records (§8). This section is normative.

It does not cover:

- Execution results. An ACTION-v1 record proves an authorisation decision. It
  does not prove the action was subsequently executed, or executed with the
  authorised arguments. See §10.
- Chaining of records into a tamper-evident log (records MAY additionally be
  committed as leaves of an RFC 6962 log; that binding is outside this
  document).
- Transport. Records are transport-agnostic.

## 3. Terminology

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174).

- **Issuer.** The enforcement gateway that produces a record.
- **Subject.** The organisation (`org_id`) on whose behalf enforcement ran.
- **Agent.** The autonomous or semi-autonomous system whose proposed action is
  the subject of the record. The agent is a claimant, not a trusted party.
- **Verifier.** Any party that checks a record's signature against the
  issuer's published public key.

## 4. Record Structure

A record is a single JSON object with exactly the following top-level fields:

| Field            | Type   | Required | Description |
|------------------|--------|----------|-------------|
| `v`              | string | yes      | Record format version. MUST be the exact string `"action-1"`. |
| `action_id`      | string | yes      | UUID v4, unique per record. |
| `org_id`         | string | yes      | Identifier of the subject organisation. |
| `session_id`     | string | yes      | Issuer-assigned identifier of the agent session the action was proposed in. MUST be `""` when the action was proposed outside a session. |
| `intent_hash`    | string | yes      | SHA-256 hex digest (64 lowercase hex chars) of the session's registered intent text. MUST be `""` when the session has no registered intent or `session_id` is `""`. |
| `agent`          | string | yes      | Caller-asserted identity of the proposing agent, e.g. `claude-code/2.1`. Recorded, not verified; see §8. |
| `tool`           | string | yes      | Namespaced identifier of the proposed action, e.g. `github.merge_pull_request`. Non-empty. |
| `args_hash`      | string | yes      | SHA-256 hex digest (64 lowercase hex chars) of the canonical byte serialisation (§6 rules) of the proposed action's argument object. |
| `outcome`        | string | yes      | One of the values listed in §5. |
| `policy_applied` | array  | yes      | Sorted JSON array of policy identifier strings. MUST be sorted lexicographically. MAY be empty. |
| `timestamp`      | string | yes      | ISO 8601 datetime with explicit timezone offset (`Z` for UTC). |
| `public_key`     | string | yes      | Base64url-encoded raw 32-byte Ed25519 public key of the issuer (no padding). |
| `signature`      | string | yes      | Base64url-encoded 64-byte Ed25519 signature (no padding). Omitted from the canonical payload (§6). |

Records MUST NOT contain any additional top-level fields in v1. Verifiers MUST
reject records containing unknown top-level fields.

**No numeric fields.** Every field in an ACTION-v1 record is a string or an
array of strings. This is deliberate: the cross-language canonicalisation
divergences observed in practice (see ATTESTATION-v1 §6 and the v1.0.8
post-mortem in the changelog) all arose from number serialisation. A profile
with no numbers has no such divergence class.

**Cross-profile discrimination.** ATTESTATION-v1 sets `v` to the JSON integer
`1`; ACTION-v1 sets `v` to the JSON string `"action-1"`. A conformant
ATTESTATION-v1 verifier rejects an ACTION-v1 record (wrong type for `v`, and
unknown fields), and a conformant ACTION-v1 verifier rejects an ATTESTATION-v1
receipt for the same reasons. Confusing the two profiles is therefore a
structural impossibility, not a policy. Verifiers MUST still require explicit
profile selection by the caller (§7) rather than auto-detecting by field
shape.

## 5. Outcome Values

`outcome` MUST be one of:

| Value     | Meaning |
|-----------|---------|
| `ALLOWED` | Every applicable policy permitted the proposed action. |
| `BLOCKED` | At least one policy refused the proposed action before execution. |

There is no `SUPPRESSED` and no execution-result outcome in this profile. The
record attests the authorisation decision only (§10).

## 6. Canonical Payload and Signing

The canonical payload is produced by:

1. Removing the `signature` field (if present).
2. Serialising the remaining fields to JSON with:
   - All object keys sorted lexicographically by UTF-16 code unit (RFC 8785
     section 3.2.3), the order JavaScript's default string sort produces.
     Sorting by Unicode code point disagrees for member names above the
     Basic Multilingual Plane and MUST NOT be used.
   - No whitespace between tokens (`","` and `":"` separators).
   - UTF-8 encoding of the resulting string to bytes.
   - Non-ASCII characters emitted literally as UTF-8, never as `\uXXXX`
     escapes. Only the escapes required by RFC 8259 (quote, backslash,
     control characters) are permitted. The rationale is identical to
     ATTESTATION-v1 §6.1 and is normative here as well.

There is no number-canonicalisation step because the profile contains no
numeric fields (§4). A future minor version that introduces one MUST adopt the
ATTESTATION-v1 §6 integer-coercion rule unchanged.

The same rules apply to the argument object hashed into `args_hash`: the
issuer MUST compute `args_hash` over the canonical byte serialisation of the
argument object (sorted keys, compact separators, literal UTF-8). Two issuers
given the same argument object MUST produce the same `args_hash`.

The signature is the Ed25519 signature (RFC 8032) of the canonical payload
bytes using the issuer's private key, base64url-encoded without padding.

Interoperability MUST be demonstrated before the format is frozen: a fixture
produced by the Python reference issuer MUST verify through the TypeScript
verifier and vice versa, across every vector in `test-vectors/action/`
(see CONFORMANCE.md). Hardcoding a single fixture value does not satisfy this
requirement; the sweep MUST cover every vector.

## 7. Verification

Verification answers "did this issuer sign this record?", not merely "is this
record internally consistent?". A record embeds its own `public_key`;
verifying against the embedded key alone proves only that someone who held
some key signed it.

A verifier performing ACTION-v1 verification MUST:

1. Be explicitly invoked for this profile by its caller (a distinct function,
   subcommand, or flag). A verifier MUST NOT silently select a profile by
   inspecting the input's fields.
2. Obtain the issuer's trusted public key out of band and pin it, exactly as
   ATTESTATION-v1 §7 requires. The reference Seal issuer publishes its key at
   `https://api.aqta.ai/v1/attestation/public-key`. ACTION-v1 records are
   signed with the same issuer key family as ATTESTATION-v1 receipts.
3. Confirm the record's `public_key` matches the pinned key byte for byte.
4. Decode `signature` from base64url to 64 bytes.
5. Compute the canonical payload bytes (§6).
6. Verify the Ed25519 signature with a constant-time routine.
7. Reject on any failure.

An integrity-only mode (embedded key, no pin) MAY be offered under the same
constraints as ATTESTATION-v1 §7: never the default, always labelled
untrusted.

Verifiers SHOULD also perform these semantic checks:

- `v` equals the string `"action-1"`.
- `outcome` is `ALLOWED` or `BLOCKED`.
- `intent_hash` and `args_hash` are `""` (intent only) or 64 lowercase hex
  characters.
- `tool` is non-empty.
- `policy_applied` is sorted and contains only strings.
- `timestamp` is a well-formed ISO 8601 datetime with explicit offset.
- `intent_hash` is `""` whenever `session_id` is `""`.

## 8. Assertion Provenance (normative)

Not every field in a signed record is evidence of the same kind. The signature
proves that the issuer produced these exact bytes; it does not upgrade a
claim the issuer could not check into a fact. Verifiers and downstream
consumers MUST interpret fields according to this table:

| Field | Provenance | What the signature establishes |
|---|---|---|
| `outcome`, `policy_applied` | **Issuer-attested** | The issuer evaluated these policies over the proposed action and reached this outcome. This is the core attestation. |
| `timestamp` | **Issuer-attested (self-clock)** | The issuer's clock read this value. Freshness requires an external time cross-reference. |
| `org_id`, `session_id`, `action_id` | **Issuer-assigned** | Identifiers the issuer controls and binds to the decision. |
| `intent_hash` | **Issuer-attested binding** | The session carried a registered intent with this digest at decision time. The signature does not establish that the proposed action semantically served that intent. |
| `tool`, `args_hash` | **Caller-declared, issuer-observed** | The proposing client declared this action and these arguments to the issuer, and the issuer evaluated policy against exactly this declaration. When the issuer also executes the action (gateway-in-path deployment), the declaration and the execution target coincide; when the issuer only authorises, the caller could execute something else. A record does not distinguish the two deployments. |
| `agent` | **Caller-asserted, recorded only** | The proposing client claimed this identity. The issuer does not verify it. A record with `agent: "claude-code/2.1"` proves the claim was made, not that it was true. |

An issuer MUST NOT populate `agent` from any source it wishes to present as
verified identity; if verified client identity is later supported it will be a
new field in a new minor version with its own provenance row, not a
reinterpretation of this one.

This section is the profile's honest boundary. Consumers who need the
distinction between "the agent claimed X" and "the issuer verified X" MUST
take it from this table, not from the presence of a valid signature.

## 9. Example

Canonical payload (pretty-printed for documentation; signing uses the compact
form of §6):

```json
{
  "v": "action-1",
  "action_id": "7c2e4a91-3b58-4f0d-9a67-12de89f04c3b",
  "org_id": "org-acme-bank",
  "session_id": "sess-2026-08-22-k7m2p",
  "intent_hash": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
  "agent": "claude-code/2.1",
  "tool": "github.merge_pull_request",
  "args_hash": "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
  "outcome": "BLOCKED",
  "policy_applied": ["production_change_review", "require_intent"],
  "timestamp": "2026-08-22T14:03:11.412903+00:00",
  "public_key": "9Y3Eiq6V8QjRDUM5nPqSwKIOPQaoEU4SbagfYFdvWa4"
}
```

The signed record appends `signature` to the same object.

Read against §8, this record proves: an issuer holding the key evaluated the
policies `production_change_review` and `require_intent` over a proposed
`github.merge_pull_request` with these exact argument bytes, in a session
bound to the intent with this digest, and refused it. It records, without
verifying, that the proposer identified itself as `claude-code/2.1`.

## 10. Non-Goals and Future Extensions

- **Execution attestation.** Proving that an ALLOWED action was executed, and
  executed with the authorised arguments, requires the issuer in the
  execution path and is a candidate second record or minor extension. v1
  deliberately attests authorisation only, because that is the claim the
  issuer can always stand behind.
- **Verified agent identity.** See §8. A future extension may bind a client
  credential; `agent` stays caller-asserted forever.
- **Human acceptance records.** The moment a responsible person accepts,
  overrides or escalates a proposed action is a distinct accountability event
  and will be specified as its own record type, not overloaded onto this one.
- **Omission.** As with ATTESTATION-v1, a record proves what was recorded; it
  cannot prove that no action went unrecorded. Deployments where the issuer
  is in the execution path narrow this gap; they do not close it. See
  ISSUER-ADVERSARY.md.

## 11. Security Considerations

The considerations of ATTESTATION-v1 §10 (private-key storage, clock skew,
replay and `action_id` deduplication) apply unchanged. Additionally:

- **Declaration gaming.** In authorise-only deployments a malicious caller can
  declare one action and execute another. The record still proves what was
  authorised, which is what the issuer can attest; consumers MUST NOT read an
  ALLOWED record as proof of what subsequently ran (§8, §10).
- **Argument canonicalisation.** `args_hash` is only cross-checkable if both
  sides canonicalise identically; implementers MUST use the §6 rules for the
  argument object and MUST NOT hash raw request bytes.

## 12. Reference Implementations

- Reference issuer: `examples/reference-action-issuer.py` (planned with the
  first vector generation; shares canonicalisation code with
  `reference-issuer.py`).
- Reference verifiers: `packages/verify-receipt` (TypeScript) and
  `packages/verify-receipt-py` (Python), both gaining an explicit ACTION-v1
  profile in v1.1.0. Conformance vectors live in `test-vectors/action/`.

## 13. Change Log

- **1.0 (2026-08-22).** Format frozen with the publication of
  `aqta-verify-receipt` 1.1.0 on npm and PyPI: both reference verifiers
  agree on all 25 conformance vectors and the cross-implementation interop
  sweep runs clean.
- **1.0-draft (2026-08-22).** Initial draft: 13-field record (twelve
  canonical fields plus signature), string version tag `"action-1"`, no
  numeric fields, normative assertion-provenance table (§8), authorisation
  scope only.
