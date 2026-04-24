# AqtaCore Attestation Receipt Format, Version 1

**Status:** Draft for public review.
**Version:** 1.0
**Last updated:** 2026-04-23
**Reference issuer:** [examples/reference-issuer.py](../examples/reference-issuer.py)
**Reference verifiers:** [`aqta-verify-receipt`](https://pypi.org/project/aqta-verify-receipt/) (PyPI), [`aqta-verify-receipt`](./packages/verify-receipt) (npm).

---

## 1. Purpose

This document specifies the on-the-wire format of **enforcement attestation
receipts** produced by an AI-governance gateway when it decides whether and
how a large-language-model call is permitted. A receipt binds the gateway's
enforcement decision to a specific request under a published public key. Any
third party holding the public key can verify a receipt **without trusting the
issuing gateway's servers**.

The format is intended as a lowest-common-denominator interchange format for
audit-evidence pipelines under the EU AI Act, DORA, SR 11-7, and equivalent
frameworks where a post-hoc log is not sufficient and cryptographic proof of
the enforcement decision is required.

## 2. Scope

This specification covers:

1. The canonical JSON structure of a receipt.
2. The canonical byte serialisation used for signing.
3. The Ed25519 signature construction.
4. The base64url encoding of the signature and public key.
5. Receipt-level verification by a third-party verifier.

It does not cover:

- Chaining of receipts into a tamper-evident log. That is a separate
  extension under development; see §9.
- Zero-knowledge proofs over receipts. A companion document specifies
  Schnorr and Groth16 extensions.
- Transport (HTTP, Kafka, S3 export). Receipts are transport-agnostic.

## 3. Terminology

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174).

- **Issuer.** The governance gateway that produces a receipt.
- **Subject.** The organisation (`org_id`) on whose behalf enforcement ran.
- **Verifier.** Any party that checks a receipt's signature against the
  issuer's published public key.

## 4. Receipt Structure

A receipt is a single JSON object with exactly the following top-level fields:

| Field                | Type    | Required | Description |
|----------------------|---------|----------|-------------|
| `v`                  | integer | yes      | Receipt format version. MUST be `1` for this specification. |
| `attestation_id`     | string  | yes      | UUID v4, unique per receipt. |
| `trace_id`           | string  | yes      | Issuer-assigned identifier for the underlying LLM call. |
| `org_id`             | string  | yes      | Identifier of the subject organisation. |
| `request_hash`       | string  | yes      | SHA-256 hex digest of the canonicalised request body. 64 lowercase hex chars. |
| `model`              | string  | yes      | Provider-qualified model identifier, e.g. `gpt-4o`, `claude-3-5-sonnet`. |
| `outcome`            | string  | yes      | One of the values listed in §5. |
| `policy_applied`     | array   | yes      | Sorted JSON array of ASCII policy identifiers, e.g. `["budget_guard","loop_guard"]`. MUST be sorted lexicographically. |
| `cost_prevented_eur` | number  | yes      | Non-negative decimal, 6 digits of precision. `0` if not applicable. |
| `timestamp`          | string  | yes      | ISO 8601 datetime with explicit timezone offset (`Z` for UTC). |
| `public_key`         | string  | yes      | Base64url-encoded raw 32-byte Ed25519 public key of the issuer (no padding). |
| `signature`          | string  | yes      | Base64url-encoded 64-byte Ed25519 signature (no padding). Omitted from the canonical payload (§6). |

Receipts MUST NOT contain any additional top-level fields in v1. Verifiers
MUST reject receipts containing unknown top-level fields.

## 5. Outcome Values

`outcome` MUST be one of:

| Value        | Meaning |
|--------------|---------|
| `ALLOWED`    | Enforcement passed all policies; request proceeded to the provider. |
| `BLOCKED`    | Enforcement blocked the request before invoking the provider. |
| `SUPPRESSED` | Enforcement detected a runaway condition (e.g. loop) and suppressed the call. |
| `PASSED`     | Synonym of `ALLOWED` retained for backward compatibility; new issuers SHOULD emit `ALLOWED`. |

## 6. Canonical Payload and Signing

The canonical payload is produced by:

1. Removing the `signature` field (if present).
2. Serialising the remaining fields to JSON with:
   - All object keys sorted lexicographically.
   - No whitespace between tokens (`","` and `":"` separators).
   - UTF-8 encoding of the resulting string to bytes.
3. **Number canonicalisation:** integer-valued numbers MUST serialise without
   a decimal point or trailing zeros. Issuers that internally represent a
   numeric field as a float MUST coerce integer-valued floats to an integer
   representation before serialising. This ensures the canonical bytes are
   identical across Python (where `json.dumps(0.0)` yields `"0.0"` by
   default) and JavaScript (where `JSON.stringify(0)` yields `"0"`). The
   reference issuer in `examples/reference-issuer.py` performs this coercion.

Expressed in Python (reference implementation):

```python
# Coerce integer-valued floats to int before canonicalisation
cost = round(cost_prevented_eur, 6)
if cost == int(cost):
    cost = int(cost)

canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

Expressed in JavaScript (reference):

```js
// JavaScript's JSON.stringify already canonicalises integer numbers to "0",
// and values like 0.5 to "0.5". The verifier re-sorts keys to match.
const canonical = new TextEncoder().encode(
  JSON.stringify(payload, Object.keys(payload).sort())
);
```

The signature is the Ed25519 signature (RFC 8032) of the canonical bytes
using the issuer's private key. The resulting 64-byte signature is
base64url-encoded without padding and placed in the `signature` field.

Interoperability of this rule is verified by
[`scripts/make-interop-fixture.mjs`](../scripts/make-interop-fixture.mjs)
which produces a receipt from the Python issuer and verifies it through the
TypeScript verifier. Any specification change that breaks that script MUST
bump the receipt `v` version.

## 7. Verification

A verifier performing receipt verification MUST:

1. Retrieve the issuer's trusted public key out of band. The reference issuer
   publishes its public key at `https://app.aqta.ai/security/pubkey.txt`. A
   verifier MAY pin the key or compare against a published key list.
2. Confirm that the `public_key` field in the receipt matches the trusted
   public key byte for byte. (The receipt is self-declaring; pinning prevents
   substitution of the issuer's identity.)
3. Decode the `signature` field from base64url to 64 bytes.
4. Compute the canonical payload bytes (§6).
5. Verify the Ed25519 signature against the canonical payload using the
   public key. A constant-time verification routine MUST be used.
6. Reject the receipt if any of the above steps fail.

Verifiers SHOULD also perform the following semantic checks, though they are
outside the cryptographic verification contract:

- `v` equals `1`.
- `outcome` is one of the values listed in §5.
- `request_hash` is 64 lowercase hex characters.
- `policy_applied` is sorted.
- `timestamp` is a well-formed ISO 8601 datetime within a reasonable clock
  skew of the current time if the receipt is being verified live.

## 8. Example

Canonical payload (pretty-printed for documentation; actual signing uses the
compact canonical form of §6):

```json
{
  "v": 1,
  "attestation_id": "a3f2b1c4-9d87-4e6f-b012-34567890abcd",
  "trace_id": "trace-2026-04-23-abc123",
  "org_id": "org-acme-bank",
  "request_hash": "8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
  "model": "gpt-4o",
  "outcome": "ALLOWED",
  "policy_applied": ["budget_guard", "loop_guard"],
  "cost_prevented_eur": 0.0,
  "timestamp": "2026-04-23T10:15:30.123456+00:00",
  "public_key": "gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE"
}
```

Signed receipt (same payload with signature appended):

```json
{
  "v": 1,
  "attestation_id": "a3f2b1c4-9d87-4e6f-b012-34567890abcd",
  "trace_id": "trace-2026-04-23-abc123",
  "org_id": "org-acme-bank",
  "request_hash": "8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
  "model": "gpt-4o",
  "outcome": "ALLOWED",
  "policy_applied": ["budget_guard", "loop_guard"],
  "cost_prevented_eur": 0.0,
  "timestamp": "2026-04-23T10:15:30.123456+00:00",
  "public_key": "gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE",
  "signature": "<64-byte Ed25519 sig, base64url, no padding>"
}
```

## 9. Non-Goals and Future Extensions

- **Receipt chaining.** v1 receipts are independent, signed individually.
  A v2 extension will add `prev_attestation_id` and a chained hash so any
  modification of a historical receipt is detectable. Implementers SHOULD
  design their storage layer with this in mind.
- **Zero-knowledge extensions.** A separate specification covers attaching a
  Schnorr (BN254 G1) proof of knowledge of the enforcement decision or a
  Groth16 proof that the decision was taken over a hidden input.
- **Selective disclosure.** A future extension may allow redacting fields
  while preserving signature validity, via a hash-committed substructure.

## 10. Security Considerations

- **Private-key storage.** The issuer's private key MUST be held in a secure
  environment. The reference implementation loads it from an environment
  variable sourced from AWS Secrets Manager or equivalent. Compromise of the
  private key invalidates every subsequent receipt.
- **Clock skew.** `timestamp` is self-attested by the issuer. Verifiers
  concerned with freshness MUST cross-reference against a trusted time
  source.
- **Replay.** Receipts are intentionally self-contained and replay-safe for
  their specific `(attestation_id, trace_id)`. Consumers SHOULD deduplicate
  on `attestation_id` when ingesting receipt streams.
- **Public-key rotation.** Issuers MAY rotate their public key. Rotation
  publishes a new key file and MUST preserve prior keys for verification of
  historical receipts. A key history file format is under development.

## 11. Reference Implementations

| Language | Package | Source |
|----------|---------|--------|
| Python (verify) | `aqta-verify-receipt` (PyPI) | [packages/verify-receipt-py](../packages/verify-receipt-py) |
| TypeScript / Node (verify) | `aqta-verify-receipt` (npm, pending publish) | [packages/verify-receipt](../packages/verify-receipt) |
| Python (minimal reference issuer) | stand-alone example | [examples/reference-issuer.py](../examples/reference-issuer.py) |

A conformant production issuer additionally manages the private signing key
in a secure enclave, enforces policy before signing, and persists receipts
to a tamper-evident log. The [AqtaCore](https://app.aqta.ai) managed service
is the canonical production issuer; the stand-alone reference issuer in
this repository covers only the format requirements of §4–§6.

All reference implementations are licensed under Apache 2.0.

## 12. Change Log

- **v1.0 (2026-04-23):** Initial public specification.

---

This specification is published under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
The reference code is licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).
