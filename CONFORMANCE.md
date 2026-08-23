# Conformance

This document defines what it means for a third-party implementation to
claim conformance with the Seal record formats:
[ATTESTATION-v1](./spec/ATTESTATION-v1.md) (model-call decisions) and
[ACTION-v1](./spec/ACTION-v1.md) (agent tool actions).

There are two kinds of conformant implementation: **issuers** and
**verifiers**. They have different requirements. Conformance is claimed
**per format**: an implementation may conform to one and not the other, and
MUST say which.

---

## Issuer conformance

An implementation MAY claim issuer conformance if it:

1. Produces receipts whose structure matches
   [`spec/ATTESTATION-v1.md`](./spec/ATTESTATION-v1.md) §4 exactly.
2. Canonicalises the payload for signing per §6, including the integer
   coercion of integer-valued numbers.
3. Signs the canonical bytes with Ed25519 (RFC 8032) using a private
   key whose corresponding public key is published at a stable URL
   that the issuer controls.
4. Supplies the Ed25519 public key, base64url-encoded without padding,
   in the `public_key` field of every issued receipt.
5. Encodes the 64-byte Ed25519 signature as base64url without padding
   in the `signature` field.
6. Passes the [cross-implementation interop script](./scripts/make-interop-fixture.mjs)
   against at least one reference verifier (Python or TypeScript) in
   both directions where applicable.

An issuer MAY implement additional operational behaviour on top of the
format, including policy enforcement, storage, key rotation, receipt
chaining, and zero-knowledge extensions. Those behaviours are out of
scope for ATTESTATION-v1 conformance; v1 defines only the format and
signature on a single receipt.

---

## Verifier conformance

An implementation MAY claim verifier conformance if, given the
[test vectors](./test-vectors/):

- Every receipt in [`test-vectors/valid/`](./test-vectors/valid) returns
  `valid: true` (or the equivalent in the verifier's API surface).
- Every receipt in [`test-vectors/invalid/`](./test-vectors/invalid)
  returns `valid: false`, for the reason documented in
  [`test-vectors/README.md`](./test-vectors/README.md).

The verifier MUST additionally:

1. Use a constant-time Ed25519 verification primitive (do not write
   signature verification by hand).
2. Reject receipts with unknown top-level fields when strict-field
   mode is enabled (spec §4, MUST-level requirement).
3. Verify the Ed25519 signature over the canonical bytes derived per
   §6. Payloads that differ only in key order or number formatting
   must produce the same canonical bytes.
4. Treat `timestamp` parsing as informative, not load-bearing for
   cryptographic verification.
5. Never raise or crash on a malformed receipt; returning
   `valid: false` with a human-readable reason is the expected API
   shape.

A verifier MAY offer optional operational features on top of
conformance, such as public-key pinning, timestamp-freshness checks,
chain-verification hooks, or batch verification. These are additive and
do not affect conformance status.

---

## Declaring conformance

To have your implementation listed as conformant in
[`spec/ATTESTATION-v1.md`](./spec/ATTESTATION-v1.md) §11:

1. Fork [github.com/Aqta-ai/attestation-spec](https://github.com/Aqta-ai/attestation-spec).
2. Add an entry to the Reference Implementations table in the spec,
   with: language/runtime, package name and registry, a link to the
   public source, and a link to a CI run showing your implementation
   passing the full test-vector suite.
3. Open a pull request.
4. A maintainer will review the CI run and the implementation for the
   MUST-level behaviours in §7 of the spec.

Listed implementations must stay current with spec minor-version
updates (for example, v1.1 additions). Implementations that fall
behind may be removed from the list if they no longer pass the
current vector suite.

---

## ACTION-v1 conformance

Everything above applies, with these differences taken from
[`spec/ACTION-v1.md`](./spec/ACTION-v1.md):

1. **Structure and semantics** follow §4, §5 and §7 of that document: the
   fourteen fields, the string version tag `"action-1"`, and outcomes
   `ALLOWED` and `BLOCKED` only. `SUPPRESSED` and `PASSED` are not valid
   here.
2. **No numeric fields exist**, so the integer-coercion rule has nothing to
   act on. A future minor version that introduces one MUST adopt the
   ATTESTATION-v1 §6 rule unchanged.
3. **Profile selection MUST be explicit.** A verifier MUST NOT decide which
   format it is looking at by inspecting field shape. ACTION-v1 records
   carry `signature` and `public_key` exactly as ATTESTATION-v1 receipts do,
   so shape-sniffing cannot distinguish them and any implementation that
   tries will misclassify. The caller names the profile.
4. **A conformant ACTION-v1 verifier MUST reject a valid ATTESTATION-v1
   receipt**, and the reverse. Vector `invalid/007-attestation-v1-receipt.json`
   exists to catch exactly this, and an implementation that accepts it is not
   conformant however well its signature checking works.
5. **Assertion provenance (§8) is normative.** An implementation that
   presents `agent` as verified identity, or presents an `ALLOWED` record as
   proof that the action was subsequently executed, does not conform.
6. **Vectors:** `test-vectors/action/valid` (10) MUST all verify and
   `test-vectors/action/invalid` (15) MUST all fail, under the vector issuer
   key named in that directory's README.
7. **Interop:** the sweep in
   [`scripts/action-interop-sweep.mjs`](./scripts/action-interop-sweep.mjs)
   MUST pass across every vector, not a single fixture. One hardcoded
   fixture value once hid a cross-language float defect for a whole release,
   which is why this is stated as a requirement rather than a suggestion.

---

## Coordinated disclosure for cross-implementation issues

If your implementation and another conformant implementation disagree
on a specific test vector, that is a specification-level issue rather
than a vendor-specific bug. Report it privately per
[SECURITY.md](./SECURITY.md) and include:

- The vector file name and SHA-256 of its bytes.
- Your implementation's result, including the full reason string.
- The other implementation's result, if you have tested against it.
- Your best guess at which side of the disagreement is wrong.

We will coordinate disclosure with both implementations before making
any public statement about the divergence.

---

## Versioning

ATTESTATION-v1 follows a format-stability contract:

- **Patch versions** (v1.0.x): clarifications, typo fixes, new test
  vectors. Existing receipts remain valid.
- **Minor versions** (v1.x.0): new optional fields, new outcome
  values. Existing receipts remain valid.
- **Major versions** (vN.0.0, N ≥ 2): breaking changes to canonical
  serialisation, signature construction, or required fields. Existing
  receipts continue to verify under their original version.

A verifier MAY declare support for multiple major versions. A receipt's
`v` field identifies which major version it was issued under.
