# Contributing to ATTESTATION-v1

Thank you for your interest in contributing to the AqtaCore attestation
specification and its reference verifier libraries.

## Scope

This repository accepts contributions in three areas.

### 1. Spec changes

The specification lives in
[`spec/ATTESTATION-v1.md`](./spec/ATTESTATION-v1.md). Changes to the
spec are approached as:

- **Clarifications** (no format-bytes change). Typos, disambiguations,
  and restated rules are welcome as pull requests; they do not require
  a version bump.
- **Additive extensions** (new optional fields, future extension points
  flagged in §9). These are discussed as GitHub Issues first. Accepted
  extensions land as a v1.x minor version.
- **Breaking changes**. These require a v2.0 and the motivation must be
  sufficient to justify migration cost on all existing verifiers and
  issuers. Open an issue with the rationale before a pull request.

### 2. Reference verifier libraries

The Python (`packages/verify-receipt-py`) and TypeScript
(`packages/verify-receipt`) verifiers are the reference implementations
of the spec. Contributions are welcome for:

- Bug fixes in verification logic.
- Additional semantic checks flagged as SHOULD in the spec.
- Performance improvements that preserve the constant-time-verify
  invariant.
- Typing and documentation polish.

A contribution that changes verification *acceptance* behaviour (making
a receipt valid that previously was not, or vice versa) MUST come with:

- A test case.
- An updated conformance entry in the spec's test vector set, if
  applicable.
- A note in the pull request describing the semantic change.

### 3. Conformance claims

An independent implementation of the spec (not maintained by Aqta) MAY
claim ATTESTATION-v1 conformance if it passes the cross-implementation
interop test at `scripts/make-interop-fixture.mjs`. To be listed as a
conformant implementation:

1. Open a pull request adding your project to the "Reference
   Implementations" table in §11 of the spec.
2. Include a link to your test harness proving the interop script
   passes against your implementation.
3. Disclose which version of the spec you target and any semantic
   checks you have implemented beyond MUST.

## How to submit changes

1. Open an issue describing the change before opening a pull request,
   unless the change is trivial (typo, broken link, test flake).
2. Branch from `main`.
3. Include tests where applicable.
4. Run `pytest packages/verify-receipt-py/tests/` and
   `cd packages/verify-receipt && npm test` locally before requesting
   review.
5. If the change touches the spec or the canonicalisation rule, run
   `node scripts/make-interop-fixture.mjs` to confirm cross-language
   parity still holds.
6. Open a pull request. GitHub Actions will run the same checks in CI.

## Licensing

By contributing, you agree that:

- Code contributions (in `packages/`, `examples/`, and `scripts/`) are
  released under the Apache License 2.0, as in
  [LICENSE](./LICENSE).
- Specification contributions (in `spec/`) are additionally released
  under the Creative Commons Attribution 4.0 International licence
  (CC-BY-4.0), so that implementers in any ecosystem may adopt the
  format without concern for software-licence compatibility.

## Code of conduct

Be professional and technical. This is an open standards repository
intended for use by regulated-industry auditors, compliance teams, and
developers implementing the format. Discussions should stay focused on
the spec and its reference implementations.

## Security issues

Please do not open public issues for cryptographic vulnerabilities.
See [SECURITY.md](./SECURITY.md) for the disclosure policy.

## Questions

Open an issue, or email the maintainers at
[hello@aqta.ai](mailto:hello@aqta.ai) for non-security questions.
