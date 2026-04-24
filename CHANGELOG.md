# Changelog

All notable changes to this repository are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this repository adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
at the repository-release level. The ATTESTATION format itself has its
own versioning contract described in [CONFORMANCE.md](./CONFORMANCE.md).

## [Unreleased]

Nothing yet.

## [1.0.0] - 2026-04-24

Initial public release of the AqtaCore attestation specification and
reference verifier libraries.

### Added

- **Specification** [`spec/ATTESTATION-v1.md`](./spec/ATTESTATION-v1.md):
  canonical JSON plus Ed25519 receipt format, licensed under CC-BY-4.0.
- **Python reference verifier** [`packages/verify-receipt-py`](./packages/verify-receipt-py):
  Apache 2.0, published to PyPI as `aqta-verify-receipt`.
- **TypeScript reference verifier** [`packages/verify-receipt`](./packages/verify-receipt):
  Apache 2.0, published source available here pending npm publication.
- **Reference issuer** [`examples/reference-issuer.py`](./examples/reference-issuer.py):
  minimal stand-alone issuer covering format and signing only, used
  for test-vector generation and the cross-implementation interop test.
- **Sample receipt** [`examples/sample-receipt.json`](./examples/sample-receipt.json):
  deterministic example.
- **Cross-implementation interop test** [`scripts/make-interop-fixture.mjs`](./scripts/make-interop-fixture.mjs):
  Python issuer signs a receipt, TypeScript verifier accepts it.
  Four assertions covering valid, tampered, pinned, and mismatched-key
  cases.
- **Conformance test vectors** [`test-vectors/`](./test-vectors/):
  six valid and eight invalid receipts, each documenting a specific
  behaviour a conformant verifier must match.
- **GitHub Actions CI**: runs the Python verifier tests against
  Python 3.9 through 3.12, the TypeScript verifier tests, and the
  cross-implementation interop test on every push and pull request.
- **Governance docs**: [CONTRIBUTING.md](./CONTRIBUTING.md),
  [SECURITY.md](./SECURITY.md), [CONFORMANCE.md](./CONFORMANCE.md).

### Notes for implementers

- Integer-valued numbers in the canonical payload MUST be serialised
  without a trailing `.0`; this is the only subtle canonicalisation rule
  and the one most likely to break cross-language interop for a new
  verifier. See spec §6 and the integer-coercion helper in the
  reference issuer.
- The published public key for the canonical AqtaCore managed service
  issuer is available at https://app.aqta.ai/security/pubkey.txt. Third
  parties running their own issuer publish their own key at a stable
  URL of their choice.

[Unreleased]: https://github.com/Aqta-ai/attestation-spec/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Aqta-ai/attestation-spec/releases/tag/v1.0.0
