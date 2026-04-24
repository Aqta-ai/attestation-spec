# Changelog

All notable changes to this repository are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this repository adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
at the repository-release level. The ATTESTATION format itself has its
own versioning contract described in [CONFORMANCE.md](./CONFORMANCE.md).

## [Unreleased]

Nothing yet.

---

## Verifier-library releases

The Python and TypeScript reference verifiers have their own patch
release line. Spec `v1.0.0` is unaffected by these patches; only the
verifier libraries are versioned.

### `aqta-verify-receipt` 1.0.2 (PyPI 2026-04-25)

**Why:** External review flagged two real documentation gaps in 1.0.1:
the `fetch_published_public_key()` helper could be misused in a way
that re-introduces vendor-server trust, and the `strict_fields`
forward-compatibility behaviour was not explicitly documented. Both
were doc fixes only; no behaviour change in either verifier.

#### Added

- Loud "PIN THE RESULT" warning on `fetch_published_public_key()` in
  both the Python docstring and the TypeScript JSDoc, plus a `⚠️`
  callout block in both READMEs.
- Forward-compatibility section in both READMEs documenting how
  `strict_fields=True` interacts with future minor versions of the
  spec, with explicit guidance on when to set it to `False`.
- Test-vectors section in both package READMEs linking the
  conformance suite at `test-vectors/` so PyPI and npm visitors can
  find the known-good and known-bad receipts directly.
- Badge row on the Python and TypeScript package READMEs (PyPI
  version, Python versions, CI status, licence; npm version, CI,
  licence). First impression for visitors landing on the package
  pages.

### `aqta-verify-receipt` 1.0.1 (PyPI and npm 2026-04-24)

**Why:** Initial 1.0.0 release linked to a private internal
repository (`aqta-app`) which returns 404 for external users.
Republished with all package-metadata URLs pointing to the public
[`Aqta-ai/attestation-spec`](https://github.com/Aqta-ai/attestation-spec)
repository.

#### Changed

- All `Project-URL` entries in `pyproject.toml` and `repository`
  in `package.json` now point at the public spec repository.
- README links updated to the public repository.

### `aqta-verify-receipt` 1.0.0 (PyPI 2026-04-23, superseded)

Initial publish. Superseded within hours by 1.0.1 due to the broken
links above. Users SHOULD upgrade to at least 1.0.1, ideally 1.0.2 or
later.

---

## [1.0.0] - 2026-04-24 (spec)

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
