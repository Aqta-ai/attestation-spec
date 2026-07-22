# Changelog

All notable changes to this repository are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this repository adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
at the repository-release level. The ATTESTATION format itself has its
own versioning contract described in [CONFORMANCE.md](./CONFORMANCE.md).

## [1.0.5] - 2026-07-22 (non-ASCII interop fix, verifier CLI mark)

### Fixed

- **Cross-language verification of receipts containing non-ASCII text.** The
  Python verifier canonicalised with `json.dumps` defaults, which escape
  non-ASCII to `\uXXXX`. `JSON.stringify` does not. A receipt with, for
  example, a policy named `Größe-Limit` therefore produced different canonical
  bytes in each language: it verified in Python and failed in JavaScript. The
  Python verifier now passes `ensure_ascii=False`, matching the JavaScript
  behaviour and spec §6.1.
- Every field is affected in principle, `policy_applied` and `model` most
  plausibly in practice. Receipts whose fields are entirely ASCII are
  unaffected: all fourteen pre-existing test vectors regenerate byte for byte
  identical, so no previously issued signature changes meaning.
- The JavaScript verifier needed no behavioural change. A comment there
  asserted that Python yields `"0"` for float `0.0`, which is untrue and
  contradicted the spec it implements. Corrected.

### Added

- Spec §6.1 makes string canonicalisation normative: literal UTF-8, never
  `\uXXXX` escapes. Previously this was implied by "UTF-8 encoding of the
  resulting string" and not stated, which is how the divergence survived.
- Test vector `valid/007-non-ascii-policy.json`, carrying German, French and
  Japanese text, pins the rule.
- Both test suites now run the published vectors directly. They are the
  cross-language contract, and until now nothing executed them, which is why
  a divergence could ship. A verifier that passes vectors 001-006 but fails
  007 has the escaping bug.

- Both CLIs print the Seal mark on a successful or failed verify. The mark is
  traced from the brand artwork, so the head, snout, eye and flippers are the
  real silhouette rather than hand-drawn approximations. A failed check shears
  the mark along its midline: the seal is visibly broken before the word is
  read.
- Package pages and the repository README carry the mark as a banner.

### Notes

- Output hygiene is unchanged and enforced: the mark is written to **stderr**,
  only when stderr is a **TTY**, and never under `-q` / `--quiet`. Piped and
  scripted runs still receive exactly `ok ...` / `fail ...` on stdout and
  nothing else, so parsers and CI are unaffected.
- Half-block glyphs are used when the locale is UTF-8, with a plain ASCII
  fallback otherwise. `NO_COLOR` is respected.
- No change to the wire format or the public API. The only logic change is the
  canonicalisation fix above, which strictly widens the set of receipts the two
  implementations agree on.

## [1.0.4] - 2026-07-21 (verifiers + docs)

### Changed

- **Breaking (verifier 1.0.4):** `verify_receipt` / `verifyReceipt` require a
  pinned trusted public key by default. A self-signed receipt no longer
  returns `valid: true` unless
  `allow_untrusted_embedded_key` / `allowUntrustedEmbeddedKey` is set
  (returns `key_source` / `keySource: "untrusted"`). CLI requires `--key`
  or `--integrity-only`.
- Published on **npm and PyPI** as `aqta-verify-receipt` **1.0.4**.
- Spec: title and issuer references use **Seal** (not AqtaCore). §7 requires
  out-of-band key pinning for counsel-grade verification; integrity-only is
  optional and must be labelled untrusted. No wire-format change.
- Root README simplified (diagram removed). Attribution and
  [CITATION.cff](./CITATION.cff) added so downstream users credit
  Aqta Technologies Ltd under CC-BY-4.0 / Apache-2.0.
- Spec wording: "enforcement gateway" instead of "governance gateway".
- Dual-licence layout: Apache-2.0 root `LICENSE`; CC-BY-4.0 for `spec/` in
  `LICENSE-SPEC`.
- Package READMEs aligned with enforcement wedge; both pubkey URLs documented.
- CI runs the 14 test vectors on Python and TypeScript.
- Community health: `CODE_OF_CONDUCT.md`, issue/PR templates, examples README.
- Wiki disabled; GitHub Release for tag `v1.0.0` (package Latest remains
  `verify-receipt-v1.0.2` until this release).

### Fixed

- Root README no longer claims TypeScript npm publication is pending.
  `aqta-verify-receipt` is published on both PyPI and npm.
- README reframed around the enforcement wedge (gateway allow/block before
  the model runs), with an ordinary-logs comparison, live browser verifier
  link, and an honest "relationship to open standards" section (SCITT /
  COSE / W3C VC / in-toto adjacent, not conforming).

---

## [Unreleased]

---

## Verifier-library releases

The Python and TypeScript reference verifiers have their own patch
release line. Spec `v1.0.0` is unaffected by these patches; only the
verifier libraries are versioned.

### `aqta-verify-receipt` 1.0.4 (npm and PyPI 2026-07-21)

**Why:** Default verify path trusted the public key embedded in the receipt,
so a self-signed forgery returned `valid: true`. Counsel-grade use already
pinned; the library default now matches that expectation.

#### Changed

- Require `trustedPublicKey` / `trusted_public_key` unless the caller opts
  into integrity-only (`allowUntrustedEmbeddedKey` /
  `allow_untrusted_embedded_key`).
- CLI: `--key` required, or `--integrity-only` for embedded-key checks.
- Successful integrity-only results are labelled `keySource` /
  `key_source: "untrusted"`.

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

Initial public release of the Seal attestation specification and
reference verifier libraries.

### Added

- **Specification** [`spec/ATTESTATION-v1.md`](./spec/ATTESTATION-v1.md):
  canonical JSON plus Ed25519 receipt format, licensed under CC-BY-4.0.
- **Python reference verifier** [`packages/verify-receipt-py`](./packages/verify-receipt-py):
  Apache 2.0, published to PyPI as `aqta-verify-receipt`.
- **TypeScript reference verifier** [`packages/verify-receipt`](./packages/verify-receipt):
  Apache 2.0, published to npm as `aqta-verify-receipt`.
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
- **Project docs**: [CONTRIBUTING.md](./CONTRIBUTING.md),
  [SECURITY.md](./SECURITY.md), [CONFORMANCE.md](./CONFORMANCE.md).

### Notes for implementers

- Integer-valued numbers in the canonical payload MUST be serialised
  without a trailing `.0`; this is the only subtle canonicalisation rule
  and the one most likely to break cross-language interop for a new
  verifier. See spec §6 and the integer-coercion helper in the
  reference issuer.
- The published public key for the canonical Seal managed service
  issuer is available at https://api.aqta.ai/v1/attestation/public-key
  (mirrored as raw base64 at https://app.aqta.ai/security/pubkey.txt). Third
  parties running their own issuer publish their own key at a stable
  URL of their choice.

[Unreleased]: https://github.com/Aqta-ai/attestation-spec/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Aqta-ai/attestation-spec/releases/tag/v1.0.0
