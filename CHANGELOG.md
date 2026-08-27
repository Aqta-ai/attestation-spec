# Changelog

All notable changes to this repository are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this repository adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
at the repository-release level. The ATTESTATION format itself has its
own versioning contract described in [CONFORMANCE.md](./CONFORMANCE.md).

## [Unreleased]

## [1.1.2] - 2026-08-27 (strict signature spelling)

### Fixed

- **Signature spelling was not fixed, so one receipt had several accepted
  byte strings (TypeScript verifier).** `base64urlDecode` padded its input
  and rewrote `-_` as `+/` before decoding, so a genuine receipt whose
  `signature` carried appended `=` padding, or the standard base64 alphabet,
  still returned `valid: true`. The Python verifier rejected both as
  `not base64url`, per spec §4. Two consequences, and the second is the
  reason this is not cosmetic:
  1. **Verifier divergence.** The two published implementations returned
     different verdicts on identical bytes, which is the one thing the format
     cannot afford: a record whose verifiers disagree cannot settle a dispute.
  2. **Receipt malleability.** `signature` is the only field the signature
     does not cover, so lenient decoding made the accepted spelling a free
     variable: at minimum three byte-distinct forms of every receipt (no
     padding, `=`, `==`), multiplied by 2^k for the k `-_` characters in the
     signature. A transparency log keyed on receipt bytes sees one decision
     as several leaves. Same failure shape as the non-canonical scalar bug
     fixed earlier, reached through the encoding rather than the curve.

  Both strict paths (ATTESTATION-v1 and ACTION-v1) now require
  `^[A-Za-z0-9_-]+$` before decoding and emit Python's exact reason string;
  the foreign-envelope path stays lenient and bounded, mirroring Python's
  `_b64_any_decode`. New vectors
  [`invalid/016-signature-padded.json`](./test-vectors/invalid/016-signature-padded.json)
  and
  [`invalid/017-signature-standard-base64-alphabet.json`](./test-vectors/invalid/017-signature-standard-base64-alphabet.json)
  pin the class; both are accepted by the pre-fix verifier and rejected by
  this one.

  Found by [`scripts/differential-fuzz.mjs`](./scripts/differential-fuzz.mjs), a
  differential fuzz of the two verifiers, on 27 August 2026. No receipt issued
  by the Seal gateway was affected: the issuer has always emitted unpadded
  base64url. What was affected is what a reviewer running
  `npx aqta-verify-receipt` would have accepted from a third party.

### Added

- `scripts/differential-fuzz.mjs`: differential fuzz of the two reference verifiers
  over mutated genuine receipts (structural, duplicate member names, numeric
  band, unicode, signature spelling, document bytes). Exits non-zero on any
  disagreement. Run it before publishing either package.

### Notes

- Conformance vectors: **52** (27 ATTESTATION-v1, 25 ACTION-v1), both
  implementations agreeing on all of them.

## [1.1.0] - 2026-08-22 (the ACTION-v1 profile: agent-action records)

### Added

- **ACTION-v1 profile** in both reference verifiers: verification of
  agent-action authorisation records per the new
  [`spec/ACTION-v1.md`](./spec/ACTION-v1.md) draft. A sibling record type,
  not a new ATTESTATION version: string version tag `"action-1"`, thirteen
  fields, outcomes `ALLOWED`/`BLOCKED` only, no numeric fields, and a
  normative assertion-provenance table (spec §8).
- Explicit profile selection everywhere, never auto-detection: library
  option `profile: 'ACTION-v1'` (TS) / `profile='ACTION-v1'` (Py),
  convenience exports `verifyActionRecord` / `verify_action_record`, CLI
  flag `--profile action-1`. Passing `envelope='ACTION-v1'` is rejected so
  an action record can never route through the signature-only
  foreign-envelope path.
- 25 new conformance vectors under `test-vectors/action/` (10 valid, 15
  invalid), including a correctly signed ATTESTATION-v1 receipt that an
  ACTION verifier MUST reject (anti-profile-sniffing) and a
  `\uXXXX`-escaped-signing vector pinning the cross-language escaping trap.
- `scripts/action-interop-sweep.mjs`: every action AND attestation vector
  through both implementations with verdict and reason compared per file,
  plus un-vectored divergence probes (type wording, option conflicts,
  unknown profile). Wired into CI. Four pre-existing 1.0.10 wording-only
  divergences are allowlisted explicitly; verdicts agree in all of them.
- `examples/reference-action-issuer.py`, importing canonicalisation from
  the ATTESTATION reference issuer so the two profiles cannot drift at the
  byte level.

### Notes

- Published as `aqta-verify-receipt` **1.1.0** on both **npm** and **PyPI**
  on 2026-08-22, which froze the ACTION-v1 wire format (spec §13). Before
  publication the format was verified end to end against the production
  issuer: live ALLOWED and BLOCKED records from api.aqta.ai verify offline
  with both implementations, and a tampered record fails.

## [1.0.8] - 2026-08-02 (compact CLI default; --pretty / --json)

### Changed

- **CLI default is one compact stdout line.** Words carry the verdict
  (`valid` / `invalid`); colour is optional and disabled under `NO_COLOR` or
  non-TTY. The large block-character seal is gone from the default path.
- Interactive and piped runs share the same compact contract. Exit `0` valid,
  `1` invalid, `2` usage/IO.
- **`--pretty`** adds a short flourish (`seal intact · verified offline`),
  never changes the exit code, and is not the README's main proof.
- **`--json`** emits one machine object on stdout for automation.
- Package READMEs lead with the compact line; package-page mark shrunk.

### Notes

- Published as `aqta-verify-receipt` **1.0.8** on both **npm** and **PyPI**.

## [1.0.7] - 2026-07-25 (CLI stamp rewrite, package-page branding)

### Changed

- **CLI stamp rewritten.** The block-character seal that sheared on a failed
  verify is replaced with a small `•ᴥ•` mark, a short field table (outcome,
  model, rules, key trust, request hash, attestation id) and a single
  coloured `sealed` / `broken` verdict line, still written to stderr and
  only when stderr is a TTY. The machine-readable `ok ...` / `fail ...` line
  now prints only when stdout is not a TTY, instead of alongside the stamp
  on every run.
- Package pages (npm and PyPI READMEs) and the repository root now show the
  Seal mark as an image (`aqta.ai/brand/seal-mark-512.png`) in place of the
  block ASCII banner.
- Two remaining internal product-name parentheticals removed from
  `CHANGELOG.md` and `spec/ATTESTATION-v1.md`, and the GitHub repository
  "About" field re-branded to Seal.

### Notes

- Published as `aqta-verify-receipt` **1.0.7** on both **npm** and **PyPI**.

## [1.0.6] - 2026-07-24 (multi-envelope verification, verifier parity)

### Added

- `detectEnvelope()` / `detect_envelope()` in both reference verifiers: a
  receipt is now recognised as either an ATTESTATION-v1 envelope or another
  issuer's anchor-v1 envelope, sharing one signature check. Structural
  validation stays format-specific: only ATTESTATION-v1 receipts get the
  twelve-field check.
- Test coverage for the new multi-envelope path: ten TypeScript and thirteen
  Python cases, mirrored case for case (detection by field name, refusal to
  guess on wrong-typed fields, genuine verify, tampered field, wrong key,
  missing pin, integrity-only, non-ASCII).

### Fixed

- Python verifier brought level with TypeScript: matching CLI stamp (tail
  removed from the seal silhouette, `aqta.ai` added to the caption, a stray
  underline removed) and the same envelope-detection capability, closing a
  gap between the two reference implementations. Stamp output and verdicts
  verified byte-identical across both.

### Changed

- Published on **npm and PyPI** as `aqta-verify-receipt` **1.0.6**.

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
- Spec: title and issuer references use **Seal**. §7 requires
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
