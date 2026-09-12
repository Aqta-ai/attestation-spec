# ATTESTATION-v1 conformance test vectors

Deterministic receipts for testing third-party verifier implementations
against ATTESTATION-v1.

## Using these vectors

A conformant verifier, pinning the public key below, MUST:

- Return `valid: true` for every receipt in [`valid/`](./valid).
- Return `valid: false` for every receipt in [`invalid/`](./invalid).

If your verifier gets any vector wrong, it does not conform to
ATTESTATION-v1.

## Trusted public key for all vectors

```
alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E
```

Derived deterministically from the seed `sha256("attestation-spec/test-vectors/v1")`.
Use it as the `trustedPublicKey` parameter to your verifier, or compare
against the `public_key` field in each receipt.

Byte-level inputs that are not valid UTF-8, and therefore cannot be JSON, are in
[`bytes/`](./bytes) with their own manifest of expected exit codes.

## Valid vectors

| File | Outcome | Notes |
|------|---------|-------|
| [`valid/001-allowed.json`](./valid/001-allowed.json) | `ALLOWED` | Canonical happy-path receipt |
| [`valid/002-blocked.json`](./valid/002-blocked.json) | `BLOCKED` | Pre-provider block; multiple policies |
| [`valid/003-suppressed.json`](./valid/003-suppressed.json) | `SUPPRESSED` | Loop-guard suppression |
| [`valid/004-passed.json`](./valid/004-passed.json) | `PASSED` | Legacy synonym of `ALLOWED` |
| [`valid/005-multi-policy.json`](./valid/005-multi-policy.json) | `ALLOWED` | Five policies applied; exercises `policy_applied` sort requirement |
| [`valid/006-cost-prevented-nonzero.json`](./valid/006-cost-prevented-nonzero.json) | `BLOCKED` | Non-integer `cost_prevented_eur` value (`2.5`) |
| [`valid/007-non-ascii-policy.json`](./valid/007-non-ascii-policy.json) | `BLOCKED` | Non-ASCII policy names. Pins §6.1: an implementation that escapes non-ASCII to `\uXXXX` produces different canonical bytes than `JSON.stringify` |
| [`valid/008-cost-sub-milli.json`](./valid/008-cost-sub-milli.json) | `BLOCKED` | `cost_prevented_eur` of `0.000015`. Pins the §6 number grammar: Python's default float repr writes `1.5e-05` where JavaScript writes `0.000015`, so an implementation using either language's default disagrees with the other across the whole band `0 < \|x\| < 1e-4` |
| [`valid/009-cost-smallest-precision.json`](./valid/009-cost-smallest-precision.json) | `BLOCKED` | `cost_prevented_eur` of `0.000001`, the smallest non-zero value §4's six digits of precision allows |
| [`valid/010-timestamp-leap-second.json`](./valid/010-timestamp-leap-second.json) | `ALLOWED` | `timestamp` of `2016-12-31T23:59:60Z`, a real leap second and legal RFC 3339. A verifier that defers well-formedness to a date parser rejects it |

## Invalid vectors

Each file encodes exactly one failure mode. A verifier MUST reject.

| File | Failure mode | Reason field (informative) |
|------|--------------|----------------------------|
| [`invalid/001-tampered-signature.json`](./invalid/001-tampered-signature.json) | Signature bytes modified | Signature check fails |
| [`invalid/002-tampered-outcome.json`](./invalid/002-tampered-outcome.json) | `outcome` changed post-signing | Signature check fails |
| [`invalid/003-tampered-public-key.json`](./invalid/003-tampered-public-key.json) | `public_key` replaced with an all-zero key | Signature check fails against the forged key |
| [`invalid/004-missing-field.json`](./invalid/004-missing-field.json) | Required `outcome` field removed | Structural check fails |
| [`invalid/005-unknown-field.json`](./invalid/005-unknown-field.json) | Extra `extra_metadata` field added | Strict-mode structural check fails |
| [`invalid/006-wrong-version.json`](./invalid/006-wrong-version.json) | `v: 2` (future version) | Unsupported version |
| [`invalid/007-bad-request-hash.json`](./invalid/007-bad-request-hash.json) | `request_hash` not 64-char hex | Semantic check fails |
| [`invalid/008-invalid-outcome.json`](./invalid/008-invalid-outcome.json) | `outcome: "MAYBE"` (not in enum) | Semantic check fails |
| [`invalid/009-policy-not-sorted.json`](./invalid/009-policy-not-sorted.json) | `policy_applied` in descending order | Semantic check fails: spec §4 requires lexicographic order |
| [`invalid/010-policy-not-strings.json`](./invalid/010-policy-not-strings.json) | `policy_applied` contains a number | Semantic check fails: elements are ASCII policy identifiers |
| [`invalid/011-timestamp-no-offset.json`](./invalid/011-timestamp-no-offset.json) | `timestamp` has no timezone offset | Semantic check fails: an explicit offset is required |
| [`invalid/012-timestamp-not-datetime.json`](./invalid/012-timestamp-not-datetime.json) | `timestamp` is not a datetime | Semantic check fails: not a well-formed RFC 3339 datetime |
| [`invalid/013-negative-cost.json`](./invalid/013-negative-cost.json) | `cost_prevented_eur` is negative | Semantic check fails: the field is non-negative |
| [`invalid/014-boolean-version.json`](./invalid/014-boolean-version.json) | `v: true` | Unsupported version: `true` is not `1` |
| [`invalid/015-uncoerced-integer-float.json`](./invalid/015-uncoerced-integer-float.json) | `cost_prevented_eur` signed as `1.0`, uncoerced by the issuer | Canonical bytes mismatch: §6(3) puts integer coercion on the issuer, so the signature check fails |
| [`invalid/016-signature-padded.json`](./invalid/016-signature-padded.json) | Genuine signature with base64 padding appended | Not base64url per spec 4; the signature field is not covered by the signature, so lenient decoding makes one receipt several byte strings |
| [`invalid/017-signature-standard-base64-alphabet.json`](./invalid/017-signature-standard-base64-alphabet.json) | Genuine signature respelled in the standard base64 alphabet | Same class: spec 4 fixes the alphabet, and accepting both spellings diverged from the Python verifier |

## Cases that cannot be shipped as vectors

Two defect classes live in each package's own tests rather than here, because
the runners above parse every file before verifying it and a parse-layer defect
does not survive being parsed:

- **Duplicate member names.** `{"v":1,"v":1}` has no single canonical payload,
  since a parser keeping the first value and one keeping the last compute
  different signed bytes. Parsers collapse the duplicate, so a vector file
  would arrive at the verifier already repaired.
- **`NaN` and `Infinity`.** Not JSON at all (RFC 8259), so a vector file would
  fail the runner's own `JSON.parse` rather than test anything. Python's `json`
  module accepts all three as an extension, which is how the two verifiers came
  to disagree on whether such input was even parseable.

Both are covered by CLI-level tests in `packages/verify-receipt` and
`packages/verify-receipt-py`, and both must exit 2 (malformed input) rather
than 1 (invalid receipt).

## Transparency adversary bundles

`transparency/valid` and `transparency/invalid` ask one question of one object: does this
inclusion proof, consistency proof or signed head verify. The classes in
[ISSUER-ADVERSARY.md](../ISSUER-ADVERSARY.md) are only visible across objects, so
`transparency/adversary/` carries **history bundles**: several signed heads obtained at
different times, consistency proofs between them, and inclusion proofs for the records in
question, each with the time the record claims for itself. A verifier assesses the bundle as a
whole and returns a named verdict rather than a boolean.

Verdicts, in precedence order, because a bundle can carry more than one fault and every
implementation must name the same one: `invalid_head`, `equivocation`, `unsigned_root`,
`fork`, `invalid_proof`, `timestamp_contradiction`, `consistent`. Only `consistent` is
`valid`.

| Bundle | Class | Verdict | What it pins |
|---|---|---|---|
| `a1-consistent-growth` | A1 | `consistent` | Two heads, an append-only extension, a record included before the head's time |
| `a1-equivocation-same-size` | A1 | `equivocation` | Two correctly signed heads at one size with different roots. Every signature verifies; only holding both reveals it |
| `a1-fork-no-extension` | A1 | `fork` | A later head whose tree does not contain the earlier entries as they were |
| `a3-included-before-head-time` | A3 | `consistent` | A head bounds a record's existence from above |
| `a3-claims-time-after-including-head` | A3 | `timestamp_contradiction` | A record cannot be created after a head that already contains it |
| `a3-lag-is-not-backdating` | A3 | `consistent` | **The honest limit.** Absence from an earlier head is not evidence of backdating: log order is submission order. A verifier that flags this is wrong |
| `a4-reordered-history` | A4 | `fork` | The moved record's inclusion proof verifies on its own; only consistency from the pinned head catches the reordering |
| `a6-pack-head-is-prefix` | A6 | `consistent` | A pack head that is a prefix of the independently fetched live head |
| `a6-side-head` | A6 | `fork` | A correctly signed head over a tree the live log never contained: a history built for one reviewer |
| `invalid-head-signature` | A5 | `invalid_head` | One head fails under the trusted key; nothing below it counts |
| `unsigned-root-target` | A6 | `unsigned_root` | A proof that verifies, against a root no head signed: a tree not in evidence |
| `a3-timestamp-grammar-is-strict` | A3 | `invalid_proof` | A `record_timestamp` with fractional seconds and an offset is refused, not parsed |

**Timestamps in a bundle.** `record_timestamp` and a head's `timestamp` are `YYYY-MM-DDTHH:MM:SSZ`,
deliberately narrower than the RFC 3339 a receipt carries, so the two implementations compare
fixed-width strings and never depend on a date parser agreeing. Whoever builds a bundle converts
the receipt's signed timestamp to UTC and floors it to the second. Flooring can only make a record
look earlier, so it cannot manufacture a `timestamp_contradiction` the signed value would not also
produce; keep the signed value beside it (`record_timestamp_as_signed`) so a reviewer can check the
conversion. A leap second (`:60`) is kept verbatim.

Not shipped, by design: any vector claiming to detect **A2, omission**. A record that was never
written leaves nothing to verify, and a bundle cannot pin the absence of evidence.

Generate with `PYTHONPATH=packages/verify-receipt-py/src python3 scripts/make-adversary-vectors.py`.
Heads are signed with a deterministic throwaway key whose private half is the bytes 0 to 31;
the public half travels in each bundle as `trusted_public_key`. The generator asserts the Python
verifier's verdict for every bundle before writing it, and
`scripts/transparency-interop-sweep.mjs` holds the TypeScript verifier and both command-line
tools to the same verdicts.

## Reproducibility

All vectors are generated by [`generate.py`](./generate.py) from the fixed
seed shown above. Re-running the script in a fresh environment produces
byte-identical output. If any vector regenerates with a different
signature, either your build of the reference issuer has drifted or the
canonicalisation rule has silently changed; investigate before
publishing.

```bash
# Regenerate (from repo root)
python3 test-vectors/generate.py
```

## Using vectors in your verifier's test suite

**Python example:**

```python
import json
import pathlib
from aqta_verify_receipt import verify_receipt

TRUSTED_KEY = "alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E"
VECTORS = pathlib.Path("test-vectors")

for path in sorted((VECTORS / "valid").glob("*.json")):
    receipt = json.loads(path.read_text())
    assert verify_receipt(receipt, trusted_public_key=TRUSTED_KEY).valid, path.name

for path in sorted((VECTORS / "invalid").glob("*.json")):
    receipt = json.loads(path.read_text())
    assert not verify_receipt(receipt, trusted_public_key=TRUSTED_KEY).valid, path.name

print("all vectors behave as specified")
```

**TypeScript example:**

```ts
import { verifyReceipt } from 'aqta-verify-receipt';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const TRUSTED_KEY = 'alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E';
const VECTORS = 'test-vectors';

for (const sub of ['valid', 'invalid']) {
  const shouldPass = sub === 'valid';
  for (const name of readdirSync(join(VECTORS, sub))) {
    const receipt = JSON.parse(readFileSync(join(VECTORS, sub, name), 'utf8'));
    const { valid } = verifyReceipt(receipt, { trustedPublicKey: TRUSTED_KEY });
    if (valid !== shouldPass) throw new Error(`${sub}/${name} behaved wrong`);
  }
}
console.log('all vectors behave as specified');
```

## Reporting a vector disagreement

If your verifier disagrees with a vector and you believe the vector is
wrong (not your verifier), open an issue on the
[attestation-spec](https://github.com/Aqta-ai/attestation-spec) repo with
the vector file name, your verifier version, and a minimal reproduction.
Do not submit a pull request that silently changes a vector without
explanation: the vectors are the canonical source of truth for cross
language parity.

## Planned: a nested-payload canonicalisation vector

No ATTESTATION-v1 envelope nests, so no vector here exercises recursive key
sorting inside canonical JSON. On 15 Aug 2026 that gap let a third-party port
(Aqta's own browser verifier) ship a canonicaliser that sorted only top-level
keys; the divergence was invisible until the first nested sidecar document was
hashed against a Python-signed value and failed. Implementations that reuse
their canonicaliser for payloads beyond the envelope will hit this silently.
A vector with a nested object in a documented sidecar context belongs here so
ports cannot repeat the mistake quietly.

