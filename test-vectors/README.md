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
