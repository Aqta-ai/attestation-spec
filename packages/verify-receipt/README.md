# aqta-verify-receipt

[![npm](https://img.shields.io/npm/v/aqta-verify-receipt.svg)](https://www.npmjs.com/package/aqta-verify-receipt)
[![CI](https://github.com/Aqta-ai/attestation-spec/actions/workflows/test.yml/badge.svg)](https://github.com/Aqta-ai/attestation-spec/actions/workflows/test.yml)
[![Licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](https://github.com/Aqta-ai/attestation-spec/blob/main/LICENSE)

Independent verifier for [AqtaCore](https://app.aqta.ai) attestation
receipts. Checks the Ed25519 signature on an enforcement-attestation
receipt using only the published public key: **no dependency on Aqta's
servers**.

## Why this exists

AqtaCore returns a signed receipt with every AI enforcement decision.
Regulators, auditors, and internal compliance teams need to verify
those receipts independently, without trusting the issuer. This
package is the reference implementation of that verifier, maintained
by Aqta under the open
[ATTESTATION-v1](https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md)
format specification.

This verifier is the same code path AqtaCore uses internally to
validate its own production receipts and to power the receipt-
verification endpoint exposed to customer audit teams.

## Install

```bash
npm install aqta-verify-receipt
```

Two dependencies: `tweetnacl` and `tweetnacl-util`, for constant-time
Ed25519 verification.

## Usage

```ts
import { verifyReceipt, fetchPublishedPublicKey } from 'aqta-verify-receipt';

// ONE-TIME, on first use of this library in your environment.
const trustedPublicKey = await fetchPublishedPublicKey();
saveToConfig(trustedPublicKey);   // file, database, KMS, secret manager

// EVERY VERIFICATION: load the pinned value, do not re-fetch.
const pinned = loadFromConfig();
const result = verifyReceipt(receipt, { trustedPublicKey: pinned });

if (!result.valid) {
  throw new Error(`Receipt invalid: ${result.reason}`);
}
```

## ⚠️ Pin the public key. Do not re-fetch on every call.

`fetchPublishedPublicKey()` performs a live HTTPS fetch. Calling it
inside a verification loop collapses the trust model back to "trust the
issuer's server right now", which is exactly what this format is
designed to avoid.

**The correct pattern is:**

1. Fetch once, on first use.
2. Persist the result (configuration, database, KMS, secret manager).
3. Pass the persisted value as `trustedPublicKey` on every verification
   thereafter.
4. Rotate only when you receive a documented key-rotation notice via a
   channel you already trust.

Re-fetching the key on every verification is a misuse.

## API

### `verifyReceipt(receipt, options?) → { valid, reason? }`

Verifies an attestation receipt against the declared (or pinned)
public key.

Options:
- `trustedPublicKey`: base64url public key. If set, the receipt's
  `public_key` field must match byte for byte. **Strongly recommended
  for production.**
- `strictFields` (default `true`): any unknown top-level field causes
  rejection, per ATTESTATION-v1 §4. See "Forward compatibility" below.

Returns `{ valid: boolean, reason?: string }`. **Never throws.**

### `fetchPublishedPublicKey(url?) → Promise<string>`

Fetches the AqtaCore public key from
`https://app.aqta.ai/security/pubkey.txt`. Pass a custom URL for
self-hosted issuers. **Pin the result; see the warning above.**

## Forward compatibility

`strictFields: true` (the default) rejects any receipt containing a
field not defined in the version of the spec this library was built
against. This is the correct behaviour for a security-critical
verifier: a receipt containing an unknown field may carry
attacker-controlled metadata that downstream systems should not treat
as signed evidence.

ATTESTATION-v1 versioning policy:

- **Patch** versions of the spec (v1.0.x): clarifications only, no
  field changes. Your verifier keeps working.
- **Minor** versions of the spec (v1.x.0): may add new optional
  fields. A v1.0-era verifier will reject v1.1 receipts under
  `strictFields: true`. Upgrade the verifier, or set
  `strictFields: false` to let forward receipts through the signature
  check. Cryptographic verification still holds in both cases; only
  the structural-allowlist check is relaxed.
- **Major** versions (vN.0, N ≥ 2): breaking changes; upgrade
  required.

Set `strictFields: false` only if your compliance team has reviewed
the forward-compatibility trade-off.

## Test vectors

A conformance suite for this library (6 valid + 8 invalid receipts,
each documenting one specific behaviour) lives in the spec repository:

- Vectors: [`test-vectors/`](https://github.com/Aqta-ai/attestation-spec/tree/main/test-vectors)
- Reproducible generator:
  [`test-vectors/generate.py`](https://github.com/Aqta-ai/attestation-spec/blob/main/test-vectors/generate.py)

If your verifier disagrees with any vector, please file an issue on
[Aqta-ai/attestation-spec](https://github.com/Aqta-ai/attestation-spec/issues).

### Quick self-test

To confirm your environment and this library behave as the spec
intends, run all 14 vectors in one command after installing:

```bash
git clone https://github.com/Aqta-ai/attestation-spec.git
cd attestation-spec
npm install aqta-verify-receipt
node - <<'JS'
const fs = require('node:fs');
const path = require('node:path');
const { verifyReceipt } = require('aqta-verify-receipt');

const TRUSTED = 'alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E';

for (const sub of ['valid', 'invalid']) {
  const shouldPass = sub === 'valid';
  for (const name of fs.readdirSync(path.join('test-vectors', sub)).sort()) {
    const r = JSON.parse(fs.readFileSync(path.join('test-vectors', sub, name), 'utf8'));
    const { valid } = verifyReceipt(r, { trustedPublicKey: TRUSTED });
    if (valid !== shouldPass) throw new Error(`${sub}/${name} behaved wrong`);
  }
}
console.log('all 14 vectors behave as specified');
JS
```

A clean run prints `all 14 vectors behave as specified` and exits 0.

## Receipt format

See [ATTESTATION-v1](https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md).

## Security issues

Please do not open public GitHub issues for cryptographic
vulnerabilities. See
[SECURITY.md](https://github.com/Aqta-ai/attestation-spec/blob/main/SECURITY.md).

## Licence

Apache-2.0.
