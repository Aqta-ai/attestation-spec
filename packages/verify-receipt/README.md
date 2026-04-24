# aqta-verify-receipt

Independent verifier for [AqtaCore](https://app.aqta.ai) attestation receipts.
Checks the Ed25519 signature on an enforcement-attestation receipt using only
the published public key: **no dependency on Aqta's servers**.

## Why this exists

AqtaCore returns a signed receipt with every AI enforcement decision.
Regulators, auditors, and internal compliance teams need to verify those
receipts independently, without trusting the issuer. This package is the
reference implementation of that verifier, maintained by Aqta under the open
[ATTESTATION-v1](https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md)
format specification.

## Install

```bash
npm install aqta-verify-receipt
```

## Usage

```ts
import { verifyReceipt, fetchPublishedPublicKey } from 'aqta-verify-receipt';

// One-time: fetch and pin the issuer's public key.
const trustedPublicKey = await fetchPublishedPublicKey();

// Per receipt:
const result = verifyReceipt(receipt, { trustedPublicKey });

if (!result.valid) {
  throw new Error(`Receipt invalid: ${result.reason}`);
}
console.log('Receipt verified without contacting Aqta.');
```

## API

### `verifyReceipt(receipt, options?) → { valid, reason? }`

Verifies an attestation receipt against the declared (or pinned) public key.

Options:
- `trustedPublicKey`: base64url public key. If set, the receipt's `public_key`
  field must match byte for byte. Strongly recommended for production.
- `strictFields`: if `true` (default), any unknown top-level field causes
  rejection, per ATTESTATION-v1 §4.

### `fetchPublishedPublicKey(url?) → Promise<string>`

Fetches the AqtaCore public key from
`https://app.aqta.ai/security/pubkey.txt`. Pass a custom URL for self-hosted
issuers.

## Receipt format

See [ATTESTATION-v1](https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md).

## Licence

Apache-2.0. See `LICENSE`.
