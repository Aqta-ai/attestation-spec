```
           ▄▄▄▄▄▄▄▄
         ▄███████▀████▄▄
       ▄████████████████
       ██████████████▀▀
      █████████████▀
     ▄█████████████
    ▄██████████████
  ▄█████████████████
▄███████████████████
████████████████████         ▄
██████████████▀ ████      ▄▀
 ▀▀█████████▀   ███▀  ▄▄▀▀
     ▀▀▀██▄▄▄▄▄▄██▀ ▀▀
```

# aqta-verify-receipt

[![npm](https://img.shields.io/npm/v/aqta-verify-receipt.svg)](https://www.npmjs.com/package/aqta-verify-receipt)
[![PyPI](https://img.shields.io/pypi/v/aqta-verify-receipt.svg)](https://pypi.org/project/aqta-verify-receipt/)
[![Licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

Offline verifier for **Seal** receipts ([ATTESTATION-v1](https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md)).

Seal signs the model call at runtime. This package checks that signature
without contacting Aqta. No account. Exit code only if you want it quiet.

Same algorithm on npm and PyPI. Reference implementation, not a platform SDK.

## 30-second check

```bash
# download a receipt JSON, then:
npx aqta-verify-receipt@1.0.5 receipt.json \
  --key gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE
```

Or pipe a public share link body:

```bash
curl -sS https://api.aqta.ai/r/YOUR_RECEIPT_ID | npx aqta-verify-receipt@1.0.5 - \
  --key gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE
```

`ok` + exit `0` means the Ed25519 signature verifies against the pinned key.
`fail` + exit `1` means it does not. Exit `2` is usage or IO.

Production public key (also at
[`/v1/attestation/public-key`](https://api.aqta.ai/v1/attestation/public-key),
key id `aqta-att-0a18c7c16bc18a12`):

```
gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE
```

Pin that string. Do not re-fetch it inside a verify loop.

## Install

```bash
npm install aqta-verify-receipt
# or one-shot:
npx aqta-verify-receipt receipt.json --key <pinned>
```

Two runtime deps: `tweetnacl`, `tweetnacl-util`.

## Library

```ts
import { verifyReceipt, fetchPublishedPublicKey } from 'aqta-verify-receipt';

// Once per environment: fetch, then pin somewhere you control.
const trustedPublicKey = await fetchPublishedPublicKey();

const result = verifyReceipt(receipt, { trustedPublicKey });
if (!result.valid) throw new Error(result.reason);
```

### Pin the key

`fetchPublishedPublicKey()` is for first-time setup. Calling it on every
verify collapses trust back to "trust the issuer's server right now".

1. Fetch once.
2. Persist (config, KMS, secret store).
3. Pass `trustedPublicKey` on every call.
4. Rotate only on a documented key-rotation notice.

## CLI

```
aqta-verify-receipt <file|-> --key <base64url> [--no-strict] [-q]
aqta-verify-receipt <file|-> --integrity-only [--no-strict] [-q]
```

| Flag | Meaning |
|------|---------|
| `--key` | Pin issuer identity (required for counsel-grade). |
| `--integrity-only` | Signature vs embedded key only; returns untrusted. Anyone can self-sign. |
| `--no-strict` | Allow unknown top-level fields |
| `-q` | Silent; exit code only |

## API

### `verifyReceipt(receipt, options?) → { valid, reason?, keySource? }`

Never throws. **Pinning is required by default.** Without `trustedPublicKey`,
returns `valid: false` unless `allowUntrustedEmbeddedKey: true` (then
`keySource: "untrusted"` on success). Default `strictFields: true` rejects
unknown top-level fields (ATTESTATION-v1 §4).

### `fetchPublishedPublicKey(url?) → Promise<string>`

Default: `https://app.aqta.ai/security/pubkey.txt`. Same material as
`https://api.aqta.ai/v1/attestation/public-key`.

## Test vectors

Conformance suite (6 valid + 8 invalid):
[`test-vectors/`](https://github.com/Aqta-ai/attestation-spec/tree/main/test-vectors).

## What this is not

Not a governance dashboard. Not a cost router. Not a chain explorer.
A small verifier for one signed model-call receipt.

## Security

Cryptographic issues: see [SECURITY.md](../../SECURITY.md). Prefer
security@aqta.ai over public issues for key or signature bugs.

## Licence

Apache-2.0. Aqta Technologies Limited.

If you implement or cite the ATTESTATION-v1 format itself, credit under
CC-BY-4.0: see the repo [CITATION.cff](https://github.com/Aqta-ai/attestation-spec/blob/main/CITATION.cff).
