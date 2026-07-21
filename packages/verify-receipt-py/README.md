# aqta-verify-receipt

[![PyPI](https://img.shields.io/pypi/v/aqta-verify-receipt.svg)](https://pypi.org/project/aqta-verify-receipt/)
[![npm](https://img.shields.io/npm/v/aqta-verify-receipt.svg)](https://www.npmjs.com/package/aqta-verify-receipt)
[![Licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

Offline verifier for **Seal** receipts ([ATTESTATION-v1](https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md)).

Seal signs the model call at runtime. This package checks that signature
without contacting Aqta. No account. Same algorithm as the npm package.

## 30-second check

```bash
pip install aqta-verify-receipt
aqta-verify-receipt receipt.json \
  --key gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE
```

Or pipe:

```bash
curl -sS https://api.aqta.ai/r/YOUR_RECEIPT_ID | aqta-verify-receipt - \
  --key gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE
```

`ok` + exit `0` means the Ed25519 signature verifies against the pinned key.
Production key id: `aqta-att-0a18c7c16bc18a12`
([`/v1/attestation/public-key`](https://api.aqta.ai/v1/attestation/public-key)).

Pin that string. Do not re-fetch it inside a verify loop.

## Library

```python
from aqta_verify_receipt import verify_receipt, fetch_published_public_key

# Once per environment: fetch, then pin somewhere you control.
trusted = fetch_published_public_key()

result = verify_receipt(receipt, trusted_public_key=trusted)
if not result.valid:
    raise ValueError(result.reason)
```

## CLI

```
aqta-verify-receipt <file|-> --key <base64url> [--no-strict] [-q]
aqta-verify-receipt <file|-> --integrity-only [--no-strict] [-q]
```

Pinning is required by default. Without `--key`, pass `--integrity-only`
(embedded key only; anyone can self-sign; result is marked untrusted).

## Dependencies

`cryptography` (>= 42) for constant-time Ed25519. Nothing else.

## What this is not

Not a governance dashboard. Not a cost router. A small verifier for one
signed model-call receipt.

## Licence

Apache-2.0. Aqta Technologies Limited.

If you implement or cite the ATTESTATION-v1 format itself, credit under
CC-BY-4.0: see the repo [CITATION.cff](https://github.com/Aqta-ai/attestation-spec/blob/main/CITATION.cff).
