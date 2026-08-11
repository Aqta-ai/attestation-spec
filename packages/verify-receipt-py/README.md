<p align="center">
  <img src="https://aqta.ai/brand/seal-mark-512.png" alt="Seal" width="96" height="96" />
</p>

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
  --key 9Y3Eiq6V8QjRDUM5nPqSwKIOPQaoEU4SbagfYFdvWa4
```

Default output is one compact line (words carry meaning; colour is optional):

```
✓ valid  ALLOWED  2d41…871e94c  pinned issuer key
```

Invalid:

```
✕ invalid  signature mismatch  2d41…871e94c
```

Optional flourish (never the proof):

```bash
aqta-verify-receipt receipt.json --key <pinned> --pretty
# …
◈ seal intact · verified offline
```

Or pipe:

```bash
curl -sS https://api.aqta.ai/r/YOUR_RECEIPT_ID | aqta-verify-receipt - \
  --key 9Y3Eiq6V8QjRDUM5nPqSwKIOPQaoEU4SbagfYFdvWa4
```

| Exit | Meaning |
|------|---------|
| `0` | valid |
| `1` | invalid |
| `2` | usage / IO |

Current production key id: `aqta-att-01269bb4b6a7d950`
([`/v1/attestation/public-key`](https://api.aqta.ai/v1/attestation/public-key)).

Pin that string; do not re-fetch it inside a verify loop. Keys rotate and
receipts do not: a receipt verifies against the key current when it was
signed, and the permanent key record (with retired keys and their validity
windows) is at
[`app.aqta.ai/security/issuer-keys.txt`](https://app.aqta.ai/security/issuer-keys.txt).

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
aqta-verify-receipt <file|-> --key <base64url> [--no-strict] [--json] [--pretty] [-q]
aqta-verify-receipt <file|-> --integrity-only [--no-strict] [--json] [--pretty] [-q]
```

| Flag | Meaning |
|------|---------|
| `--key` | Pin issuer identity (required for counsel-grade). |
| `--integrity-only` | Signature vs embedded key only; returns untrusted. Anyone can self-sign. |
| `--no-strict` | Allow unknown top-level fields |
| `--json` | One JSON object on stdout |
| `--pretty` | Optional human flourish after the compact line (not the proof) |
| `-q` | Silent; exit code only |

`NO_COLOR=1` disables colour. Meaning never depends on colour alone.

Pinning is required by default. Without `--key`, pass `--integrity-only`
(embedded key only; anyone can self-sign; result is marked untrusted).

## Dependencies

`cryptography` (>= 42) for constant-time Ed25519. Nothing else.

## What this is not

Not a governance dashboard. Not a cost router. A small verifier for one
signed model-call receipt. The novel part is the receipt format and offline
verification model, not ASCII theatre.

## Licence

Apache-2.0. Aqta Technologies Limited.

If you implement or cite the ATTESTATION-v1 format itself, credit under
CC-BY-4.0: see the repo [CITATION.cff](https://github.com/Aqta-ai/attestation-spec/blob/main/CITATION.cff).
