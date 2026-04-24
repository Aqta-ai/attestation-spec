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
pip install aqta-verify-receipt
```

## Usage

```python
from aqta_verify_receipt import verify_receipt, fetch_published_public_key

# One-time: fetch and pin the issuer's public key.
trusted = fetch_published_public_key()

# Per receipt:
result = verify_receipt(receipt, trusted_public_key=trusted)

if not result.valid:
    raise ValueError(f"Receipt invalid: {result.reason}")

print("Receipt verified without contacting Aqta.")
```

## API

### `verify_receipt(receipt, *, trusted_public_key=None, strict_fields=True) → VerifyResult`

Verifies an attestation receipt against the declared (or pinned) public key.

- `trusted_public_key`: base64url public key. If set, the receipt's `public_key`
  field must match byte for byte. Strongly recommended for production.
- `strict_fields`: if `True` (default), any unknown top-level field causes
  rejection, per ATTESTATION-v1 §4.

Returns a `VerifyResult` with fields `valid: bool` and `reason: Optional[str]`.
Never raises.

### `fetch_published_public_key(url=..., *, timeout=10.0) → str`

Fetches the AqtaCore public key from
`https://app.aqta.ai/security/pubkey.txt`. Pass a custom URL for self-hosted
issuers.

## Dependencies

- `cryptography` for Ed25519 verification (pinned ≥ 42.0.0).

No other dependencies. Pure-Python spec checks, plus `cryptography`'s
constant-time Ed25519 primitive.

## Receipt format

See [ATTESTATION-v1](https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md).

## Licence

Apache-2.0. See `LICENSE`.
