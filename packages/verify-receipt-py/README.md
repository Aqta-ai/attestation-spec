# aqta-verify-receipt

[![PyPI](https://img.shields.io/pypi/v/aqta-verify-receipt.svg)](https://pypi.org/project/aqta-verify-receipt/)
[![Python versions](https://img.shields.io/pypi/pyversions/aqta-verify-receipt.svg)](https://pypi.org/project/aqta-verify-receipt/)
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

## Install

```bash
pip install aqta-verify-receipt
```

One dependency: `cryptography`, for constant-time Ed25519 verification.

## Usage

```python
from aqta_verify_receipt import verify_receipt, fetch_published_public_key

# ONE-TIME, on first use of this library in your environment.
trusted = fetch_published_public_key()
save_to_config(trusted)   # file, database, KMS, secret manager

# EVERY VERIFICATION: load the pinned value, do not re-fetch.
trusted = load_from_config()
result = verify_receipt(receipt, trusted_public_key=trusted)

if not result.valid:
    raise ValueError(f"Receipt invalid: {result.reason}")
```

## ⚠️ Pin the public key. Do not re-fetch on every call.

`fetch_published_public_key()` performs a live HTTPS fetch. Calling it
inside a verification loop collapses the trust model back to "trust the
issuer's server right now", which is exactly what this format is
designed to avoid.

**The correct pattern is:**

1. Fetch once, on first use.
2. Persist the result (configuration, database, KMS, secret manager).
3. Pass the persisted value as `trusted_public_key` on every
   verification thereafter.
4. Rotate only when you receive a documented key-rotation notice via a
   channel you already trust.

Re-fetching the key on every verification is a misuse.

## API

### `verify_receipt(receipt, *, trusted_public_key=None, strict_fields=True) → VerifyResult`

Verifies an attestation receipt against the declared (or pinned)
public key.

- `trusted_public_key`: base64url public key. If set, the receipt's
  `public_key` field must match byte for byte. **Strongly recommended
  for production.**
- `strict_fields` (default `True`): any unknown top-level field causes
  rejection, per ATTESTATION-v1 §4. See "Forward compatibility" below.

Returns a `VerifyResult` with fields `valid: bool` and
`reason: Optional[str]`. **Never raises.**

### `fetch_published_public_key(url=..., *, timeout=10.0) → str`

Fetches the AqtaCore public key from
`https://app.aqta.ai/security/pubkey.txt`. Pass a custom URL for
self-hosted issuers. **Pin the result; see the warning above.**

## Forward compatibility

`strict_fields=True` (the default) rejects any receipt containing a
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
  `strict_fields=True`. Upgrade the verifier, or set
  `strict_fields=False` to let forward receipts through the
  signature check. Cryptographic verification still holds in both
  cases; only the structural-allowlist check is relaxed.
- **Major** versions (vN.0, N ≥ 2): breaking changes; upgrade
  required.

Set `strict_fields=False` only if your compliance team has reviewed
the forward-compatibility trade-off.

## Test vectors

A conformance suite for this library (6 valid + 8 invalid receipts,
each documenting one specific behaviour) lives in the spec repository:

- Vectors: [`test-vectors/`](https://github.com/Aqta-ai/attestation-spec/tree/main/test-vectors)
- Reproducible generator:
  [`test-vectors/generate.py`](https://github.com/Aqta-ai/attestation-spec/blob/main/test-vectors/generate.py)

If your verifier disagrees with any vector, please file an issue on
[Aqta-ai/attestation-spec](https://github.com/Aqta-ai/attestation-spec/issues).

## Receipt format

See [ATTESTATION-v1](https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md).

## Security issues

Please do not open public GitHub issues for cryptographic
vulnerabilities. See
[SECURITY.md](https://github.com/Aqta-ai/attestation-spec/blob/main/SECURITY.md).

## Licence

Apache-2.0.
