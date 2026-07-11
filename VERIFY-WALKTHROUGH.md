# Verify a receipt in five minutes

A reviewer-shaped walkthrough: no account, no permission from us, nothing but the published
artefacts. Every step below was run against production before this document was committed.

## What you will prove

That an ATTESTATION-v1 receipt verifies against a published Ed25519 key using only
open-source code, offline, with no Aqta server in the trust path. What that does and does
not establish is documented honestly in [THREAT-MODEL.md](./THREAT-MODEL.md).

## 1. Install the published verifier (about 10 seconds)

Python:

```bash
pip install aqta-verify-receipt   # v1.0.2 on PyPI
```

or TypeScript/Node:

```bash
npm install aqta-verify-receipt   # v1.0.2 on npm
```

Both are reference implementations of the spec in this repository. They are small enough to
read before you run them.

## 2. Fetch the published production key (5 seconds)

```bash
curl https://api.aqta.ai/v1/attestation/public-key
```

Returns the raw 32-byte Ed25519 key (base64url), its key id, and pointers back to this spec
and the verifiers:

```json
{"public_key":"gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE","key_id":"aqta-att-0a18c7c16bc18a12","algorithm":"Ed25519", ...}
```

The same key is published on the trust page, so a compromised API answer alone cannot swap
it silently.

## 3. Verify a receipt (10 seconds)

Take any receipt envelope: one from a shared link (`https://app.aqta.ai/api/r/<id>` returns
the canonical JSON), or the signed sample at
[spec/sample-receipt.json](./spec/sample-receipt.json).

Python:

```python
import json
from aqta_verify_receipt import verify_receipt

receipt = json.load(open("receipt.json"))
result = verify_receipt(receipt, trusted_public_key="<the key from step 2>", strict_fields=True)
print(result)   # VerifyResult(valid=True, reason=None)
```

TypeScript:

```ts
import { verifyReceipt } from 'aqta-verify-receipt';
const result = verifyReceipt(receipt, { trustedPublicKey: '<the key from step 2>' });
if (!result.valid) throw new Error(result.reason);
```

No network access happens during verification. Turn your wifi off first if you want to make
the point to yourself.

## 4. Try to break it (the part worth your time)

- Change one character of `model` or `outcome` in the JSON and re-run: `valid: false`.
- Swap in a different public key: `valid: false` (`public_key does not match trusted key`).
- Run the conformance vectors in [CONFORMANCE.md](./CONFORMANCE.md): 14 vectors, 6 valid and
  8 deliberately invalid (wrong signature, mutated fields, malformed hashes, unknown
  top-level fields under strict mode). A conformant verifier must agree on all 14.
- There is also an in-browser verifier at [aqta.ai/verify](https://aqta.ai/verify) that runs
  the same check client-side; the page pre-verifies a signed sample on load.

## 5. What you have and have not established

You have established: this receipt was signed by the holder of the published key and has not
been altered since. You have not established: that the model named in the receipt is what
actually ran, or that the signer's account of the decision is true. Those limits are the
point of [THREAT-MODEL.md](./THREAT-MODEL.md), which we wrote against our own system.
