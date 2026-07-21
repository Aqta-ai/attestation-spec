# Verify a receipt in five minutes

A reviewer-shaped walkthrough using only the published artefacts: the spec in this
repository, the verifiers on PyPI and npm, the signed sample here, and the issuer's public
key served over HTTPS. Steps 1 to 3 are reproducible today by anyone; the exact commands
below were run before this document was committed.

## What you will prove

That an ATTESTATION-v1 receipt verifies against its Ed25519 key using only open-source code,
offline, with no Aqta server in the trust path. What that does and does not establish is set
out honestly in [THREAT-MODEL.md](./THREAT-MODEL.md).

## 1. Install the published verifier (about 10 seconds)

TypeScript/Node (current counsel-grade release; pinning required by default):

```bash
npm install aqta-verify-receipt@1.0.4
```

Python (registry catch-up may lag npm; always pass `trusted_public_key`):

```bash
pip install aqta-verify-receipt
```

Both are reference implementations of the spec in this repository, small enough to read
before you run them.

## 2. Fetch the issuer's published production key (5 seconds)

```bash
curl https://api.aqta.ai/v1/attestation/public-key
```

Returns the raw 32-byte Ed25519 key (base64url), plus pointers back to this spec and the
verifiers:

```json
{"public_key":"gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE","key_id":"aqta-att-0a18c7c16bc18a12","algorithm":"Ed25519", ...}
```

Note `key_id` and `algorithm` here are fields of the *key endpoint*, not of a receipt: the
receipt envelope itself is exactly the twelve canonical fields in the spec and carries its
signing key in `public_key`.

## 3. Verify the signed sample (10 seconds)

This repository ships a signed receipt at
[examples/sample-receipt.json](./examples/sample-receipt.json). It is signed with a
demonstration key (embedded in its own `public_key`), not the production key, which matters
in step 4.

Python:

```python
import json
from aqta_verify_receipt import verify_receipt

receipt = json.load(open("examples/sample-receipt.json"))
# Pin to the receipt's own embedded key: checks integrity and that it was
# signed by the key it claims.
result = verify_receipt(receipt, trusted_public_key=receipt["public_key"], strict_fields=True)
print(result)   # VerifyResult(valid=True, reason=None)
```

TypeScript:

```ts
import { verifyReceipt } from 'aqta-verify-receipt';
import receipt from './examples/sample-receipt.json';
const result = verifyReceipt(receipt, { trustedPublicKey: receipt.public_key });
if (!result.valid) throw new Error(result.reason);   // valid: true
```

Both implementations return valid on this sample. No network access happens during
verification: turn your wifi off first if you want to make the point to yourself.

## 4. Understand key pinning (the part that matters)

A valid signature only proves *someone* signed the receipt, not that Aqta did: anyone can
self-sign a well-formed receipt with their own keypair. Identity comes from pinning the
receipt's embedded key to the issuer's published key. Pin the demonstration sample to the
production key from step 2 and it correctly fails:

```python
verify_receipt(receipt, trusted_public_key="gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE")
# VerifyResult(valid=False, reason='public_key does not match trusted key')
```

That failure is the point: a real production receipt embeds, and pins to, the production key;
this demonstration receipt does not, and the verifier says so.

## 5. Try to break it

- Change one character of `model` or `outcome` and re-run: `valid: false`.
- Add any thirteenth top-level field: `valid: false` under strict mode (the spec forbids
  extra fields in v1).
- Run the conformance vectors in [CONFORMANCE.md](./CONFORMANCE.md): 14 vectors, 6 valid and
  8 deliberately invalid (wrong signature, mutated fields, malformed hashes, unknown fields).
  A conformant verifier must agree on all 14.
- There is also an in-browser verifier at [aqta.ai/verify](https://aqta.ai/verify) that runs
  the same check client-side and pre-verifies a signed sample on load.

## 6. Verifying a receipt issued to you

When Seal issues a receipt for one of your calls, it is shareable at
`https://app.aqta.ai/r/<id>`, and the JSON at `https://app.aqta.ai/api/r/<id>` is the
spec-pure twelve-field envelope, so it verifies with the commands above and no massaging.
Pin it to the production key from step 2 to confirm it is a genuine Aqta receipt.

## 7. What you have and have not established

You have established: this receipt was signed by the holder of the key it embeds and has not
been altered, and whether that key is Aqta's. You have not established that the model named
in the receipt is what actually ran, or that the signer's account of the decision is true.
Those limits, and the ones around key custody, ordering and completeness, are the subject of
[THREAT-MODEL.md](./THREAT-MODEL.md), which we wrote against our own system.
