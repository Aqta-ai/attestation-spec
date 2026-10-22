<p align="center">
  <img src="https://aqta.ai/brand/seal-mark-512.png" alt="Seal" width="96" height="96" />
</p>

# aqta-verify-receipt

[![npm](https://img.shields.io/npm/v/aqta-verify-receipt.svg)](https://www.npmjs.com/package/aqta-verify-receipt)
[![PyPI](https://img.shields.io/pypi/v/aqta-verify-receipt.svg)](https://pypi.org/project/aqta-verify-receipt/)
[![Licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

**Check what an AI was allowed to do, without trusting the company that ran it.**

Seal signs each AI decision that passes through it, at the moment it happens: model calls and agent actions, refusals included. This package checks those signed records on your own machine. No account, no call to Aqta. Change one field and the check fails.

## Try it in 10 seconds

```bash
curl -sO https://app.aqta.ai/samples/sample-receipt.json
npx aqta-verify-receipt sample-receipt.json --key 9Y3Eiq6V8QjRDUM5nPqSwKIOPQaoEU4SbagfYFdvWa4
# ✓ valid  ALLOWED  520a…853a94  pinned issuer key
```

Now change `"outcome"` in the file and run it again:

```text
✕ invalid  signature check failed  520a…853a94
```

## Why it exists

- A log is kept by whoever runs the system. A signed record can be checked by anyone else, offline, against a published key.
- Two verifiers, written separately: this one and the Python (PyPI) one. They must return the same verdict on every published test vector.
- In use: [Authority Arena](https://arena.aqta.ai), an open evaluation of 21 AI models, checks all 1,529 of its signed records with this package.

## 30-second check

```bash
npx aqta-verify-receipt receipt.json \
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

Optional human-readable summary (the compact line and exit code are the result):

```bash
npx aqta-verify-receipt receipt.json --key <pinned> --pretty
# …
◈ seal intact · verified offline
```

Automation:

```bash
npx aqta-verify-receipt receipt.json --key <pinned> --json
npx aqta-verify-receipt receipt.json --key <pinned> -q; echo $?
```

| Exit | Meaning |
|------|---------|
| `0` | valid |
| `1` | invalid |
| `2` | usage / IO |

Production public key (also at
[`/v1/attestation/public-key`](https://api.aqta.ai/v1/attestation/public-key),
key id `aqta-att-01269bb4b6a7d950`):

```
9Y3Eiq6V8QjRDUM5nPqSwKIOPQaoEU4SbagfYFdvWa4
```

Pin that string; do not re-fetch it inside a verify loop. Keys rotate and
receipts do not: a receipt verifies against the key current when it was
signed, and the permanent key record (with retired keys and their validity
windows) is at
[`app.aqta.ai/security/issuer-keys.txt`](https://app.aqta.ai/security/issuer-keys.txt).

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
aqta-verify-receipt <file|-> --key <base64url> [options]
aqta-verify-receipt <file|-> --integrity-only [options]
```

| Flag | Meaning |
|------|---------|
| `--key` | Pin the issuer key. Required unless `--integrity-only`. |
| `--integrity-only` | Signature vs embedded key only; returns untrusted. Anyone can self-sign. |
| `--no-strict` | Allow unknown top-level fields |
| `--json` | One JSON object on stdout |
| `--pretty` | Optional human-readable summary after the compact line |
| `-q` | Silent; exit code only |

`NO_COLOR=1` disables colour. Meaning never depends on colour alone.

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

Conformance suite, covering receipts, agent action records and transparency proofs:
[`test-vectors/`](https://github.com/Aqta-ai/attestation-spec/tree/main/test-vectors).

## Chain profile (draft)

GRANT-v1 and USE-v1 are **draft specifications, not frozen**; their wire
formats may change. `--profile chain` checks a bundle of GRANT-v1 approvals,
USE-v1 records and the ACTION-v1 records they authorised, and returns `PASS`,
`FAIL` or `INCOMPLETE`. Missing evidence is `INCOMPLETE`, never `PASS`, and
without `--approver-keys` an authorised action is `INCOMPLETE`.

```bash
npx aqta-verify-receipt bundle.json --profile chain --key <issuer key> --approver-keys <k1,k2>
```

Exit 0 `PASS`, 1 `FAIL`, 3 `INCOMPLETE`, 2 usage or IO. `--key` is required;
`--integrity-only` and `--no-strict` are refused. Library:
`require('aqta-verify-receipt/dist/chain.js').verifyChain(bundle, { trustedPublicKey, approverKeys })`.
Opt-in only: nothing selects this profile from a record's shape. The two
separately written verifiers, this one and the Python one, must return the
same verdict and reason on every vector in
[`test-vectors/chain/`](https://github.com/Aqta-ai/attestation-spec/tree/main/test-vectors/chain).

## Transparency proofs

A receipt signature answers what the issuer asserted. It cannot answer whether
that entry is in the issuer's log, or whether the log has only ever grown.
Those are different questions, so they get a different command.

```bash
npx -p aqta-verify-receipt aqta-verify-proof inclusion.json
npx -p aqta-verify-receipt aqta-verify-proof consistency.json
npx -p aqta-verify-receipt aqta-verify-proof sth.json --key <pinned>
```

RFC 6962 inclusion and consistency verification, plus the signed-tree-head
signature. Written separately in TypeScript and Python rather than ported, and
checked against the transparency vectors in the repository. Adds no dependency:
hashing uses the runtime.

```ts
import { verifyInclusionProof, verifyConsistencyProof } from 'aqta-verify-receipt';

const result = verifyInclusionProof(proof);
if (!result.valid) throw new Error(result.reason);
```

An inclusion proof establishes that what you were shown is genuinely in the
log. It does not establish that what you were **not** shown is irrelevant.
That is omission, and it is open.

## Scope

A small offline verifier for signed decision records and the log proofs that accompany them. It reads a
record and a key, and reports a verdict. It does not store, send or host records, and it never contacts Aqta.

## Security

Cryptographic issues: see [SECURITY.md](../../SECURITY.md). Prefer
security@aqta.ai over public issues for key or signature bugs.

## Licence

Apache-2.0. Aqta Technologies Limited.

If you implement or cite the ATTESTATION-v1 format itself, credit under
CC-BY-4.0: see the repo [CITATION.cff](https://github.com/Aqta-ai/attestation-spec/blob/main/CITATION.cff).
