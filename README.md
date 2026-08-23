<p align="center">
  <img src="https://aqta.ai/brand/seal-mark-512.png" alt="Seal" width="96" height="96" />
</p>

# ATTESTATION-v1 · ACTION-v1

Open formats and reference verifiers for **Seal** records: what an AI
decided, and what an agent was allowed to do. Ed25519. Offline-verifiable.
No call to the issuer required.

[![CI](https://img.shields.io/github/actions/workflow/status/Aqta-ai/attestation-spec/test.yml?branch=main&label=CI)](https://github.com/Aqta-ai/attestation-spec/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/aqta-verify-receipt.svg)](https://pypi.org/project/aqta-verify-receipt/)
[![npm](https://img.shields.io/npm/v/aqta-verify-receipt.svg)](https://www.npmjs.com/package/aqta-verify-receipt)
[![Spec CC-BY-4.0](https://img.shields.io/badge/spec-CC--BY--4.0-lightgrey.svg)](./LICENSE-SPEC)
[![Code Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue.svg)](./LICENSE)

**[Check a receipt in the browser](https://aqta.ai/verify)** ·
[ATTESTATION-v1](./spec/ATTESTATION-v1.md) ·
[ACTION-v1](./spec/ACTION-v1.md) ·
[5-minute walkthrough](./VERIFY-WALKTHROUGH.md)

## What this is

Two record formats in one family, signed by the same key and checked by the
same verifiers:

| Format | Answers | Fields |
|---|---|---|
| [**ATTESTATION-v1**](./spec/ATTESTATION-v1.md) | What did the gateway decide about this model call? | 12 |
| [**ACTION-v1**](./spec/ACTION-v1.md) | What was this agent allowed to do? | 14 |

`ACTION-v1` covers agent tool actions: a declared tool call authorised or
refused under policy before it runs, bound to the session's registered
intent, with the arguments hashed canonically. A refusal is a record in its
own right. It is a **sibling format, not a new version**: the v1 receipt
envelope is untouched and every existing receipt verifies exactly as before.
Profile selection is always explicit, never guessed from field shape:

```bash
npx aqta-verify-receipt record.json --profile action-1 --key <key>
```

Anyone with the issuer's published public key can verify either offline.

This repo is the **formats**, two **reference verifiers**, stand-alone
**reference issuers**, and **50 test vectors**. It is not the managed Seal
gateway ([app.aqta.ai](https://app.aqta.ai)).

A valid signature proves what the gateway *said*, not what the provider's
compute *did*. Details: [WHAT-RECEIPTS-PROVE.md](./WHAT-RECEIPTS-PROVE.md),
[THREAT-MODEL.md](./THREAT-MODEL.md).

## Verify (pin the key)

```bash
pip install aqta-verify-receipt
# or: npm install aqta-verify-receipt
```

```python
from aqta_verify_receipt import verify_receipt, fetch_published_public_key

trusted = fetch_published_public_key()  # once, then pin
result = verify_receipt(receipt, trusted_public_key=trusted)
print(result.valid)
```

From **v1.0.4**, a pinned `trusted_public_key` is required by default.
Verifying against the key embedded in the receipt alone only proves
integrity, not issuer identity. CLI: `--key <pinned>` or `--integrity-only`.

Current production key (also at
[`/v1/attestation/public-key`](https://api.aqta.ai/v1/attestation/public-key)):

```
9Y3Eiq6V8QjRDUM5nPqSwKIOPQaoEU4SbagfYFdvWa4
```

Keys rotate; receipts do not. A receipt verifies against the key that was
current when it was signed. The permanent key record, including retired keys
and their validity windows, is at
[`app.aqta.ai/security/issuer-keys.txt`](https://app.aqta.ai/security/issuer-keys.txt).

## What you'll see

Default output is one compact line. Words carry the verdict; colour is optional.

```console
$ aqta-verify-receipt test-vectors/valid/001-allowed.json --integrity-only
✓ valid  ALLOWED  0000…0001  untrusted embedded key (integrity only)
```

Tampered signature:

```console
$ aqta-verify-receipt test-vectors/invalid/001-tampered-signature.json --integrity-only
✕ invalid  signature mismatch  0000…ffff
```

Exit `0` valid, `1` invalid, `2` usage/IO. `--json` for automation. `--pretty`
adds a short flourish (`seal intact · verified offline`); it is never the proof.

`--integrity-only` checks the receipt against the key embedded in it, which
proves internal consistency but not who issued it. Pass `--key` with the
published key above to bind it to the issuer.

## Contents

| Path | What |
|---|---|
| [spec/ATTESTATION-v1.md](./spec/ATTESTATION-v1.md) | Wire format (CC-BY-4.0) |
| [packages/verify-receipt-py](./packages/verify-receipt-py) | Python verifier ([PyPI](https://pypi.org/project/aqta-verify-receipt/)) |
| [packages/verify-receipt](./packages/verify-receipt) | TypeScript verifier ([npm](https://www.npmjs.com/package/aqta-verify-receipt)) |
| [examples/](./examples) | Reference issuer and sample receipt |
| [test-vectors/](./test-vectors) | Known-good and known-bad receipts |
| [CONFORMANCE.md](./CONFORMANCE.md) | Issuer and verifier expectations |
| [RELATIONSHIP-TO-SCITT.md](./RELATIONSHIP-TO-SCITT.md) | Where this sits against RFC 9943, and where it is weaker |

Run the whole suite from a clean checkout. Each block is independent, so you can
paste them one at a time or all together.

```bash
# Python verifier: 38 tests
pip install -e packages/verify-receipt-py
pip install pytest cryptography
pytest packages/verify-receipt-py/tests/ -q

# TypeScript verifier: 11 tests. The build step is required, dist/ is not committed.
(cd packages/verify-receipt && npm ci && npm run build && npm test)

# Cross-implementation check: every test vector, both verifiers, same verdict.
node scripts/make-interop-fixture.mjs
```

## Attribution

Please credit the authors when you implement, fork, cite, or redistribute.

**Specification** (`spec/`): [CC-BY-4.0](./LICENSE-SPEC). You must give
appropriate credit to **Aqta Technologies Ltd**, link the licence, and note
if you changed the text. Suggested credit line:

> ATTESTATION-v1 by Aqta Technologies Ltd,
> https://github.com/Aqta-ai/attestation-spec
> (CC-BY-4.0)

**Code** (`packages/`, `examples/`, `scripts/`, `test-vectors/`):
[Apache-2.0](./LICENSE). Keep copyright and licence notices when you
redistribute.

Machine-readable citation: [CITATION.cff](./CITATION.cff)
(GitHub → Cite this repository).

ATTESTATION-v1 is adjacent to SCITT/COSE, W3C Verifiable Credentials, and
in-toto/SLSA. It is not a conforming profile of those standards.

## Links

- Browser verifier: https://aqta.ai/verify
- Published key: https://api.aqta.ai/v1/attestation/public-key
- Security: [SECURITY.md](./SECURITY.md)
- Changelog: [CHANGELOG.md](./CHANGELOG.md)
- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)
