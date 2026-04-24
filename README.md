# AqtaCore Attestation Specification

> The open specification and reference verifier libraries for **AqtaCore
> attestation receipts**: cryptographic proof that an AI enforcement
> decision actually ran.

[![CI](https://github.com/Aqta-ai/attestation-spec/actions/workflows/test.yml/badge.svg)](https://github.com/Aqta-ai/attestation-spec/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/aqta-verify-receipt.svg)](https://pypi.org/project/aqta-verify-receipt/)
[![Spec CC-BY-4.0](https://img.shields.io/badge/spec-CC--BY--4.0-lightgrey.svg)](./spec/ATTESTATION-v1.md)
[![Code Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue.svg)](./LICENSE)

## What this is

AqtaCore is a managed service that sits between enterprise AI applications
and the model providers. Every enforcement decision AqtaCore makes returns
a **signed receipt**: Ed25519, hash-chained on export, independently
verifiable.

This repository is **not** the AqtaCore service. It is the open spec, two
reference verifier libraries, a stand-alone reference issuer, and a
conformance test suite so that any third party can verify a receipt, or
build their own compliant issuer or verifier.

## The trust model in one picture

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│  Enterprise  │      │   AqtaCore   │      │     LLM      │
│     app      │─────▶│   gateway    │─────▶│   provider   │
└──────────────┘      └──────┬───────┘      └──────────────┘
                             │
                             │  Ed25519-signed
                             │    attestation
                             ▼
                      ┌──────────────┐      ┌──────────────┐
                      │   Receipt    │      │   Auditor    │
                      │   (inline    │─────▶│     or       │
                      │  w/ response)│      │  regulator   │
                      └──────────────┘      └──────┬───────┘
                                                   │
                                    verify locally with
                                    aqta-verify-receipt and
                                    the published public key
                                    (no contact with AqtaCore)
```

Every receipt is self-describing. The auditor never has to trust
AqtaCore's servers.

## Contents

- 📄 **[ATTESTATION-v1](./spec/ATTESTATION-v1.md)**: the open
  specification for the receipt format, CC-BY-4.0.
- 🐍 **[packages/verify-receipt-py](./packages/verify-receipt-py)**:
  reference Python verifier, Apache 2.0, on
  [PyPI](https://pypi.org/project/aqta-verify-receipt/).
- 🟦 **[packages/verify-receipt](./packages/verify-receipt)**: reference
  TypeScript verifier, Apache 2.0, npm publication pending.
- 🧪 **[examples/reference-issuer.py](./examples/reference-issuer.py)**:
  stand-alone minimal issuer, used for test-vector generation and the
  cross-implementation interop test.
- 📋 **[test-vectors/](./test-vectors)**: deterministic conformance
  vectors for third-party verifiers; six valid, eight invalid, each
  documenting a specific behaviour.
- 📏 **[CONFORMANCE.md](./CONFORMANCE.md)**: what it takes for an
  independent implementation to claim ATTESTATION-v1 conformance.

## Why it is published

Regulators, auditors, and internal compliance teams who rely on AqtaCore
receipts need to be able to verify them **without trusting AqtaCore's
servers**. An auditor who could not independently verify a receipt would
not trust a vendor-stamped receipt in the first place.

Publishing the spec and the verifiers is the credibility floor for the
product.

## Verify a receipt in 30 seconds

```bash
pip install aqta-verify-receipt
```

```python
from aqta_verify_receipt import verify_receipt, fetch_published_public_key

trusted = fetch_published_public_key()   # pin once
result = verify_receipt(receipt, trusted_public_key=trusted)

print(result.valid)   # → True if the signature is genuine
```

The TypeScript verifier mirrors this API (pending npm publication; clone
from this repo and build locally in the meantime).

## Conformance

Any issuer or verifier claiming ATTESTATION-v1 conformance must pass the
cross-implementation interop test:

```bash
cd packages/verify-receipt
npm install && npm run build
cd ../..
node scripts/make-interop-fixture.mjs
```

This generates a receipt with the reference issuer (Python) and verifies
it with the reference verifier (TypeScript). If both sides agree on the
canonical payload, signing, and verification rules, the test exits 0.

Independent verifiers should additionally pass every vector in
[`test-vectors/`](./test-vectors/). See [CONFORMANCE.md](./CONFORMANCE.md)
for the full requirements.

## Licences

- **Specification** (`spec/`): Creative Commons Attribution 4.0
  International (CC-BY-4.0).
- **Code** (`packages/`, `examples/`, `scripts/`, `test-vectors/`):
  Apache License 2.0.

## Learn more

- **AqtaCore managed service:** https://app.aqta.ai
- **Security and published public key:** https://app.aqta.ai/security
- **Disclosure policy:** [SECURITY.md](./SECURITY.md)
- **Change history:** [CHANGELOG.md](./CHANGELOG.md)
- **How to contribute:** [CONTRIBUTING.md](./CONTRIBUTING.md)
