# AqtaCore Attestation Specification

> The open specification and reference verifier libraries for **AqtaCore
> attestation receipts**: cryptographic proof that an AI enforcement
> decision actually ran.

[![PyPI](https://img.shields.io/pypi/v/aqta-verify-receipt.svg)](https://pypi.org/project/aqta-verify-receipt/)
[![Spec CC-BY-4.0](https://img.shields.io/badge/spec-CC--BY--4.0-lightgrey.svg)](./spec/ATTESTATION-v1.md)
[![Code Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue.svg)](./LICENSE)

## What this is

AqtaCore is a managed service that sits between enterprise AI applications
and the model providers. Every enforcement decision AqtaCore makes returns
a **signed receipt**: Ed25519, hash-chained on export, independently
verifiable.

This repository is **not** the AqtaCore service. It is:

- 📄 **[ATTESTATION-v1](./spec/ATTESTATION-v1.md)**: the open specification
  for the receipt format, published under CC-BY-4.0.
- 🐍 **[packages/verify-receipt-py](./packages/verify-receipt-py)**:
  reference Python verifier, Apache 2.0, on [PyPI](https://pypi.org/project/aqta-verify-receipt/).
- 🟦 **[packages/verify-receipt](./packages/verify-receipt)**: reference
  TypeScript verifier, Apache 2.0, npm publication pending.
- 🧪 **[examples/reference-issuer.py](./examples/reference-issuer.py)**:
  stand-alone minimal issuer for generating test vectors and understanding
  the format end to end.

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
# From the repo root:
cd packages/verify-receipt
npm install && npm run build
cd ../..
node scripts/make-interop-fixture.mjs
```

This generates a receipt with the reference issuer (Python) and verifies
it with the reference verifier (TypeScript). If both sides agree on the
canonical payload, signing, and verification rules, the test exits 0.

The public reference issuer is intentionally minimal (format only). A
production issuer additionally manages the private key in a secure
enclave, enforces policy before signing, and maintains a tamper-evident
audit log. All of these are the responsibility of the
[AqtaCore](https://app.aqta.ai) managed service.

## Licences

- **Specification** (`spec/`): Creative Commons Attribution 4.0
  International (CC-BY-4.0).
- **Code** (`packages/`, `examples/`, `scripts/`): Apache License 2.0.

## Learn more

- **AqtaCore managed service:** https://app.aqta.ai
- **Security and published public key:** https://app.aqta.ai/security
- **Issue tracker for the spec:** file bugs and questions via GitHub
  Issues on this repository.
