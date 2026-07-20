# ATTESTATION-v1

<p align="center">
  <strong>Don't just log the model call. Prove the enforcement ran.</strong><br/>
  <sub>Open format and reference verifiers for AI enforcement receipts. Ed25519. Offline-verifiable. Independent of the issuer's servers.</sub>
</p>

<p align="center">
  <a href="https://github.com/Aqta-ai/attestation-spec/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/Aqta-ai/attestation-spec/test.yml?branch=main&label=CI" alt="CI"></a>
  <a href="https://pypi.org/project/aqta-verify-receipt/"><img src="https://img.shields.io/pypi/v/aqta-verify-receipt.svg" alt="PyPI"></a>
  <a href="https://www.npmjs.com/package/aqta-verify-receipt"><img src="https://img.shields.io/npm/v/aqta-verify-receipt.svg" alt="npm"></a>
  <a href="./spec/ATTESTATION-v1.md"><img src="https://img.shields.io/badge/spec-CC--BY--4.0-lightgrey.svg" alt="Spec CC-BY-4.0"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/code-Apache--2.0-blue.svg" alt="Code Apache-2.0"></a>
</p>

<p align="center">
  <a href="https://aqta.ai/verify"><strong>▶ Check a receipt in the browser</strong></a>
  · <a href="./VERIFY-WALKTHROUGH.md">5-minute offline walkthrough</a>
  · <a href="./THREAT-MODEL.md">Threat model</a>
</p>

## What this is

This repository is the open specification and reference verifier libraries for
**enforcement attestation receipts**: cryptographic proof that an AI gateway
decided whether a model call was allowed to run.

It is **not** the managed gateway service. It is the format, two reference
verifiers, a stand-alone reference issuer, and a conformance suite so a third
party can verify a receipt, or build their own conformant issuer or verifier,
without trusting the issuer's servers.

## Ordinary logs vs enforcement receipts

| Ordinary logs | ATTESTATION-v1 receipts |
|---|---|
| Issuer says it happened | Anyone can verify the signature offline |
| Mutable after the fact | Signature breaks on tamper |
| No independent check | Check against a published public key |
| Trust the log host | No call to the issuer required |

Use logs for observability. Use a receipt when you need evidence of the
enforcement decision.

What a valid receipt proves, and what it does **not** prove, is stated in
[THREAT-MODEL.md](./THREAT-MODEL.md) and [WHAT-RECEIPTS-PROVE.md](./WHAT-RECEIPTS-PROVE.md).
Short version: a signature proves what the gateway *said*, not what the
provider's compute *did*.

## Where this sits

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│  Enterprise  │      │   Gateway    │      │     LLM      │
│     app      │─────▶│  (enforces   │─────▶│   provider   │
└──────────────┘      │   policy)    │      └──────────────┘
                      └──────┬───────┘
                             │  Ed25519-signed receipt
                             ▼
                      ┌──────────────┐      ┌──────────────┐
                      │   Receipt    │─────▶│   Auditor    │
                      │  (inline w/  │      │  verifies    │
                      │   response)  │      │  locally     │
                      └──────────────┘      └──────────────┘
```

The receipt binds `request_hash`, `model`, `outcome`
(`ALLOWED` / `BLOCKED` / `SUPPRESSED`), and `policy_applied` under the
issuer's key. Adjacent work often attests **agent tool calls**; this format
attests the **gateway enforcement decision** before the model runs.

## Verify in 30 seconds

```bash
pip install aqta-verify-receipt
# or: npm install aqta-verify-receipt
```

```python
from aqta_verify_receipt import verify_receipt, fetch_published_public_key

trusted = fetch_published_public_key()   # fetch once, then pin
result = verify_receipt(receipt, trusted_public_key=trusted)

print(result.valid)
```

Pin the key. Re-fetching on every verification collapses the trust model back
to "trust the issuer's server right now". See the package READMEs.

Browser: [aqta.ai/verify](https://aqta.ai/verify). CLI walkthrough:
[VERIFY-WALKTHROUGH.md](./VERIFY-WALKTHROUGH.md).

## Contents

- 📄 **[ATTESTATION-v1](./spec/ATTESTATION-v1.md)** — receipt format (CC-BY-4.0). Status: draft for public review.
- 🐍 **[packages/verify-receipt-py](./packages/verify-receipt-py)** — Python verifier on [PyPI](https://pypi.org/project/aqta-verify-receipt/).
- 🟦 **[packages/verify-receipt](./packages/verify-receipt)** — TypeScript verifier on [npm](https://www.npmjs.com/package/aqta-verify-receipt).
- 🧪 **[examples/reference-issuer.py](./examples/reference-issuer.py)** — minimal stand-alone issuer for vectors and interop.
- 📋 **[test-vectors/](./test-vectors)** — six valid, eight invalid receipts.
- 📏 **[CONFORMANCE.md](./CONFORMANCE.md)** — issuer and verifier conformance.
- 🛡 **[THREAT-MODEL.md](./THREAT-MODEL.md)** — trust assumptions and attacks.
- 📑 **[WHAT-RECEIPTS-PROVE.md](./WHAT-RECEIPTS-PROVE.md)** — gateway layer vs hardware attestation.

## Conformance

```bash
cd packages/verify-receipt
npm install && npm run build
cd ../..
node scripts/make-interop-fixture.mjs
```

Python issuer signs; TypeScript verifier accepts. Independent implementations
must also pass every vector in [`test-vectors/`](./test-vectors/). See
[CONFORMANCE.md](./CONFORMANCE.md).

## Relationship to open standards

ATTESTATION-v1 is a purpose-built JSON + Ed25519 envelope for gateway
enforcement receipts. It is **adjacent to, not conforming to**:

| Standard | Relationship |
|---|---|
| **SCITT** / **COSE** | Same problem family (signed statements about artifacts). Different envelope; no COSE_Sign1 or SCITT Receipt claim set in v1. |
| **W3C Verifiable Credentials** | Same "portable signed claim" idea. v1 is not a VC data model. |
| **in-toto / SLSA** | Supply-chain attestation of builds. This format attests inference-time enforcement, not build provenance. |
| **Sigstore / DSSE** | Rekor-style transparency is a stronger omission defence than v1's per-receipt signatures. Anchoring to an append-only log is planned work, not shipped in v1. |

We publish this so auditors can verify without us, and so other issuers can
implement the same format. We do not claim this is an IETF standard or a drop-in
for SCITT.

## Why it is published

Auditors who rely on enforcement receipts need to verify them without trusting
the issuer's servers. A vendor-only stamp is not evidence. Publishing the spec
and the verifiers is the credibility floor.

## Licences

- **Code** (`packages/`, `examples/`, `scripts/`, `test-vectors/`): [Apache License 2.0](./LICENSE).
- **Specification** (`spec/`): [Creative Commons Attribution 4.0 International (CC-BY-4.0)](./LICENSE-SPEC).

GitHub's licence badge reports Apache-2.0 for the repository root. The
specification remains CC-BY-4.0 so other issuers can adopt the format without
software-licence friction.

## Learn more

- Browser verifier: https://aqta.ai/verify
- Published production key: https://api.aqta.ai/v1/attestation/public-key
- Managed issuer (optional): https://app.aqta.ai
- Disclosure policy: [SECURITY.md](./SECURITY.md)
- Change history: [CHANGELOG.md](./CHANGELOG.md)
- How to contribute: [CONTRIBUTING.md](./CONTRIBUTING.md)
