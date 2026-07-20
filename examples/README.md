# Examples

Minimal stand-alone tooling for ATTESTATION-v1. Not a production issuer.

| File | Purpose |
|---|---|
| [`reference-issuer.py`](./reference-issuer.py) | Sign a receipt for interop and vector generation |
| [`sample-receipt.json`](./sample-receipt.json) | Deterministic example receipt |

## Quick path

```bash
# Generate a throwaway key and a signed receipt (see script --help)
python3 examples/reference-issuer.py --help

# Verify with the published packages (install from registry)
pip install aqta-verify-receipt
# or: npm install aqta-verify-receipt
```

Full offline walkthrough: [`../VERIFY-WALKTHROUGH.md`](../VERIFY-WALKTHROUGH.md).
Conformance vectors: [`../test-vectors/`](../test-vectors/).
