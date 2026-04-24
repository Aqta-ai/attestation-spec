# Security Policy

## Reporting a vulnerability

Thank you for taking the time to report a security issue in the AqtaCore
attestation specification or the reference verifier libraries in this
repository.

**Please do not open a public GitHub issue for anything that could be a
signature-forgery, key-disclosure, or similar cryptographic flaw.**

### How to report

Email **security@aqta.ai** with:

- A description of the issue.
- Steps to reproduce, if applicable.
- The affected component (for example: the Python verifier, the
  TypeScript verifier, the canonicalisation rule in the spec, the
  reference issuer example).
- Whether you have already tested the behaviour against an issuer other
  than the reference implementation.

We aim to acknowledge reports within two working days and to publish a
remediation plan within ten working days for confirmed issues.

### What counts as a security issue

- Signature forgery against a receipt that was produced by a conformant
  issuer.
- Any way to make a verifier return `valid: true` for a tampered receipt.
- A deviation in the canonicalisation rule of §6 that allows two
  semantically-equivalent payloads to produce different canonical bytes
  (and therefore different signatures).
- Private-key leakage paths from the reference issuer example (noting
  that the example is documented as non-production and not suitable for
  handling real signing keys).
- Denial-of-service paths in the verifiers that a malicious receipt can
  trigger (excessive memory allocation, unbounded loops, etc.).

### What is out of scope

- The security of the AqtaCore managed service itself. Those reports
  belong on the service's own disclosure channel at
  https://app.aqta.ai/security.
- Vulnerabilities in the upstream `cryptography` (Python) or `tweetnacl`
  (JavaScript) libraries. Please report those to the upstream projects;
  we will upgrade the pin once a fix ships.
- Issues in third-party issuers or verifiers that claim ATTESTATION-v1
  conformance. Please contact the implementer; we are happy to
  coordinate disclosure for cross-implementer issues.

### Disclosure policy

We prefer coordinated disclosure. Once a fix is available:

- A patch release is cut for the affected package.
- A security advisory is opened on this repository's GitHub Security
  Advisories tab.
- Credit is given to the reporter in the advisory, unless the reporter
  prefers to remain anonymous.

Thank you for keeping the attestation ecosystem honest.
