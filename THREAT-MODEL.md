# Threat model: ATTESTATION-v1 and the AqtaCore issuer

A self-authored adversarial analysis of our own system. We wrote this because a verification
format that does not state its own trust assumptions is asking to be trusted, which is the
failure mode this project exists to remove. Reporting a flaw: see [SECURITY.md](./SECURITY.md).

Scope: the ATTESTATION-v1 envelope, the published reference verifiers (v1.0.2 on PyPI and
npm), and the production AqtaCore issuer (signing since April 2026).

## What a receipt actually proves

A valid receipt proves exactly two things:

1. **Origin**: the envelope was signed by the holder of the Ed25519 key embedded in its
   `public_key` field.
2. **Integrity**: no canonical field has changed since signing.

Everything else in the envelope (model, outcome, policy list, timestamp, request hash) is a
**claim by the signer**, made tamper-evident but not independently true. That distinction
drives every row below. The v1 envelope is exactly twelve fields and no others (see the
spec); there is no `key_id`, no algorithm field, and no chain pointer in v1. Where those
would help is called out honestly under each gap.

## Trust assumptions, stated plainly

| # | Assumption | If it fails |
|---|---|---|
| A1 | The `public_key` in a receipt really is the issuer's, and its private half is held only by the issuer | Forged receipts indistinguishable from real ones |
| A2 | The issuer (the gateway) truthfully records what it decided and forwarded | Receipts are honest-looking statements of false events |
| A3 | The model named in the receipt is what the provider actually ran | The receipt attests the request, not the compute |
| A4 | The issuer's clock is honest | Timestamps are signer-asserted, not proven |
| A5 | The set of receipts a verifier sees is complete | Omission is invisible to per-receipt verification |

## Adversaries and attacks

**Signature forgery (outsider).** Breaking Ed25519 or the canonicalisation. Mitigated by
standard cryptography (RFC 8032 over canonical JSON) and by verifier strictness: the
published verifier rejects unknown top-level fields and malformed values, and the repository
ships conformance vectors (6 valid, 8 invalid) an independent implementation must agree on.
Residual risk: implementation bugs; both verifiers are open source and deliberately small.

**Key substitution (the important subtlety).** A receipt is self-verifying against its own
embedded `public_key`, so a valid signature alone only proves "someone signed this", not
"Aqta signed this": an attacker can self-sign a well-formed receipt with their own keypair.
The defence is **key pinning**: a verifier must compare the receipt's embedded `public_key`
against the issuer's published production key (served at
`https://api.aqta.ai/v1/attestation/public-key` and shown on the aqta.ai/verify page) and
treat any other key as untrusted even when the signature checks out. The reference verifiers
expose this as the `trusted_public_key` argument; using them without it checks integrity but
not identity.

**Key theft (insider or intruder).** The production signing key is a single Ed25519 key held
in the serving environment's configuration, not an HSM. This is our largest honest gap at
the custody layer. Mitigations today: the key never leaves the signing service, and each
receipt embeds the `public_key` it was signed with, so a rotation is detectable by verifiers
that pin. Planned: hardened custody and a public key-transparency story so a silent key swap
is externally visible.

**Malicious or compromised issuer (the hard one).** A gateway that lies signs lies. This is
assumption A2 and no gateway-level signature can remove it: **a signature proves what the
signer said, not what the compute did.** This is the boundary between application-layer
attestation (this spec) and workload attestation (TEE quotes, hardware-rooted mechanisms
such as guarantee processors). Our position: receipts are the deployed, portable layer above
that boundary; binding them downward to hardware-rooted workload identity is open work, not a
solved feature. We say so in public because a buyer or regulator who discovers it later
should never feel it was hidden.

**Backdating and clock fraud.** `timestamp` is signer-asserted (A4). v1 receipts are
**independently signed and not chained to one another**, so v1 alone does not prove ordering
or bound backdating: the only in-band evidence of time is the signed timestamp itself. A
chained variant (`prev_attestation_id` plus a running hash) is a documented v2 extension, and
anchoring issuance to an external append-only log is the stronger fix. Neither ships in v1;
do not read ordering guarantees into a v1 receipt.

**Replay and re-presentation.** A valid receipt can be shown twice; it cannot be altered.
Receipts are unique by `attestation_id` and bound to a `request_hash` (full 64-char SHA-256),
so re-presentation proves only what it always proved. Consumers correlating receipts to
business events should key on `attestation_id`.

**Omission (A5).** Because v1 receipts are not chained, a verifier holding some receipts
cannot tell whether others were withheld: per-receipt verification sees presence, never
absence. Denied requests are audit-logged rather than receipt-signed, so the receipt stream
alone is deliberately not a complete account of traffic and is not presented as one.
Completeness needs an anchored, publicly auditable log; that is roadmap, not shipped.

**Quantum adversary.** Ed25519 is not post-quantum secure; a cryptographically relevant
quantum computer forges against any captured public key. Crypto-agility in v1 comes from the
`v` version field: the migration path is a v2 envelope format, whose documented target is
hybrid signing with ML-DSA-65 (NIST FIPS 204) alongside Ed25519. Production today is
classical Ed25519 and we do not claim otherwise.

## Gaps we have not closed, ranked

1. **Workload binding (A3).** Nothing binds a receipt to the weights and code that produced
   the response. Closing it means anchoring receipts to TEE-based workload attestation or
   hardware-rooted mechanisms; this is the research edge of the field, not our shipped layer.
2. **Signer trust (A2).** Structural: mitigable by transparency (public logs, third-party
   verifiers, transparency-service receipts over our receipts), never by our own signature.
3. **Key custody (A1).** Single key in service configuration; HSM or threshold custody and
   key transparency are engineering debts we can pay, and intend to.
4. **Completeness and ordering (A5, A4).** Both need chaining and an anchored public log;
   per-receipt verification will never see what was never logged, nor prove issuance order.

## Why publish this

Every mechanism in this spec exists to let a claim be checked rather than trusted. The same
standard has to apply to the spec itself: these are the checks we cannot yet offer, written
down before anyone asks. Corrections and attacks are welcome at security@aqta.ai.
