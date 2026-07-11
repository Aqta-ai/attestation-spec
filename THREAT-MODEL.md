# Threat model: ATTESTATION-v1 and the AqtaCore issuer

A self-authored adversarial analysis of our own system. We wrote this because a verification
format that does not state its own trust assumptions is asking to be trusted, which is the
failure mode this project exists to remove. Reporting a flaw: see [SECURITY.md](./SECURITY.md).

Scope: the ATTESTATION-v1 envelope, the published reference verifiers (v1.0.2 on PyPI and
npm), and the production AqtaCore issuer (signing in production since April 2026).

## What a receipt actually proves

A valid receipt proves exactly two things:

1. **Origin**: the envelope was signed by the holder of the stated Ed25519 key.
2. **Integrity**: no canonical field has changed since signing.

Everything else in the envelope (model, outcome, policy list, timestamp, request hash) is a
**claim by the signer**, made tamper-evident but not independently true. This distinction
drives every row below.

## Trust assumptions, stated plainly

| # | Assumption | If it fails |
|---|---|---|
| A1 | The published public key is authentic and its private half is controlled only by the issuer | Forged receipts indistinguishable from real ones |
| A2 | The issuer (the gateway) truthfully records what it decided and what it forwarded | Receipts are honest-looking statements of false events |
| A3 | The model named in the receipt is what the provider actually ran | The receipt attests the request, not the compute |
| A4 | The issuer's clock is honest | Timestamps are signer-asserted, not proven |
| A5 | The ledger a verifier sees is complete | Omission is invisible to per-receipt verification |

## Adversaries and attacks

**Signature forgery (outsider).** Breaking Ed25519 or the canonicalisation. Mitigated by
standard cryptography (RFC 8032 over canonical JSON), strict-field verification, and public
conformance vectors. Residual risk: implementation bugs; both verifiers are open source and
small deliberately.

**Key theft (insider or intruder).** The production signing key is a single Ed25519 key held
in the serving environment's configuration, not an HSM. This is our largest honest gap at
the custody layer. Mitigations today: the key never leaves the signing service, the envelope
carries `key_id` for rotation, and the published key is pinned in two places. Planned:
custody hardening and a public key-transparency story.

**Malicious or compromised issuer (the hard one).** A gateway that lies signs lies. This is
assumption A2 and no gateway-level signature can remove it: **a signature proves what the
signer said, not what the compute did.** This is the boundary between application-layer
attestation (this spec) and workload attestation (TEE quotes, hardware-rooted mechanisms
such as guarantee processors). Our position: receipts are the deployed, portable layer above
that boundary; binding them downward to hardware-rooted workload identity is the open work,
not a solved feature. We say this in public because a buyer or regulator who discovers it
later should never feel it was hidden.

**Backdating and clock fraud.** `timestamp` is signer-asserted (A4). Hash-chaining
(`prev_attestation_id`) gives receipts a tamper-evident order relative to each other, which
bounds backdating within a chain, but chain position is currently verified structurally, not
by a full public chain walk. An anchored transparency log (SCITT-style) is the correct fix
and is on the roadmap, not shipped.

**Replay and re-presentation.** A valid receipt can be shown twice; it cannot be altered.
Receipts are unique by `attestation_id` and bound to a `request_hash` (full 64-char SHA-256),
so re-presentation proves only what it always proved. Consumers correlating receipts to
business events should key on `attestation_id`.

**Chain splicing and omission.** Deleting or reordering ledger entries invalidates the hash
chain when walked; per-receipt verification, however, cannot see omission (A5). Denied
requests are audit-logged rather than receipt-signed, so the receipt stream alone is not a
complete account of traffic and is not presented as one.

**Quantum adversary.** Ed25519 is not post-quantum secure; a cryptographically relevant
quantum computer forges against any captured public key. The envelope is crypto-agile
(`key_id`, algorithm field) and the documented ATTESTATION-v2 target is hybrid signing with
ML-DSA-65 (NIST FIPS 204) alongside Ed25519. Production today is classical Ed25519; we do
not claim otherwise.

## Gaps we have not closed, ranked

1. **Workload binding (A3).** Nothing binds a receipt to the weights and code that produced
   the response. Closing it means anchoring receipts to TEE-based workload attestation or
   hardware-rooted mechanisms; this is the research edge of the field, not our shipped layer.
2. **Signer trust (A2).** Structural: mitigable by transparency (public logs, third-party
   verifiers, SCITT-style receipts over our receipts), never by our own signature.
3. **Key custody (A1).** Single key in service configuration; HSM/threshold custody and key
   transparency are engineering debts we can pay, and intend to.
4. **Completeness (A5).** Needs an anchored, publicly auditable log; per-receipt
   verification will never see what was never logged.
5. **Timestamps (A4).** Bounded by chain order today; anchoring to an external log
   tightens it.

## Why publish this

Every mechanism in this spec exists to let a claim be checked rather than trusted. The same
standard has to apply to the spec itself: these are the checks we cannot yet offer, written
down before anyone asks. Corrections and attacks are welcome at security@aqta.ai.
