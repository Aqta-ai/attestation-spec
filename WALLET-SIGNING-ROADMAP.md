# Wallet countersignature roadmap

Published 18 August 2026. This documents the staged path for how a reviewer's
wallet countersigns a review verdict over an ATTESTATION-v1 receipt, and why
the stages are ordered this way. It is published so the reasoning is on the
record, dated, in the open.

## The property that orders everything

A review verdict must be the **reviewer's own signing act** over a fixed
binding (receipt hash, question hash, decision, timestamp), made with a
credential the evidence issuer did not issue. Disclosure alone does not give
this: a wallet proving "this person holds this email" tells the relying party
something, but the relying party then asserts the verdict. The signature must
come from the wallet side, or the trust model collapses back into "the
operator's server says so."

## Stage 1 — now: attribute-based signatures (Yivi/IRMA)

The Yivi wallet family supports Idemix attribute-based signatures: the wallet
signs an arbitrary message with disclosed attributes bound in. This is today
the only deployed wallet capability that matches the required property, which
is why the flow at review.aqta.ai uses it. Aqta is registered in the Yivi
ecosystem as an organisation and relying party.

Known limits, stated since the first prototype: the disclosed credential
(verified email) establishes control of a mailbox, not reviewer authority;
verification of the attribute-based signature requires irmago, as no browser
implementation of Idemix verification exists.

## Stage 2 — when available: qualified electronic signatures in EUDI wallets

EUDI-ARF wallets are slated to carry qualified electronic signature (QES)
capability. The day an ARF wallet can sign this flow's binding message via
QES, cross-wallet support arrives with the required property intact, and
stronger: a QES verdict carries eIDAS legal weight and answers the
reviewer-authority question better than any email attribute. This is the
trigger we build against. Interoperability that weakens the signature into
disclosure-plus-server-assertion is not on the roadmap under the name
interoperability.

## Stage 3 — role credentials

Independent of signature mechanics: a credential asserting reviewer role or
organisational affiliation, issued inside an established wallet ecosystem,
replacing the email placeholder. This is an ecosystem conversation, invited
publicly on the review surface since the prototype shipped.

## Interim, on demand only

If a specific reviewer's organisation mandates a wallet that cannot sign, the
flow can accept OpenID4VP disclosure for identity plus a separate signature
step, with the weakened property named in the evidence pack rather than
hidden. This exists as a documented compromise, not a default.
