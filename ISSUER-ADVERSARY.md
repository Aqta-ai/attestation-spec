# The issuer as adversary

Every one of the fifteen adversarial vectors in [`test-vectors/invalid/`](./test-vectors/invalid)
attacks a receipt **after it was signed**: a flipped field, a swapped key, a
malformed timestamp, an extra property. They model a third party interfering
with evidence in transit or at rest.

A dishonest issuer never needs to do any of that.

The issuer holds the signing key. It can produce receipts that are perfectly
well-formed, canonically correct, and cryptographically valid under a published
key, and still misrepresent what happened. **The published verifiers return
`valid` on every attack in this document, and they are right to.** The envelope
is not defective. The defect is in the set, or in what is missing from it.

This document names those classes, states what is required to detect each, and
says plainly which ones we can detect today. It exists because a conformance
suite that only tests envelopes will certify a verifier that cannot see any of
this, and because our own research claim is that the interesting adversary is
the party issuing the evidence.

## Why single-receipt verification cannot help

The six classes below are properties of a **sequence** or of an **absence**.
A verifier handed one receipt sees one receipt. No amount of signature checking
recovers a decision that was never written down, and no signature distinguishes
the second of two contradictory records from the first.

Detection therefore requires at least one of: the full issuance history, an
external observer who saw the history at a past point in time, or a second party
who holds a receipt the issuer would prefer to forget.

## The classes

### A1. Equivocation

The issuer signs two different receipts describing the same decision, and shows
each to a different party. Both verify. Both are genuine.

*Detection:* an append-only log with consistency proofs between tree heads. The
two receipts cannot both be members of the same consistent history.

*Requires:* signed tree heads published to an external party at intervals, so
that "the log I showed you then" and "the log I show you now" can be compared.

### A2. Omission

A decision ran and no receipt was issued. Nothing is tampered with, because
nothing exists.

*Detection:* completeness cannot be established from the evidence itself. It
requires an independent count from outside the issuer, a counterparty receipt,
or a gap made visible by an externally anchored sequence.

*This is the hardest class and we do not claim to have solved it.* An issuer that
never writes a record leaves no cryptographic trace of not having written it.
The honest position is that anchoring narrows the window in which omission is
undetectable, and does not close it.

### A3. Backdating

A receipt is signed later than the moment its `timestamp` field claims.

*Detection:* an external timestamp authority, or inclusion in an anchored log
whose head was published before the claimed time is impossible.

*Requires:* the anchor to be bound to the leaf hash rather than to a log
position, so an issuer cannot renumber its way out.

### A4. Retrospective reordering

The issuance history is presented in an order other than the one in which
receipts were produced, to make a sequence of decisions look reasonable.

*Detection:* RFC 6962 consistency proofs between an earlier published tree head
and the current one.

### A5. Silent key substitution

The issuer rotates to a key it controls but has not published, signs a
convenient record, and presents it as historical. Verification against the
receipt's embedded key succeeds.

*Detection:* pinning to a **published** key record with an effective-from date,
rather than trusting the key the receipt carries. This is why the reference CLI
refuses to verify without an explicit `--key` and reports
`keySource: "untrusted"` when the embedded key is used.

*Note:* this class is the reason key-pinning is a correctness property and not a
convenience.

### A6. Selective history disclosure

The issuer shows a reviewer a subset of receipts that is internally consistent,
complete-looking, and omits the inconvenient ones.

*Detection:* inclusion proofs against a tree head the reviewer obtained
independently, so that "these are all of them" becomes a checkable claim rather
than an assertion.

## What is implemented today

| Class | Mechanism present | Status |
|---|---|---|
| A1 Equivocation | RFC 6962 log, signed tree heads, consistency proofs | Mechanism implemented; no conformance vectors |
| A2 Omission | External anchoring narrows the window | **Open. Not solved, and not claimed** |
| A3 Backdating | Anchor bound by leaf hash, never by log position | Mechanism implemented; no conformance vectors |
| A4 Reordering | Consistency proofs between tree heads | Mechanism implemented; no conformance vectors |
| A5 Key substitution | Pinned-key verification, refuses unpinned by default | Implemented and tested at the single-receipt layer |
| A6 Selective disclosure | Inclusion proofs against an independent tree head | Mechanism implemented; no conformance vectors |

The gap is not the cryptography. It is that five of these six have working
mechanisms and no adversarial vectors, so a third-party implementation claiming
conformance today is claiming envelope conformance only.

## What a second conformance dimension would look like

Existing vectors are single JSON documents with a boolean expected verdict. These
cannot be, because the unit under test is a history rather than a document. A
vector in this dimension is:

- a set of receipts,
- one or more signed tree heads with their publication times,
- an external anchor,
- and an expected finding, which is a class from A1 to A6 rather than a
  pass or fail on one file.

A conformant *history* verifier must return the same finding as a second
independent implementation, in the same way the two envelope verifiers must
agree today. That is a harder bar and a more useful one.

## Relationship to SCITT

RFC 9943 (June 2026) standardises transparency for signed statements from a
single issuer, which is the same adversary model this document takes seriously.
ATTESTATION-v1 is a payload-level profile that could be registered with such a
service. Where SCITT provides the registry and the receipt of registration, the
classes above describe what an adversarial issuer does *around* such a registry,
and what a reviewer needs in order to notice.

## Honest limits

We are not claiming to have solved verifiable inference, and this document does
not address it. A6 and A2 in particular remain partially and wholly open. What is
claimed is narrower: that the adversary worth modelling for decision evidence is
the party that signs it, that this is testable, and that no conformance suite we
are aware of, including our own, currently tests it. Publishing the gap is the
first step to closing it.

See also [THREAT-MODEL.md](./THREAT-MODEL.md) and
[WHAT-RECEIPTS-PROVE.md](./WHAT-RECEIPTS-PROVE.md), which state the limits of a
gateway signature in the same register.
