# Relationship to SCITT (RFC 9943)

Short version: **ATTESTATION-v1 is positioned as a payload profile for SCITT, not
as a competing envelope standard.** This document states where the two overlap,
where this specification is currently weaker, and what we are doing about it.

We publish this because the alternative is worse. A reader who knows RFC 9943
will notice the overlap within a minute, and a specification that appears
unaware of the standard covering its own problem shape is harder to trust than
one that says plainly where it sits.

## What RFC 9943 is

[RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html), *An Architecture for
Trustworthy and Transparent Digital Supply Chains*, was published on the IETF
Standards Track in June 2026. It defines an architecture for single-issuer
signed-statement transparency, built from three pieces:

- **Signed Statements**, which RFC 9943 requires to be `COSE_Sign1` messages
  as defined by STD 96, carrying CWT Claims for Issuer and Subject in the
  protected header.
- **A Transparency Service**, which maintains "a consistent, append-only,
  cryptographically verifiable, publicly available record of entries".
- **Receipts**, which are proofs of registration into that log, built on a
  Verifiable Data Structure.

## Where ATTESTATION-v1 differs, honestly

**1. The envelope.** ATTESTATION-v1 is canonical JSON with a bare embedded
public key. A conforming SCITT Signed Statement is `COSE_Sign1` in CBOR. An
ATTESTATION-v1 receipt is therefore **not** a conforming Signed Statement
without re-envelopment.

**2. The word "receipt".** This is the sharper difference and it is worth
stating explicitly. In RFC 9943 a Receipt is *proof of registration in an
append-only log*. In ATTESTATION-v1 a receipt is *an issuer signature over a
decision record*. Those are different guarantees. An issuer signature gives
**authenticity**: this issuer asserted this. It does not give
**transparency**: it carries no inclusion proof, and a signature alone cannot
show that an issuer has not suppressed or back-dated an entry.

Our use of the term predates our reading of RFC 9943 and is now the weaker
sense of the word. We are not going to redefine the standard's term to suit
ourselves, so where precision matters this specification says *decision record*
or *signed decision receipt*, and reserves *Receipt* in the SCITT sense for
proof of log registration.

**3. Scope.** SCITT is designed for statements *about* artefacts, recorded
after the fact. ATTESTATION-v1 records a policy decision taken *before* an
action runs. That difference is the reason this specification exists and it is
not something SCITT addresses: SCITT is a transparency architecture, not an
enforcement one.

## Why a profile rather than a rival

RFC 9943 is deliberately payload-agnostic. It states that conformance
prioritises STD 96 and that "profiles and implementation-specific choices
should be used to determine admissibility of conforming messages", and the
payload types it cites include SBOM formats, in-toto, SPDX, SLSA and audit
reports.

An AI-decision record is exactly that shape of payload. Competing on envelopes
against a published Standards Track RFC would be a poor use of everyone's time
and would not make any receipt more verifiable. Carrying this payload inside a
SCITT Signed Statement, and registering it with a Transparency Service, gives
strictly more than this specification does alone.

## What is built, and what is not

**Built.** An append-only Merkle log with RFC 6962 construction: leaf and
interior domain separation, inclusion proofs, consistency proofs, and signed
tree heads. It is verified against the published Certificate Transparency test
vectors rather than only against itself. This supplies the property a bare
signature cannot: a party who pinned an earlier tree head can detect a log that
has been rewritten or had entries removed.

**Not built.** COSE_Sign1 re-envelopment, CWT claim mapping, and registration
with a public Transparency Service. Until those exist, do not describe an
ATTESTATION-v1 receipt as SCITT-conformant. It is not.

## What this means for an implementer

If you need a signed, offline-checkable record of an AI decision today, this
specification and its verifiers do that and are stable at v1.0.7.

If you need transparency in the RFC 9943 sense, with inclusion proofs and
third-party monitoring, you need a Transparency Service. Use SCITT. We intend
to be a profile that runs inside it rather than an alternative to it.

## References

- RFC 9943, *An Architecture for Trustworthy and Transparent Digital Supply
  Chains*, IETF Standards Track, June 2026.
  https://www.rfc-editor.org/rfc/rfc9943.html
- RFC 6962, *Certificate Transparency*, for the Merkle log construction used
  here.
- STD 96 (RFC 9052), *CBOR Object Signing and Encryption (COSE)*.
- `draft-chueayen-attestation-receipts`, an individual IETF Internet-Draft.
  Not adopted by any working group and not a standard.
