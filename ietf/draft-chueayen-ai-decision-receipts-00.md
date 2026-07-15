---
title: "Signed Receipts for AI Decision Evidence"
abbrev: ai-decision-receipts
docname: draft-chueayen-ai-decision-receipts-00
category: info
submissiontype: independent
workgroup: Independent Submission
ipr: trust200902
keyword:
  - attestation
  - signed receipt
  - audit evidence
  - AI agents
  - Ed25519
  - canonical JSON
  - transparency
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: A. Chueayen
    name: Anya Chueayen
    organization: Aqta Technologies Limited
    email: hello@aqta.ai
    uri: https://aqta.ai

normative:
  RFC2119:
  RFC8174:
  RFC8259:
  RFC8032:
  RFC4648:
  RFC3339:
  RFC9562:
  RFC6234:

informative:
  RFC8785:
  RFC9052:
  RFC9943:
  RFC7942:
  I-D.farley-acta-signed-receipts:
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    author:
      org: National Institute of Standards and Technology
    date: 2024-08
    seriesinfo:
      FIPS: "204"
    target: https://doi.org/10.6028/NIST.FIPS.204
  ATTESTATION-V1:
    title: "AqtaCore Attestation Receipt Format, Version 1"
    author:
      org: Aqta Technologies Limited
    date: 2026-04
    target: https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md
  THREAT-MODEL:
    title: "Threat Model: ATTESTATION-v1 and the AqtaCore Issuer"
    author:
      org: Aqta Technologies Limited
    date: 2026
    target: https://github.com/Aqta-ai/attestation-spec/blob/main/THREAT-MODEL.md
  SPEC-REPO:
    title: "attestation-spec: Specification, Reference Verifiers, and Conformance Vectors"
    author:
      org: Aqta Technologies Limited
    date: 2026
    target: https://github.com/Aqta-ai/attestation-spec
  EU-AI-Act:
    title: "Regulation (EU) 2024/1689 of the European Parliament and of the Council laying down harmonised rules on artificial intelligence (Artificial Intelligence Act)"
    date: 2024
    target: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
  DORA:
    title: "Regulation (EU) 2022/2554 of the European Parliament and of the Council on digital operational resilience for the financial sector"
    date: 2022
    target: https://eur-lex.europa.eu/eli/reg/2022/2554/oj
  SR11-7:
    title: "Supervisory Guidance on Model Risk Management (SR Letter 11-7)"
    author:
      org: Board of Governors of the Federal Reserve System
    date: 2011
    target: https://www.federalreserve.gov/supervisionreg/srletters/sr1107.htm
---

--- abstract

This document describes ATTESTATION-v1, a deployed format for signed
receipts recording the decisions of gateways that mediate calls from
applications to large language model (LLM) providers. A receipt is a
twelve-field JSON envelope that binds a decision outcome, the
identifiers of the policies applied, and a SHA-256 hash of the
underlying request to an Ed25519 signature computed over a canonical
serialisation of the envelope. Any holder of the issuer's public key
can verify a receipt offline, without access to the issuer's systems.
This document specifies the envelope, its canonical serialisation,
and its verification procedure; states precisely what a valid receipt
proves and what it does not; reports implementation and deployment
status; and maps the format onto the SCITT architecture. It records
deployed practice and is offered as input to standardisation of audit
records for actions taken by AI agents.

--- middle

# Introduction

Organisations that deploy LLM-based applications in regulated sectors
are asked to produce evidence about individual automated decisions:
what was requested, what a policy evaluation concluded, and when.
Expectations of this kind appear in audit-evidence provisions of the
EU Artificial Intelligence Act {{EU-AI-Act}}, in operational-resilience
rules for the financial sector {{DORA}}, and in supervisory guidance on
model risk {{SR11-7}}. Evidence intended for such review benefits from
three properties:

- it can be verified by a party other than the system that produced
  it;
- it remains verifiable after the producing system has changed or
  been decommissioned, including after a migration between LLM
  providers; and
- verification requires neither network access to, nor the
  cooperation of, the producer.

ATTESTATION-v1 {{ATTESTATION-V1}} is a deliberately small format with
these properties. It is produced at the point of decision by a
gateway interposed between an application and one or more LLM
providers. For each mediated call, the gateway evaluates its
configured policies (for example budget limits and loop detection),
reaches a decision, and signs a receipt recording that decision.

The format's design goals are:

Small and closed:
: A receipt has exactly twelve top-level fields ({{fields}}).
  Additional top-level fields are prohibited rather than ignored, so
  the input surface of a verifier is the format itself.

Offline verification:
: Verification needs only the receipt and the issuer's published
  public key. No request is made to the issuer.

Provider portability:
: The envelope contains no provider-proprietary identifier apart from
  the free-form model string. A receipt issued before an organisation
  migrates between LLM providers verifies unchanged afterwards.

Two claims only:
: A valid receipt proves origin and integrity, and nothing else.
  {{trust}} states this boundary precisely, because a verification
  format that overstates what it proves invites misplaced reliance.

This document is Informational. It documents a format that has been
publicly specified since April 2026 and deployed by a production
issuer since April 2026 ({{impl}}), and it is offered as input to
standardisation of audit records for actions taken by or on behalf of
AI agents, in particular to work building on the SCITT architecture
{{RFC9943}} ({{scitt}}).

## Scope

This document covers the canonical JSON structure of a receipt, the
canonical byte serialisation used for signing, the Ed25519 signature
construction, the base64url encoding of the signature and public key,
and receipt-level verification by a third party.

It does not cover chaining of receipts into a tamper-evident log
(a documented version 2 extension; see {{evolution}}), zero-knowledge
proofs over receipts, selective disclosure, or transport. Receipts
are transport-agnostic.

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all
capitals, as shown here.

The following terms are used:

Issuer:
: The gateway that produces and signs a receipt.

Subject:
: The organisation, identified by `org_id`, on whose behalf
  enforcement ran.

Verifier:
: Any party that checks a receipt's signature against the issuer's
  published public key.

Receipt:
: Unqualified, the ATTESTATION-v1 JSON envelope defined in
  {{envelope}}. The SCITT architecture uses "Receipt" for a different
  object, a proof of registration issued by a Transparency Service;
  this document writes "SCITT Receipt" for that object and uses it
  only in {{scitt}}.

# Receipt Structure {#envelope}

## Fields {#fields}

A receipt is a single JSON object {{RFC8259}} with exactly the
following twelve top-level fields. All twelve are REQUIRED.

`v`:
: Integer. The receipt format version. MUST be `1` for receipts
  conforming to this document.

`attestation_id`:
: String. A version 4 UUID {{RFC9562}}, unique per receipt.

`trace_id`:
: String. An issuer-assigned identifier for the underlying LLM call.

`org_id`:
: String. An identifier of the subject organisation.

`request_hash`:
: String. The SHA-256 {{RFC6234}} digest of the canonicalised request
  body, in hexadecimal: exactly 64 lowercase hexadecimal characters.
  The full digest is carried; it is never truncated.

`model`:
: String. A provider-qualified model identifier, for example
  `gpt-4o` or `claude-3-5-sonnet`.

`outcome`:
: String. One of the four values defined in {{outcomes}}.

`policy_applied`:
: Array of strings. The ASCII identifiers of the policies applied to
  the call, for example `["budget_guard","loop_guard"]`. The array
  MUST be sorted lexicographically.

`cost_prevented_eur`:
: Number. Non-negative decimal, six decimal digits of precision;
  `0` if not applicable. The reference issuer rounds the value to six
  decimal places before canonicalisation ({{numbers}}).

`timestamp`:
: String. An ISO 8601 date-time with an explicit timezone offset,
  `Z` denoting UTC. All published examples and conformance vectors
  conform to the date-time production of {{RFC3339}} and carry the
  UTC offset written as `+00:00`.

`public_key`:
: String. The issuer's raw 32-byte Ed25519 {{RFC8032}} public key,
  encoded as base64url without padding ({{RFC4648}}, Section 5).

`signature`:
: String. The 64-byte Ed25519 signature over the canonical payload
  ({{canonical}}), encoded as base64url without padding. This field
  is excluded from the canonical payload.

A version 1 receipt MUST NOT contain any additional top-level
fields. Verifiers MUST reject receipts containing unknown top-level
fields; see {{behaviour}} for the forward-compatibility option the
published verifiers expose.

## Outcome Values {#outcomes}

The `outcome` field MUST be one of the following values:

| Value | Meaning |
|-------|---------|
| `ALLOWED` | Enforcement passed all policies; the request proceeded to the provider. |
| `BLOCKED` | Enforcement blocked the request before invoking the provider. |
| `SUPPRESSED` | Enforcement detected a runaway condition (for example a loop) and suppressed the call. |
| `PASSED` | Synonym of `ALLOWED` retained for backward compatibility; new issuers SHOULD emit `ALLOWED`. |
{: title="Outcome values"}

Receipts carrying any other value do not conform to this document;
the published conformance suite requires verifiers to reject them
({{semantic}}).

# Canonical Payload and Signing {#canonical}

The canonical payload of a receipt is produced by:

1. Removing the `signature` field, if present.

2. Serialising the remaining eleven fields to JSON with all object
   keys sorted lexicographically, with no whitespace between tokens
   (the separators are `,` and `:`), and with numbers serialised per
   {{numbers}}.

3. Encoding the resulting string as UTF-8.

The signature is the Ed25519 {{RFC8032}} signature over these bytes
under the issuer's private key. The 64-byte result is base64url
encoded without padding and placed in the `signature` field.

Because a version 1 receipt contains exactly the fields of {{fields}}
and every field name is ASCII, the key order of the canonical payload
is fixed:

~~~
attestation_id, cost_prevented_eur, model, org_id, outcome,
policy_applied, public_key, request_hash, timestamp, trace_id, v
~~~

## Number Serialisation {#numbers}

Integer-valued numbers MUST be serialised without a decimal point or
trailing zeros. An issuer that internally represents a numeric field
as a floating-point value MUST coerce an integer-valued float to an
integer representation before serialising.

This rule exists because common platform serialisers disagree:
Python's `json.dumps` renders the float value 0.0 as `0.0` by
default, while JavaScript's `JSON.stringify` renders the number 0 as
`0`. Without the coercion, the same receipt produces different
signing bytes in different runtimes and is unverifiable across them.
The only number fields in version 1 are `v` (always the integer 1)
and `cost_prevented_eur`.

## Relationship to the JSON Canonicalization Scheme {#jcs}

The rules above resemble the JSON Canonicalization Scheme (JCS)
{{RFC8785}} but are not JCS, and this document deliberately does not
cite RFC 8785 normatively. The differences, in decreasing order of
practical significance:

String escaping:
: JCS serialises strings as ECMAScript's `JSON.stringify` does,
  emitting characters outside ASCII literally in UTF-8. The Python
  reference implementations of this format serialise with
  `json.dumps` defaults, which escape every character outside ASCII
  as a `\uXXXX` sequence. For any string value containing such a
  character, the JCS bytes and the reference bytes differ.

Property ordering:
: JCS sorts property names by UTF-16 code units. This format requires
  lexicographic order without further definition; its Python
  reference sorts by Unicode code point and its TypeScript reference
  by UTF-16 code units. All three orders coincide on the fixed ASCII
  field names of version 1.

Number serialisation:
: JCS requires ECMAScript shortest-round-trip serialisation for every
  number. This format normatively defines only the integer-coercion
  rule of {{numbers}} and otherwise inherits the platform serialiser.

For receipts whose string values contain only ASCII characters and
whose `cost_prevented_eur` has a short decimal expansion, a JCS
serialiser happens to produce the same bytes as the rules above. That
coincidence is not guaranteed by the format. An implementation that
substitutes an RFC 8785 library for the rules of this section will
produce different signing bytes for receipts whose string values
include characters outside ASCII, and signature verification will
fail.

## String Values Outside ASCII {#ascii}

The format specification does not define an escaping rule for
characters outside ASCII in string values, and the two published
reference implementations differ in that case: the Python
implementation escapes such characters as `\uXXXX` sequences, while
the TypeScript implementation emits them literally in UTF-8. All
fourteen published conformance vectors and the published sample
receipt contain only ASCII string values, on which the two
implementations agree byte for byte.

Cross-implementation interoperability is therefore established for
ASCII string values only. Issuers that keep string field values
within ASCII obtain identical canonical bytes from both reference
implementations. Making the rule explicit is a matter for a future
revision of the format specification.

# Verification {#verification}

## Procedure {#procedure}

A verifier performing receipt verification MUST:

1. Obtain the issuer's trusted public key out of band. A conformant
   issuer publishes its public key at a stable URL that it controls
   ({{impl}}). The verifier MAY pin the key or compare against a
   published key list.

2. Confirm that the `public_key` field in the receipt matches the
   trusted public key byte for byte. The receipt is self-declaring;
   this comparison is what prevents substitution of the issuer's
   identity ({{substitution}}).

3. Decode the `signature` field from base64url to 64 bytes.

4. Compute the canonical payload bytes ({{canonical}}).

5. Verify the Ed25519 signature over the canonical payload using the
   public key. A constant-time verification routine MUST be used.

6. Reject the receipt if any of the above steps fails.

## Semantic Checks {#semantic}

Verifiers SHOULD additionally check that:

- `v` equals `1`;
- `outcome` is one of the values in {{outcomes}};
- `request_hash` is exactly 64 lowercase hexadecimal characters;
- `policy_applied` is sorted; and
- `timestamp` is a well-formed date-time within a reasonable clock
  skew of the current time, if the receipt is being verified live.

The format specification places these checks outside the
cryptographic verification contract. Three of them are nonetheless
exercised by the published conformance vectors, which include
receipts failing the version, hash-syntax, and outcome checks and
require their rejection ({{vectors}}); a verifier that passes the
vector suite therefore implements at least those three.

## Verifier Behaviour {#behaviour}

The published conformance criteria additionally require of a
verifier:

- Ed25519 verification uses a constant-time primitive from an
  established library; signature verification is not hand-written.

- A malformed receipt never causes the verifier to raise or crash;
  the expected API shape is a structured result carrying a validity
  flag and a human-readable reason.

- With strict field checking enabled, unknown top-level fields cause
  rejection, per the MUST-level requirement of {{fields}}. Both
  published verifiers enable strict field checking by default and
  expose an option to disable it, intended for forward compatibility
  with future minor versions of the format.

- Payloads that differ only in key order or number formatting produce
  the same canonical bytes.

- `timestamp` parsing is informative and never load-bearing for
  cryptographic verification.

# What a Receipt Proves {#trust}

A valid receipt proves exactly two things:

Origin:
: The envelope was signed by the holder of the Ed25519 private key
  corresponding to the `public_key` field.

Integrity:
: No canonical field has changed since signing.

Every other property asserted by the envelope, the model identifier,
the outcome, the policy list, the timestamp, and the request hash, is
a claim by the signer: made tamper-evident by the signature, but not
made independently true by it. The trust assumptions behind reliance
on those claims, taken from the format's published threat model
{{THREAT-MODEL}}, are:

| # | Assumption | If it fails |
|---|------------|-------------|
| A1 | The `public_key` in a receipt is the issuer's, and its private half is held only by the issuer | Forged receipts are indistinguishable from real ones |
| A2 | The issuer truthfully records what it decided and forwarded | Receipts are honest-looking statements of false events |
| A3 | The model named in the receipt is what the provider ran | The receipt attests the request, not the compute |
| A4 | The issuer's clock is honest | Timestamps are signer-asserted, not proven |
| A5 | The set of receipts a verifier sees is complete | Omission is invisible to per-receipt verification |
{: title="Trust assumptions"}

Assumption A2 marks a structural boundary: a gateway that lies signs
lies, and no signature at this layer can remove that. A signature
proves what the signer said, not what the compute did. This is the
boundary between application-layer attestation, which this format
provides, and workload attestation rooted in trusted execution
environments or other hardware mechanisms, which it does not.
Binding receipts to hardware-rooted workload identity (assumption
A3) is open work, not a property of this format.

Assumptions A4 and A5 bound what a set of version 1 receipts can
establish. Version 1 receipts are independently signed and not
chained to one another, so the only in-band evidence of time is the
signed timestamp itself, and a holder of some receipts cannot detect
that others were withheld. No ordering or completeness guarantee can
be read into version 1 receipts. {{scitt}} describes the intended
mechanism for closing both gaps.

# Relationship to the SCITT Architecture {#scitt}

The SCITT architecture {{RFC9943}} defines an Issuer that signs
Statements about Artifacts, producing Signed Statements; a
Transparency Service that registers Signed Statements on an
append-only log subject to a Registration Policy, issuing a SCITT
Receipt as proof of registration; and the combination of a Signed
Statement with its SCITT Receipt as a Transparent Statement.

The format described here maps onto those concepts directly:

- The issuer of this format performs the role of a SCITT Issuer.

- A receipt as defined in {{envelope}} is a Statement whose subject
  Artifact is the mediated LLM call: it states what was requested
  (by hash), what was decided, and under which policies. Carried as
  the payload of a COSE_Sign1 structure {{RFC9052}}, it takes the
  Signed Statement form that SCITT expects.

- Registering each issued receipt with a Transparency Service yields
  a SCITT Receipt, and thereby a Transparent Statement.

Registration addresses exactly the two limits that {{trust}}
identifies as out of reach for per-receipt verification. An
inclusion proof establishes that a given receipt existed no later
than its registration, providing an upper bound on issuance time
asserted by a party other than the signer (assumption A4). And where
the registration policy requires every issued receipt to be
registered, absence from the log becomes observable rather than
silent (assumption A5).

The sequencing is stated plainly: ATTESTATION-v1 predates its own
SCITT integration. Version 1 signs JSON directly rather than a COSE
structure, and no transparency-service registration of production
receipts is deployed at the time of writing. The intended
registration-friendly form is a COSE-native version 2 envelope
carrying the same canonical payload, signed hybridly with ML-DSA-65
{{FIPS204}} alongside Ed25519, a version 2 receipt being valid only
if both signatures verify ({{evolution}}, {{pq}}).

This document records deployed practice with the version 1 JSON
envelope. It is offered as input to standardisation of audit records
for actions taken by or on behalf of AI agents, a setting in which
the Artifact about which Statements are made is an action or a
decision rather than a software artefact. It claims no conformance
to {{RFC9943}} and requests no registry action.

## Related Independent Work {#related}

{{I-D.farley-acta-signed-receipts}} independently specifies
Ed25519-signed, offline-verifiable decision receipts for
machine-to-machine access control, attesting whether a caller was
permitted to invoke a tool or capability, with tool invocation via
the Model Context Protocol as its motivating deployment. The two
formats share design instincts: detached offline verification
against a published key, canonical serialisation before signing,
and refusal to make the issuer's availability part of the trust
path.

They attest different subjects. An acta receipt's subject is an
access-control verdict at a tool boundary: whether this caller may
take this action. The subject of the receipt defined here is the
mediated LLM inference call itself: what was requested of which
model, bound by request hash, and how the gateway's policy
enforcement disposed of it before the model produced tokens. In a
deployment containing both an agent's tool invocations and its
underlying model calls, the two formats are complementary layers of
evidence rather than substitutes, and a complete audit trail for an
agentic system plausibly carries both.

# Format Evolution {#evolution}

The format follows a published stability contract:

- Patch revisions clarify text and add test vectors; existing
  receipts remain valid.

- Minor revisions may add optional fields or new outcome values;
  existing receipts remain valid.

- Major revisions may change the canonical serialisation, the
  signature construction, or the required fields; existing receipts
  continue to verify under their original version. The `v` field
  identifies the major version, and a verifier MAY support several.

Two version 2 directions are documented by the format specification
and are explicitly not part of version 1:

Chaining:
: A version 2 extension adds a predecessor identifier
  (`prev_attestation_id`) and a chained hash, so that modification of
  a historical receipt is detectable from later ones. Version 1
  receipts are independent and unchained ({{trust}}).

Hybrid signing:
: The documented version 2 target signs the canonical payload with
  ML-DSA-65 {{FIPS204}} alongside Ed25519, a version 2 receipt being
  valid only if both signatures verify ({{pq}}).

Separate documents are planned for zero-knowledge proofs over
receipts and for selective disclosure of fields; neither affects the
version 1 envelope.

# Implementation Status {#impl}

This section records the status of known implementations of the
format at the time of posting of this Internet-Draft, following the
practice described in {{RFC7942}}. [RFC Editor: please remove this
section before publication.]

Specification:
: The format specification {{ATTESTATION-V1}} has been publicly
  available since 24 April 2026 under CC BY 4.0; the version 1.0
  specification text is dated 23 April 2026. It is maintained, with
  the threat model, conformance criteria, vectors, and reference
  code, in a public repository {{SPEC-REPO}}.

Reference verifiers:
: Two independently implemented verifier libraries are published,
  both named `aqta-verify-receipt` and both at version 1.0.2: a
  Python package on PyPI and a TypeScript package on npm. Both are
  licensed under Apache 2.0, enable strict field checking by
  default, accept a pinned trusted public key, and return a
  structured result rather than raising on malformed input.

Conformance vectors:
: Fourteen deterministic vectors are published: six valid and eight
  invalid, each invalid vector encoding exactly one failure mode
  ({{vectors}}). The vectors regenerate byte-identically from a
  fixed seed. A verifier claims conformance by classifying all
  fourteen correctly.

Cross-implementation interoperability:
: A fixture script signs a receipt with the Python reference issuer
  and verifies it with the TypeScript verifier, asserting the valid,
  tampered, pinned, and mismatched-key cases. Continuous integration
  runs both verifier test suites and this script on every change.

Production deployment:
: A production issuer operated by Aqta Technologies Limited has
  signed receipts in this format since April 2026. It publishes its
  verification key at a stable URL,
  `https://api.aqta.ai/v1/attestation/public-key`, mirrored as a raw
  value at `https://app.aqta.ai/security/pubkey.txt`.

# Security Considerations {#security}

## Key Custody {#custody}

The issuer's private key MUST be held in a secure environment.
Compromise of the private key invalidates every subsequent receipt.
Issuers MAY rotate keys; a rotation publishes a new key and MUST
preserve prior public keys for verification of historical receipts.

The deployed practice is stated honestly: the production issuer's
signing key is a single Ed25519 key held in the serving
environment's configuration, not in a hardware security module.
Hardened custody and a public key-transparency mechanism, which
would make a silent key swap externally visible, are planned and not
shipped. Because every receipt embeds the public key it was signed
with, a rotation is detectable by verifiers that pin.

## Key Substitution {#substitution}

A receipt verifies against its own embedded `public_key`, so a valid
signature alone proves only that someone signed the envelope, not
that a particular issuer did: an attacker can self-sign a
well-formed receipt under a fresh keypair. The defence is the
pinning comparison in steps 1 and 2 of {{procedure}}. Verification
without that comparison checks integrity but not identity. The
published verifiers take the trusted key as a parameter; supplying
it is the intended mode of use.

## Replay and Re-presentation {#replay}

A valid receipt can be presented more than once; it cannot be
altered. Re-presentation proves only what the receipt always proved
and is not evidence that the underlying event is recent or recurred.
Receipts are unique by `attestation_id` and bound to a
`request_hash`; consumers ingesting receipt streams SHOULD
deduplicate on `attestation_id`. Verifiers requiring freshness apply
the timestamp check of {{semantic}} together with {{timestamps}}.

## Timestamps and Ordering {#timestamps}

`timestamp` is asserted by the signer (assumption A4). Verifiers
concerned with freshness MUST cross-reference a trusted time source.
Version 1 receipts are not chained, so version 1 provides no proof
of issuance order and no in-band bound on backdating beyond the
signed timestamp itself. Registration on a transparency service
({{scitt}}) establishes an upper bound on issuance time asserted by
a party other than the signer.

## Omission {#omission}

Per-receipt verification sees presence, never absence (assumption
A5). A verifier holding a set of receipts cannot determine from the
receipts alone whether others were withheld, and an issuer's receipt
stream is not, by itself, a complete account of the traffic the
issuer handled. Completeness requires an anchored, externally
auditable log; registration under {{scitt}} is the intended
mechanism and is not deployed at the time of writing. Relying
parties MUST NOT treat a collection of valid receipts as proof that
no other receipts exist.

## Signer Honesty {#honesty}

Nothing at this layer removes assumption A2: a signature proves what
the signer said, not what the compute did. Transparency measures,
such as public logs, independent verifier implementations, and
registration receipts issued by a party other than the signer,
mitigate the assumption; the issuer's own signature never can.

## Canonicalisation {#canon-sec}

The integer-coercion rule of {{numbers}} addresses the one known
cross-runtime divergence for version 1 fields. Implementations MUST
derive canonical bytes by the rules of {{canonical}} and not with a
general-purpose canonical-JSON library; as described in {{jcs}}, an
RFC 8785 serialiser produces different bytes for string values
outside ASCII. Any transformation of string values between signing
and verification, including Unicode normalisation, changes the
canonical bytes and invalidates the signature. Until the format
specification defines an escaping rule for characters outside ASCII,
interoperability across the published implementations holds for
ASCII string values ({{ascii}}).

## Post-Quantum Position {#pq}

Ed25519 is not secure against a cryptographically relevant quantum
computer (CRQC): a CRQC can forge signatures against any captured
public key, including keys retired before its arrival. Receipts
contain no plaintext prompt or response content, so the format has
no harvest-now-decrypt-later confidentiality exposure; the quantum
risk is forgery. Audit-retention obligations of five to ten years in
financial-sector frameworks overlap published CRQC arrival
estimates, which is why the documented version 2 target is hybrid
signing: ML-DSA-65 {{FIPS204}} alongside Ed25519 over the same
canonical payload, with a version 2 receipt valid only if both
signatures verify. Deployed practice today is classical Ed25519, and
this document does not claim otherwise. Crypto-agility in version 1
rests on the `v` field: verifiers reject versions they do not
support.

# IANA Considerations

This document has no IANA actions.

--- back

# Worked Example {#example}

The following receipt is the deterministic sample published with the
format specification. It is regenerated byte-identically from a
fixed seed and verifies under both published verifier libraries,
pinned to the `public_key` value it carries. The `request_hash` and
`signature` values are single unbroken strings; line breaks inside
quoted values below are for display only.

~~~ json
{
  "attestation_id": "00000000-0000-0000-0000-000000000001",
  "cost_prevented_eur": 0,
  "model": "gpt-4o",
  "org_id": "org-example",
  "outcome": "ALLOWED",
  "policy_applied": ["budget_guard", "loop_guard"],
  "public_key": "BCnbtpAGKli3cVUVkAsHGdFZHElOH2GDs7rMzPNH6Fk",
  "request_hash": "8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c
                   3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
  "signature": "ce0z4fuGh9gQSOWiYnOjXGN0ZUK-27D0Oyk20EQQ
                g93xJIl7K6L80XM8DEWyFzP6YoxfNP_3_cjlEESs
                p-DRCA",
  "timestamp": "2026-04-23T10:15:30.000000+00:00",
  "trace_id": "trace-example-0001",
  "v": 1
}
~~~

The canonical payload is this object with the `signature` field
removed, serialised per {{canonical}}: keys in the fixed order given
there, `,` and `:` separators with no whitespace, and
`cost_prevented_eur` as the integer literal `0` rather than the
float literal `0.0`, per {{numbers}}.

# Conformance Vectors {#vectors}

The format's repository {{SPEC-REPO}} publishes fourteen
deterministic conformance vectors under `test-vectors/`. All vectors
verify (or fail) against the pinned public key

~~~
alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E
~~~

which is derived deterministically from the seed
`sha256("attestation-spec/test-vectors/v1")`. A conformant verifier,
pinning that key, returns valid for every vector in `valid/` and
invalid for every vector in `invalid/`.

The six valid vectors cover:

| Vector | Exercises |
|--------|-----------|
| `001-allowed` | Canonical happy path, `ALLOWED` |
| `002-blocked` | Pre-provider block, multiple policies |
| `003-suppressed` | Loop-guard suppression |
| `004-passed` | `PASSED` as legacy synonym of `ALLOWED` |
| `005-multi-policy` | Five policies; `policy_applied` sort rule |
| `006-cost-prevented-nonzero` | Non-integer `cost_prevented_eur` (2.5) |
{: title="Valid vectors"}

The eight invalid vectors each encode exactly one failure mode:

| Vector | Failure mode |
|--------|--------------|
| `001-tampered-signature` | Signature bytes modified |
| `002-tampered-outcome` | `outcome` changed after signing |
| `003-tampered-public-key` | `public_key` replaced with an all-zero key |
| `004-missing-field` | Required `outcome` field removed |
| `005-unknown-field` | Extra top-level field added |
| `006-wrong-version` | `v` is 2 (unsupported version) |
| `007-bad-request-hash` | `request_hash` not 64-character lowercase hex |
| `008-invalid-outcome` | `outcome` value outside the enumeration |
{: title="Invalid vectors"}

# Acknowledgements
{:numbered="false"}

The format documented here was designed and deployed at Aqta
Technologies Limited. The author thanks the external reviewers of
the published verifier libraries, whose feedback led to the 1.0.2
documentation revisions, and the operators of the production issuer.
