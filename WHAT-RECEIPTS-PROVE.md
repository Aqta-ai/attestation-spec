# What gateway-level receipts can and cannot prove

An Aqta Research note. We operate Seal, a production gateway whose request path signs
an ATTESTATION-v1 receipt for each call it allows through; refusals are audit-logged rather
than receipt-signed, and per-request production issuance begins when upstream provider keys
are provisioned. This note places that layer precisely in the verification stack described
by the flexHEG reports (ARIA-commissioned; arXiv 2506.15093, 2506.03409, 2506.15100) and
Attestable Audits (arXiv 2506.23706, ICML 2025), and states plainly which trust assumptions
our layer does not remove. It is a companion to [THREAT-MODEL.md](./THREAT-MODEL.md).

The short version: a gateway signature proves what the gateway said, not what the compute
did. That sentence is not a concession we were forced into; it is the design boundary of
the layer we chose to build first, and the literature below is precise about what sits
underneath it.

## The layer we operate

A signed receipt proves two things: origin (the envelope was signed by the holder of the
embedded key) and integrity (no canonical field changed since signing). One further
property is real but easy to overstate: because the gateway sits in the request path and
applies policy before forwarding, it can refuse to forward, so for traffic routed through
it there is genuine pre-execution enforcement, not just after-the-fact logging. What it
cannot see is traffic that never came through it. flexHEG II grounds why that matters in
hardware terms: its preferred architecture puts the verifying component on the data path
precisely so it is "the only path for data and instructions" into the accelerator. A
gateway holds that position by convention and configuration, not by physics. And the
receipt stream is narrower still than what the gateway observes: receipts are issued for
allowed requests, refusals live in the audit log, so receipts are claims about allowed
routed traffic, not all routed traffic, and never all traffic.

## What the literature says sits below us

**Workload binding.** Nothing in a gateway signature proves that the policy engine which
made the decision is the code we published, or that the model named in the receipt is what
the provider ran. This is the gap trusted execution environments exist to close: flexHEG II
describes TEEs as providing "difficult-to-fake evidence that the computing environment is
configured as claimed", and Attestable Audits builds its whole protocol on it, with remote
attestation signing measurements of the loaded code (Platform Configuration Registers over
the trusted computing base) using "a non-extractable secret key", and results bound to
hashes of the model and the audit code and data inside the attestation, not alongside it.
The signature that matters in that design is never made by the audited party. Our receipts
are, and we say so.

**Verification versus enforcement.** flexHEG II is blunt about software-level guarantees:
TEE-backed software "could enable verification about how hardware has been used, but would
not be able to enforce that the hardware cannot be used in guarantee-breaking ways".
flexHEG III generalises the ceiling: any verification mechanism "cannot physically prevent
rule violations, nor can it force actual verification of activities". Our pre-execution
refusal is real enforcement for routed traffic, but nothing stops an operator running
un-gatewayed calls beside it. Only hardware below us can make that claim, and only
partially.

**Physical custody.** flexHEG guarantee processors can pair with tamper-responsive
enclosures where guarantees about future usage are needed (tamper evidence suffices for
verification-only uses, flexHEG II notes), and flexHEG I's tamper response is the detail
our layer should envy: on tampering it wipes "the private key that the chip would use to
sign verifiable claims". The corollary, ours rather than the papers', is that under such a
design the continued ability to produce valid signatures is itself evidence of physical
integrity. Our production signing key lives in service configuration, not tamper-responsive
hardware. A receipt's validity says nothing about the physical custody of the machine that
signed it.

**Vendor and design trust.** Even the layers below us bottom out in trust: Attestable
Audits notes its parties must "trust the hardware vendor of the CC technology", and
flexHEG III reaches for collaboratively justified designs, international design review and
redundant implementations because backdoors "introduced at the design stage" cannot easily
be spotted after the fact, then layers production oversight and supply-chain tracking
against compromise at later stages. There is no layer at which verification becomes free
of assumptions; each layer just moves them somewhere more defensible.

**The semantic ceiling.** No layer proves intent. flexHEG I: what counts as misuse
"ultimately depend[s] on what is done with the result of some computation, which the
flexHEG device itself cannot know". A receipt proves what a computation was, never what it
was for. That ceiling applies to hardware and gateways alike.

## Why build the gateway layer at all

Because the stack is not a ladder you must climb from the bottom. flexHEG I itself uses
receipts as its evidence vocabulary: guarantee processors "producing verifiable 'receipts'
of what data were processed and how", receipts that aggregate ("higher-level receipts")
and travel with intermediate results, carrying hashes of the data used. The artefact shape
is the one our published spec, reference issuer and verifiers implement today at the
application layer; what changes as you descend the stack is who signs and what the
signature binds. Attestable Audits adds the publication
half: attestations "published to a transparency log", converting a point-to-point proof
into a record that "acts as evidence for third parties", with user recourse to a regulator.
Neither paper uses IETF SCITT vocabulary; mapping receipt formats onto SCITT's Signed
Statements and transparency services is our positioning, and we flag it as such.

And the required depth of the stack is set by the adversary and the audience, not by
ambition. flexHEG II, on TEE-backed software verification: its "limited security may be
sufficient for domestic regulation, where it could be difficult to hide major efforts to
attack verification mechanisms". A bank evidencing its AI decisions to a regulator is not
a state verifying a rival state's training runs. In the enterprise regime, the binding
constraints are portability, cost and auditability across providers. An application-layer
receipt that anyone can verify offline in seconds is designed to clear the evidential bars
regulators actually set, provided its limits are stated rather than papered over. The
offline verification property works today; the evidential claim is for auditors and
regulators to accept, not for us to assert. Stating the limits is what this note and our
threat model are for.

## The work we want to do next

The interesting engineering is the join: receipts as the portable serialisation of claims
whose signers sit progressively lower in the stack. Concretely, an envelope whose
statements are bound to a TEE-attested measurement of the serving environment, so that
"model": what-we-forwarded-to becomes "model": what-a-measured-environment-reports, and a
transparency log over issuance so omission and ordering stop being blind spots. The
literature above names every gap between our layer and that one; none of it is mysterious,
all of it is unbuilt in portable, cross-provider form. That is the gap we intend to work
in, in the open, against this spec.

## Sources

- flexHEG I: Flexible Hardware-Enabled Guarantees for AI Compute, arXiv 2506.15093
- flexHEG II: Technical Options for Flexible Hardware-Enabled Guarantees, arXiv 2506.03409
- flexHEG III: International Security Applications of Flexible Hardware-Enabled
  Guarantees, arXiv 2506.15100
- Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments,
  arXiv 2506.23706, ICML 2025
- IETF SCITT working group, datatracker.ietf.org/group/scitt (our mapping, not the papers')
