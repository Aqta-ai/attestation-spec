# Seal Policy Statement Format, Version 1, and the `policy` Profile

**Status:** DRAFT. Not frozen. The wire format may change before it is frozen; a frozen version will say so here.
**Version:** 1.0-draft
**Last updated:** 2026-10-23
**Sibling specifications:** [ACTION-v1](./ACTION-v1.md) (frozen; unchanged by this document), [CHECKPOINT-v1](./CHECKPOINT-v1.md) (log entry tags).
**Conformance vectors:** [test-vectors/policy/](../test-vectors/policy/)

---

## 1. Purpose

An ACTION-v1 record names the policies it was evaluated under in `policy_applied`, a signed list of strings. A name
says which policy; it does not say which version. An operator who edits a policy after the fact can present the
edited text as the one in force, and nothing in the record contradicts it.

A POLICY-v1 statement fixes one version: **the issuer signs that policy `policy_name` of organisation `org_id` had
exactly these rules, with content hash `policy_hash`, from `created_at`.** With binding on, each `policy_applied`
entry is written `<policy_name>@sha256:<policy_hash>`, so the decision record commits to the exact version, and the
`policy` profile (section 8) checks the commitment offline.

## 2. Why the frozen formats do not change

ACTION-v1 is frozen. `policy_applied` is already a signed array of strings, sorted by UTF-16 code unit, with no
grammar beyond that (ACTION-v1 section 4). A bound entry is such a string. So:

- a record with bound entries is a valid ACTION-v1 record, and every published verifier since 1.1.0 checks its
  signature unchanged (vector `pass/001` decisions verify under `--profile action-1`);
- the binding is a convention inside a member the format already signs, and only a verifier that opts in to the
  `policy` profile reads it. Nothing is inferred from an entry's shape without that opt-in.

ATTESTATION-v1 is not covered by this draft. Its `policy_applied` is restricted to ASCII identifiers (ATTESTATION-v1
section 3); a bound entry built from an ASCII name is ASCII, so the convention would fit, but receipts are not bound
by the reference boundary and this profile accepts ACTION-v1 records only.

## 3. Terminology

- **Version**: one POLICY-v1 statement. Its content address is `policy_hash`.
- **Lineage**: the versions sharing (`org_id`, `policy_name`), numbered from 1.
- **Binding**: a `policy_applied` entry of the form `<name>@sha256:<hash>`.
- **Unbound entry**: a `policy_applied` entry with no `@`. It names a policy without naming a version.

## 4. Record Structure

A flat JSON object of exactly ten members, every one a string. There are no numeric members: `version` is a
canonical decimal string.

| Member | Meaning |
|---|---|
| `v` | the string `"policy-1"` |
| `org_id` | non-empty; the organisation, as in the ACTION-v1 records that bind it |
| `policy_name` | non-empty; the identifier exactly as it appears in `policy_applied` before `@`. MUST NOT contain `@` |
| `version` | canonical decimal of at least 1 (a non-zero ASCII digit followed by ASCII digits), at most 2^53 - 1 |
| `prev_policy_hash` | `""` for version 1; otherwise the `policy_hash` of the version this one replaces (64 lowercase hex) |
| `rules` | non-empty; the rule set, as the issuer evaluates it, written as RFC 8785 canonical JSON text |
| `policy_hash` | 64 lowercase hex; the content address (section 5) |
| `created_at` | RFC 3339 with an explicit offset (the ACTION-v1 grammar); when the issuer signed this version |
| `public_key` | the issuer key, strict base64url |
| `signature` | Ed25519 over the canonical payload, strict base64url |

Any other member is refused.

`rules` is a string, not a nested object, on purpose. A verifier never parses it: the hash covers its bytes. That
keeps numbers inside a rule (a rate ceiling, say) out of the one place where two languages disagree about canonical
bytes. An issuer MUST write it as the RFC 8785 canonical serialisation of the rule array it evaluates, so a reader
can recompute it from the rules.

## 5. Content Address

    policy_hash = lowercase hex SHA-256 of canonical_json({"v": "policy-body-1", "org_id": org_id,
                                                           "policy_name": policy_name, "rules": rules})

Canonical JSON as ACTION-v1 section 6. The body tag `"policy-body-1"` keeps the preimage distinct from every signed
payload in this family. `version`, `prev_policy_hash` and `created_at` are outside the hash: the hash names the
content, so the same rules under the same name always have the same address, and a decision binds what was
evaluated, not when it was numbered. Reverting a policy to an earlier text therefore binds the earlier statement.

## 6. Issuance and Logging (normative for an issuer)

1. A new statement is issued whenever the issuer is about to evaluate a policy content it has not stated before
   (a creation, an edit, a revert to text never stated). Its `version` is one more than the lineage's latest and
   `prev_policy_hash` names that latest.
2. The statement is signed with the issuer key and entered into the public transparency log under entry tag `0x05`
   (receipts `0x00`, anchors `0x01`, ACTION-v1 `0x02`, USE-v1 `0x03`, CHECKPOINT-v1 `0x04`):

       0x05 || uint64be(len(payload)) || payload || utf8(signature)

   where `payload` is the canonical payload. The leaf hash is `SHA-256(0x00 || entry)`. It is numbered from the same
   sequence as every other leaf, append-only: an issued leaf index never changes.
3. The statement is committed, and so entered into the log order, **before** any decision that binds it is signed.
4. Every `policy_applied` entry that names an evaluated customer policy is written as its binding. Reserved markers
   that name no policy (a refusal because the rules could not be read, a decision error) stay unbound.

## 7. Verification of One Statement

In this order; the first failure is the result:

1. An object; each member of section 4 is present, in table order; no other member.
2. `v` is the string `"policy-1"`; every member is a string.
3. `org_id`, `policy_name`, `rules` are not `""`; `policy_name` contains no `@`.
4. `version` is canonical decimal of at least 1 and at most 2^53 - 1.
5. `prev_policy_hash` is `""` exactly when `version` is `"1"`, else 64 lowercase hex.
6. `policy_hash` is 64 lowercase hex; `created_at` is RFC 3339 with an offset.
7. A pinned issuer key is supplied and `public_key` equals it. There is no embedded-key mode.
8. The payload canonicalises; `signature` and `public_key` are strict base64url of 64 and 32 bytes; it verifies.
9. `policy_hash` equals the content address of section 5.

Patterns are matched against the whole string with ASCII semantics: a trailing line feed or a non-ASCII digit fails.

## 8. The `policy` Profile

Explicit opt-in (`--profile policy`, or a direct call). A verifier MUST NOT select it by inspecting the input.

### 8.1 Inputs and bundle

The pinned issuer key (required). The bundle:

    {"v": "policy-1", "head": <public tree head> | null,
     "policies": [{"statement": POLICY-v1, "proof": <inclusion proof against head> | null}, ...],
     "decisions": [{"record": ACTION-v1, "proof": <inclusion proof against head> | null}, ...]}

### 8.2 Binding grammar

An entry containing `@` is a binding claim and MUST match, as a whole string, `^([^@]+)@sha256:([0-9a-f]{64})$`.
An entry with no `@` is unbound.

### 8.3 Checks, in order

The first FAIL is the result. INCOMPLETE reasons are collected; if no FAIL occurs, the first one collected is the
result. Indices are array positions.

1. **Inputs.** A pinned issuer key is supplied.
2. **Bundle.** An object with `v`, `head`, `policies`, `decisions` (checked present in that order) and no other;
   `v` is `"policy-1"`; `policies` and `decisions` are arrays.
3. **Head.** `null`, or a public tree head that verifies under the pinned key.
4. **Statements**, each: an object with exactly `statement` and `proof`; the statement verifies (section 7); no two
   share a `policy_hash`; no two share (`org_id`, `policy_name`, `version`) (a fork); a non-null proof needs a head,
   targets it (`tree_size`, `root_hash`), is for the statement's leaf (section 6) and verifies. Then, for each
   statement whose `prev_policy_hash` names a statement in the bundle: that one has the same `org_id` and
   `policy_name`, a `version` one less, and a `created_at` not after this one's.
5. **Decisions**, each: an object with exactly `record` and `proof`; the record verifies as ACTION-v1 under the
   pinned key; no two share an `action_id`; a non-null proof is checked as in step 4 against the action leaf (`0x02`).
6. **Bindings**, for each decision, each `policy_applied` entry:
   1. Unbound: INCOMPLETE.
   2. A binding claim that does not match 8.2: FAIL.
   3. No statement with that hash in the bundle: INCOMPLETE.
   4. The statement's `policy_name` differs from the entry's name: FAIL.
   5. The statement's `org_id` differs from the record's: FAIL.
   6. The statement's `created_at` is after the record's `timestamp` (exact instants, GRANT-v1 section 6.1): FAIL.
   7. Either proof is absent: INCOMPLETE (log order not shown).
   8. The statement's leaf index is not less than the decision's: FAIL (logged after the decision).
7. **Empty.** A bundle with no decision is INCOMPLETE.

A decision whose `policy_applied` is empty binds nothing and passes step 6 vacuously.

### 8.4 What the verdicts establish, and what they do not

PASS establishes: every policy each decision names is bound to a version the pinned issuer signed, with exactly the
rules the bundle shows; that version was created no later than the decision's claimed time; and it entered the
public log before the decision did. An edit made after the decision has a different hash and cannot be presented
as the version the decision names.

PASS does **not** establish that the evaluation was correct. The issuer says which version it evaluated; a
dishonest issuer could bind a version and evaluate something else, or reach the wrong outcome under the right one.
Log order is submission order (RFC 9943 section 9.1): the issuer controls it, and it bounds a backdated
`created_at` only relative to the decision's own leaf. Against an issuer that withholds both a decision and its
statements, or writes them late together, this profile needs the `witnessed` and `complete` profiles beside it.

## 9. Assertion Provenance (normative)

| Member | Provenance | What the signature establishes |
|---|---|---|
| `rules`, `policy_hash` | **Issuer-attested** | The issuer stated this exact rule content for this policy. Not that it evaluated it correctly. |
| `version`, `prev_policy_hash` | **Issuer-attested** | The issuer's numbering of the lineage. A fork is detectable when both branches are presented. |
| `created_at` | **Issuer-attested (self-clock)** | The issuer's clock. Bounded by log order relative to the binding decision, not absolutely. |
| `org_id`, `policy_name` | **Issuer-assigned** | Identifiers the issuer controls. |

## 10. Reference Implementations

`aqta-verify-receipt` (TypeScript and Python), `--profile policy` with `--key`. CLI exit codes: 0 PASS, 1 FAIL,
3 INCOMPLETE, 2 usage or input error. The two implementations must return the same verdict and the same reason on
every vector; `scripts/policy-interop-sweep.mjs` enforces it, including re-signed mutations of every binding.

## 11. Change Log

- 2026-10-23: first draft.
