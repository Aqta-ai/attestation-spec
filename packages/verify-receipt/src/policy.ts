/**
 * The `policy` profile and POLICY-v1 (spec/POLICY-v1.md). DRAFT: not frozen.
 *
 * A decision record names the policies it was evaluated under in
 * `policy_applied`. With policy binding, each entry is `<name>@sha256:<hash>`,
 * and the hash is the content address of one signed POLICY-v1 statement: which
 * exact version of the policy the issuer says it evaluated. ACTION-v1 is frozen
 * and gains no field for this; the binding rides inside the string list it
 * already signs.
 *
 * Three verdicts, never two: PASS, FAIL, INCOMPLETE. The check order and every
 * reason string are a cross-implementation contract with the Python verifier
 * (aqta_verify_receipt/policy.py): first FAIL wins, and the two must return the
 * same verdict and reason on the same bytes.
 *
 * Explicit opt-in only. Nothing here is reached by inspecting input shape.
 */

import { createHash } from 'node:crypto';
import { _internal } from './index.js';
import { _chainInternal } from './chain.js';
import type { ChainResult } from './chain.js';
import { checkRecordOfKind, recordLeaf } from './complete.js';
import { leafHash, verifyInclusionProof, verifySignedTreeHead } from './transparency.js';

const { RFC3339_OFFSET } = _internal;
const {
  cmpInstant, isObject, has, firstUnknown, canonicalBytes, withoutSignature, signatureReason, isKey, Fail,
  DECIMAL_POSITIVE, HEX64,
} = _chainInternal;

type Obj = Record<string, unknown>;
type Str = Record<string, string>;

export interface PolicyOptions {
  trustedPublicKey?: string;
}

const POLICY_FIELDS = [
  'v', 'org_id', 'policy_name', 'version', 'prev_policy_hash', 'rules', 'policy_hash', 'created_at',
  'public_key', 'signature',
];
const BUNDLE_MEMBERS = ['v', 'head', 'policies', 'decisions'];
const BODY_TAG = 'policy-body-1';
/** Log entry tags: receipts 0x00, anchors 0x01, ACTION-v1 0x02, USE-v1 0x03, CHECKPOINT-v1 0x04, POLICY-v1 0x05. */
const ENTRY_TAG = 0x05;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const BINDING = /^([^@]+)@sha256:([0-9a-f]{64})$/;

/** The content address of one policy version: SHA-256 over the canonical body (section 5). */
export function policyBodyHash(orgId: string, policyName: string, rules: string): string {
  return createHash('sha256')
    .update(canonicalBytes({ v: BODY_TAG, org_id: orgId, policy_name: policyName, rules }))
    .digest('hex');
}

/** RFC 6962 leaf hash of a POLICY-v1 log entry: 0x05 || uint64be(len(payload)) || payload || signature. */
export function policyLeaf(statement: Obj): Uint8Array {
  const payload = canonicalBytes(withoutSignature(statement));
  const sig = new TextEncoder().encode(statement.signature as string);
  const entry = new Uint8Array(1 + 8 + payload.length + sig.length);
  entry[0] = ENTRY_TAG;
  let n = payload.length;
  for (let i = 8; i >= 1; i--) {
    entry[i] = n % 256;
    n = Math.floor(n / 256);
  }
  entry.set(payload, 9);
  entry.set(sig, 9 + payload.length);
  return leafHash(entry);
}

/** [name, policy_hash] for a well-formed `name@sha256:hash` entry, else null. */
export function parseBinding(entry: string): [string, string] | null {
  const m = BINDING.exec(entry);
  return m ? [m[1], m[2]] : null;
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

// --- POLICY-v1 (spec/POLICY-v1.md section 7) --------------------------------------------------------------------

/** null when the statement is a well-formed POLICY-v1 statement under the pinned issuer key, else the reason. */
export function checkPolicyRecord(st: unknown, trustedPublicKey: string | undefined): string | null {
  if (!isObject(st)) return 'policy statement must be an object';
  for (const f of POLICY_FIELDS) if (!has(st, f)) return `missing required field: ${f}`;
  const unknown = firstUnknown(st, new Set(POLICY_FIELDS));
  if (unknown !== null) return `unknown top-level field: ${unknown}`;
  if (st.v !== 'policy-1') return "v must be the string 'policy-1'";
  for (const f of POLICY_FIELDS) if (typeof st[f] !== 'string') return `${f} must be a string`;
  const s = st as Str;
  for (const f of ['org_id', 'policy_name', 'rules']) if (s[f] === '') return `${f} must be a non-empty string`;
  if (s.policy_name.includes('@')) return "policy_name must not contain '@'";
  if (!DECIMAL_POSITIVE.test(s.version)) return 'version must be a canonical decimal string of at least 1';
  if (s.version.length > 16 || BigInt(s.version) > MAX_SAFE) return 'version is too large';
  if (s.version === '1') {
    if (s.prev_policy_hash !== '') return 'prev_policy_hash must be empty for version 1';
  } else if (!HEX64.test(s.prev_policy_hash)) {
    return 'prev_policy_hash must be 64 lowercase hex characters';
  }
  if (!HEX64.test(s.policy_hash)) return 'policy_hash must be 64 lowercase hex characters';
  if (!RFC3339_OFFSET.test(s.created_at)) return 'created_at must be an RFC 3339 datetime with an explicit offset';
  if (trustedPublicKey === undefined || trustedPublicKey === null) return 'trusted_public_key required';
  if (s.public_key !== trustedPublicKey) return 'public_key does not match trusted key';
  const why = signatureReason(withoutSignature(st), st.signature, st.public_key);
  if (why !== null) return why;
  if (s.policy_hash !== policyBodyHash(s.org_id, s.policy_name, s.rules)) return 'policy_hash does not match the policy body';
  return null;
}

// --- The profile (spec/POLICY-v1.md section 8) ------------------------------------------------------------------

/** Verify a policy-binding bundle. Never throws. */
export function verifyPolicy(bundle: unknown, options: PolicyOptions = {}): ChainResult {
  try {
    return verifyPolicyInner(bundle, options);
  } catch (e) {
    if (e instanceof Fail) return { verdict: 'FAIL', reason: e.message };
    return { verdict: 'FAIL', reason: 'verification error' };
  }
}

function isInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v);
}

function verifyPolicyInner(bundle: unknown, options: PolicyOptions): ChainResult {
  const incomplete: string[] = [];
  const fail = (reason: string): never => {
    throw new Fail(reason);
  };
  const pinned = options.trustedPublicKey as string;

  // 1. Inputs.
  if (typeof pinned !== 'string' || !isKey(pinned)) fail('a pinned issuer key is required');

  // 2. Bundle.
  if (!isObject(bundle)) fail('bundle must be an object');
  const b = bundle as Obj;
  for (const m of BUNDLE_MEMBERS) if (!has(b, m)) fail(`bundle missing member: ${m}`);
  const unknown = firstUnknown(b, new Set(BUNDLE_MEMBERS));
  if (unknown !== null) fail(`bundle has unknown member: ${unknown}`);
  if (b.v !== 'policy-1') fail("bundle v must be the string 'policy-1'");
  for (const m of ['policies', 'decisions']) if (!Array.isArray(b[m])) fail(`bundle ${m} must be an array`);

  // 3. The head, when one is given: a public head the pinned issuer key signed.
  const head = b.head;
  if (head !== null) {
    if (!isObject(head) || head.log !== 'public') fail('head must be null or a public tree head');
    if (!verifySignedTreeHead(head, pinned).valid) fail('head does not verify under the pinned key');
  }

  const checkProof = (where: string, proof: unknown, leaf: Uint8Array): number | null => {
    if (proof === null) return null;
    if (head === null) fail(`${where}.proof is given without a head`);
    const h = head as Obj;
    if (!isObject(proof) || !isInt(proof.tree_size) || proof.tree_size !== h.tree_size || proof.root_hash !== h.root_hash) {
      fail(`${where}.proof does not target the head`);
    }
    const p = proof as Obj;
    if (p.leaf_hash !== hex(leaf)) fail(`${where}.proof is for a different leaf`);
    if (!verifyInclusionProof(p).valid) fail(`${where}.proof does not verify`);
    return p.leaf_index as number;
  };

  // 4. Policy statements.
  const byHash = new Map<string, [Str, number | null]>();
  const versions = new Set<string>();
  const policies = b.policies as unknown[];
  policies.forEach((item, i) => {
    if (!isObject(item) || Object.keys(item).length !== 2 || !has(item, 'statement') || !has(item, 'proof')) {
      fail(`policies[${i}] must be an object with statement and proof`);
    }
    const it = item as Obj;
    const why = checkPolicyRecord(it.statement, pinned);
    if (why !== null) fail(`policies[${i}]: ${why}`);
    const st = it.statement as Str;
    if (byHash.has(st.policy_hash)) fail(`policies[${i}] repeats an earlier policy version`);
    const lineage = JSON.stringify([st.org_id, st.policy_name, st.version]);
    if (versions.has(lineage)) fail(`policies[${i}] forks the version history of its policy`);
    versions.add(lineage);
    byHash.set(st.policy_hash, [st, checkProof(`policies[${i}]`, it.proof, policyLeaf(st))]);
  });
  policies.forEach((item, i) => {
    const st = (item as Obj).statement as Str;
    const prev = byHash.get(st.prev_policy_hash);
    if (prev === undefined) return;
    const p = prev[0];
    if (p.org_id !== st.org_id || p.policy_name !== st.policy_name || Number(p.version) + 1 !== Number(st.version)) {
      fail(`policies[${i}] does not follow the version its prev_policy_hash names`);
    }
    if (cmpInstant(p.created_at, st.created_at) > 0) fail(`policies[${i}] is created before the version it follows`);
  });

  // 5. Decisions.
  const decisions = b.decisions as unknown[];
  const seen = new Set<string>();
  const indexed: (number | null)[] = [];
  decisions.forEach((item, i) => {
    if (!isObject(item) || Object.keys(item).length !== 2 || !has(item, 'record') || !has(item, 'proof')) {
      fail(`decisions[${i}] must be an object with record and proof`);
    }
    const it = item as Obj;
    const why = checkRecordOfKind('action', it.record, pinned);
    if (why !== null) fail(`decisions[${i}]: ${why}`);
    const rec = it.record as Obj;
    const aid = rec.action_id as string;
    if (seen.has(aid)) fail(`decisions[${i}] repeats an action_id`);
    seen.add(aid);
    indexed.push(checkProof(`decisions[${i}]`, it.proof, recordLeaf('action', rec)));
  });

  // 6. Each binding.
  decisions.forEach((item, i) => {
    const rec = (item as Obj).record as Obj;
    (rec.policy_applied as string[]).forEach((entry, j) => {
      const where = `decisions[${i}].policy_applied[${j}]`;
      if (!entry.includes('@')) {
        incomplete.push(`${where} is not bound to a policy version`);
        return;
      }
      const parsed = parseBinding(entry);
      if (parsed === null) fail(`${where} is not a well-formed binding`);
      const [name, h] = parsed as [string, string];
      const found = byHash.get(h);
      if (found === undefined) {
        incomplete.push(`${where} names a policy version that is not in the bundle`);
        return;
      }
      const [st, stIndex] = found;
      if (st.policy_name !== name) fail(`${where} names the version under a different policy name`);
      if (st.org_id !== rec.org_id) fail(`${where} names a policy version of another organisation`);
      if (cmpInstant(st.created_at, rec.timestamp as string) > 0) {
        fail(`${where} names a policy version created after the decision`);
      }
      const decIndex = indexed[i];
      if (stIndex === null || decIndex === null) {
        incomplete.push(`${where} is not shown to be logged before the decision`);
        return;
      }
      if (stIndex >= decIndex) fail(`${where} names a policy version logged after the decision`);
    });
  });

  // 7. Empty.
  if (decisions.length === 0) incomplete.push('the bundle carries no decision');

  if (incomplete.length) return { verdict: 'INCOMPLETE', reason: incomplete[0] };
  return { verdict: 'PASS', reason: null };
}
