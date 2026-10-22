/**
 * The `witnessed` profile (spec/WITNESS-v1.md section 7) and WITNESS-v1
 * (spec/WITNESS-v1.md). DRAFT: not frozen.
 *
 * Backdating (ISSUER-ADVERSARY A3) needs a clock the issuer does not control.
 * A witness fetches the public log head every hour and a time authority stamps
 * it; a record whose claimed time is more than the stated tolerance before the
 * witnessed time of a head that does not contain it was logged late by more
 * than the tolerance. Absence from an unwitnessed head proves nothing (vector
 * a3-lag-is-not-backdating still holds for assessHistory); absence from a
 * witnessed head, beyond the tolerance, does.
 *
 * Three verdicts, never two: PASS, FAIL, INCOMPLETE. The check order and every
 * reason string are a cross-implementation contract with the Python verifier
 * (aqta_verify_receipt/witnessed.py): first FAIL wins, and the two must return
 * the same verdict and reason on the same bytes.
 *
 * Explicit opt-in only. Nothing here is reached by inspecting input shape.
 */

import { createHash } from 'node:crypto';
import { _internal } from './index.js';
import { _chainInternal } from './chain.js';
import type { ChainResult } from './chain.js';
import { checkRecordOfKind, recordLeaf } from './complete.js';
import { verifyConsistencyProof, verifyInclusionProof, verifySignedTreeHead } from './transparency.js';

const { RFC3339_OFFSET, B64URL_STRICT } = _internal;
const {
  cmpInstant, instant, isObject, has, firstUnknown, canonicalBytes, withoutSignature, signatureReason, isKey, Fail,
  DECIMAL_POSITIVE, HEX64,
} = _chainInternal;

type Obj = Record<string, unknown>;
type Str = Record<string, string>;

export interface WitnessedOptions {
  trustedPublicKey?: string;
  /** The relying party's designated time-authority keys. Absent: INCOMPLETE. */
  witnessKeys?: string[] | null;
  /** How late, in seconds, an honest record may enter the log. Default 3600. */
  toleranceSeconds?: number;
}

const WITNESS_FIELDS = [
  'v', 'witness_id', 'statement_seq', 'prev_statement_hash', 'log_public_key', 'tree_size', 'root_hash',
  'head_timestamp', 'head_signature', 'witnessed_at', 'public_key', 'signature',
];
const BUNDLE_MEMBERS = ['v', 'head', 'witnessed', 'consistency', 'records'];
export const DEFAULT_TOLERANCE_SECONDS = 3600;
const HEAD_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

export function statementHash(w: Obj): string {
  return createHash('sha256').update(canonicalBytes(withoutSignature(w))).digest('hex');
}

function isInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v);
}

/** w > claimed + tolerance seconds, exactly, to every fractional digit. */
function laterThan(w: string, claimed: string, tolerance: number): boolean {
  const [sw, fw0] = instant(w);
  const [sc0, fc0] = instant(claimed);
  const sc = sc0 + tolerance;
  if (sw !== sc) return sw > sc;
  const n = Math.max(fw0.length, fc0.length);
  return fw0.padEnd(n, '0') > fc0.padEnd(n, '0');
}

// --- WITNESS-v1 (spec/WITNESS-v1.md section 6) ------------------------------------------------------------------

/** Integrity of one witness statement under its own embedded key; says nothing about designation or the head. */
export function checkWitnessRecord(w: unknown): string | null {
  if (!isObject(w)) return 'statement must be an object';
  for (const f of WITNESS_FIELDS) if (!has(w, f)) return `missing required field: ${f}`;
  const unknown = firstUnknown(w, new Set(WITNESS_FIELDS));
  if (unknown !== null) return `unknown top-level field: ${unknown}`;
  if (w.v !== 'witness-1') return "v must be the string 'witness-1'";
  for (const f of WITNESS_FIELDS) if (typeof w[f] !== 'string') return `${f} must be a string`;
  const s = w as Str;
  if (s.witness_id === '') return 'witness_id must be a non-empty string';
  if (!DECIMAL_POSITIVE.test(s.statement_seq)) return 'statement_seq must be a canonical decimal string of at least 1';
  if (s.statement_seq === '1') {
    if (s.prev_statement_hash !== '') return 'prev_statement_hash must be empty for statement_seq 1';
  } else if (!HEX64.test(s.prev_statement_hash)) {
    return 'prev_statement_hash must be 64 lowercase hex characters';
  }
  if (!isKey(s.log_public_key)) return 'log_public_key must be a base64url Ed25519 key';
  if (!DECIMAL_POSITIVE.test(s.tree_size)) return 'tree_size must be a canonical decimal string of at least 1';
  if (s.tree_size.length > 16 || BigInt(s.tree_size) > MAX_SAFE) return 'tree_size is too large';
  if (!HEX64.test(s.root_hash)) return 'root_hash must be 64 lowercase hex characters';
  if (!HEAD_TS.test(s.head_timestamp)) return 'head_timestamp must be YYYY-MM-DDTHH:MM:SSZ';
  if (!B64URL_STRICT.test(s.head_signature)) return 'head_signature must be base64url';
  if (!RFC3339_OFFSET.test(s.witnessed_at)) return 'witnessed_at must be an RFC 3339 datetime with an explicit offset';
  if (!isKey(s.public_key)) return 'public_key must be a base64url Ed25519 key';
  return signatureReason(withoutSignature(w), w.signature, w.public_key);
}

/** The public tree head a statement names, in the shape verifySignedTreeHead reads. */
export function witnessedHead(w: Str): Obj {
  return { v: 1, log: 'public', tree_size: Number(w.tree_size), root_hash: w.root_hash,
    timestamp: w.head_timestamp, signature: w.head_signature };
}

// --- The profile (spec/WITNESS-v1.md section 7) -----------------------------------------------------------------

/** Verify a witnessed-time bundle. Never throws. */
export function verifyWitnessed(bundle: unknown, options: WitnessedOptions = {}): ChainResult {
  try {
    return verifyWitnessedInner(bundle, options);
  } catch (e) {
    if (e instanceof Fail) return { verdict: 'FAIL', reason: e.message };
    return { verdict: 'FAIL', reason: 'verification error' };
  }
}

function verifyWitnessedInner(bundle: unknown, options: WitnessedOptions): ChainResult {
  const incomplete: string[] = [];
  const fail = (reason: string): never => {
    throw new Fail(reason);
  };
  const pinned = options.trustedPublicKey as string;
  const tol = options.toleranceSeconds === undefined ? DEFAULT_TOLERANCE_SECONDS : options.toleranceSeconds;

  // 1. Inputs.
  if (typeof pinned !== 'string' || !isKey(pinned)) fail('a pinned issuer key is required');
  let trusted: Set<string> | null = null;
  if (options.witnessKeys !== undefined && options.witnessKeys !== null) {
    if (!Array.isArray(options.witnessKeys) || !options.witnessKeys.every(isKey)) {
      fail('witness_keys must be base64url Ed25519 keys');
    }
    trusted = new Set(options.witnessKeys);
  }
  if (typeof tol !== 'number' || !Number.isSafeInteger(tol) || tol < 0) {
    fail('tolerance_seconds must be a non-negative integer');
  }

  // 2. Bundle.
  if (!isObject(bundle)) fail('bundle must be an object');
  const b = bundle as Obj;
  for (const m of BUNDLE_MEMBERS) if (!has(b, m)) fail(`bundle missing member: ${m}`);
  const unknown = firstUnknown(b, new Set(BUNDLE_MEMBERS));
  if (unknown !== null) fail(`bundle has unknown member: ${unknown}`);
  if (b.v !== 'witnessed-1') fail("bundle v must be the string 'witnessed-1'");
  for (const m of ['witnessed', 'consistency', 'records']) if (!Array.isArray(b[m])) fail(`bundle ${m} must be an array`);

  // 3. The head the record proofs target: a public head the pinned issuer key signed.
  const head = b.head;
  if (!isObject(head) || head.log !== 'public') fail('head must be a public tree head');
  if (!verifySignedTreeHead(head, pinned).valid) fail('head does not verify under the pinned key');
  const size = (head as Obj).tree_size as number;
  const root = (head as Obj).root_hash as string;

  // 4. Witness statements: each one, then the chain.
  const ws = b.witnessed as Str[];
  ws.forEach((w, i) => {
    const why = checkWitnessRecord(w);
    if (why !== null) fail(`witnessed[${i}]: ${why}`);
    if (w.log_public_key !== pinned) fail(`witnessed[${i}] witnesses a different log key`);
    if (!verifySignedTreeHead(witnessedHead(w), pinned).valid) {
      fail(`witnessed[${i}] names a head the pinned issuer key did not sign`);
    }
    if (trusted === null) {
      if (!incomplete.includes('no witness key set was supplied')) incomplete.push('no witness key set was supplied');
    } else if (!trusted.has(w.public_key)) {
      fail(`witnessed[${i}] is not signed by a designated witness key`);
    }
    if (i > 0) {
      const prev = ws[i - 1];
      if (w.witness_id !== prev.witness_id || BigInt(w.statement_seq) !== BigInt(prev.statement_seq) + 1n ||
          w.prev_statement_hash !== statementHash(prev)) {
        fail(`witnessed[${i}] does not follow witnessed[${i - 1}]`);
      }
      if (cmpInstant(w.witnessed_at, prev.witnessed_at) < 0) fail(`witnessed[${i}] is witnessed before witnessed[${i - 1}]`);
      if (Number(w.tree_size) < Number(prev.tree_size)) fail(`witnessed[${i}] has a smaller tree than witnessed[${i - 1}]`);
      if (w.tree_size === prev.tree_size && w.root_hash !== prev.root_hash) {
        fail(`witnessed[${i}] and witnessed[${i - 1}] name one size with different roots`);
      }
    }
    if (Number(w.tree_size) > size) fail(`witnessed[${i}] is larger than the head`);
  });

  // 5. Each witnessed head is a prefix of the head.
  const sizes = new Set(ws.map((w) => Number(w.tree_size)));
  const cons = b.consistency as Obj[];
  cons.forEach((c, j) => {
    if (!isObject(c) || !isInt(c.old_size) || !sizes.has(c.old_size)) {
      fail(`consistency[${j}] does not start at a witnessed head`);
    }
  });
  ws.forEach((w, i) => {
    const wsSize = Number(w.tree_size);
    if (wsSize === size) {
      if (w.root_hash !== root) fail(`witnessed[${i}] and the head name one size with different roots`);
      return;
    }
    const c = cons.find((x) => x.old_size === wsSize);
    if (c === undefined) {
      incomplete.push(`no consistency proof from witnessed[${i}] to the head`);
      return;
    }
    if (c.old_root !== w.root_hash || !isInt(c.new_size) || c.new_size !== size || c.new_root !== root) {
      fail(`the consistency proof for witnessed[${i}] does not join it to the head`);
    }
    if (!verifyConsistencyProof(c).valid) fail(`the consistency proof for witnessed[${i}] does not verify`);
  });

  // 6. Records: each verifies, is in the head, and its claimed time agrees with the witnessed heads.
  const recs = b.records as unknown[];
  recs.forEach((item, i) => {
    if (!isObject(item) || Object.keys(item).length !== 3 || !has(item, 'kind') || !has(item, 'record') ||
        !has(item, 'proof')) {
      fail(`records[${i}] must be an object with kind, record and proof`);
    }
    const it = item as Obj;
    const kind = it.kind;
    if (kind !== 'action' && kind !== 'use' && kind !== 'checkpoint') {
      fail(`records[${i}].kind must be action, use or checkpoint`);
    }
    const why = checkRecordOfKind(kind as string, it.record, pinned);
    if (why !== null) fail(`records[${i}]: ${why}`);
    const rec = it.record as Str;
    const p = it.proof;
    if (!isObject(p) || !isInt(p.tree_size) || p.tree_size !== size || p.root_hash !== root) {
      fail(`records[${i}].proof does not target the head`);
    }
    const proof = p as Obj;
    if (proof.leaf_hash !== Buffer.from(recordLeaf(kind as string, rec)).toString('hex')) {
      fail(`records[${i}].proof is for a different leaf`);
    }
    if (!verifyInclusionProof(proof).valid) fail(`records[${i}].proof does not verify`);
    const index = proof.leaf_index as number;
    const claimed = rec.timestamp;
    const k = ws.findIndex((w) => Number(w.tree_size) > index);
    if (k < 0) {
      incomplete.push(`records[${i}] is not yet in a witnessed head`);
      return;
    }
    const wInc = ws[k];
    if (cmpInstant(claimed, wInc.witnessed_at) > 0) {
      fail(`records[${i}] claims a time after a witnessed head that already contains it`);
    }
    if (k > 0) {
      const wPrev = ws[k - 1];
      if (laterThan(wPrev.witnessed_at, claimed, tol)) {
        fail(`records[${i}] claims ${claimed}, and the head witnessed at ${wPrev.witnessed_at} ` +
          `does not contain it: logged more than ${tol} seconds late`);
      }
    } else if (laterThan(wInc.witnessed_at, claimed, tol)) {
      incomplete.push(`records[${i}]: the first witnessed head is more than ${tol} seconds after its ` +
        'claimed time, so how late it was logged cannot be bounded');
    }
  });

  // 7. Empty.
  if (recs.length === 0) incomplete.push('the bundle carries no record');

  if (incomplete.length) return { verdict: 'INCOMPLETE', reason: incomplete[0] };
  return { verdict: 'PASS', reason: null };
}
