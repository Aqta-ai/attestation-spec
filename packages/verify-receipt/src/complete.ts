/**
 * The `complete` profile (spec/CHECKPOINT-v1.md section 8), CHECKPOINT-v1
 * (spec/CHECKPOINT-v1.md) and EXECUTION-v1 (spec/EXECUTION-v1.md). DRAFT: both
 * record formats are drafts, not frozen.
 *
 * A reviewer holding an organisation's signed hourly checkpoints can tell when
 * records are missing from a bundle; a reviewer also holding an executor's
 * signed log can tell when the executor acted on a Seal record the bundle does
 * not carry. The second needs the executor's cooperation, and catches only
 * what reached the executor.
 *
 * Three verdicts, never two: PASS, FAIL, INCOMPLETE. The check order and every
 * reason string are a cross-implementation contract with the Python verifier
 * (aqta_verify_receipt/complete.py): first FAIL wins, and the two must return
 * the same verdict and reason on the same bytes.
 *
 * Explicit opt-in only. Nothing here is reached by inspecting input shape.
 */

import { createHash } from 'node:crypto';
import { _internal, verifyActionRecord } from './index.js';
import { _chainInternal, checkUseRecord } from './chain.js';
import type { ChainResult } from './chain.js';
import { leafHash } from './transparency.js';

const { RFC3339_OFFSET } = _internal;
const {
  cmpInstant, isObject, has, firstUnknown, canonicalBytes, withoutSignature, signatureReason, isKey, Fail,
  DECIMAL, DECIMAL_POSITIVE, HEX64,
} = _chainInternal;

type Obj = Record<string, unknown>;
type Str = Record<string, string>;

export interface CompleteOptions {
  trustedPublicKey?: string;
  /** The review window the relying party asks about, RFC 3339 with an offset. */
  reviewFrom?: string;
  reviewTo?: string;
  /** The relying party's designated executor keys. Absent with an executor log: INCOMPLETE. */
  executorKeys?: string[] | null;
}

const CHECKPOINT_FIELDS = [
  'v', 'org_id', 'checkpoint_seq', 'prev_checkpoint_hash', 'period_start', 'period_end', 'record_count',
  'total_count', 'records_hash', 'timestamp', 'public_key', 'signature',
];
const EXECUTION_FIELDS = [
  'v', 'executor_id', 'entry_seq', 'prev_entry_hash', 'org_id', 'result', 'action_id', 'action_leaf_hash',
  'use_id', 'use_leaf_hash', 'args_hash', 'timestamp', 'public_key', 'signature',
];
const BUNDLE_MEMBERS = ['v', 'org_id', 'checkpoints', 'records', 'executions'];

/** Log entry tags: receipts 0x00, anchors 0x01, ACTION-v1 0x02, USE-v1 0x03, CHECKPOINT-v1 0x04. */
const ENTRY_TAGS: Record<string, number> = { action: 0x02, use: 0x03, checkpoint: 0x04 };
const EMPTY_RECORDS_HASH = createHash('sha256').update(new Uint8Array(0)).digest('hex');

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

// --- Shared: verifying a record of a named kind, and its log leaf -----------------------------------------------

/** null when the record is a well-formed record of `kind` under the pinned issuer key, else the reason. */
export function checkRecordOfKind(kind: string, record: unknown, pinned: string): string | null {
  // One wording for a non-object in both languages: the published ACTION-v1
  // paths say "not an object" here and "not a mapping" in Python.
  if (!isObject(record)) return 'record must be an object';
  if (kind === 'action') {
    const r = verifyActionRecord(record as never, { trustedPublicKey: pinned });
    if (r.valid) return null;
    // The published ACTION-v1 paths word a canonicalisation failure
    // differently in each language (same verdict). Here it is one string.
    return (r.reason ?? '').startsWith('failed to canonicalise') ? 'record is not canonicalisable' : (r.reason ?? '');
  }
  if (kind === 'use') return checkUseRecord(record, pinned);
  if (kind === 'checkpoint') return checkCheckpointRecord(record, pinned);
  return 'unknown record kind';
}

/** RFC 6962 leaf hash of a verified record's log entry: tag || uint64be(len(payload)) || payload || signature. */
export function recordLeaf(kind: string, record: Obj): Uint8Array {
  const payload = canonicalBytes(withoutSignature(record));
  const sig = new TextEncoder().encode(record.signature as string);
  const entry = new Uint8Array(1 + 8 + payload.length + sig.length);
  entry[0] = ENTRY_TAGS[kind];
  let n = payload.length;
  for (let i = 8; i >= 1; i--) {
    entry[i] = n % 256;
    n = Math.floor(n / 256);
  }
  entry.set(payload, 9);
  entry.set(sig, 9 + payload.length);
  return leafHash(entry);
}

/** SHA-256 over the 32-byte leaf hashes, sorted ascending bytewise and concatenated. */
export function recordsHash(leaves: Uint8Array[]): string {
  const sorted = leaves.map(hex).sort();
  return createHash('sha256').update(Buffer.from(sorted.join(''), 'hex')).digest('hex');
}

function hashUnsigned(record: Obj): string {
  return createHash('sha256').update(canonicalBytes(withoutSignature(record))).digest('hex');
}

export const checkpointHash = hashUnsigned;
export const executionHash = hashUnsigned;

function stringsReason(o: Obj, fields: string[]): string | null {
  for (const f of fields) if (typeof o[f] !== 'string') return `${f} must be a string`;
  return null;
}

// --- CHECKPOINT-v1 (spec/CHECKPOINT-v1.md section 7) ------------------------------------------------------------

export function checkCheckpointRecord(cp: unknown, trustedPublicKey: string | undefined): string | null {
  if (!isObject(cp)) return 'checkpoint must be an object';
  for (const f of CHECKPOINT_FIELDS) if (!has(cp, f)) return `missing required field: ${f}`;
  const unknown = firstUnknown(cp, new Set(CHECKPOINT_FIELDS));
  if (unknown !== null) return `unknown top-level field: ${unknown}`;
  if (cp.v !== 'checkpoint-1') return "v must be the string 'checkpoint-1'";
  const why = stringsReason(cp, CHECKPOINT_FIELDS);
  if (why) return why;
  const c = cp as Str;
  if (c.org_id === '') return 'org_id must be a non-empty string';
  if (!DECIMAL_POSITIVE.test(c.checkpoint_seq)) return 'checkpoint_seq must be a canonical decimal string of at least 1';
  if (c.checkpoint_seq === '1') {
    if (c.prev_checkpoint_hash !== '') return 'prev_checkpoint_hash must be empty for checkpoint_seq 1';
  } else if (!HEX64.test(c.prev_checkpoint_hash)) {
    return 'prev_checkpoint_hash must be 64 lowercase hex characters';
  }
  for (const f of ['period_start', 'period_end', 'timestamp']) {
    if (!RFC3339_OFFSET.test(c[f])) return `${f} must be an RFC 3339 datetime with an explicit offset`;
  }
  if (cmpInstant(c.period_start, c.period_end) >= 0) return 'period_end must be after period_start';
  if (cmpInstant(c.timestamp, c.period_end) < 0) return 'timestamp must not be before period_end';
  for (const f of ['record_count', 'total_count']) {
    if (!DECIMAL.test(c[f])) return `${f} must be a canonical decimal string`;
  }
  if (BigInt(c.total_count) < BigInt(c.record_count)) return 'total_count must be at least record_count';
  if (c.checkpoint_seq === '1' && c.total_count !== c.record_count) {
    return 'total_count must equal record_count for checkpoint_seq 1';
  }
  if (!HEX64.test(c.records_hash)) return 'records_hash must be 64 lowercase hex characters';
  if (c.record_count === '0' && c.records_hash !== EMPTY_RECORDS_HASH) {
    return 'records_hash of an empty period must be the hash of nothing';
  }
  if (trustedPublicKey === undefined) return 'trusted_public_key required';
  if (c.public_key !== trustedPublicKey) return 'public_key does not match trusted key';
  return signatureReason(withoutSignature(cp), cp.signature, cp.public_key);
}

// --- EXECUTION-v1 (spec/EXECUTION-v1.md section 6) --------------------------------------------------------------

const LINK_FIELDS = ['action_leaf_hash', 'use_leaf_hash', 'args_hash'];

/** Integrity of one executor log entry under its own embedded key; says nothing about designation. */
export function checkExecutionRecord(entry: unknown): string | null {
  if (!isObject(entry)) return 'entry must be an object';
  for (const f of EXECUTION_FIELDS) if (!has(entry, f)) return `missing required field: ${f}`;
  const unknown = firstUnknown(entry, new Set(EXECUTION_FIELDS));
  if (unknown !== null) return `unknown top-level field: ${unknown}`;
  if (entry.v !== 'execution-1') return "v must be the string 'execution-1'";
  const why = stringsReason(entry, EXECUTION_FIELDS);
  if (why) return why;
  const e = entry as Str;
  for (const f of ['executor_id', 'org_id']) if (e[f] === '') return `${f} must be a non-empty string`;
  if (!DECIMAL_POSITIVE.test(e.entry_seq)) return 'entry_seq must be a canonical decimal string of at least 1';
  if (e.entry_seq === '1') {
    if (e.prev_entry_hash !== '') return 'prev_entry_hash must be empty for entry_seq 1';
  } else if (!HEX64.test(e.prev_entry_hash)) {
    return 'prev_entry_hash must be 64 lowercase hex characters';
  }
  if (e.result !== 'EXECUTED' && e.result !== 'REFUSED') return 'result must be EXECUTED or REFUSED';
  if (e.result === 'EXECUTED') {
    for (const f of ['action_id', 'use_id']) {
      if (e[f] === '') return `${f} must be a non-empty string for an EXECUTED entry`;
    }
    for (const f of LINK_FIELDS) if (!HEX64.test(e[f])) return `${f} must be 64 lowercase hex characters`;
  } else {
    for (const f of LINK_FIELDS) {
      if (e[f] !== '' && !HEX64.test(e[f])) return `${f} must be empty or 64 lowercase hex characters`;
    }
    if (e.action_leaf_hash === '' && e.action_id !== '') return 'action_id must be empty when action_leaf_hash is';
    if (e.use_leaf_hash === '' && e.use_id !== '') return 'use_id must be empty when use_leaf_hash is';
  }
  if (!RFC3339_OFFSET.test(e.timestamp)) return 'timestamp must be an RFC 3339 datetime with an explicit offset';
  if (!isKey(e.public_key)) return 'public_key must be a base64url Ed25519 key';
  return signatureReason(withoutSignature(entry), entry.signature, entry.public_key);
}

// --- The profile (spec/CHECKPOINT-v1.md section 8) --------------------------------------------------------------

/** Verify a completeness bundle. Never throws. */
export function verifyComplete(bundle: unknown, options: CompleteOptions = {}): ChainResult {
  try {
    return verifyCompleteInner(bundle, options);
  } catch (e) {
    if (e instanceof Fail) return { verdict: 'FAIL', reason: e.message };
    return { verdict: 'FAIL', reason: 'verification error' };
  }
}

function verifyCompleteInner(bundle: unknown, options: CompleteOptions): ChainResult {
  const incomplete: string[] = [];
  const fail = (reason: string): never => {
    throw new Fail(reason);
  };
  const pinned = options.trustedPublicKey as string;

  // 1. Inputs.
  if (typeof pinned !== 'string' || !isKey(pinned)) fail('a pinned issuer key is required');
  for (const w of [options.reviewFrom, options.reviewTo]) {
    if (typeof w !== 'string' || !RFC3339_OFFSET.test(w)) {
      fail('a review window (review_from and review_to, RFC 3339 with an offset) is required');
    }
  }
  const reviewFrom = options.reviewFrom as string;
  const reviewTo = options.reviewTo as string;
  if (cmpInstant(reviewFrom, reviewTo) >= 0) fail('review_from must be before review_to');
  let trustedExec: Set<string> | null = null;
  if (options.executorKeys !== undefined && options.executorKeys !== null) {
    if (!Array.isArray(options.executorKeys) || !options.executorKeys.every(isKey)) {
      fail('executor_keys must be base64url Ed25519 keys');
    }
    trustedExec = new Set(options.executorKeys);
  }

  // 2. Bundle.
  if (!isObject(bundle)) fail('bundle must be an object');
  const b = bundle as Obj;
  for (const m of BUNDLE_MEMBERS) if (!has(b, m)) fail(`bundle missing member: ${m}`);
  const unknown = firstUnknown(b, new Set(BUNDLE_MEMBERS));
  if (unknown !== null) fail(`bundle has unknown member: ${unknown}`);
  if (b.v !== 'complete-1') fail("bundle v must be the string 'complete-1'");
  const org = b.org_id;
  if (typeof org !== 'string' || org === '') fail('bundle org_id must be a non-empty string');
  for (const m of ['checkpoints', 'records', 'executions']) if (!Array.isArray(b[m])) fail(`bundle ${m} must be an array`);

  // 3. Checkpoints: each one, then the chain.
  const cps = b.checkpoints as Str[];
  cps.forEach((cp, i) => {
    const why = checkCheckpointRecord(cp, pinned);
    if (why !== null) fail(`checkpoints[${i}]: ${why}`);
    if (cp.org_id !== org) fail(`checkpoints[${i}] is for a different organisation`);
    if (i > 0) {
      const prev = cps[i - 1];
      if (BigInt(cp.checkpoint_seq) !== BigInt(prev.checkpoint_seq) + 1n) {
        fail(`checkpoints[${i}] does not follow checkpoints[${i - 1}] (sequence)`);
      }
      if (cp.prev_checkpoint_hash !== checkpointHash(prev)) {
        fail(`checkpoints[${i}] does not follow checkpoints[${i - 1}] (previous hash)`);
      }
      if (cmpInstant(cp.period_start, prev.period_end) !== 0) {
        fail(`checkpoints[${i}] does not follow checkpoints[${i - 1}] (period)`);
      }
      if (BigInt(cp.total_count) !== BigInt(prev.total_count) + BigInt(cp.record_count)) {
        fail(`checkpoints[${i}] does not follow checkpoints[${i - 1}] (total)`);
      }
    }
  });

  // 4. Coverage of the review window.
  if (cps.length === 0) {
    incomplete.push('the bundle carries no checkpoint');
  } else if (cmpInstant(cps[0].period_start, reviewFrom) > 0 || cmpInstant(cps[cps.length - 1].period_end, reviewTo) < 0) {
    incomplete.push('the checkpoints do not cover the review window');
  }

  // 5. Records: each verifies, belongs to the organisation, appears once, and falls in a checkpoint's period.
  const byLeaf = new Map<string, [string, Str]>();
  const perCp: Uint8Array[][] = cps.map(() => []);
  (b.records as unknown[]).forEach((item, i) => {
    if (!isObject(item) || Object.keys(item).length !== 2 || !has(item, 'kind') || !has(item, 'record')) {
      fail(`records[${i}] must be an object with kind and record`);
    }
    const it = item as Obj;
    const kind = it.kind;
    if (kind !== 'action' && kind !== 'use') fail(`records[${i}].kind must be action or use`);
    const why = checkRecordOfKind(kind as string, it.record, pinned);
    if (why !== null) fail(`records[${i}]: ${why}`);
    const rec = it.record as Str;
    if (rec.org_id !== org) fail(`records[${i}] is for a different organisation`);
    const leaf = recordLeaf(kind as string, rec);
    const key = hex(leaf);
    if (byLeaf.has(key)) fail(`records[${i}] repeats a record`);
    byLeaf.set(key, [kind as string, rec]);
    let slot = -1;
    for (let j = 0; j < cps.length; j++) {
      if (cmpInstant(cps[j].period_start, rec.timestamp) <= 0 && cmpInstant(rec.timestamp, cps[j].period_end) < 0) {
        slot = j;
        break;
      }
    }
    if (slot < 0) {
      if (cps.length) incomplete.push(`records[${i}] lies outside every checkpoint in the bundle`);
      return;
    }
    perCp[slot].push(leaf);
  });

  // 6. Each checkpoint against the records the bundle carries for its period.
  cps.forEach((cp, j) => {
    const n = perCp[j].length;
    const counted = BigInt(cp.record_count);
    if (BigInt(n) > counted) {
      fail(`checkpoints[${j}] counts ${cp.record_count} records in its period and the bundle carries ${n}`);
    }
    if (BigInt(n) < counted) {
      incomplete.push(`checkpoints[${j}] counts ${cp.record_count} records in its period and the bundle carries ${n}`);
      return;
    }
    if (recordsHash(perCp[j]) !== cp.records_hash) {
      fail(`the records the bundle carries for checkpoints[${j}] do not match its records_hash`);
    }
  });

  // 7. The executor's log, reconciled against the records.
  const execs = b.executions as Str[];
  const executed = new Set<string>();
  execs.forEach((e, i) => {
    const why = checkExecutionRecord(e);
    if (why !== null) fail(`executions[${i}]: ${why}`);
    if (e.org_id !== org) fail(`executions[${i}] is for a different organisation`);
    if (i > 0) {
      const first = execs[0];
      const prev = execs[i - 1];
      if (e.executor_id !== first.executor_id || e.public_key !== first.public_key) {
        fail(`executions[${i}] is from a different executor`);
      }
      if (BigInt(e.entry_seq) !== BigInt(prev.entry_seq) + 1n || e.prev_entry_hash !== executionHash(prev)) {
        fail(`executions[${i}] does not follow executions[${i - 1}]`);
      }
    }
    if (trustedExec === null) {
      if (!incomplete.includes('no executor key set was supplied')) incomplete.push('no executor key set was supplied');
    } else if (!trustedExec.has(e.public_key)) {
      fail(`executions[${i}] is not signed by a designated executor key`);
    }
    if (cps.length && (cmpInstant(e.timestamp, cps[0].period_start) < 0 ||
        cmpInstant(e.timestamp, cps[cps.length - 1].period_end) >= 0)) {
      incomplete.push(`executions[${i}] lies outside the checkpointed span`);
    }
    if (e.action_leaf_hash !== '') {
      const found = byLeaf.get(e.action_leaf_hash);
      if (found === undefined) fail(`executions[${i}] names an action record that is not in the bundle`);
      const [kind, rec] = found as [string, Str];
      if (kind !== 'action') fail(`executions[${i}].action_leaf_hash names a record that is not an action`);
      if (rec.action_id !== e.action_id) fail(`executions[${i}].action_id differs from the record's`);
      if (e.args_hash !== '' && e.args_hash !== rec.args_hash) fail(`executions[${i}].args_hash differs from the record's`);
      if (e.result === 'EXECUTED' && rec.outcome !== 'ALLOWED') {
        fail(`executions[${i}] executed an action that was not ALLOWED`);
      }
    }
    if (e.use_leaf_hash !== '') {
      const found = byLeaf.get(e.use_leaf_hash);
      if (found === undefined) fail(`executions[${i}] names a USE record that is not in the bundle`);
      const [kind, use] = found as [string, Str];
      if (kind !== 'use') fail(`executions[${i}].use_leaf_hash names a record that is not a USE`);
      if (use.use_id !== e.use_id) fail(`executions[${i}].use_id differs from the record's`);
      if (use.action_id !== e.action_id) fail(`executions[${i}] names a USE record for a different action`);
    }
    if (e.result === 'EXECUTED') {
      if (executed.has(e.action_id)) fail(`executions[${i}] executes an action already executed`);
      executed.add(e.action_id);
    }
  });

  if (incomplete.length) return { verdict: 'INCOMPLETE', reason: incomplete[0] };
  return { verdict: 'PASS', reason: null };
}
