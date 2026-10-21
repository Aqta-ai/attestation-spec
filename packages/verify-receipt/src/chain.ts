/**
 * The `chain` profile (spec/USE-v1.md section 9), GRANT-v1 (spec/GRANT-v1.md)
 * and USE-v1 (spec/USE-v1.md). DRAFT: both record formats are drafts, not
 * frozen.
 *
 * Three verdicts, never two: PASS, FAIL, INCOMPLETE. Missing evidence is never
 * a pass. The check order and every reason string are a cross-implementation
 * contract with the Python verifier (aqta_verify_receipt/chain.py): first FAIL
 * wins, and the two must return the same verdict and reason on the same bytes.
 *
 * Explicit opt-in only. Nothing here is reached by inspecting input shape.
 * Node-only, like transparency.ts: it needs SHA-256.
 */

import nacl from 'tweetnacl';
import { createHash } from 'node:crypto';
import { _internal, verifyActionRecord } from './index.js';

const { canonicalValue, RFC3339_OFFSET, B64URL_STRICT, base64urlDecode, canonicalScalar } = _internal;

export type ChainVerdict = 'PASS' | 'FAIL' | 'INCOMPLETE';
export interface ChainResult {
  verdict: ChainVerdict;
  reason: string | null;
}
export interface ChainOptions {
  trustedPublicKey?: string;
  /** The relying party's designated approver keys. Absent: authorised actions are INCOMPLETE. */
  approverKeys?: string[] | null;
}

const GRANT_FIELDS = [
  'v', 'grant_id', 'intent_ref', 'org_id', 'approver', 'signing_mode', 'scope_tool', 'scope_resource',
  'scope_environment', 'max_uses', 'not_before', 'not_after', 'require_args', 'public_key', 'signature',
];
const GRANT_OPTIONAL = ['scope_args', 'agent_key_id'];
const USE_FIELDS = [
  'v', 'use_id', 'org_id', 'action_id', 'args_hash', 'grant_id', 'grant_hash', 'approver_public_key',
  'consumption_key', 'use_index', 'max_uses', 'timestamp', 'public_key', 'signature',
];
const BUNDLE_MEMBERS = ['v', 'grants', 'uses', 'actions'];

const DECIMAL = /^(0|[1-9][0-9]*)$/;
const DECIMAL_POSITIVE = /^[1-9][0-9]*$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ARG_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
const KEY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const UNBINDABLE = new Set(['aqta_grant', 'aqta_grant_id', 'aqta_grant_hash']);
const TS = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/;

type Obj = Record<string, unknown>;

class Fail extends Error {}

function isObject(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function has(o: Obj, k: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, k);
}

/** Own-property read: `args.constructor` must not reach Object.prototype. */
function own(o: Obj, k: string): unknown {
  return has(o, k) ? o[k] : undefined;
}

function firstUnknown(o: Obj, allowed: Set<string>): string | null {
  const unknown = Object.keys(o).filter((k) => !allowed.has(k)).sort();
  return unknown.length ? unknown[0] : null;
}

function canonicalBytes(o: Obj): Uint8Array {
  return new TextEncoder().encode(canonicalValue(o));
}

function withoutSignature(o: Obj): Obj {
  const p: Obj = { ...o };
  delete p.signature;
  return p;
}

function signatureReason(payload: Obj, signature: unknown, publicKey: unknown): string | null {
  let canonical: Uint8Array;
  try {
    canonical = canonicalBytes(payload);
  } catch {
    return 'record is not canonicalisable';
  }
  if (typeof signature !== 'string' || !B64URL_STRICT.test(signature) ||
      typeof publicKey !== 'string' || !B64URL_STRICT.test(publicKey)) {
    return 'signature decode error: not base64url';
  }
  let sig: Uint8Array;
  let pub: Uint8Array;
  try {
    sig = base64urlDecode(signature);
    pub = base64urlDecode(publicKey);
  } catch {
    return 'signature decode error: not base64url';
  }
  if (sig.length !== 64) return 'signature length != 64 bytes';
  if (pub.length !== 32) return 'public key length != 32 bytes';
  if (!canonicalScalar(sig)) return 'signature check failed';
  try {
    if (!nacl.sign.detached.verify(canonical, sig, pub)) return 'signature check failed';
  } catch {
    return 'signature check failed';
  }
  return null;
}

function isKey(v: unknown): boolean {
  if (typeof v !== 'string' || !B64URL_STRICT.test(v)) return false;
  try {
    return base64urlDecode(v).length === 32;
  } catch {
    return false;
  }
}

// --- Times: exact instants without a date library (spec/GRANT-v1.md section 6.1) ------------------------------

function daysFromCivil(y0: number, m: number, d: number): number {
  const y = m <= 2 ? y0 - 1 : y0;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

function instant(ts: string): [number, string] {
  const m = TS.exec(ts) as RegExpExecArray;
  const n = (i: number) => parseInt(m[i], 10);
  let secs = daysFromCivil(n(1), n(2), n(3)) * 86400 + n(4) * 3600 + n(5) * 60 + n(6);
  if (m[8]) {
    const off = n(9) * 3600 + n(10) * 60;
    secs -= m[8] === '+' ? off : -off;
  }
  return [secs, m[7] ?? ''];
}

function cmpInstant(a: string, b: string): number {
  const [sa, fa0] = instant(a);
  const [sb, fb0] = instant(b);
  if (sa !== sb) return sa < sb ? -1 : 1;
  const len = Math.max(fa0.length, fb0.length);
  const fa = fa0.padEnd(len, '0');
  const fb = fb0.padEnd(len, '0');
  return fa === fb ? 0 : fa < fb ? -1 : 1;
}

function decLe(a: string, b: string): boolean {
  if (a.length !== b.length) return a.length < b.length;
  return a <= b;
}

// --- GRANT-v1 (spec/GRANT-v1.md section 7.1) -------------------------------------------------------------------

/** Integrity of one grant: null when it holds, else the reason. Says nothing about authority. */
export function checkGrantRecord(grant: unknown): string | null {
  if (!isObject(grant)) return 'grant must be an object';
  for (const f of GRANT_FIELDS) if (!has(grant, f)) return `missing required field: ${f}`;
  const unknown = firstUnknown(grant, new Set([...GRANT_FIELDS, ...GRANT_OPTIONAL]));
  if (unknown !== null) return `unknown top-level field: ${unknown}`;
  if (grant.v !== 'grant-1') return "v must be the string 'grant-1'";
  for (const f of [...GRANT_FIELDS, ...GRANT_OPTIONAL]) {
    if (!has(grant, f)) continue;
    if (f === 'require_args' || f === 'scope_args') {
      if (!Array.isArray(grant[f])) return `${f} must be an array`;
    } else if (typeof grant[f] !== 'string') {
      return `${f} must be a string`;
    }
  }
  const g = grant as Record<string, string> & Obj;
  if (g.signing_mode !== 'approver-signed') return "signing_mode must be 'approver-signed'";
  for (const f of ['grant_id', 'org_id', 'approver', 'scope_tool']) {
    if (g[f] === '') return `${f} must be a non-empty string`;
  }
  if (g.max_uses !== '' && !DECIMAL.test(g.max_uses)) return "max_uses must be '' or a canonical decimal string";
  if (g.not_before !== '' && !RFC3339_OFFSET.test(g.not_before)) {
    return "not_before must be '' or an RFC 3339 datetime with an explicit offset";
  }
  if (!RFC3339_OFFSET.test(g.not_after)) return 'not_after must be an RFC 3339 datetime with an explicit offset';
  const req = grant.require_args as unknown[];
  if (!req.every((x) => typeof x === 'string')) return 'require_args must contain only strings';
  const reqSorted = [...(req as string[])].sort();
  if (req.some((x, i) => x !== reqSorted[i])) return 'require_args must be in lexicographic order';
  if (has(grant, 'scope_args')) {
    const entries = grant.scope_args as unknown[];
    if (entries.length === 0) return 'scope_args must be a non-empty list of name=value strings';
    const names = new Set<string>();
    for (const e of entries) {
      if (typeof e !== 'string' || !e.includes('=')) return 'scope_args entries must be name=value strings';
      const at = e.indexOf('=');
      const name = e.slice(0, at);
      const value = e.slice(at + 1);
      if (!ARG_NAME.test(name) || UNBINDABLE.has(name) || value === '') {
        return 'scope_args entry has an invalid name or an empty value';
      }
      if (names.has(name)) return `scope_args names ${name} twice`;
      names.add(name);
    }
    const sorted = [...(entries as string[])].sort();
    if (entries.some((x, i) => x !== sorted[i])) return 'scope_args must be sorted';
  }
  if (has(grant, 'agent_key_id') && !KEY_ID.test(g.agent_key_id)) return 'agent_key_id must be an API key id';
  return signatureReason(withoutSignature(grant), grant.signature, grant.public_key);
}

export function grantHash(grant: Obj): string {
  return createHash('sha256').update(canonicalBytes(withoutSignature(grant))).digest('hex');
}

// --- USE-v1 (spec/USE-v1.md section 7) -------------------------------------------------------------------------

export function checkUseRecord(use: unknown, trustedPublicKey: string | undefined): string | null {
  if (!isObject(use)) return 'use must be an object';
  for (const f of USE_FIELDS) if (!has(use, f)) return `missing required field: ${f}`;
  const unknown = firstUnknown(use, new Set(USE_FIELDS));
  if (unknown !== null) return `unknown top-level field: ${unknown}`;
  if (use.v !== 'use-1') return "v must be the string 'use-1'";
  for (const f of USE_FIELDS) if (typeof use[f] !== 'string') return `${f} must be a string`;
  const u = use as Record<string, string>;
  for (const f of ['use_id', 'org_id', 'action_id', 'grant_id', 'consumption_key']) {
    if (u[f] === '') return `${f} must be a non-empty string`;
  }
  for (const f of ['args_hash', 'grant_hash']) {
    if (!HEX64.test(u[f])) return `${f} must be 64 lowercase hex characters`;
  }
  if (!isKey(u.approver_public_key)) return 'approver_public_key must be a base64url Ed25519 key';
  if (!DECIMAL_POSITIVE.test(u.use_index)) return 'use_index must be a canonical decimal string of at least 1';
  if (!DECIMAL.test(u.max_uses)) return 'max_uses must be a canonical decimal string';
  if (!RFC3339_OFFSET.test(u.timestamp)) return 'timestamp must be an RFC 3339 datetime with an explicit offset';
  if (trustedPublicKey === undefined) return 'trusted_public_key required';
  if (u.public_key !== trustedPublicKey) return 'public_key does not match trusted key';
  return signatureReason(withoutSignature(use), use.signature, use.public_key);
}

// --- Scope (spec/GRANT-v1.md section 6) ------------------------------------------------------------------------

function matches(pattern: string, value: string): boolean {
  if (pattern.endsWith('*')) return value.startsWith(pattern.slice(0, -1));
  return pattern === value;
}

function isEmptyEvidence(v: unknown): boolean {
  if (v === null || v === undefined || v === '') return true;
  if (Array.isArray(v)) return v.length === 0;
  if (isObject(v)) return Object.keys(v).length === 0;
  return false;
}

function scopeReason(g: Obj, rec: Obj, args: Obj): string | null {
  if (g.org_id !== rec.org_id) return 'the grant was issued for a different organisation';
  if (!matches(g.scope_tool as string, rec.tool as string)) return "the tool is outside the grant's scope_tool";
  const res = g.scope_resource as string;
  if (res !== '') {
    const declared = ['device_id', 'resource'].filter((k) => has(args, k) && args[k] !== null && args[k] !== '');
    if (declared.length === 0) return 'the action declares no resource and the grant names one';
    for (const k of declared) {
      if (typeof args[k] !== 'string' || args[k] !== res) return `the action's ${k} is not the grant's resource`;
    }
  }
  const env = g.scope_environment as string;
  if (env !== '') {
    const e = own(args, 'environment');
    if (typeof e !== 'string' || e !== env) return "the action's environment is not the grant's";
  }
  for (const entry of (has(g, 'scope_args') ? (g.scope_args as string[]) : [])) {
    const at = entry.indexOf('=');
    const name = entry.slice(0, at);
    const value = entry.slice(at + 1);
    const v = own(args, name);
    if (typeof v !== 'string' || v !== value) return `the action does not match the value the grant fixes for ${name}`;
  }
  for (const name of g.require_args as string[]) {
    if (!has(args, name) || isEmptyEvidence(args[name])) return `the action lacks evidence the grant requires: ${name}`;
  }
  return null;
}

function inWindow(g: Obj, ts: string): boolean {
  if (g.not_before !== '' && cmpInstant(ts, g.not_before as string) < 0) return false;
  return cmpInstant(ts, g.not_after as string) <= 0;
}

function ckey(g: Obj, orgId: string): string {
  return g.intent_ref !== '' ? `org:${orgId}|intent:${g.intent_ref}` : `org:${orgId}|grant:${g.grant_id}`;
}

// --- The chain (spec/USE-v1.md section 9.3) --------------------------------------------------------------------

/** Verify a chain bundle. Never throws. */
export function verifyChain(bundle: unknown, options: ChainOptions = {}): ChainResult {
  try {
    return verifyChainInner(bundle, options);
  } catch (e) {
    if (e instanceof Fail) return { verdict: 'FAIL', reason: e.message };
    return { verdict: 'FAIL', reason: 'verification error' };
  }
}

function verifyChainInner(bundle: unknown, options: ChainOptions): ChainResult {
  const incomplete: string[] = [];
  const fail = (reason: string): never => {
    throw new Fail(reason);
  };
  const pinned = options.trustedPublicKey;

  // 1. Inputs.
  if (typeof pinned !== 'string' || !isKey(pinned)) fail('a pinned issuer key is required');
  let trusted: Set<string> | null = null;
  if (options.approverKeys !== undefined && options.approverKeys !== null) {
    if (!Array.isArray(options.approverKeys) || !options.approverKeys.every(isKey)) {
      fail('approver_keys must be base64url Ed25519 keys');
    }
    trusted = new Set(options.approverKeys);
  }

  // 2. Bundle.
  if (!isObject(bundle)) fail('bundle must be an object');
  const b = bundle as Obj;
  for (const m of BUNDLE_MEMBERS) if (!has(b, m)) fail(`bundle missing member: ${m}`);
  const unknown = firstUnknown(b, new Set(BUNDLE_MEMBERS));
  if (unknown !== null) fail(`bundle has unknown member: ${unknown}`);
  if (b.v !== 'chain-1') fail("bundle v must be the string 'chain-1'");
  for (const m of ['grants', 'uses', 'actions']) if (!Array.isArray(b[m])) fail(`bundle ${m} must be an array`);

  // 3. Actions.
  const actions = b.actions as unknown[];
  const byAction = new Map<string, { record: Obj; args: Obj }>();
  actions.forEach((a, i) => {
    if (!isObject(a) || Object.keys(a).length !== 2 || !has(a, 'record') || !has(a, 'args')) {
      fail(`actions[${i}] must be an object with record and args`);
    }
    const item = a as Obj;
    if (!isObject(item.args)) fail(`actions[${i}].args must be an object`);
    const r = verifyActionRecord(item.record, { trustedPublicKey: pinned });
    if (!r.valid) {
      // The published ACTION-v1 paths word a canonicalisation failure
      // differently in each language (same verdict). The chain reason is one
      // string in both.
      const reason = (r.reason ?? '').startsWith('failed to canonicalise') ? 'record is not canonicalisable' : r.reason;
      fail(`actions[${i}]: ${reason}`);
    }
    let h = '';
    try {
      h = createHash('sha256').update(canonicalBytes(item.args as Obj)).digest('hex');
    } catch {
      fail(`actions[${i}].args is not canonicalisable`);
    }
    const rec = item.record as Obj;
    if (h !== rec.args_hash) fail(`actions[${i}].args do not match the record's args_hash`);
    const aid = rec.action_id as string;
    if (byAction.has(aid)) fail(`actions[${i}] repeats an action_id`);
    byAction.set(aid, { record: rec, args: item.args as Obj });
  });

  // 4. Grants.
  const byHash = new Map<string, Obj>();
  (b.grants as unknown[]).forEach((g, i) => {
    const why = checkGrantRecord(g);
    if (why !== null) fail(`grants[${i}]: ${why}`);
    const h = grantHash(g as Obj);
    if (byHash.has(h)) fail(`grants[${i}] repeats an earlier grant`);
    byHash.set(h, g as Obj);
  });
  const ids = new Set([...byHash.values()].map((g) => g.grant_id as string));

  // 5. Uses.
  const uses = b.uses as unknown[];
  const seenUseIds = new Set<string>();
  uses.forEach((u, i) => {
    const why = checkUseRecord(u, pinned);
    if (why !== null) fail(`uses[${i}]: ${why}`);
    const id = (u as Obj).use_id as string;
    if (seenUseIds.has(id)) fail(`uses[${i}] repeats a use_id`);
    seenUseIds.add(id);
  });
  const U = uses as Array<Record<string, string>>;

  // 6. Conflicts.
  const claims = new Set<string>();
  const named = new Set<string>();
  U.forEach((u, i) => {
    const c = JSON.stringify([u.consumption_key, u.use_index]);
    if (claims.has(c)) fail(`uses[${i}] claims a use another USE record already claims`);
    claims.add(c);
    if (named.has(u.action_id)) fail(`uses[${i}] names an action another USE record already names`);
    named.add(u.action_id);
  });

  // 7. Each USE.
  U.forEach((u, i) => {
    const g = byHash.get(u.grant_hash);
    if (g === undefined) {
      if (ids.has(u.grant_id)) fail(`uses[${i}].grant_hash does not match the grant presented`);
      incomplete.push(`uses[${i}] names a grant that is not in the bundle`);
      return;
    }
    if (u.grant_id !== g.grant_id) fail(`uses[${i}].grant_id differs from the grant's`);
    if (u.org_id !== g.org_id) fail(`uses[${i}].org_id differs from the grant's`);
    if (u.approver_public_key !== g.public_key) fail(`uses[${i}].approver_public_key differs from the grant's key`);
    if (u.max_uses !== g.max_uses) fail(`uses[${i}].max_uses differs from the grant's`);
    if (g.max_uses === '') fail(`uses[${i}] consumes a grant with no use limit`);
    if (!decLe(u.use_index, g.max_uses as string)) fail(`uses[${i}] is use ${u.use_index} of ${g.max_uses}`);
    if (u.consumption_key !== ckey(g, u.org_id)) {
      fail(`uses[${i}].consumption_key is not the key the grant is counted against`);
    }
    if (!inWindow(g, u.timestamp)) fail(`uses[${i}] was recorded outside the grant's validity window`);
    const a = byAction.get(u.action_id);
    if (a === undefined) {
      incomplete.push(`uses[${i}] names an action that is not in the bundle`);
      return;
    }
    if (a.record.outcome !== 'ALLOWED') fail(`uses[${i}] names an action that was not ALLOWED`);
    if (a.record.org_id !== u.org_id) fail(`uses[${i}].org_id differs from the action's`);
    if (a.record.args_hash !== u.args_hash) fail(`uses[${i}].args_hash differs from the action's`);
    if (own(a.args, 'aqta_grant_hash') !== u.grant_hash) {
      fail(`uses[${i}] names an action whose arguments do not reference its grant`);
    }
  });

  // 8. Each action that references a grant.
  actions.forEach((item, i) => {
    const args = (item as Obj).args as Obj;
    const rec = (item as Obj).record as Obj;
    if (!has(args, 'aqta_grant_id') && !has(args, 'aqta_grant_hash')) return;
    const gid = own(args, 'aqta_grant_id');
    const gh = own(args, 'aqta_grant_hash');
    if (typeof gid !== 'string' || typeof gh !== 'string') fail(`actions[${i}].args carry a partial grant reference`);
    const g = byHash.get(gh as string);
    if (g === undefined) {
      if (ids.has(gid as string)) fail(`actions[${i}] names a grant whose content differs from the grant presented`);
      if (rec.outcome === 'ALLOWED') incomplete.push(`actions[${i}] names a grant that is not in the bundle`);
      return;
    }
    if (gid !== g.grant_id) fail(`actions[${i}].aqta_grant_id differs from the grant's`);
    if (rec.outcome !== 'ALLOWED') return;
    const why = scopeReason(g, rec, args);
    if (why !== null) fail(`actions[${i}] is outside its grant: ${why}`);
    if (trusted === null) {
      incomplete.push('no approver key set was supplied');
    } else if (!trusted.has(g.public_key as string)) {
      fail(`actions[${i}] was authorised by a grant whose key is not a designated approver`);
    }
    if (g.max_uses !== '') {
      if (!U.some((u) => u.action_id === rec.action_id)) {
        incomplete.push(`actions[${i}] consumed a counted grant and its USE record is not in the bundle`);
      }
    } else if (!inWindow(g, rec.timestamp as string)) {
      fail(`actions[${i}] is outside its grant's validity window`);
    }
  });

  // 9. Empty.
  if (actions.length === 0) incomplete.push('the bundle carries no action');

  if (incomplete.length) return { verdict: 'INCOMPLETE', reason: incomplete[0] };
  return { verdict: 'PASS', reason: null };
}

/** Internal, for the interop sweep only: the exact-instant comparator. */
export const _chainInternal = { cmpInstant };
