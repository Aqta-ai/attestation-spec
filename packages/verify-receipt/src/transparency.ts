/**
 * Transparency proof verification: RFC 6962 inclusion and consistency.
 *
 * A receipt signature answers "did this issuer assert this". It cannot answer
 * "is this one of the entries the issuer has committed to, and has that
 * commitment only ever grown". Those are log questions, and answering them
 * needs a signed tree head plus a proof, verified without holding the log.
 *
 * Nothing here contacts a server. A reviewer holding a proof, a head and the
 * published key can settle both questions offline, which is the only reason
 * the proofs are worth issuing.
 *
 * What these proofs do NOT establish, and no proof in this file claims:
 * that the entries you were not shown are irrelevant. Inclusion proves that
 * what you were shown is genuinely in the log. Omission stays open.
 */
import nacl from 'tweetnacl';
import { createHash } from 'node:crypto';

/**
 * SHA-256 via the Node runtime rather than a new dependency. A verifier's
 * value is inversely proportional to how much code a reviewer has to trust,
 * so this module adds no third-party hashing. The receipt module stays free
 * of Node built-ins and remains isomorphic; proof checking is a CLI job.
 */
function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/** RFC 6962 §2.1 domain separation. */
const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    throw new Error('not lowercase hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** SHA-256(0x01 || left || right). */
function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + left.length + right.length);
  buf[0] = NODE_PREFIX;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha256(buf);
}

/** SHA-256(0x00 || entry). Exported so a caller can derive a leaf from receipt bytes. */
export function leafHash(entry: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + entry.length);
  buf[0] = LEAF_PREFIX;
  buf.set(entry, 1);
  return sha256(buf);
}

export interface InclusionProof {
  leaf_hash: string;
  leaf_index: number;
  tree_size: number;
  root_hash: string;
  audit_path: string[];
}

export interface ConsistencyProof {
  old_size: number;
  new_size: number;
  old_root: string;
  new_root: string;
  consistency_path: string[];
}

export interface SignedTreeHead {
  org_id: string;
  tree_size: number;
  root_hash: string;
  signature: string;
}

export interface ProofResult {
  valid: boolean;
  reason?: string;
}

function isSafeSize(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
}

// Cursor arithmetic must stay in double-precision integer operations: the JS
// bitwise operators coerce their operands to 32 bits, so `n >>= 1` maps 2^32
// to 0 and lets an audit path 32 nodes short satisfy the exact-consumption
// check below. isSafeSize admits sizes up to 2^53. Division by 2 plus floor
// is exact for every integer in that range.
function halve(n: number): number {
  return Math.floor(n / 2);
}

function isPowerOfTwo(n: number): boolean {
  if (n < 1) return false;
  while (n % 2 === 0) n /= 2;
  return n === 1;
}

/**
 * Verify that a leaf is in a tree of the stated size with the stated root.
 *
 * Follows RFC 6962 §2.1.1. The walk consumes the audit path exactly; a path
 * with a node left over, or one that runs out early, fails rather than being
 * tolerated, because a verifier that accepts a sloppy proof accepts a forged
 * one built the same way.
 */
export function verifyInclusionProof(proof: unknown): ProofResult {
  if (typeof proof !== 'object' || proof === null) {
    return { valid: false, reason: 'proof is not an object' };
  }
  const p = proof as Record<string, unknown>;
  if (!isSafeSize(p.tree_size) || p.tree_size < 1) {
    return { valid: false, reason: 'tree_size must be a positive integer' };
  }
  if (!isSafeSize(p.leaf_index) || (p.leaf_index as number) >= (p.tree_size as number)) {
    return { valid: false, reason: 'leaf_index must be an integer inside the tree' };
  }
  if (!Array.isArray(p.audit_path)) {
    return { valid: false, reason: 'audit_path must be an array' };
  }

  let leaf: Uint8Array;
  let root: Uint8Array;
  let path: Uint8Array[];
  try {
    leaf = hexToBytes(p.leaf_hash as string);
    root = hexToBytes(p.root_hash as string);
    path = (p.audit_path as string[]).map(hexToBytes);
  } catch {
    return { valid: false, reason: 'hashes must be lowercase hex' };
  }
  if (leaf.length !== 32 || root.length !== 32 || path.some((n) => n.length !== 32)) {
    return { valid: false, reason: 'every hash must be 32 bytes' };
  }

  let fn = p.leaf_index as number;
  let sn = (p.tree_size as number) - 1;
  let r = leaf;

  for (const sibling of path) {
    if (sn === 0) return { valid: false, reason: 'audit_path is longer than the tree allows' };
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(sibling, r);
      while (fn !== 0 && fn % 2 === 0) {
        fn = halve(fn);
        sn = halve(sn);
      }
    } else {
      r = nodeHash(r, sibling);
    }
    fn = halve(fn);
    sn = halve(sn);
  }

  if (sn !== 0) return { valid: false, reason: 'audit_path is shorter than the tree requires' };
  if (!bytesEqual(r, root)) return { valid: false, reason: 'computed root does not match root_hash' };
  return { valid: true };
}

/**
 * Verify that a later tree is an append-only extension of an earlier one.
 *
 * Follows RFC 6962 §2.1.2. This is the check that makes a log a log: without
 * it, an issuer can publish a head, then publish another that quietly drops or
 * reorders what came before.
 */
export function verifyConsistencyProof(proof: unknown): ProofResult {
  if (typeof proof !== 'object' || proof === null) {
    return { valid: false, reason: 'proof is not an object' };
  }
  const p = proof as Record<string, unknown>;
  if (!isSafeSize(p.old_size) || (p.old_size as number) < 1) {
    return { valid: false, reason: 'old_size must be a positive integer' };
  }
  if (!isSafeSize(p.new_size) || (p.new_size as number) < (p.old_size as number)) {
    return { valid: false, reason: 'new_size must be an integer at least old_size' };
  }
  if (!Array.isArray(p.consistency_path)) {
    return { valid: false, reason: 'consistency_path must be an array' };
  }

  let oldRoot: Uint8Array;
  let newRoot: Uint8Array;
  let nodes: Uint8Array[];
  try {
    oldRoot = hexToBytes(p.old_root as string);
    newRoot = hexToBytes(p.new_root as string);
    nodes = (p.consistency_path as string[]).map(hexToBytes);
  } catch {
    return { valid: false, reason: 'hashes must be lowercase hex' };
  }
  if (oldRoot.length !== 32 || newRoot.length !== 32 || nodes.some((n) => n.length !== 32)) {
    return { valid: false, reason: 'every hash must be 32 bytes' };
  }

  const oldSize = p.old_size as number;
  const newSize = p.new_size as number;

  if (oldSize === newSize) {
    // Nothing appended. The roots must be identical and a proof would be noise.
    if (nodes.length > 0) return { valid: false, reason: 'no consistency_path is expected when the tree has not grown' };
    if (!bytesEqual(oldRoot, newRoot)) return { valid: false, reason: 'tree did not grow but roots differ' };
    return { valid: true };
  }

  // When old_size is an exact power of two its root is the first node of the
  // path, and RFC 6962 omits it because the verifier already holds it.
  if (isPowerOfTwo(oldSize)) nodes = [oldRoot, ...nodes];
  if (nodes.length === 0) return { valid: false, reason: 'consistency_path is empty' };

  let fn = oldSize - 1;
  let sn = newSize - 1;
  while (fn % 2 === 1) {
    fn = halve(fn);
    sn = halve(sn);
  }

  let fr = nodes[0];
  let sr = nodes[0];

  for (const node of nodes.slice(1)) {
    if (sn === 0) return { valid: false, reason: 'consistency_path is longer than the trees allow' };
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(node, fr);
      sr = nodeHash(node, sr);
      while (fn !== 0 && fn % 2 === 0) {
        fn = halve(fn);
        sn = halve(sn);
      }
    } else {
      sr = nodeHash(sr, node);
    }
    fn = halve(fn);
    sn = halve(sn);
  }

  if (sn !== 0) return { valid: false, reason: 'consistency_path is shorter than the trees require' };
  if (!bytesEqual(fr, oldRoot)) return { valid: false, reason: 'computed old root does not match old_root' };
  if (!bytesEqual(sr, newRoot)) return { valid: false, reason: 'computed new root does not match new_root' };
  return { valid: true };
}

/**
 * Verify the Ed25519 signature on a signed tree head.
 *
 * The head is signed over a fixed byte string rather than JSON, so there is no
 * canonicalisation question here and no opportunity for the encoding-level
 * divergence that JSON payloads invite.
 */
export function verifySignedTreeHead(head: unknown, trustedPublicKey: string): ProofResult {
  if (typeof head !== 'object' || head === null) {
    return { valid: false, reason: 'head is not an object' };
  }
  const h = head as Record<string, unknown>;

  /* Two logs, two signed prefixes, deliberately different so a head from one
     can never be presented as the other. Discriminate on log === "public",
     never on the absence of org_id: an attacker who strips org_id must not be
     able to change which preimage is checked. A public head that also carries
     an org_id is a contradiction and is refused.
     Must stay byte-identical in reasoning and wording to the Python verifier;
     the two must return the same verdict on the same head. */
  const isPublic = h.log === 'public';
  if (isPublic) {
    if (h.org_id !== undefined && h.org_id !== null) {
      return { valid: false, reason: 'a public head must not carry org_id' };
    }
    if (!isSafeSize(h.tree_size)) {
      return { valid: false, reason: 'head must carry an integer tree_size' };
    }
    if (typeof h.timestamp !== 'string' || h.timestamp.length === 0) {
      return { valid: false, reason: 'a public head must carry a timestamp' };
    }
  } else if (typeof h.org_id !== 'string' || !isSafeSize(h.tree_size)) {
    return { valid: false, reason: 'head must carry org_id and an integer tree_size' };
  }
  if (typeof h.root_hash !== 'string' || typeof h.signature !== 'string') {
    return { valid: false, reason: 'head must carry root_hash and signature' };
  }
  if (!/^[A-Za-z0-9_-]+$/.test(h.signature) || !/^[A-Za-z0-9_-]+$/.test(trustedPublicKey)) {
    return { valid: false, reason: 'signature and key must be base64url without padding' };
  }

  let root: Uint8Array;
  try {
    root = hexToBytes(h.root_hash);
  } catch {
    return { valid: false, reason: 'root_hash must be lowercase hex' };
  }
  if (root.length !== 32) return { valid: false, reason: 'root_hash must be 32 bytes' };

  let signed: Uint8Array;
  if (isPublic) {
    // PUBLIC_STH_PREFIX || ascii(tree_size) || "|" || root || "|" || ts
    const head0 = new TextEncoder().encode(`aqta-sth-public-v1|${h.tree_size}|`);
    const tail = new TextEncoder().encode(`|${h.timestamp as string}`);
    signed = new Uint8Array(head0.length + root.length + tail.length);
    signed.set(head0, 0);
    signed.set(root, head0.length);
    signed.set(tail, head0.length + root.length);
  } else {
    const prefix = new TextEncoder().encode(`aqta-sth-v1|${h.org_id}|${h.tree_size}|`);
    signed = new Uint8Array(prefix.length + root.length);
    signed.set(prefix, 0);
    signed.set(root, prefix.length);
  }

  const b64url = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

  let sig: Uint8Array;
  let pub: Uint8Array;
  try {
    sig = b64url(h.signature);
    pub = b64url(trustedPublicKey);
  } catch {
    return { valid: false, reason: 'signature decode error' };
  }
  if (sig.length !== 64) return { valid: false, reason: 'signature length != 64 bytes' };
  if (pub.length !== 32) return { valid: false, reason: 'public key length != 32 bytes' };
  if (!nacl.sign.detached.verify(signed, sig, pub)) {
    return { valid: false, reason: 'tree head signature check failed' };
  }
  return { valid: true };
}


/* ------------------------------------------------------------------------ */
/* History bundles: adversary-class checks composed from the primitives.    */
/* ------------------------------------------------------------------------ */

/**
 * A history bundle is what a reviewer actually holds after a dispute: several
 * signed heads obtained at different times, consistency proofs between them,
 * and inclusion proofs for the records in question, each with the time the
 * record claims for itself. The primitives above check one object each. The
 * adversary classes in ISSUER-ADVERSARY.md are only visible across objects:
 * two valid heads at one size, a later head that does not extend a pinned
 * one, a record that claims a time after a head that already contains it.
 *
 * Verdict vocabulary, in precedence order, because a bundle can carry more
 * than one fault and both implementations must name the same one:
 *
 *   invalid_head             a head does not verify under the trusted key, so
 *                            nothing below it can be relied on
 *   equivocation             two verified heads, one size, two roots (A1)
 *   unsigned_root            a proof targets a root no head in the bundle signed
 *   fork                     a consistency proof between two verified heads
 *                            fails: the later head does not extend the earlier
 *                            one (A4 reordering and an A6 side head look the
 *                            same from outside, and that is the point)
 *   invalid_proof            an inclusion proof fails against its head
 *   timestamp_contradiction  a record claims a time after the timestamp of a
 *                            head that already includes it (A3)
 *   consistent               nothing above applied
 *
 * What this deliberately does not do: treat absence from an earlier head as
 * evidence of backdating. Log order is submission order, and a record can be
 * created before a head and submitted after it. The vector
 * a3-lag-is-not-backdating pins that this returns `consistent`.
 */
export interface HistoryBundle {
  heads: unknown[];
  consistency?: unknown[];
  inclusions?: Array<{ proof: unknown; record_timestamp?: string }>;
}

export type HistoryVerdict =
  | 'invalid_head'
  | 'equivocation'
  | 'unsigned_root'
  | 'fork'
  | 'invalid_proof'
  | 'timestamp_contradiction'
  | 'consistent';

export interface HistoryResult {
  valid: boolean;
  verdict: HistoryVerdict;
  reason?: string;
}

const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export function assessHistory(bundle: unknown, trustedPublicKey: string): HistoryResult {
  const fail = (verdict: HistoryVerdict, reason: string): HistoryResult => ({ valid: false, verdict, reason });
  if (typeof bundle !== 'object' || bundle === null) return fail('invalid_head', 'bundle is not an object');
  const b = bundle as Record<string, unknown>;
  if (!Array.isArray(b.heads) || b.heads.length === 0) return fail('invalid_head', 'bundle must carry at least one head');

  // 1. Every head verifies, and every head is a public head, because only
  //    public heads carry the signing timestamp the A3 rule needs.
  const heads: Array<{ tree_size: number; root_hash: string; timestamp: string }> = [];
  for (let i = 0; i < b.heads.length; i++) {
    const h = b.heads[i] as Record<string, unknown>;
    if (typeof h !== 'object' || h === null || h.log !== 'public') {
      return fail('invalid_head', `head ${i}: history bundles require public heads with timestamps`);
    }
    const r = verifySignedTreeHead(h, trustedPublicKey);
    if (!r.valid) return fail('invalid_head', `head ${i}: ${r.reason ?? 'verification failed'}`);
    if (!TIMESTAMP.test(h.timestamp as string)) return fail('invalid_head', `head ${i}: timestamp must be YYYY-MM-DDTHH:MM:SSZ`);
    heads.push({ tree_size: h.tree_size as number, root_hash: (h.root_hash as string).toLowerCase(), timestamp: h.timestamp as string });
  }

  // 2. Equivocation: one size, two roots, both signed.
  for (let i = 0; i < heads.length; i++) {
    for (let j = i + 1; j < heads.length; j++) {
      if (heads[i].tree_size === heads[j].tree_size && heads[i].root_hash !== heads[j].root_hash) {
        return fail('equivocation', `heads ${i} and ${j} are both signed at size ${heads[i].tree_size} with different roots`);
      }
    }
  }
  const headFor = (size: unknown, root: unknown) =>
    heads.find((h) => h.tree_size === size && typeof root === 'string' && h.root_hash === root.toLowerCase());

  // 3. Consistency proofs between signed heads. An endpoint nobody signed is
  //    not a fork, it is a proof about a tree that is not in evidence.
  const cons = Array.isArray(b.consistency) ? b.consistency : [];
  for (let i = 0; i < cons.length; i++) {
    const c = cons[i] as Record<string, unknown>;
    if (typeof c !== 'object' || c === null) return fail('unsigned_root', `consistency ${i}: not an object`);
    if (!headFor(c.old_size, c.old_root) || !headFor(c.new_size, c.new_root)) {
      return fail('unsigned_root', `consistency ${i}: an endpoint is not a signed head in this bundle`);
    }
    const r = verifyConsistencyProof(c);
    if (!r.valid) return fail('fork', `consistency ${i}: ${r.reason ?? 'verification failed'}`);
  }

  // 4. Inclusion proofs, each against a signed head, and 5. the A3 rule.
  const incs = Array.isArray(b.inclusions) ? b.inclusions : [];
  let contradiction: string | undefined;
  for (let i = 0; i < incs.length; i++) {
    const entry = incs[i] as Record<string, unknown>;
    const p = (typeof entry === 'object' && entry !== null ? entry.proof : undefined) as Record<string, unknown> | undefined;
    if (typeof p !== 'object' || p === null) return fail('invalid_proof', `inclusion ${i}: no proof object`);
    const head = headFor(p.tree_size, p.root_hash);
    if (!head) return fail('unsigned_root', `inclusion ${i}: proof targets a root no head in this bundle signed`);
    const r = verifyInclusionProof(p);
    if (!r.valid) return fail('invalid_proof', `inclusion ${i}: ${r.reason ?? 'verification failed'}`);
    const ts = entry.record_timestamp;
    if (ts !== undefined) {
      if (typeof ts !== 'string' || !TIMESTAMP.test(ts)) return fail('invalid_proof', `inclusion ${i}: record_timestamp must be YYYY-MM-DDTHH:MM:SSZ`);
      // Fixed-width UTC strings compare correctly as strings.
      if (ts > head.timestamp && contradiction === undefined) {
        contradiction = `inclusion ${i}: record claims ${ts}, after the head at ${head.timestamp} that already includes it`;
      }
    }
  }
  if (contradiction !== undefined) return fail('timestamp_contradiction', contradiction);
  return { valid: true, verdict: 'consistent' };
}
