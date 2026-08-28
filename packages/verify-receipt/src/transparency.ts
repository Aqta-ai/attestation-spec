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
  if (typeof h.org_id !== 'string' || !isSafeSize(h.tree_size)) {
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

  const prefix = new TextEncoder().encode(`aqta-sth-v1|${h.org_id}|${h.tree_size}|`);
  const signed = new Uint8Array(prefix.length + root.length);
  signed.set(prefix, 0);
  signed.set(root, prefix.length);

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
