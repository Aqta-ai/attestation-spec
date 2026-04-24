/**
 * aqta-verify-receipt
 *
 * Independent verifier for AqtaCore attestation receipts (ATTESTATION-v1).
 * Verifies the Ed25519 signature on a receipt using only the published
 * public key: no dependency on any third-party server.
 *
 * Spec: https://github.com/Aqta-ai/attestation-spec/blob/main/spec/ATTESTATION-v1.md
 */

import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

/** Required top-level fields of an ATTESTATION-v1 receipt. */
export interface AttestationReceipt {
  v: number;
  attestation_id: string;
  trace_id: string;
  org_id: string;
  request_hash: string;
  model: string;
  outcome: 'ALLOWED' | 'BLOCKED' | 'SUPPRESSED' | 'PASSED';
  policy_applied: string[];
  cost_prevented_eur: number;
  timestamp: string;
  public_key: string;
  signature: string;
}

export interface VerifyOptions {
  /**
   * The trusted public key (base64url, no padding). If supplied, the receipt
   * is rejected unless its `public_key` field matches byte-for-byte. This
   * prevents an attacker from substituting a different key.
   *
   * If omitted, the receipt is verified against whatever public key it
   * declares. This is lower trust but useful for offline / one-shot checks.
   */
  trustedPublicKey?: string;

  /**
   * If true, unknown top-level fields in the receipt cause rejection. Default
   * true per spec §4: "Verifiers MUST reject receipts containing unknown
   * top-level fields."
   */
  strictFields?: boolean;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
}

const ALLOWED_OUTCOMES: ReadonlySet<string> = new Set([
  'ALLOWED',
  'BLOCKED',
  'SUPPRESSED',
  'PASSED',
]);

const REQUIRED_FIELDS: ReadonlySet<string> = new Set([
  'v',
  'attestation_id',
  'trace_id',
  'org_id',
  'request_hash',
  'model',
  'outcome',
  'policy_applied',
  'cost_prevented_eur',
  'timestamp',
  'public_key',
  'signature',
]);

/** Decode a base64url string (no padding) into a Uint8Array. */
function base64urlDecode(s: string): Uint8Array {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return naclUtil.decodeBase64(b64);
}

/**
 * Canonical JSON serialisation per ATTESTATION-v1 §6.
 *
 * Equivalent to Python's:
 *   json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
 *
 * This function handles only the receipt shape (flat object with scalar +
 * array values). It is NOT a general-purpose canonical-JSON library.
 */
function canonicalise(payload: Record<string, unknown>): Uint8Array {
  const keys = Object.keys(payload).sort();
  const parts: string[] = [];
  for (const k of keys) {
    parts.push(`${JSON.stringify(k)}:${canonicalValue(payload[k])}`);
  }
  return new TextEncoder().encode('{' + parts.join(',') + '}');
}

function canonicalValue(v: unknown): string {
  if (v === null || v === undefined) {
    return 'null';
  }
  if (Array.isArray(v)) {
    return '[' + v.map(canonicalValue).join(',') + ']';
  }
  if (typeof v === 'number') {
    // Preserving the serialisation of floats such as 0.0 as "0.0" is NOT
    // spec. JSON.stringify(0) yields "0" and that is what Python json.dumps
    // yields for float 0.0 when sort_keys=True on a rounded value. For the
    // one float field on the receipt (cost_prevented_eur) the issuer rounds
    // to 6 dp and integers serialise as integers.
    return JSON.stringify(v);
  }
  // Strings, booleans
  return JSON.stringify(v);
}

/**
 * Verify an AqtaCore attestation receipt.
 *
 * @param receipt  The full receipt object (including `signature`).
 * @param options  Optional verification constraints.
 * @returns        `{ valid: true }` if the signature is valid under the
 *                 declared (and optionally pinned) public key; otherwise
 *                 `{ valid: false, reason: string }`.
 *
 * @example
 *   const result = verifyReceipt(receipt, {
 *     trustedPublicKey: 'gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE',
 *   });
 *   if (!result.valid) throw new Error(`Receipt invalid: ${result.reason}`);
 */
export function verifyReceipt(
  receipt: unknown,
  options: VerifyOptions = {}
): VerifyResult {
  if (typeof receipt !== 'object' || receipt === null) {
    return { valid: false, reason: 'receipt is not an object' };
  }
  const r = receipt as Record<string, unknown>;

  // Structural checks
  for (const field of REQUIRED_FIELDS) {
    if (!(field in r)) {
      return { valid: false, reason: `missing required field: ${field}` };
    }
  }
  if (options.strictFields !== false) {
    for (const k of Object.keys(r)) {
      if (!REQUIRED_FIELDS.has(k)) {
        return { valid: false, reason: `unknown top-level field: ${k}` };
      }
    }
  }

  // Semantic sanity
  if (r.v !== 1) {
    return { valid: false, reason: `unsupported version: ${r.v}` };
  }
  if (typeof r.outcome !== 'string' || !ALLOWED_OUTCOMES.has(r.outcome)) {
    return { valid: false, reason: `invalid outcome: ${String(r.outcome)}` };
  }
  if (!Array.isArray(r.policy_applied)) {
    return { valid: false, reason: 'policy_applied must be an array' };
  }
  if (typeof r.request_hash !== 'string' || !/^[0-9a-f]{64}$/.test(r.request_hash)) {
    return { valid: false, reason: 'request_hash must be 64 lowercase hex chars' };
  }

  // Public-key pinning
  if (
    options.trustedPublicKey !== undefined &&
    options.trustedPublicKey !== r.public_key
  ) {
    return {
      valid: false,
      reason: 'public_key does not match trusted key',
    };
  }

  // Canonical payload (all fields except signature)
  const payload: Record<string, unknown> = { ...r };
  delete payload.signature;

  let canonical: Uint8Array;
  try {
    canonical = canonicalise(payload);
  } catch (e) {
    return { valid: false, reason: `failed to canonicalise: ${String(e)}` };
  }

  // Ed25519 verification
  try {
    const sig = base64urlDecode(r.signature as string);
    const pub = base64urlDecode(r.public_key as string);
    if (sig.length !== 64) {
      return { valid: false, reason: 'signature length != 64 bytes' };
    }
    if (pub.length !== 32) {
      return { valid: false, reason: 'public key length != 32 bytes' };
    }
    const ok = nacl.sign.detached.verify(canonical, sig, pub);
    return ok ? { valid: true } : { valid: false, reason: 'signature check failed' };
  } catch (e) {
    return { valid: false, reason: `signature decode error: ${String(e)}` };
  }
}

/**
 * Fetch the AqtaCore public key from the published URL and return it as a
 * base64url string ready to pass to `verifyReceipt` as `trustedPublicKey`.
 *
 * **PIN THE RESULT.** This helper performs a live HTTPS fetch. Calling it
 * inside a verification loop collapses the trust model back to "trust the
 * issuer's server right now", which is exactly what the attestation format
 * is designed to avoid.
 *
 * Correct usage:
 *   1. Call this once on first use.
 *   2. Persist the returned string (configuration file, database, KMS,
 *      environment variable, secret manager).
 *   3. Pass the persisted value as `trustedPublicKey` on every subsequent
 *      verification.
 *   4. Rotate only in response to a documented key-rotation notice
 *      received via a channel you already trust.
 *
 * Re-fetching the key on every verification is a misuse.
 */
export async function fetchPublishedPublicKey(
  url = 'https://app.aqta.ai/security/pubkey.txt'
): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`failed to fetch public key: HTTP ${res.status}`);
  }
  return (await res.text()).trim();
}
