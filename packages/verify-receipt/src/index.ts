/**
 * aqta-verify-receipt
 *
 * Independent verifier for Seal attestation receipts (ATTESTATION-v1).
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
   * Trusted issuer public key (base64url, no padding). Required for a
   * counsel-grade check: the receipt must carry this key and verify under it.
   *
   * Omit only with `allowUntrustedEmbeddedKey: true` for integrity-only
   * checks against whatever key the receipt embeds (anyone can self-sign).
   */
  trustedPublicKey?: string;

  /**
   * If true, verify against the receipt's embedded `public_key` without
   * pinning an issuer. Result includes `keySource: "untrusted"`. Default
   * false: without `trustedPublicKey`, verification fails.
   */
  allowUntrustedEmbeddedKey?: boolean;

  /**
   * If true, unknown top-level fields in the receipt cause rejection. Default
   * true per spec §4: "Verifiers MUST reject receipts containing unknown
   * top-level fields."
   */
  strictFields?: boolean;
}

export type KeySource = 'pinned' | 'untrusted';

export interface VerifyResult {
  /** Which envelope format was recognised, when one was. */
  envelope?: EnvelopeFormat;
  valid: boolean;
  reason?: string;
  /** Present when `valid` is true. */
  keySource?: KeySource;
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
    // Spec section 6: integer-valued numbers serialise without a decimal
    // point. JSON.stringify does that natively, so nothing extra is needed
    // here. Python's json.dumps does NOT (it yields "0.0" for float 0.0),
    // which is why the spec puts the coercion duty on the issuer: an
    // integer-valued float must become an int before it is signed. A receipt
    // carrying a literal "0.0" was signed by a non-conforming issuer, and
    // failing it is correct behaviour, not a gap in this verifier.
    return JSON.stringify(v);
  }
  // Strings, booleans
  return JSON.stringify(v);
}

/**
 * Verify a Seal attestation receipt.
 *
 * Pinning is required by default. A self-signed receipt must not return
 * `valid: true` unless `allowUntrustedEmbeddedKey` is set.
 *
 * @param receipt  The full receipt object (including `signature`).
 * @param options  Verification constraints.
 * @returns        `{ valid: true, keySource }` if the signature is valid under
 *                 the pinned (or explicitly allowed embedded) public key;
 *                 otherwise `{ valid: false, reason: string }`.
 *
 * @example
 *   const result = verifyReceipt(receipt, {
 *     trustedPublicKey: 'gUoUhIvptKAoLTnry3VrDtOQEWggGQveLrHFVrfNqmE',
 *   });
 *   if (!result.valid) throw new Error(`Receipt invalid: ${result.reason}`);
 */
/**
 * Envelope formats this verifier can read.
 *
 * The point of accepting more than one is that an auditor should install a
 * single tool, not one per issuer. The formats differ only in which fields
 * carry the signature and the signer's key, and in base64 versus base64url
 * encoding, which `base64urlDecode` already normalises. The canonicalisation
 * rule is the same in both: sorted keys, no whitespace, literal UTF-8.
 */
export type EnvelopeFormat = 'ATTESTATION-v1' | 'anchor-v1';

const ENVELOPE_FIELDS: Record<EnvelopeFormat, { signature: string; publicKey: string }> = {
  'ATTESTATION-v1': { signature: 'signature', publicKey: 'public_key' },
  'anchor-v1': { signature: 'signature_b64', publicKey: 'public_key_b64' },
};

/** Identify an envelope by the field names it carries, or null if unrecognised. */
export function detectEnvelope(receipt: unknown): EnvelopeFormat | null {
  if (typeof receipt !== 'object' || receipt === null) return null;
  const r = receipt as Record<string, unknown>;
  if (typeof r.signature === 'string' && typeof r.public_key === 'string') {
    return 'ATTESTATION-v1';
  }
  if (typeof r.signature_b64 === 'string' && typeof r.public_key_b64 === 'string') {
    return 'anchor-v1';
  }
  return null;
}

/**
 * Signature check shared by every envelope.
 *
 * Deliberately makes no claim about the receipt's meaning: it answers only
 * "were these bytes signed by this key". Format-specific structural rules,
 * such as ATTESTATION-v1's twelve-field requirement, are applied by the
 * caller before this runs.
 */
function verifySignedEnvelope(
  r: Record<string, unknown>,
  envelope: EnvelopeFormat,
  options: VerifyOptions
): VerifyResult {
  const fields = ENVELOPE_FIELDS[envelope];
  const pinned = options.trustedPublicKey;
  const allowUntrusted = options.allowUntrustedEmbeddedKey === true;

  if (pinned === undefined && !allowUntrusted) {
    return {
      valid: false,
      reason:
        'trustedPublicKey required (pass allowUntrustedEmbeddedKey for integrity-only)',
    };
  }

  const embeddedKey = r[fields.publicKey] as string;
  if (pinned !== undefined && pinned !== embeddedKey) {
    return { valid: false, reason: 'public key does not match trusted key' };
  }

  const payload: Record<string, unknown> = { ...r };
  delete payload[fields.signature];

  let canonical: Uint8Array;
  try {
    canonical = canonicalise(payload);
  } catch (e) {
    return { valid: false, reason: `failed to canonicalise: ${String(e)}` };
  }

  try {
    const sig = base64urlDecode(r[fields.signature] as string);
    const pub = base64urlDecode(embeddedKey);
    if (sig.length !== 64) return { valid: false, reason: 'signature length != 64 bytes' };
    if (pub.length !== 32) return { valid: false, reason: 'public key length != 32 bytes' };
    if (!nacl.sign.detached.verify(canonical, sig, pub)) {
      return { valid: false, reason: 'signature check failed' };
    }
    return {
      valid: true,
      envelope,
      keySource: pinned !== undefined ? 'pinned' : 'untrusted',
    };
  } catch (e) {
    return { valid: false, reason: `signature decode error: ${String(e)}` };
  }
}

export function verifyReceipt(
  receipt: unknown,
  options: VerifyOptions = {}
): VerifyResult {
  if (typeof receipt !== 'object' || receipt === null) {
    return { valid: false, reason: 'receipt is not an object' };
  }
  const r = receipt as Record<string, unknown>;

  const envelope = detectEnvelope(r);
  if (envelope === null) {
    return {
      valid: false,
      reason:
        'unrecognised envelope: expected signature/public_key or signature_b64/public_key_b64',
    };
  }
  // Other issuers' envelopes carry their own field sets, so only the signature
  // is checked. The structural rules below are ATTESTATION-v1's alone.
  if (envelope !== 'ATTESTATION-v1') {
    return verifySignedEnvelope(r, envelope, options);
  }

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

  const pinned = options.trustedPublicKey;
  const allowUntrusted = options.allowUntrustedEmbeddedKey === true;

  if (pinned === undefined && !allowUntrusted) {
    return {
      valid: false,
      reason:
        'trustedPublicKey required (pass allowUntrustedEmbeddedKey for integrity-only)',
    };
  }

  // Public-key pinning
  if (pinned !== undefined && pinned !== r.public_key) {
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
    if (!ok) {
      return { valid: false, reason: 'signature check failed' };
    }
    return {
      valid: true,
      envelope: 'ATTESTATION-v1',
      keySource: pinned !== undefined ? 'pinned' : 'untrusted',
    };
  } catch (e) {
    return { valid: false, reason: `signature decode error: ${String(e)}` };
  }
}

/**
 * Fetch the Seal public key from the published URL and return it as a
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
