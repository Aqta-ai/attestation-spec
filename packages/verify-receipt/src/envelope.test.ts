/**
 * Multi-envelope tests.
 *
 * The claim being defended: an auditor installs one verifier, not one per
 * issuer. These cover envelope detection and the shared signature path for
 * anchor-v1 receipts, which the ATTESTATION-v1 tests do not reach.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'tweetnacl';
import { verifyReceipt, detectEnvelope } from './index.js';

/** The canonical form both envelopes share: sorted keys, no whitespace. */
function canonical(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  const e = Object.entries(v as Record<string, unknown>)
    .filter(([, x]) => x !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${e.map(([k, x]) => `${JSON.stringify(k)}:${canonical(x)}`).join(',')}}`;
}

const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');

/** Mint a signed anchor-v1 receipt with a throwaway key. */
function makeAnchor(overrides: Record<string, unknown> = {}) {
  const kp = nacl.sign.keyPair();
  const signed = {
    checked_at: '2026-07-22T21:00:00Z',
    transcript_sha256: 'a'.repeat(64),
    summary_sha256: 'b'.repeat(64),
    bound: 7,
    gaps: 1,
    public_key_b64: b64(kp.publicKey),
    ...overrides,
  };
  const sig = nacl.sign.detached(Buffer.from(canonical(signed), 'utf8'), kp.secretKey);
  return { receipt: { ...signed, signature_b64: b64(sig) }, key: signed.public_key_b64 };
}

test('detectEnvelope identifies ATTESTATION-v1 by its field names', () => {
  assert.equal(detectEnvelope({ signature: 'x', public_key: 'y' }), 'ATTESTATION-v1');
});

test('detectEnvelope identifies anchor-v1 by its field names', () => {
  assert.equal(detectEnvelope({ signature_b64: 'x', public_key_b64: 'y' }), 'anchor-v1');
});

test('detectEnvelope returns null rather than guessing', () => {
  assert.equal(detectEnvelope({ hello: 'world' }), null);
  assert.equal(detectEnvelope(null), null);
  assert.equal(detectEnvelope('a string'), null);
  // present but wrong type must not be treated as an envelope
  assert.equal(detectEnvelope({ signature: 1, public_key: 2 }), null);
});

test('a genuine anchor-v1 receipt verifies against its pinned key', () => {
  const { receipt, key } = makeAnchor();
  const r = verifyReceipt(receipt, { trustedPublicKey: key });
  assert.equal(r.valid, true);
  assert.equal(r.envelope, 'anchor-v1');
  assert.equal(r.keySource, 'pinned');
});

test('altering any signed field breaks an anchor-v1 receipt', () => {
  const { receipt, key } = makeAnchor();
  const r = verifyReceipt({ ...receipt, bound: 99 }, { trustedPublicKey: key });
  assert.equal(r.valid, false);
  assert.equal(r.reason, 'signature check failed');
});

test('anchor-v1 will not verify against a key it was not signed with', () => {
  const { receipt } = makeAnchor();
  const other = makeAnchor().key;
  const r = verifyReceipt(receipt, { trustedPublicKey: other });
  assert.equal(r.valid, false);
  assert.equal(r.reason, 'public key does not match trusted key');
});

test('anchor-v1 refuses to run without a pinned key', () => {
  const { receipt } = makeAnchor();
  const r = verifyReceipt(receipt);
  assert.equal(r.valid, false);
  assert.match(r.reason ?? '', /trustedPublicKey required/);
});

test('anchor-v1 integrity-only mode reports the key as untrusted', () => {
  const { receipt } = makeAnchor();
  const r = verifyReceipt(receipt, { allowUntrustedEmbeddedKey: true });
  assert.equal(r.valid, true);
  assert.equal(r.keySource, 'untrusted');
});

test('non-ASCII in an anchor-v1 field still verifies', () => {
  const { receipt, key } = makeAnchor({ note: 'Größe · héllo · 世界' });
  assert.equal(verifyReceipt(receipt, { trustedPublicKey: key }).valid, true);
});

test('an unrecognised envelope is rejected, not assumed', () => {
  const r = verifyReceipt({ some: 'object' }, { trustedPublicKey: 'k' });
  assert.equal(r.valid, false);
  assert.match(r.reason ?? '', /unrecognised envelope/);
});
