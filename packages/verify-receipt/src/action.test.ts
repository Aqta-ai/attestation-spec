/**
 * ACTION-v1 profile conformance tests.
 *
 * The vectors under test-vectors/action/ are the cross-language contract:
 * the Python verifier's suite checks the same bytes, and the two
 * implementations must return the same verdict (and the same reason) on
 * every one. Run: `npm run build && node --test dist/action.test.js`.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyReceipt, verifyActionRecord } from './index.js';

/** Pinned issuer key for the action vector suite (test-vectors/action/README.md). */
const ACTION_VECTOR_KEY = 'pOaccW6Csyo1POtxjixPH80oux9--YC1tzzaENT4vQ0';
const ACTION_VECTOR_DIR = join(__dirname, '..', '..', '..', 'test-vectors', 'action');

function loadVectors(kind: 'valid' | 'invalid'): Array<[string, unknown]> {
  const dir = join(ACTION_VECTOR_DIR, kind);
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => [f, JSON.parse(readFileSync(join(dir, f), 'utf8'))]);
}

test('every valid action vector verifies under the pinned vector key', () => {
  const vectors = loadVectors('valid');
  assert.equal(vectors.length, 10, 'expected 10 valid action vectors');
  for (const [name, record] of vectors) {
    const result = verifyReceipt(record, {
      trustedPublicKey: ACTION_VECTOR_KEY,
      profile: 'ACTION-v1',
    });
    assert.equal(result.valid, true, `${name} must verify (${result.reason ?? 'no reason'})`);
    assert.equal(result.envelope, 'ACTION-v1', `${name} must report the ACTION-v1 profile`);
    assert.equal(result.keySource, 'pinned', `${name} must report a pinned key`);
  }
});

test('every invalid action vector is rejected', () => {
  const vectors = loadVectors('invalid');
  assert.equal(vectors.length, 15, 'expected 15 invalid action vectors');
  for (const [name, record] of vectors) {
    const result = verifyReceipt(record, {
      trustedPublicKey: ACTION_VECTOR_KEY,
      profile: 'ACTION-v1',
    });
    assert.equal(result.valid, false, `${name} must be rejected`);
  }
});

test('verifyActionRecord convenience wrapper selects the ACTION-v1 profile', () => {
  const vectors = loadVectors('valid');
  const [name, record] = vectors[0];
  const result = verifyActionRecord(record, { trustedPublicKey: ACTION_VECTOR_KEY });
  assert.equal(result.valid, true, `${name} must verify via verifyActionRecord`);
  assert.equal(result.envelope, 'ACTION-v1');
  assert.equal(result.keySource, 'pinned');
});

test('profile and envelope are mutually exclusive', () => {
  const [, record] = loadVectors('valid')[0];
  const result = verifyReceipt(record, {
    trustedPublicKey: ACTION_VECTOR_KEY,
    profile: 'ACTION-v1',
    envelope: 'anchor-v1',
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'profile and envelope are mutually exclusive');
});

test('ACTION-v1 cannot be named as a foreign envelope', () => {
  // The foreign-envelope path is signature-only. Routing an action record
  // through it would skip every structural and semantic rule, which is the
  // bypass ACTION-v1 §7 exists to close.
  const [, record] = loadVectors('valid')[0];
  const result = verifyReceipt(record, {
    trustedPublicKey: ACTION_VECTOR_KEY,
    envelope: 'ACTION-v1',
  });
  assert.equal(result.valid, false);
  assert.equal(
    result.reason,
    'ACTION-v1 is a profile, not a foreign envelope; use the profile option'
  );
});

test('a genuine ATTESTATION-v1 receipt fails the ACTION-v1 profile', () => {
  // Invalid vector 007 is a complete, correctly signed ATTESTATION-v1
  // receipt. Under the ACTION-v1 profile it must fail: accepting it would
  // mean the verifier profile-sniffs by field shape.
  const file = join(ACTION_VECTOR_DIR, 'invalid', '007-attestation-v1-receipt.json');
  const receipt = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;

  const asAction = verifyActionRecord(receipt, { trustedPublicKey: ACTION_VECTOR_KEY });
  assert.equal(asAction.valid, false);
  assert.equal(asAction.reason, 'missing required field: action_id');

  // The same bytes remain a valid ATTESTATION-v1 receipt when the profile
  // option is absent and its embedded key is pinned: the record itself is
  // genuine, only the profile claim about it was wrong.
  const asAttestation = verifyReceipt(receipt, {
    trustedPublicKey: receipt.public_key as string,
  });
  assert.equal(
    asAttestation.valid,
    true,
    `007 must verify as ATTESTATION-v1 (${asAttestation.reason ?? 'no reason'})`
  );
  assert.equal(asAttestation.envelope, 'ATTESTATION-v1');
});
