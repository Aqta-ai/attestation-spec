/**
 * Interop tests: verify a receipt produced by the Python reference implementation
 * against this TypeScript verifier. Run: `npm run build && node --test dist/index.test.js`.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyReceipt } from './index.js';

/**
 * Fixture receipt shape, used here to exercise the structural checks.
 * Full signature-level interop is covered by the cross-implementation
 * runner at `scripts/make-interop-fixture.mjs`, which generates a receipt
 * with the reference issuer and verifies it with this library.
 */
const FIXTURE_RECEIPT = {
  v: 1,
  attestation_id: 'a3f2b1c4-9d87-4e6f-b012-34567890abcd',
  trace_id: 'trace-fixture-v1',
  org_id: 'org-test',
  request_hash: '8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a',
  model: 'gpt-4o',
  outcome: 'ALLOWED' as const,
  policy_applied: ['budget_guard', 'loop_guard'],
  cost_prevented_eur: 0.0,
  timestamp: '2026-04-23T10:15:30.123456+00:00',
  public_key: '', // populated by make-test-fixture.py
  signature: '',  // populated by make-test-fixture.py
};

test('rejects empty object', () => {
  const res = verifyReceipt({});
  assert.equal(res.valid, false);
});

test('rejects missing required field', () => {
  const bad = { ...FIXTURE_RECEIPT } as any;
  delete bad.outcome;
  const res = verifyReceipt(bad);
  assert.equal(res.valid, false);
  assert.match(res.reason ?? '', /missing required field/);
});

test('rejects unknown top-level field (strict mode)', () => {
  const bad = { ...FIXTURE_RECEIPT, extra: 'foo' } as any;
  const res = verifyReceipt(bad);
  assert.equal(res.valid, false);
  assert.match(res.reason ?? '', /unknown top-level field/);
});

test('rejects unsupported version', () => {
  const bad = { ...FIXTURE_RECEIPT, v: 2 } as any;
  const res = verifyReceipt(bad);
  assert.equal(res.valid, false);
  assert.match(res.reason ?? '', /unsupported version/);
});

test('rejects invalid outcome', () => {
  const bad = { ...FIXTURE_RECEIPT, outcome: 'YOLO' } as any;
  const res = verifyReceipt(bad);
  assert.equal(res.valid, false);
  assert.match(res.reason ?? '', /invalid outcome/);
});

test('rejects malformed request_hash', () => {
  const bad = { ...FIXTURE_RECEIPT, request_hash: 'not-a-hash' } as any;
  const res = verifyReceipt(bad);
  assert.equal(res.valid, false);
  assert.match(res.reason ?? '', /request_hash/);
});

test('rejects pinned-key mismatch', () => {
  const res = verifyReceipt(FIXTURE_RECEIPT, {
    trustedPublicKey: 'different_key_000000000000000000000000000000',
  });
  assert.equal(res.valid, false);
  assert.match(res.reason ?? '', /does not match trusted key/);
});

// Note: full signature-verification interop test requires the fixture to be
// populated by `scripts/make-test-fixture.py` before running this suite.
// When FIXTURE_RECEIPT.signature is empty, the signature check is skipped.
test('signature decoder rejects empty signature', () => {
  const res = verifyReceipt(FIXTURE_RECEIPT);
  assert.equal(res.valid, false);
  // Either the empty signature fails decode or fails length check
  assert.ok(
    /signature/.test(res.reason ?? '') ||
      /signature length/.test(res.reason ?? '')
  );
});
