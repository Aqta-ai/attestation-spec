/**
 * policy profile conformance (spec/POLICY-v1.md section 8; DRAFT).
 *
 * Every vector under test-vectors/policy/ must reach the verdict its directory
 * names. The Python suite checks the same files, and
 * scripts/policy-interop-sweep.mjs requires both to give the same verdict and
 * reason on every one.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseBinding, verifyPolicy } from './policy.js';
import { verifyChain } from './chain.js';
import { verifyActionRecord, verifyReceipt } from './index.js';

const VEC = join(__dirname, '..', '..', '..', 'test-vectors', 'policy');
const PIN = readFileSync(join(VEC, 'INDEX.md'), 'utf8').split('Vector issuer key (pin it): `')[1].split('`')[0];
const KINDS: Array<[string, string]> = [['pass', 'PASS'], ['fail', 'FAIL'], ['incomplete', 'INCOMPLETE']];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type V = any;
const one = (rel: string): V => JSON.parse(readFileSync(join(VEC, rel), 'utf8')).bundle;

for (const [kind, want] of KINDS) {
  test(`every policy/${kind} vector returns ${want}`, () => {
    const files = readdirSync(join(VEC, kind)).filter((f) => f.endsWith('.json')).sort();
    assert.ok(files.length >= 5, `expected vectors in policy/${kind}, got ${files.length}`);
    for (const f of files) {
      const r = verifyPolicy(one(`${kind}/${f}`), { trustedPublicKey: PIN });
      assert.equal(r.verdict, want, `policy/${kind}/${f}: got ${r.verdict} (${r.reason})`);
      if (want !== 'PASS') assert.ok(r.reason, `policy/${kind}/${f} must carry a reason`);
    }
  });
}

test('bound records still verify without the profile', () => {
  for (const item of one('pass/001-bound-history.json').decisions) {
    assert.equal(verifyActionRecord(item.record, { trustedPublicKey: PIN }).valid, true);
  }
});

test('no pinned key is FAIL', () => {
  const r = verifyPolicy(one('pass/001-bound-history.json'));
  assert.deepEqual(r, { verdict: 'FAIL', reason: 'a pinned issuer key is required' });
});

test('the profile is opt-in: a bundle is no other kind of record', () => {
  const b = one('pass/001-bound-history.json');
  assert.equal(verifyReceipt(b, { trustedPublicKey: PIN }).valid, false);
  assert.equal(verifyChain(b, { trustedPublicKey: PIN }).verdict, 'FAIL');
});

test('binding grammar', () => {
  const h = 'a'.repeat(64);
  assert.deepEqual(parseBinding(`policy_x@sha256:${h}`), ['policy_x', h]);
  assert.deepEqual(parseBinding(`policy_\u{1F600}@sha256:${h}`), ['policy_\u{1F600}', h]);
  for (const bad of [`@sha256:${h}`, `p@sha256:${h}\n`, `p@sha256:${h.toUpperCase()}`, `p@sha512:${h}`,
    `a@b@sha256:${h}`, `p@sha256:${h.slice(0, 63)}`, `p@sha256:${h}0`]) {
    assert.equal(parseBinding(bad), null, bad);
  }
});
