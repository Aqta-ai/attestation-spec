/**
 * complete and witnessed profile conformance (spec/CHECKPOINT-v1.md section 8,
 * spec/WITNESS-v1.md section 7; DRAFTS).
 *
 * Every vector under test-vectors/complete/ and test-vectors/witnessed/ must
 * reach the verdict its directory names. The Python suite checks the same
 * files, and scripts/e79-interop-sweep.mjs requires both to give the same
 * verdict and reason on every one.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyComplete } from './complete.js';
import { verifyWitnessed } from './witnessed.js';
import { verifyChain } from './chain.js';
import { verifyReceipt } from './index.js';

const VEC = join(__dirname, '..', '..', '..', 'test-vectors');
const PIN = readFileSync(join(VEC, 'complete', 'INDEX.md'), 'utf8').split('Vector issuer key (pin it): `')[1].split('`')[0];
const KINDS: Array<[string, string]> = [['pass', 'PASS'], ['fail', 'FAIL'], ['incomplete', 'INCOMPLETE']];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type V = any;

function load(profile: string, kind: string): Array<[string, V]> {
  return readdirSync(join(VEC, profile, kind))
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => [f, JSON.parse(readFileSync(join(VEC, profile, kind, f), 'utf8'))]);
}

function run(profile: string, v: V) {
  if (profile === 'complete') {
    return verifyComplete(v.bundle, { trustedPublicKey: PIN, reviewFrom: v.review_from, reviewTo: v.review_to,
      executorKeys: v.executor_keys });
  }
  return verifyWitnessed(v.bundle, { trustedPublicKey: PIN, witnessKeys: v.witness_keys,
    toleranceSeconds: v.tolerance_seconds });
}

for (const profile of ['complete', 'witnessed']) {
  for (const [kind, want] of KINDS) {
    test(`every ${profile}/${kind} vector returns ${want}`, () => {
      const vectors = load(profile, kind);
      assert.ok(vectors.length >= 5, `expected vectors in ${profile}/${kind}, got ${vectors.length}`);
      for (const [name, v] of vectors) {
        const r = run(profile, v);
        assert.equal(r.verdict, want, `${profile}/${kind}/${name}: got ${r.verdict} (${r.reason})`);
        if (want !== 'PASS') assert.ok(r.reason, `${profile}/${kind}/${name} must carry a reason`);
      }
    });
  }
}

const one = (profile: string, rel: string): V => JSON.parse(readFileSync(join(VEC, profile, rel), 'utf8'));

test('the tolerance is the line: the boundary vector passes at 3600 and fails at 3599', () => {
  const v = one('witnessed', 'pass/002-exactly-at-the-tolerance.json');
  assert.equal(verifyWitnessed(v.bundle, { trustedPublicKey: PIN, witnessKeys: v.witness_keys, toleranceSeconds: 3600 }).verdict, 'PASS');
  const tight = verifyWitnessed(v.bundle, { trustedPublicKey: PIN, witnessKeys: v.witness_keys, toleranceSeconds: 3599 });
  assert.equal(tight.verdict, 'FAIL');
  assert.match(tight.reason ?? '', /logged more than 3599 seconds late/);
});

test('missing trust sets are INCOMPLETE, never PASS', () => {
  const c = one('complete', 'pass/001-complete-with-executor-log.json');
  assert.equal(verifyComplete(c.bundle, { trustedPublicKey: PIN, reviewFrom: c.review_from, reviewTo: c.review_to }).verdict, 'INCOMPLETE');
  const w = one('witnessed', 'pass/001-honest-history.json');
  assert.equal(verifyWitnessed(w.bundle, { trustedPublicKey: PIN }).verdict, 'INCOMPLETE');
});

test('the profiles are opt-in: a bundle is no other kind of record', () => {
  for (const [profile, rel] of [['complete', 'pass/001-complete-with-executor-log.json'], ['witnessed', 'pass/001-honest-history.json']]) {
    const b = one(profile, rel).bundle;
    assert.equal(verifyReceipt(b, { trustedPublicKey: PIN }).valid, false);
    assert.equal(verifyReceipt(b, { trustedPublicKey: PIN, profile: 'ACTION-v1' }).valid, false);
    assert.equal(verifyChain(b, { trustedPublicKey: PIN }).verdict, 'FAIL');
  }
});
