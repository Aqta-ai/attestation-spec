/**
 * chain profile conformance (spec/USE-v1.md section 9; DRAFT).
 *
 * Every vector under test-vectors/chain/ must reach the verdict its directory
 * names. The Python suite checks the same files, and
 * scripts/chain-interop-sweep.mjs requires both to give the same verdict and
 * reason on every one.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { verifyChain } from './chain.js';
import { verifyReceipt } from './index.js';

const PIN = 'VZh1DjZPXa6voCmlv7MU7APjSr-HFxrG2WSqDm-eBGE';
const DIR = join(__dirname, '..', '..', '..', 'test-vectors', 'chain');
const KINDS: Array<[string, string]> = [['pass', 'PASS'], ['fail', 'FAIL'], ['incomplete', 'INCOMPLETE']];

function load(kind: string): Array<[string, { approver_keys: string[] | null; bundle: unknown }]> {
  return readdirSync(join(DIR, kind))
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => [f, JSON.parse(readFileSync(join(DIR, kind, f), 'utf8'))]);
}

for (const [kind, want] of KINDS) {
  test(`every chain/${kind} vector returns ${want}`, () => {
    const vectors = load(kind);
    assert.ok(vectors.length >= 5, `expected vectors in ${kind}, got ${vectors.length}`);
    for (const [name, v] of vectors) {
      const r = verifyChain(v.bundle, { trustedPublicKey: PIN, approverKeys: v.approver_keys });
      assert.equal(r.verdict, want, `${kind}/${name}: got ${r.verdict} (${r.reason})`);
      if (want !== 'PASS') assert.ok(r.reason, `${kind}/${name} must carry a reason`);
    }
  });
}

test('INCOMPLETE is never PASS: the honest bundle without an approver set', () => {
  const v = JSON.parse(readFileSync(join(DIR, 'pass', '001-single-use.json'), 'utf8'));
  assert.equal(verifyChain(v.bundle, { trustedPublicKey: PIN, approverKeys: v.approver_keys }).verdict, 'PASS');
  assert.equal(verifyChain(v.bundle, { trustedPublicKey: PIN }).verdict, 'INCOMPLETE');
});

test('no pinned issuer key is a FAIL, never an embedded-key pass', () => {
  const v = JSON.parse(readFileSync(join(DIR, 'pass', '001-single-use.json'), 'utf8'));
  assert.equal(verifyChain(v.bundle, { approverKeys: v.approver_keys }).verdict, 'FAIL');
});

test('the chain profile is opt-in: a bundle is not a receipt', () => {
  const v = JSON.parse(readFileSync(join(DIR, 'pass', '001-single-use.json'), 'utf8'));
  assert.equal(verifyReceipt(v.bundle as never, { trustedPublicKey: PIN }).valid, false);
  assert.equal(verifyReceipt(v.bundle as never, { trustedPublicKey: PIN, profile: 'ACTION-v1' }).valid, false);
});

test('CLI exit codes: 0 PASS, 1 FAIL, 3 INCOMPLETE', () => {
  const cli = join(__dirname, 'cli.js');
  const run = (file: string, keys: string[] | null): number => {
    const v = JSON.parse(readFileSync(file, 'utf8'));
    const argv = [cli, '-', '--key', PIN, '--profile', 'chain', '-q'];
    if (keys) argv.push('--approver-keys', keys.join(','));
    try {
      execFileSync(process.execPath, argv, { input: JSON.stringify(v.bundle) });
      return 0;
    } catch (e) {
      return (e as { status: number }).status;
    }
  };
  const p = JSON.parse(readFileSync(join(DIR, 'pass', '001-single-use.json'), 'utf8'));
  assert.equal(run(join(DIR, 'pass', '001-single-use.json'), p.approver_keys), 0);
  assert.equal(run(join(DIR, 'fail', '007-use-index-over-limit.json'), p.approver_keys), 1);
  assert.equal(run(join(DIR, 'pass', '001-single-use.json'), null), 3);
});
