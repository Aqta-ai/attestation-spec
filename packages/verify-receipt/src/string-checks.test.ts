/**
 * Whole-string, ASCII-only matching and the string edge cases (1.2.7).
 * Run: `npm run build && node --test dist/string-checks.test.js`.
 *
 * JavaScript's `\d` is ASCII only and `$` matches only at the end of the input,
 * so this side was already strict on those classes. These tests keep it so and
 * pin the reasons both implementations now share: the Python suite
 * (tests/test_string_checks.py) asserts the same strings for the same files.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import nacl from 'tweetnacl';
import { verifyReceipt } from './index.js';
import { verifySignedTreeHead } from './transparency.js';

const V = join(__dirname, '..', '..', '..', 'test-vectors');
const ATT_KEY = 'alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E';
const ACT_KEY = 'pOaccW6Csyo1POtxjixPH80oux9--YC1tzzaENT4vQ0';
const TS_REASON = 'timestamp must be an RFC 3339 datetime with an explicit offset';
const load = (rel: string) => JSON.parse(readFileSync(join(V, rel), 'utf8'));

const EXPECTED: Record<string, string> = {
  'invalid/018-request-hash-trailing-newline.json': 'request_hash must be 64 lowercase hex chars',
  'invalid/019-timestamp-trailing-newline.json': TS_REASON,
  'invalid/020-signature-trailing-newline.json': 'signature decode error: not base64url',
  'invalid/021-timestamp-non-ascii-digits.json': TS_REASON,
  'invalid/022-outcome-not-a-string.json': 'outcome must be a string',
  'invalid/023-policy-lone-surrogate.json': 'policy_applied must be in lexicographic order',
  'action/invalid/017-args-hash-trailing-newline.json': 'args_hash must be 64 lowercase hex characters',
  'action/invalid/018-intent-hash-trailing-newline.json': "intent_hash must be '' or 64 lowercase hex characters",
  'action/invalid/019-timestamp-trailing-newline.json': TS_REASON,
  'action/invalid/020-signature-trailing-newline.json': 'signature decode error: not base64url',
  'action/invalid/021-timestamp-non-ascii-digits.json': TS_REASON,
  'action/invalid/022-outcome-not-a-string.json': 'outcome must be a string',
  'action/invalid/023-policy-lone-surrogate.json': 'policy_applied must be in lexicographic order',
};

for (const [rel, reason] of Object.entries(EXPECTED)) {
  test(`${rel} is refused with the shared reason`, () => {
    const r = rel.startsWith('action/')
      ? verifyReceipt(load(rel), { trustedPublicKey: ACT_KEY, profile: 'ACTION-v1' })
      : verifyReceipt(load(rel), { trustedPublicKey: ATT_KEY });
    assert.deepEqual([r.valid, r.reason], [false, reason]);
  });
}

test('a non-string outcome gets the ACTION-v1 wording', () => {
  const rec = load('valid/001-allowed.json');
  for (const outcome of [['ALLOWED'], { a: 1 }, 1, null]) {
    const r = verifyReceipt({ ...rec, outcome }, { trustedPublicKey: ATT_KEY });
    assert.deepEqual([r.valid, r.reason], [false, 'outcome must be a string']);
  }
});

test('an anchor-v1 signature with a trailing line feed is refused', () => {
  const kp = nacl.sign.keyPair();
  const signed = { n: 1, public_key_b64: Buffer.from(kp.publicKey).toString('base64') };
  const sig = Buffer.from(nacl.sign.detached(Buffer.from(JSON.stringify(signed)), kp.secretKey)).toString('base64');
  const opts = { allowUntrustedEmbeddedKey: true, envelope: 'anchor-v1' as const };
  assert.equal(verifyReceipt({ ...signed, signature_b64: sig }, opts).valid, true);
  const r = verifyReceipt({ ...signed, signature_b64: sig + '\n' }, opts);
  assert.deepEqual([r.valid, r.reason], [false, 'signature decode error: not base64']);
});

test('a signed tree head refuses a trailing line feed in its signature or key', () => {
  const head = load('transparency/valid/sth-public-live.json');
  const key = head._trusted_public_key;
  assert.equal(verifySignedTreeHead(head, key).valid, true);
  const reason = 'signature and key must be base64url without padding';
  assert.equal(verifySignedTreeHead({ ...head, signature: head.signature + '\n' }, key).reason, reason);
  assert.equal(verifySignedTreeHead(head, key + '\n').reason, reason);
});

for (const name of ['sth-org-id-lone-surrogate.json', 'sth-public-timestamp-lone-surrogate.json']) {
  test(`transparency/invalid/${name} is refused, not verified over U+FFFD`, () => {
    const head = load(`transparency/invalid/${name}`);
    const r = verifySignedTreeHead(head, head._trusted_public_key);
    assert.deepEqual([r.valid, r.reason], [false, 'head contains an unpaired surrogate']);
  });
}

test('aqta-verify-proof exits 2 on NaN and on invalid UTF-8, as the Python command now does', () => {
  const dir = mkdtempSync(join(tmpdir(), 'aqta-proof-'));
  const bin = join(__dirname, 'verify-proof.js');
  const bodies = [
    Buffer.from('{"audit_path": [], "x": NaN}'),
    Buffer.concat([Buffer.from('{"audit_path": ['), Buffer.from([0x80]), Buffer.from(']}')]),
  ];
  for (const body of bodies) {
    const f = join(dir, 'proof.json');
    writeFileSync(f, body);
    assert.equal(spawnSync(process.execPath, [bin, f, '--json']).status, 2);
  }
});
