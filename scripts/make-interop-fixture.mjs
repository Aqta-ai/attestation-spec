#!/usr/bin/env node
/**
 * Cross-implementation interop test.
 *
 * 1. Shell out to Python to generate a real receipt using the stand-alone
 *    reference issuer in examples/reference-issuer.py.
 * 2. Parse the JSON and run it through this TypeScript verifier.
 * 3. Run tamper-detection checks against the same receipt.
 *
 * If this script exits 0, the reference issuer and the TypeScript verifier
 * agree on the ATTESTATION-v1 spec. Use this as a conformance check for any
 * new issuer or verifier implementation.
 *
 * Usage: npm run build && node scripts/make-interop-fixture.mjs
 */

import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyReceipt } from '../packages/verify-receipt/dist/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const issuerPath = path.join(repoRoot, 'examples', 'reference-issuer.py');

const pyScript = `
import sys, json, importlib.util
spec = importlib.util.spec_from_file_location("ref", "${issuerPath}")
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)

issuer = ref.ReferenceIssuer.new()
receipt = issuer.sign(
    trace_id="trace-interop-test",
    org_id="org-interop-test",
    request_hash="8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
    model="gpt-4o",
    outcome="ALLOWED",
    policy_applied=["budget_guard", "loop_guard"],
    cost_prevented_eur=0.0,
)
print(json.dumps(receipt))
`;

const py = spawnSync('python3', ['-c', pyScript], { encoding: 'utf8' });
if (py.status !== 0) {
  console.error('Reference issuer failed:', py.stderr);
  process.exit(1);
}

const receipt = JSON.parse(py.stdout.trim());
console.log('Receipt produced by reference issuer:');
console.log('  spec version:', receipt.v);
console.log('  attestation_id:', receipt.attestation_id);
console.log('  public_key:', receipt.public_key.slice(0, 16) + '...');
console.log('  signature:', receipt.signature.slice(0, 16) + '...');
console.log();

// Test 1: valid receipt verifies
const res1 = verifyReceipt(receipt);
console.log('Test 1 valid receipt:', res1.valid ? 'PASS' : `FAIL (${res1.reason})`);

// Test 2: tampered outcome rejects
const tampered = { ...receipt, outcome: 'BLOCKED' };
const res2 = verifyReceipt(tampered);
console.log('Test 2 tampered outcome:', !res2.valid ? 'PASS' : 'FAIL (accepted tampered receipt)');

// Test 3: pinned public key works
const res3 = verifyReceipt(receipt, { trustedPublicKey: receipt.public_key });
console.log('Test 3 pinned public key:', res3.valid ? 'PASS' : `FAIL (${res3.reason})`);

// Test 4: pinned mismatch rejects
const res4 = verifyReceipt(receipt, { trustedPublicKey: 'different_key_here' });
console.log('Test 4 mismatched pinned key:', !res4.valid ? 'PASS' : 'FAIL');

const allPass = res1.valid && !res2.valid && res3.valid && !res4.valid;
console.log();
console.log(allPass ? '✅ All interop tests passed' : '❌ Interop failure');
process.exit(allPass ? 0 : 1);
