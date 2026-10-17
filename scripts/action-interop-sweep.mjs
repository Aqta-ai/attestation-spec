// Cross-implementation interop sweep for the ACTION-v1 profile.
//
// Runs EVERY vector in test-vectors/action/{valid,invalid} through both
// reference verifiers (TypeScript in-process, Python via a subprocess) and
// compares verdict AND reason string per file. Also probes divergence
// surfaces no vector exercises: type-check wording, the unknown-profile
// value, and the option-conflict cases. Exit 0 only on full agreement.
//
// This exists because hardcoding one fixture hid the 1.0.8 float bug for a
// full release; the sweep rule is normative in spec/ACTION-v1.md section 6.

import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const { verifyReceipt } = await import(
  join(ROOT, 'packages/verify-receipt/dist/index.js')
);

const PIN = 'pOaccW6Csyo1POtxjixPH80oux9--YC1tzzaENT4vQ0';
const PY = join(ROOT, 'packages/verify-receipt-py/src');

function pyVerify(record, opts) {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(PY)})
from aqta_verify_receipt import verify_receipt
inp = json.load(sys.stdin)
r = verify_receipt(inp["record"], **inp["opts"])
print(json.dumps({"valid": r.valid, "reason": r.reason, "key_source": r.key_source, "envelope": r.envelope}))
`;
  const out = execFileSync('python3', ['-c', script], {
    input: JSON.stringify({ record, opts }),
  });
  return JSON.parse(out.toString());
}

// Pre-existing, deliberate wording-only divergences in published 1.0.10.
// Verdicts agree in every one; the wording differs because each language
// names its own parameter or stringifies its own primitives. Anything NOT
// on this list that differs, in verdict or wording, fails the sweep.
const KNOWN_WORDING_DIVERGENCES = new Set([
  'misuse:no-pin-no-optin',        // trustedPublicKey vs trusted_public_key
  'non-object:null',               // "not an object" vs "not a mapping"
  'att/invalid/008-invalid-outcome.json',   // MAYBE vs 'MAYBE'
  'att/invalid/014-boolean-version.json',   // true vs True
  // Record-type confusion under the ATTESTATION-v1 path. Both verifiers reject.
  // 025 and 027 differ only in quoting the string tag (action-1 vs 'action-1').
  // 024 and 026 lack several ATTESTATION-v1 fields: TypeScript names the first
  // in field order, Python iterates a frozenset and names whichever field its
  // hash order reaches first, which varies between processes.
  'att/invalid/024-action-v1-record.json',
  'att/invalid/025-action-version-tag.json',
  'att/invalid/026-accept-v1-record.json',
  'att/invalid/027-accept-version-tag.json',
]);

let failures = 0;
function compare(label, record, tsOpts, pyOpts) {
  const ts = verifyReceipt(record, tsOpts);
  const py = pyVerify(record, pyOpts);
  const verdictAgree =
    ts.valid === py.valid && (ts.keySource ?? null) === (py.key_source ?? null);
  const agree = verdictAgree &&
    ((ts.reason ?? null) === (py.reason ?? null) ||
      (KNOWN_WORDING_DIVERGENCES.has(label)));
  if (KNOWN_WORDING_DIVERGENCES.has(label) && !verdictAgree) {
    // an allowlisted label still must agree on the verdict
  }
  if (agree) {
    console.log(`  ok   ${label}: valid=${ts.valid}${ts.reason ? ` reason="${ts.reason}"` : ''}`);
  } else {
    failures++;
    console.log(`  DIVERGE ${label}`);
    console.log(`    ts: ${JSON.stringify(ts)}`);
    console.log(`    py: ${JSON.stringify(py)}`);
  }
  return ts;
}

const tsOptsPinned = { profile: 'ACTION-v1', trustedPublicKey: PIN };
const pyOptsPinned = { profile: 'ACTION-v1', trusted_public_key: PIN };

console.log('valid vectors (must all verify):');
for (const f of readdirSync(join(ROOT, 'test-vectors/action/valid')).sort()) {
  const rec = JSON.parse(readFileSync(join(ROOT, 'test-vectors/action/valid', f)));
  const ts = compare(`valid/${f}`, rec, tsOptsPinned, pyOptsPinned);
  if (!ts.valid) { failures++; console.log(`    EXPECTED valid, got invalid`); }
}

console.log('invalid vectors (must all fail, identically):');
for (const f of readdirSync(join(ROOT, 'test-vectors/action/invalid')).sort()) {
  const rec = JSON.parse(readFileSync(join(ROOT, 'test-vectors/action/invalid', f)));
  const ts = compare(`invalid/${f}`, rec, tsOptsPinned, pyOptsPinned);
  if (ts.valid) { failures++; console.log(`    EXPECTED invalid, got valid`); }
}

console.log('un-vectored divergence probes:');
const base = JSON.parse(
  readFileSync(join(ROOT, 'test-vectors/action/valid/001-allowed.json'))
);

// Type-check wording: one probe per field class.
for (const [field, bad] of [
  ['tool', 42], ['agent', null], ['session_id', 7], ['org_id', []],
  ['action_id', 1], ['intent_hash', 9], ['args_hash', true],
  ['timestamp', 100], ['outcome', 2], ['public_key', 5], ['signature', 6],
  ['policy_applied', 'not-an-array'], ['v', 1.5],
]) {
  compare(`type:${field}=${JSON.stringify(bad)}`, { ...base, [field]: bad }, tsOptsPinned, pyOptsPinned);
}

// Option-conflict and misuse surfaces.
compare('conflict:profile+envelope', base,
  { profile: 'ACTION-v1', envelope: 'anchor-v1', trustedPublicKey: PIN },
  { profile: 'ACTION-v1', envelope: 'anchor-v1', trusted_public_key: PIN });
compare('misuse:envelope=ACTION-v1', base,
  { envelope: 'ACTION-v1', trustedPublicKey: PIN },
  { envelope: 'ACTION-v1', trusted_public_key: PIN });
compare('misuse:unknown-profile', base,
  { profile: 'ACTION-v2', trustedPublicKey: PIN },
  { profile: 'ACTION-v2', trusted_public_key: PIN });
compare('misuse:no-pin-no-optin', base, { profile: 'ACTION-v1' }, { profile: 'ACTION-v1' });
compare('integrity-only', base,
  { profile: 'ACTION-v1', allowUntrustedEmbeddedKey: true },
  { profile: 'ACTION-v1', allow_untrusted_embedded_key: true });
compare('non-object:null', null, tsOptsPinned, pyOptsPinned);

// Argument-object canonicalisation (test-vectors/action/args). Each file
// carries the canonical bytes for an argument object whose member names order
// differently by UTF-16 code unit and by code point. The anchor-v1 envelope is
// the public entry point that canonicalises arbitrary member names, so a
// verifier's key order is checked through it: the envelope signed over the
// code-unit bytes MUST verify, and the one signed over the code-point bytes
// MUST NOT wherever the two orders differ. The reference issuer's args_hash is
// checked against the same files.
console.log('argument canonicalisation vectors:');
const ARGS_DIR = join(ROOT, 'test-vectors/action/args');
const argFiles = readdirSync(ARGS_DIR).filter((f) => f.endsWith('.json')).sort();
const issuerHashes = JSON.parse(execFileSync('python3', ['-c', `
import hashlib, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("a", ${JSON.stringify(join(ROOT, 'examples/reference-action-issuer.py'))})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
vs = json.load(sys.stdin)
print(json.dumps({k: [m.args_hash_of(v["args"]), m.canonical_payload(v["args"]).hex()] for k, v in vs.items()}))
`], { input: JSON.stringify(Object.fromEntries(argFiles.map((f) =>
  [f, JSON.parse(readFileSync(join(ARGS_DIR, f)))]))) }).toString());
for (const f of argFiles) {
  const v = JSON.parse(readFileSync(join(ARGS_DIR, f)));
  const [hash, hex] = issuerHashes[f];
  if (hash !== v.args_hash || hex !== v.canonical_hex) {
    failures++;
    console.log(`  ISSUER MISMATCH args/${f}: ${hash}`);
  } else {
    console.log(`  ok   issuer args/${f}: args_hash=${hash.slice(0, 16)}...`);
  }
  const envTs = { envelope: 'anchor-v1', trustedPublicKey: PIN };
  const envPy = { envelope: 'anchor-v1', trusted_public_key: PIN };
  const good = compare(`args/${f}:code-unit`, v.envelope, envTs, envPy);
  if (!good.valid) { failures++; console.log('    EXPECTED valid, got invalid'); }
  const cp = compare(`args/${f}:code-point`, v.envelope_code_point_order, envTs, envPy);
  if (cp.valid !== !v.orders_differ) {
    failures++;
    console.log(`    EXPECTED valid=${!v.orders_differ}, got valid=${cp.valid}`);
  }
}

// The ATTESTATION suite must be unaffected: sweep it too.
console.log('ATTESTATION-v1 regression sweep:');
const ATT_PIN = 'alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E';
for (const dir of ['valid', 'invalid']) {
  for (const f of readdirSync(join(ROOT, 'test-vectors', dir)).sort()) {
    const rec = JSON.parse(readFileSync(join(ROOT, 'test-vectors', dir, f)));
    compare(`att/${dir}/${f}`, rec,
      { trustedPublicKey: ATT_PIN }, { trusted_public_key: ATT_PIN });
  }
}

console.log(failures === 0 ? `\nSWEEP CLEAN` : `\n${failures} DIVERGENCES`);
process.exit(failures === 0 ? 0 : 1);
