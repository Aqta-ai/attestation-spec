// Byte-level interop sweep: both reference CLIs must return the same exit code
// on every file in test-vectors/bytes, and that code must match expected.json.
// These inputs cannot be JSON vectors because they are not valid UTF-8, and the
// library-level sweeps never see bytes at all. Verdict = exit code: 0 valid,
// 1 invalid, 2 malformed.
//
//   node scripts/bytes-interop-sweep.mjs
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIR = join(ROOT, 'test-vectors/bytes');
const TS_CLI = join(ROOT, 'packages/verify-receipt/dist/cli.js');
const PY_ENV = { ...process.env, PYTHONPATH: join(ROOT, 'packages/verify-receipt-py/src') };
const manifest = JSON.parse(readFileSync(join(DIR, 'expected.json'), 'utf8'));
const PIN = manifest.trusted_public_key;
const code = (r) => (r.status === null ? -1 : r.status);
let failures = 0;
for (const f of readdirSync(DIR).filter((n) => n.endsWith('.bin')).sort()) {
  const path = join(DIR, f);
  const want = manifest.vectors[f]?.expected_exit;
  const ts = code(spawnSync('node', [TS_CLI, path, '--key', PIN]));
  const py = code(spawnSync('python3', ['-m', 'aqta_verify_receipt', path, '--key', PIN], { env: PY_ENV }));
  const ok = ts === py && ts === want;
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${f.padEnd(36)} ts=${ts} py=${py} expected=${want}`);
}
console.log(failures === 0 ? 'BYTES SWEEP CLEAN' : `${failures} BYTE-LEVEL DIVERGENCES`);
process.exit(failures === 0 ? 0 : 1);
