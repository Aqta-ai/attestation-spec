// Cross-implementation sweep for transparency proofs.
//
// Every vector in test-vectors/transparency/{valid,invalid} through both
// reference implementations, comparing the verdict per file. Valid vectors
// must verify, invalid vectors must not, and the two implementations must
// agree on every one. Exit 0 only on full agreement AND correct verdicts.
//
// A proof checker that is merely self-consistent proves nothing: the whole
// claim is that two independently written implementations reach the same
// answer about the same bytes.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VECTORS = join(ROOT, 'test-vectors/transparency');
const PY = join(ROOT, 'packages/verify-receipt-py/src');

const { verifyInclusionProof, verifyConsistencyProof, verifySignedTreeHead, assessHistory } = await import(
  join(ROOT, 'packages/verify-receipt/dist/transparency.js')
);

function pyVerify(kind, proof, key) {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(PY)})
from aqta_verify_receipt.transparency import (
    verify_inclusion_proof, verify_consistency_proof, verify_signed_tree_head, assess_history)
data = json.load(sys.stdin)
if data["kind"] == "history":
    r = assess_history(data["proof"], data["key"])
    print(json.dumps({"valid": r.valid, "reason": r.reason, "verdict": r.verdict})); raise SystemExit(0)
if data["kind"] == "sth":
    r = verify_signed_tree_head(data["proof"], data["key"])
else:
    fn = verify_inclusion_proof if data["kind"] == "inclusion" else verify_consistency_proof
    r = fn(data["proof"])
print(json.dumps({"valid": r.valid, "reason": r.reason}))
`;
  const out = execFileSync('python3', ['-c', script], {
    input: JSON.stringify({ kind, proof, key: key ?? '' }),
    encoding: 'utf8',
  });
  return JSON.parse(out);
}


/* The CLI leg (4 Sep 2026). The library verdicts above agreed on every vector
   while the published CLI crashed on the live signed tree head: its envelope
   unwrapping took the head's string "proof" hint for a nested document. A
   sweep that only calls the library cannot see that, so every vector also
   goes through both command-line entry points, and a crash (no JSON verdict)
   is a failure in its own right, not a verdict. */
function cliVerdict(argv0, args, file, key) {
  const full = [...args, file, '--json', ...(key ? ['--key', key] : [])];
  const r = spawnSync(argv0, full, { encoding: 'utf8' });
  try {
    const out = JSON.parse(r.stdout.trim().split('\n').pop());
    return { valid: out.valid === true, reason: out.reason ?? undefined, crashed: false };
  } catch {
    return { valid: false, reason: `no verdict: exit ${r.status} ${String(r.stderr).trim().split('\n')[0]}`, crashed: true };
  }
}
const TS_CLI = join(ROOT, 'packages/verify-receipt/dist/verify-proof.js');
const PY_ENV = { ...process.env, PYTHONPATH: PY };

let checked = 0;
const problems = [];

for (const bucket of ['valid', 'invalid']) {
  const dir = join(VECTORS, bucket);
  if (!existsSync(dir)) continue;
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.json')).sort()) {
    const proof = JSON.parse(readFileSync(join(dir, file), 'utf8'));
    /* Dispatch by vector kind. A signed tree head is not a proof and must not
       be fed to a proof verifier: doing so returned "old_size must be a
       positive integer", which made every invalid STH vector pass for a reason
       that had nothing to do with what it tests. An invalid vector that would
       still be invalid with the rule under test removed is not a test. */
    const kind = file.startsWith('inclusion')
      ? 'inclusion'
      : file.startsWith('sth')
        ? 'sth'
        : 'consistency';
    /* Heads are checked against a key. The vector carries the trusted key it
       is to be checked under, so the harness never supplies one of its own. */
    const key = kind === 'sth' ? (proof._trusted_public_key ?? '') : undefined;
    if (kind === 'sth' && !key) {
      problems.push(`MALFORMED ${bucket}/${file}: sth vector carries no _trusted_public_key`);
      continue;
    }
    const ts =
      kind === 'inclusion'
        ? verifyInclusionProof(proof)
        : kind === 'sth'
          ? verifySignedTreeHead(proof, key)
          : verifyConsistencyProof(proof);
    const py = pyVerify(kind, proof, key);
    const file_ = join(dir, file);
    const tsCli = cliVerdict('node', [TS_CLI], file_, key);
    const pyCli = (() => {
      const r = spawnSync('python3', ['-m', 'aqta_verify_receipt.verify_proof', file_, '--json', ...(key ? ['--key', key] : [])], { encoding: 'utf8', env: PY_ENV });
      try { const out = JSON.parse(r.stdout.trim().split('\n').pop()); return { valid: out.valid === true, reason: out.reason ?? undefined, crashed: false }; }
      catch { return { valid: false, reason: `no verdict: exit ${r.status} ${String(r.stderr).trim().split('\n')[0]}`, crashed: true }; }
    })();
    checked++;
    for (const [name, v] of [['ts-cli', tsCli], ['py-cli', pyCli]]) {
      if (v.crashed) problems.push(`CRASH ${bucket}/${file}: ${name} gave no verdict (${v.reason})`);
      else if (v.valid !== ts.valid) problems.push(`CLI DIVERGENCE ${bucket}/${file}: ${name}=${v.valid} library=${ts.valid}`);
    }

    const expected = bucket === 'valid';
    const agree = ts.valid === py.valid;
    const correct = ts.valid === expected;

    if (!agree) problems.push(`DIVERGENCE ${bucket}/${file}: ts=${ts.valid} (${ts.reason ?? ''}) py=${py.valid} (${py.reason ?? ''})`);
    else if (!correct) problems.push(`WRONG VERDICT ${bucket}/${file}: both returned ${ts.valid}, expected ${expected}`);
    else console.log(`  ok   ${bucket}/${file}: valid=${ts.valid}${ts.reason ? ` reason="${ts.reason}"` : ''}`);
  }
}

/* Adversary bundles (12 Sep 2026). A primitive vector asks one question of one
   object. These ask the questions ISSUER-ADVERSARY.md actually poses, which are
   only visible across objects, and the answer is a named verdict rather than a
   boolean. Both libraries and both CLIs must name the same verdict, and it must
   be the one the bundle expects. */
const ADV = join(VECTORS, 'adversary');
if (existsSync(ADV)) {
  for (const file of readdirSync(ADV).filter((f) => f.endsWith('.json')).sort()) {
    const bundle = JSON.parse(readFileSync(join(ADV, file), 'utf8'));
    const key = bundle.trusted_public_key ?? '';
    const expected = bundle.expect?.verdict;
    if (!key || !expected) { problems.push(`MALFORMED adversary/${file}: needs trusted_public_key and expect.verdict`); continue; }
    const ts = assessHistory(bundle, key);
    const py = pyVerify('history', bundle, key);
    const file_ = join(ADV, file);
    const tsCli = (() => {
      const r = spawnSync('node', [TS_CLI, file_, '--json', '--key', key], { encoding: 'utf8' });
      try { const out = JSON.parse(r.stdout.trim().split('\n').pop()); return { verdict: out.verdict, valid: out.valid === true, crashed: false }; }
      catch { return { verdict: undefined, valid: false, crashed: true, reason: `exit ${r.status} ${String(r.stderr).trim().split('\n')[0]}` }; }
    })();
    const pyCli = (() => {
      const r = spawnSync('python3', ['-m', 'aqta_verify_receipt.verify_proof', file_, '--json', '--key', key], { encoding: 'utf8', env: PY_ENV });
      try { const out = JSON.parse(r.stdout.trim().split('\n').pop()); return { verdict: out.verdict, valid: out.valid === true, crashed: false }; }
      catch { return { verdict: undefined, valid: false, crashed: true, reason: `exit ${r.status} ${String(r.stderr).trim().split('\n')[0]}` }; }
    })();
    checked++;
    if (ts.verdict !== py.verdict) problems.push(`DIVERGENCE adversary/${file}: ts=${ts.verdict} (${ts.reason ?? ''}) py=${py.verdict} (${py.reason ?? ''})`);
    else if (ts.verdict !== expected) problems.push(`WRONG VERDICT adversary/${file}: both say ${ts.verdict}, expected ${expected}`);
    else console.log(`  ok   adversary/${file}: verdict=${ts.verdict}${ts.reason ? ` reason="${ts.reason}"` : ''}`);
    for (const [name, v] of [['ts-cli', tsCli], ['py-cli', pyCli]]) {
      if (v.crashed) problems.push(`CRASH adversary/${file}: ${name} gave no verdict (${v.reason})`);
      else if (v.verdict !== ts.verdict) problems.push(`CLI DIVERGENCE adversary/${file}: ${name}=${v.verdict} library=${ts.verdict}`);
      else if (v.valid !== (ts.verdict === 'consistent')) problems.push(`CLI DIVERGENCE adversary/${file}: ${name} valid=${v.valid} for verdict ${v.verdict}`);
    }
  }
}

console.log(`\nvectors checked: ${checked}`);
if (problems.length) {
  for (const p of problems) console.log(`  ${p}`);
  console.log('\nSWEEP FAILED');
  process.exit(1);
}
console.log('SWEEP CLEAN: both implementations agree and every verdict is correct');
