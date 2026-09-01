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
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VECTORS = join(ROOT, 'test-vectors/transparency');
const PY = join(ROOT, 'packages/verify-receipt-py/src');

const { verifyInclusionProof, verifyConsistencyProof, verifySignedTreeHead } = await import(
  join(ROOT, 'packages/verify-receipt/dist/transparency.js')
);

function pyVerify(kind, proof, key) {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(PY)})
from aqta_verify_receipt.transparency import (
    verify_inclusion_proof, verify_consistency_proof, verify_signed_tree_head)
data = json.load(sys.stdin)
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
    checked++;

    const expected = bucket === 'valid';
    const agree = ts.valid === py.valid;
    const correct = ts.valid === expected;

    if (!agree) problems.push(`DIVERGENCE ${bucket}/${file}: ts=${ts.valid} (${ts.reason ?? ''}) py=${py.valid} (${py.reason ?? ''})`);
    else if (!correct) problems.push(`WRONG VERDICT ${bucket}/${file}: both returned ${ts.valid}, expected ${expected}`);
    else console.log(`  ok   ${bucket}/${file}: valid=${ts.valid}${ts.reason ? ` reason="${ts.reason}"` : ''}`);
  }
}

console.log(`\nvectors checked: ${checked}`);
if (problems.length) {
  for (const p of problems) console.log(`  ${p}`);
  console.log('\nSWEEP FAILED');
  process.exit(1);
}
console.log('SWEEP CLEAN: both implementations agree and every verdict is correct');
