// Cross-implementation interop sweep for the chain profile (spec/USE-v1.md
// section 9; GRANT-v1 and USE-v1 are drafts).
//
// Runs EVERY vector in test-vectors/chain/{pass,fail,incomplete} through both
// reference verifiers (TypeScript in-process, Python in one subprocess batch)
// and requires the same verdict AND the same reason on every one, and the
// verdict the directory names. Then probes surfaces no vector pins: for each
// vector, deterministic mutations of every record member (deleted, set to a
// number, to null, to a list, to a non-BMP string, to a lone surrogate, to a
// trailing line feed), each approver-set variant, and members reordered (which
// changes no signed byte). Exit 0 only on full agreement.

import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const { verifyChain } = await import(join(ROOT, 'packages/verify-receipt/dist/chain.js'));
const PY = join(ROOT, 'packages/verify-receipt-py/src');
const PIN = 'VZh1DjZPXa6voCmlv7MU7APjSr-HFxrG2WSqDm-eBGE';
const DIR = join(ROOT, 'test-vectors/chain');
const EXPECT = { pass: 'PASS', fail: 'FAIL', incomplete: 'INCOMPLETE' };

function pyBatch(jobs) {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(PY)})
from aqta_verify_receipt import verify_chain
jobs = json.load(sys.stdin)
out = []
for j in jobs:
    r = verify_chain(j["bundle"], trusted_public_key=j["pin"], approver_keys=j["approver_keys"])
    out.append({"verdict": r.verdict, "reason": r.reason})
sys.stdout.write(json.dumps(out))
`;
  const out = execFileSync('python3', ['-c', script], {
    input: JSON.stringify(jobs), maxBuffer: 1 << 28,
  });
  return JSON.parse(out.toString());
}

const jobs = [];
function add(label, bundle, approverKeys, expected = null, pin = PIN) {
  jobs.push({ label, bundle, approver_keys: approverKeys, pin, expected });
}

const vectors = [];
for (const kind of Object.keys(EXPECT)) {
  for (const f of readdirSync(join(DIR, kind)).filter((x) => x.endsWith('.json')).sort()) {
    const v = JSON.parse(readFileSync(join(DIR, kind, f), 'utf8'));
    vectors.push([`${kind}/${f}`, v]);
    add(`${kind}/${f}`, v.bundle, v.approver_keys, EXPECT[kind]);
  }
}

const clone = (x) => JSON.parse(JSON.stringify(x));
const BAD_VALUES = [
  ['deleted', undefined], ['number', 1], ['null', null], ['list', []], ['object', {}],
  ['non-bmp', '\u{1F600}'], ['lone-surrogate', '\uD800'], ['line-feed', null],
];

for (const [label, v] of vectors) {
  const b = v.bundle;
  // approver-set variants
  add(`${label} :: approver set absent`, b, null);
  add(`${label} :: approver set empty`, b, []);
  add(`${label} :: approver set malformed`, b, ['not-a-key']);
  add(`${label} :: no pinned key`, b, v.approver_keys, null, null);
  // members reordered: no signed byte changes, so the verdict must not either
  if (b && typeof b === 'object' && !Array.isArray(b)) {
    const rev = (o) => Object.fromEntries(Object.entries(o).reverse());
    const r = rev(b);
    for (const k of ['grants', 'uses']) if (Array.isArray(r[k])) r[k] = r[k].map((x) => (x && typeof x === 'object' ? rev(x) : x));
    add(`${label} :: members reordered`, r, v.approver_keys);
  }
  // per-member mutations on the first grant, first use and first action
  for (const [coll, sub, pick] of [['grants', '', (x) => x], ['uses', '', (x) => x], ['actions', '.record', (x) => x.record], ['actions', '.args', (x) => x.args]]) {
    if (!b || !Array.isArray(b[coll]) || b[coll].length === 0) continue;
    const target = pick(b[coll][0]);
    if (!target || typeof target !== 'object') continue;
    for (const key of Object.keys(target)) {
      for (const [name, val] of BAD_VALUES) {
        const m = clone(b);
        const t = pick(m[coll][0]);
        if (name === 'deleted') delete t[key];
        else if (name === 'line-feed') {
          if (typeof t[key] !== 'string') continue;
          t[key] = t[key] + '\n';
        } else t[key] = val;
        const where = `${coll}[0]${sub}`;
        add(`${label} :: ${where}.${key} ${name}`, m, v.approver_keys);
      }
    }
  }
}

const py = pyBatch(jobs.map(({ bundle, approver_keys, pin }) => ({ bundle, approver_keys, pin })));
let divergences = 0;
let wrong = 0;
const counts = { PASS: 0, FAIL: 0, INCOMPLETE: 0 };
jobs.forEach((j, i) => {
  const ts = verifyChain(j.bundle, { trustedPublicKey: j.pin ?? undefined, approverKeys: j.approver_keys });
  const p = py[i];
  counts[ts.verdict]++;
  if (ts.verdict !== p.verdict || (ts.reason ?? null) !== (p.reason ?? null)) {
    divergences++;
    console.log(`  DIVERGE ${j.label}`);
    console.log(`    ts: ${JSON.stringify(ts)}`);
    console.log(`    py: ${JSON.stringify(p)}`);
  } else if (j.expected !== null) {
    if (ts.verdict !== j.expected) {
      wrong++;
      console.log(`  WRONG ${j.label}: expected ${j.expected}, both gave ${ts.verdict} (${ts.reason})`);
    } else {
      console.log(`  ok   ${j.label}: ${ts.verdict}${ts.reason ? ` "${ts.reason}"` : ''}`);
    }
  }
});

console.log(`\n${vectors.length} vectors, ${jobs.length} items in all (${counts.PASS} PASS, ${counts.FAIL} FAIL, ` +
  `${counts.INCOMPLETE} INCOMPLETE)`);
const clean = divergences === 0 && wrong === 0;
console.log(clean ? 'CHAIN SWEEP CLEAN: both implementations agree on verdict and reason, and every vector is correct'
  : `${divergences} DIVERGENCES, ${wrong} WRONG VERDICTS`);
process.exit(clean ? 0 : 1);
