// Cross-implementation interop sweep for the complete and witnessed profiles
// (spec/CHECKPOINT-v1.md, spec/EXECUTION-v1.md, spec/WITNESS-v1.md; drafts).
//
// Runs EVERY vector in test-vectors/{complete,witnessed}/{pass,fail,incomplete}
// through both reference verifiers (TypeScript in-process, Python in one
// subprocess batch) and requires the same verdict AND the same reason on every
// one, and the verdict the directory names. Then probes surfaces no vector
// pins: for each vector, deterministic mutations of every member of the first
// checkpoint, record, executor entry, witness statement, head, proof and
// consistency proof (deleted, set to a number, to null, to a list, to an
// object, to a non-BMP string, to a lone surrogate, with a trailing line feed,
// upper-cased, with a leading zero, with a non-ASCII digit), every parameter
// variant (key sets absent, empty or malformed; tolerances on and around the
// boundary; review windows shifted by a microsecond or written in another
// offset), and members reordered (which changes no signed byte).
// Exit 0 only on full agreement.

import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const { verifyComplete } = await import(join(ROOT, 'packages/verify-receipt/dist/complete.js'));
const { verifyWitnessed } = await import(join(ROOT, 'packages/verify-receipt/dist/witnessed.js'));
const PY = join(ROOT, 'packages/verify-receipt-py/src');
const PIN = readFileSync(join(ROOT, 'test-vectors/complete/INDEX.md'), 'utf8').split('Vector issuer key (pin it): `')[1].split('`')[0];
const EXPECT = { pass: 'PASS', fail: 'FAIL', incomplete: 'INCOMPLETE' };

function pyBatch(jobs) {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(PY)})
from aqta_verify_receipt import verify_complete, verify_witnessed
jobs = json.load(sys.stdin)
out = []
for j in jobs:
    p = j["params"]
    if j["profile"] == "complete":
        r = verify_complete(j["bundle"], trusted_public_key=j["pin"], review_from=p.get("review_from"),
                            review_to=p.get("review_to"), executor_keys=p.get("executor_keys"))
    else:
        kw = {"tolerance_seconds": p["tolerance_seconds"]} if "tolerance_seconds" in p else {}
        r = verify_witnessed(j["bundle"], trusted_public_key=j["pin"], witness_keys=p.get("witness_keys"), **kw)
    out.append({"verdict": r.verdict, "reason": r.reason})
sys.stdout.write(json.dumps(out))
`;
  const out = execFileSync('python3', ['-c', script], { input: JSON.stringify(jobs), maxBuffer: 1 << 30 });
  return JSON.parse(out.toString());
}

function tsRun(j) {
  const p = j.params;
  if (j.profile === 'complete') {
    return verifyComplete(j.bundle, { trustedPublicKey: j.pin ?? undefined, reviewFrom: p.review_from ?? undefined,
      reviewTo: p.review_to ?? undefined, executorKeys: p.executor_keys });
  }
  const opts = { trustedPublicKey: j.pin ?? undefined, witnessKeys: p.witness_keys };
  if ('tolerance_seconds' in p) opts.toleranceSeconds = p.tolerance_seconds;
  return verifyWitnessed(j.bundle, opts);
}

const jobs = [];
function add(label, profile, bundle, params, expected = null, pin = PIN) {
  jobs.push({ label, profile, bundle, params, pin, expected });
}

const vectors = [];
for (const profile of ['complete', 'witnessed']) {
  for (const kind of Object.keys(EXPECT)) {
    for (const f of readdirSync(join(ROOT, 'test-vectors', profile, kind)).filter((x) => x.endsWith('.json')).sort()) {
      const v = JSON.parse(readFileSync(join(ROOT, 'test-vectors', profile, kind, f), 'utf8'));
      const { bundle, ...params } = v;
      vectors.push([`${profile}/${kind}/${f}`, profile, bundle, params]);
      add(`${profile}/${kind}/${f}`, profile, bundle, params, EXPECT[kind]);
    }
  }
}

const clone = (x) => JSON.parse(JSON.stringify(x));
const ARABIC = '٠١٢٣٤٥٦٧٨٩';
const BAD_VALUES = [
  ['deleted', undefined], ['number', 1], ['null', null], ['list', []], ['object', {}],
  ['non-bmp', '\u{1F600}'], ['lone-surrogate', '\uD800'], ['line-feed', null], ['upper', null],
  ['leading-zero', null], ['arabic-digit', null],
];

function mutateString(name, s) {
  if (typeof s !== 'string') return undefined;
  if (name === 'line-feed') return s + '\n';
  if (name === 'upper') return s.toUpperCase() === s ? undefined : s.toUpperCase();
  if (name === 'leading-zero') return '0' + s;
  if (name === 'arabic-digit') {
    const i = s.search(/[0-9]/);
    return i < 0 ? undefined : s.slice(0, i) + ARABIC[Number(s[i])] + s.slice(i + 1);
  }
  return undefined;
}

function shiftMicro(ts, delta) {
  // ts like 2026-10-20T10:00:00.000000+00:00 -> one microsecond either side
  const m = /^(.*\.)(\d{6})(\+00:00)$/.exec(ts);
  if (!m) return null;
  const n = Number(m[2]) + delta;
  if (n < 0 || n > 999999) return null;
  return `${m[1]}${String(n).padStart(6, '0')}${m[3]}`;
}

function inOffset(ts) {
  const m = /^2026-10-20T(\d{2})(:.*)\+00:00$/.exec(ts);
  if (!m) return null;
  const h = Number(m[1]) + 1;
  return h > 23 ? null : `2026-10-20T${String(h).padStart(2, '0')}${m[2]}+01:00`;
}

const targets = {
  complete: [['checkpoints', (b) => b.checkpoints[0]], ['records', (b) => b.records[0]?.record],
    ['records', (b) => b.records[0]], ['executions', (b) => b.executions[0]]],
  witnessed: [['witnessed', (b) => b.witnessed[0]], ['head', (b) => b.head], ['records', (b) => b.records[0]?.record],
    ['records', (b) => b.records[0]?.proof], ['records', (b) => b.records[0]], ['consistency', (b) => b.consistency[0]]],
};
const paths = {
  complete: ['checkpoints[0]', 'records[0].record', 'records[0]', 'executions[0]'],
  witnessed: ['witnessed[0]', 'head', 'records[0].record', 'records[0].proof', 'records[0]', 'consistency[0]'],
};

for (const [label, profile, b, params] of vectors) {
  // parameter variants
  if (profile === 'complete') {
    add(`${label} :: executor set absent`, profile, b, { ...params, executor_keys: null });
    add(`${label} :: executor set empty`, profile, b, { ...params, executor_keys: [] });
    add(`${label} :: executor set malformed`, profile, b, { ...params, executor_keys: ['not-a-key'] });
    add(`${label} :: no review window`, profile, b, { executor_keys: params.executor_keys });
    for (const [w, d] of [['review_from', -1], ['review_from', 1], ['review_to', -1], ['review_to', 1]]) {
      const s = shiftMicro(params[w], d);
      if (s) add(`${label} :: ${w} ${d > 0 ? '+' : '-'}1us`, profile, b, { ...params, [w]: s });
    }
    const f1 = inOffset(params.review_from);
    const t1 = inOffset(params.review_to);
    if (f1 && t1) add(`${label} :: review window in +01:00`, profile, b, { ...params, review_from: f1, review_to: t1 });
  } else {
    add(`${label} :: witness set absent`, profile, b, { ...params, witness_keys: null });
    add(`${label} :: witness set empty`, profile, b, { ...params, witness_keys: [] });
    add(`${label} :: witness set malformed`, profile, b, { ...params, witness_keys: ['not-a-key'] });
    const { tolerance_seconds: _t, ...noTol } = params;
    add(`${label} :: tolerance default`, profile, b, noTol);
    for (const t of [0, 1, 59, 3599, 3601, 7200, 86400, -1, 1.5, '3600', null, 2 ** 53]) {
      add(`${label} :: tolerance ${JSON.stringify(t)}`, profile, b, { ...params, tolerance_seconds: t });
    }
  }
  add(`${label} :: no pinned key`, profile, b, params, null, null);
  // members reordered: no signed byte changes, so the verdict must not either
  if (b && typeof b === 'object' && !Array.isArray(b)) {
    const rev = (o) => (o && typeof o === 'object' && !Array.isArray(o) ? Object.fromEntries(Object.entries(o).reverse()) : o);
    const r = rev(clone(b));
    for (const k of Object.keys(r)) if (Array.isArray(r[k])) r[k] = r[k].map(rev);
    add(`${label} :: members reordered`, profile, r, params);
  }
  // per-member mutations
  targets[profile].forEach(([coll, pick], ti) => {
    if (!b || typeof b !== 'object') return;
    if (coll !== 'head' && (!Array.isArray(b[coll]) || b[coll].length === 0)) return;
    const target = pick(b);
    if (!target || typeof target !== 'object' || Array.isArray(target)) return;
    for (const key of Object.keys(target)) {
      for (const [name, val] of BAD_VALUES) {
        const m = clone(b);
        const t = pick(m);
        if (name === 'deleted') delete t[key];
        else if (val === null && name !== 'null') {
          const s = mutateString(name, t[key]);
          if (s === undefined) continue;
          t[key] = s;
        } else t[key] = val;
        add(`${label} :: ${paths[profile][ti]}.${key} ${name}`, profile, m, params);
      }
    }
  });
}

const py = pyBatch(jobs.map(({ profile, bundle, params, pin }) => ({ profile, bundle, params, pin })));
let divergences = 0;
let wrong = 0;
const counts = { PASS: 0, FAIL: 0, INCOMPLETE: 0 };
jobs.forEach((j, i) => {
  const ts = tsRun(j);
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
console.log(clean ? 'E79 SWEEP CLEAN: both implementations agree on verdict and reason, and every vector is correct'
  : `${divergences} DIVERGENCES, ${wrong} WRONG VERDICTS`);
process.exit(clean ? 0 : 1);
