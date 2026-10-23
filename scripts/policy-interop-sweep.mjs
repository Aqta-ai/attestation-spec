// Cross-implementation interop sweep for the policy profile (spec/POLICY-v1.md; draft).
//
// Runs EVERY vector in test-vectors/policy/{pass,fail,incomplete} through both
// reference verifiers (TypeScript in-process, Python in one subprocess batch)
// and requires the same verdict AND the same reason on every one, and the
// verdict the directory names. Then probes surfaces no vector pins:
//
// - unsigned mutations: every member of the first statement, decision record,
//   proof, item and the head deleted, set to a number, to null, to a list, to
//   an object, to a non-BMP string, to a lone surrogate, with a trailing line
//   feed, upper-cased, with a leading zero, with a non-ASCII digit;
// - re-signed mutations, with the vector issuer key derived from its public
//   seed, so the signature holds and the binding rules themselves are reached:
//   every policy_applied entry with its name or hash altered (upper case,
//   truncated, a line feed, another algorithm, a second '@', a non-BMP name,
//   the binding removed), the list in code-point order, and statements with
//   created_at a microsecond either side of the decision, another
//   organisation, another name, another version;
// - parameters: no pinned key, a malformed key, another key;
// - members reordered (which changes no signed byte).
// Exit 0 only on full agreement.

import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const { verifyPolicy, policyBodyHash } = await import(join(ROOT, 'packages/verify-receipt/dist/policy.js'));
const { _chainInternal } = await import(join(ROOT, 'packages/verify-receipt/dist/chain.js'));
const PY = join(ROOT, 'packages/verify-receipt-py/src');
const PIN = readFileSync(join(ROOT, 'test-vectors/policy/INDEX.md'), 'utf8').split('Vector issuer key (pin it): `')[1].split('`')[0];
const EXPECT = { pass: 'PASS', fail: 'FAIL', incomplete: 'INCOMPLETE' };

// The vector issuer key, from the public seed in scripts/make-policy-vectors.py. A throwaway.
const SEED = createHash('sha256').update('attestation-spec/test-vectors/policy-1/issuer').digest();
const SK = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEED]),
  format: 'der', type: 'pkcs8' });
function resign(rec, changes) {
  const payload = { ...rec, ...changes };
  delete payload.signature;
  const sig = sign(null, Buffer.from(_chainInternal.canonicalBytes(payload)), SK).toString('base64url');
  return { ...payload, signature: sig };
}
if (resign({ v: 'x' }, {}).signature.length !== 86) throw new Error('signing setup');

function pyBatch(jobs) {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(PY)})
from aqta_verify_receipt import verify_policy
jobs = json.load(sys.stdin)
out = []
for j in jobs:
    r = verify_policy(j["bundle"], trusted_public_key=j["pin"])
    out.append({"verdict": r.verdict, "reason": r.reason})
sys.stdout.write(json.dumps(out))
`;
  const out = execFileSync('python3', ['-c', script], { input: JSON.stringify(jobs), maxBuffer: 1 << 30 });
  return JSON.parse(out.toString());
}

const jobs = [];
function add(label, bundle, expected = null, pin = PIN) {
  jobs.push({ label, bundle, pin, expected });
}

const vectors = [];
for (const kind of Object.keys(EXPECT)) {
  for (const f of readdirSync(join(ROOT, 'test-vectors', 'policy', kind)).filter((x) => x.endsWith('.json')).sort()) {
    const { bundle } = JSON.parse(readFileSync(join(ROOT, 'test-vectors', 'policy', kind, f), 'utf8'));
    vectors.push([`policy/${kind}/${f}`, bundle]);
    add(`policy/${kind}/${f}`, bundle, EXPECT[kind]);
  }
}

const clone = (x) => JSON.parse(JSON.stringify(x));
const ARABIC = '٠١٢٣٤٥٦٧٨٩';
const BAD_VALUES = [
  ['deleted', undefined], ['number', 1], ['null', null], ['list', []], ['object', {}],
  ['non-bmp', '\u{1F600}'], ['lone-surrogate', '\uD800'], ['line-feed', null], ['upper', null],
  ['leading-zero', null], ['arabic-digit', null],
];
const utf16Sort = (xs) => [...xs].sort();
const cpSort = (xs) => [...xs].sort((a, b) => {
  const A = [...a].map((c) => c.codePointAt(0));
  const B = [...b].map((c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(A.length, B.length); i++) if (A[i] !== B[i]) return A[i] - B[i];
  return A.length - B.length;
});

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
  const m = /^(.*\.)(\d{6})(\+00:00)$/.exec(ts);
  if (!m) return null;
  const n = Number(m[2]) + delta;
  if (n < 0 || n > 999999) return null;
  return `${m[1]}${String(n).padStart(6, '0')}${m[3]}`;
}

const isObj = (o) => o && typeof o === 'object' && !Array.isArray(o);
const targets = [
  ['head', (b) => b.head], ['policies[0].statement', (b) => b.policies?.[0]?.statement],
  ['policies[0].proof', (b) => b.policies?.[0]?.proof], ['policies[0]', (b) => b.policies?.[0]],
  ['decisions[0].record', (b) => b.decisions?.[0]?.record], ['decisions[0].proof', (b) => b.decisions?.[0]?.proof],
  ['decisions[0]', (b) => b.decisions?.[0]],
];

// Strip the log evidence so a re-signed record reaches the binding rules (its leaf, and so its proof, changed).
function unlogged(b) {
  const m = clone(b);
  m.head = null;
  for (const k of ['policies', 'decisions']) if (Array.isArray(m[k])) for (const it of m[k]) if (isObj(it)) it.proof = null;
  return m;
}

function bindingVariants(entry) {
  const at = entry.indexOf('@sha256:');
  if (at < 0) {
    return [['bound to a made-up hash', `${entry}@sha256:${'0'.repeat(64)}`], ['with a line feed', `${entry}\n`]];
  }
  const name = entry.slice(0, at);
  const h = entry.slice(at + 8);
  return [
    ['hash upper', `${name}@sha256:${h.toUpperCase()}`], ['hash truncated', `${name}@sha256:${h.slice(0, 63)}`],
    ['hash extended', `${name}@sha256:${h}0`], ['hash line feed', `${name}@sha256:${h}\n`],
    ['sha512 tag', `${name}@sha512:${h}`], ['second at', `${name}@x@sha256:${h}`], ['empty name', `@sha256:${h}`],
    ['name non-bmp', `${name}\u{1F600}@sha256:${h}`], ['name upper', `${name.toUpperCase()}@sha256:${h}`],
    ['unbound', name], ['hash of nothing', `${name}@sha256:${createHash('sha256').digest('hex')}`],
    ['arabic digit', `${name}@sha256:${h.replace(/[0-9]/, (d) => ARABIC[Number(d)])}`],
  ];
}

for (const [label, b] of vectors) {
  add(`${label} :: no pinned key`, b, null, null);
  add(`${label} :: malformed pinned key`, b, null, 'not-a-key');
  add(`${label} :: another pinned key`, b, null, 'yV38x5N4n1PvEq7F8dcmoYtfhu4S_8qI9p8e2cRYJeA');
  add(`${label} :: unlogged`, unlogged(b));
  if (isObj(b)) {
    const rev = (o) => (isObj(o) ? Object.fromEntries(Object.entries(o).reverse()) : o);
    const r = rev(clone(b));
    for (const k of Object.keys(r)) if (Array.isArray(r[k])) r[k] = r[k].map((it) => (isObj(it) ? Object.fromEntries(Object.entries(rev(it)).map(([kk, vv]) => [kk, rev(vv)])) : it));
    add(`${label} :: members reordered`, r);
  }
  // unsigned per-member mutations
  for (const [path, pick] of targets) {
    if (!isObj(b)) continue;
    const target = pick(b);
    if (!isObj(target)) continue;
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
        add(`${label} :: ${path}.${key} ${name}`, m);
      }
    }
  }
  // re-signed decision mutations: the binding rules themselves
  const decs = isObj(b) && Array.isArray(b.decisions) ? b.decisions : [];
  decs.forEach((it, di) => {
    const rec = isObj(it) ? it.record : null;
    if (!isObj(rec) || !Array.isArray(rec.policy_applied) || typeof rec.signature !== 'string') return;
    const base = unlogged(b);
    rec.policy_applied.forEach((entry, j) => {
      if (typeof entry !== 'string') return;
      for (const [vname, v] of bindingVariants(entry)) {
        const m = clone(base);
        const list = [...rec.policy_applied];
        list[j] = v;
        m.decisions[di].record = resign(rec, { policy_applied: utf16Sort(list) });
        add(`${label} :: decisions[${di}].policy_applied[${j}] ${vname} (re-signed)`, m);
      }
    });
    if (rec.policy_applied.length > 1) {
      const m = clone(base);
      m.decisions[di].record = resign(rec, { policy_applied: cpSort(rec.policy_applied) });
      add(`${label} :: decisions[${di}] code-point order (re-signed)`, m);
      const m2 = clone(base);
      m2.decisions[di].record = resign(rec, { policy_applied: [...rec.policy_applied].reverse() });
      add(`${label} :: decisions[${di}] reversed (re-signed)`, m2);
    }
    for (const d of [-1, 1]) {
      const s = shiftMicro(rec.timestamp, d);
      if (!s) continue;
      const m = clone(base);
      m.decisions[di].record = resign(rec, { timestamp: s });
      add(`${label} :: decisions[${di}].timestamp ${d > 0 ? '+' : '-'}1us (re-signed)`, m);
    }
  });
  // re-signed statement mutations
  const pols = isObj(b) && Array.isArray(b.policies) ? b.policies : [];
  pols.forEach((it, pi) => {
    const st = isObj(it) ? it.statement : null;
    if (!isObj(st) || typeof st.signature !== 'string' || typeof st.rules !== 'string') return;
    const base = unlogged(b);
    const rehash = (o) => ({ ...o, policy_hash: policyBodyHash(o.org_id, o.policy_name, o.rules) });
    const variants = [
      ['created_at +1us', { created_at: shiftMicro(st.created_at, 1) }],
      ['created_at -1us', { created_at: shiftMicro(st.created_at, -1) }],
      ['created_at at a decision', { created_at: decs[0]?.record?.timestamp }],
      ['created_at a microsecond after a decision', { created_at: shiftMicro(decs[0]?.record?.timestamp ?? '', 1) }],
      ['another organisation, rehashed', rehash({ ...st, org_id: 'org-elsewhere' })],
      ['another name, rehashed', rehash({ ...st, policy_name: `${st.policy_name}_x` })],
      ['non-bmp name, rehashed', rehash({ ...st, policy_name: `${st.policy_name}\u{1F600}` })],
      ['rules edited, rehashed', rehash({ ...st, rules: `${st.rules} ` })],
      ['rules edited, hash kept', { rules: `${st.rules} ` }],
      ['version bumped', { version: String(Number(st.version) + 1), prev_policy_hash: st.prev_policy_hash || st.policy_hash }],
      ['version 2^53', { version: '9007199254740992', prev_policy_hash: st.prev_policy_hash || st.policy_hash }],
      ['version 2^53-1', { version: '9007199254740991', prev_policy_hash: st.prev_policy_hash || st.policy_hash }],
      ['rules empty', rehash({ ...st, rules: '' })],
      ['public key another', { public_key: 'yV38x5N4n1PvEq7F8dcmoYtfhu4S_8qI9p8e2cRYJeA' }],
    ];
    for (const [vname, ch] of variants) {
      if (Object.values(ch).some((x) => x === null || x === undefined)) continue;
      const m = clone(base);
      m.policies[pi].statement = resign(st, ch);
      add(`${label} :: policies[${pi}].statement ${vname} (re-signed)`, m);
    }
  });
}

const py = pyBatch(jobs.map(({ bundle, pin }) => ({ bundle, pin })));
let divergences = 0;
let wrong = 0;
const counts = { PASS: 0, FAIL: 0, INCOMPLETE: 0 };
const reasons = new Set();
jobs.forEach((j, i) => {
  const ts = verifyPolicy(j.bundle, { trustedPublicKey: j.pin ?? undefined });
  const p = py[i];
  counts[ts.verdict]++;
  reasons.add(`${ts.verdict} ${(ts.reason ?? '').replace(/\[\d+\]/g, '[i]')}`);
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
  `${counts.INCOMPLETE} INCOMPLETE), ${reasons.size} distinct verdict-reason pairs reached`);
if (process.env.POLICY_SWEEP_REASONS) for (const r of [...reasons].sort()) console.log(`  reason ${r}`);
const clean = divergences === 0 && wrong === 0;
console.log(clean ? 'POLICY SWEEP CLEAN: both implementations agree on verdict and reason, and every vector is correct'
  : `${divergences} DIVERGENCES, ${wrong} WRONG VERDICTS`);
process.exit(clean ? 0 : 1);
