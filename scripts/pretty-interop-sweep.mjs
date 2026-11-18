// Cross-implementation sweep for the human-readable output: --pretty and --help.
//
// Runs BOTH reference CLIs as processes on every vector in test-vectors/
// (ATTESTATION-v1 valid and invalid, pinned and --integrity-only; ACTION-v1
// under --profile action-1; ACCEPT-v1 records offered as receipts; chain,
// complete and witnessed bundles with their parameters; the byte-level files),
// in four output modes (a UTF-8 locale; a plain C locale; a UTF-8 locale with
// --ascii; a UTF-8 locale with NO_UNICODE set), and requires:
//
//   - the same card, byte for byte, and the same exit code from both;
//   - the first --pretty line equal to that CLI's own default compact line,
//     so `head -1` keeps working and --pretty never changes the verdict;
//   - the same exit code with and without --pretty;
//   - no line wider than 78 columns and no ANSI escape when piped;
//   - pure ASCII output in the three fallback modes;
//   - the block-letter header in UTF-8 mode, the plain ASCII letters in the
//     fallback modes, and in no mode the old emblem.
//
// The compact line itself is compared with each CLI's own default output, not
// across implementations: on ACTION-v1 records the TypeScript line names the
// profile and the Python line does not, and that line is frozen. The card
// carries the library's reason string, which also differs on a few inputs
// (Python quotes an invalid outcome and writes True for a boolean version;
// ACCEPT-v1 records are not a CLI format and fail on different missing
// fields). Where --json shows the two libraries giving different reasons, the
// cards must still match once their Reason rows are set aside; anywhere else
// they must match outright, so the card adds no divergence of its own.
//
// Then the same for --help (TypeScript writes it to stderr with exit 2, Python
// to stdout with exit 0, as before; the text must match).
//
//   node scripts/pretty-interop-sweep.mjs
import { execFile } from 'node:child_process';
import { readFileSync, readdirSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TV = join(ROOT, 'test-vectors');
const TS_CLI = join(ROOT, 'packages/verify-receipt/dist/cli.js');
const PY_SRC = join(ROOT, 'packages/verify-receipt-py/src');
const PY = process.env.PYTHON || 'python3';

const ATT_KEY = 'alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E';
const ACT_KEY = 'pOaccW6Csyo1POtxjixPH80oux9--YC1tzzaENT4vQ0';
const ACC_KEY = 'j3Mkkm9t2FJCeuFwNfnFLJOQv_iqMit-2jLaiUuV8sE';
const CHAIN_KEY = 'VZh1DjZPXa6voCmlv7MU7APjSr-HFxrG2WSqDm-eBGE';
const E79_KEY = readFileSync(join(TV, 'complete/INDEX.md'), 'utf8').split('Vector issuer key (pin it): `')[1].split('`')[0];

const BASE_ENV = Object.fromEntries(
  Object.entries(process.env).filter(([k]) => !['NO_COLOR', 'FORCE_COLOR', 'LC_CTYPE'].includes(k))
);
// PYTHONHASHSEED is fixed because the Python library names the first missing
// field in set order, which otherwise changes from run to run on records with
// several missing fields (the ACCEPT-v1 vectors).
const UTF8_ENV = { ...BASE_ENV, LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8', PYTHONIOENCODING: 'utf-8', PYTHONPATH: PY_SRC, PYTHONHASHSEED: '0' };
delete UTF8_ENV.NO_UNICODE;
// Each mode is an environment plus extra arguments; every mode but utf8 must
// fall back to plain ASCII.
const MODES = {
  utf8: { env: UTF8_ENV, extra: [] },
  ascii: { env: { ...UTF8_ENV, LANG: 'C', LC_ALL: 'C', PYTHONIOENCODING: 'ascii' }, extra: [] },
  'ascii-flag': { env: UTF8_ENV, extra: ['--ascii'] },
  'no-unicode': { env: { ...UTF8_ENV, NO_UNICODE: '1' }, extra: [] },
};
const BLOCK_TOP = '███████╗███████╗ █████╗ ██╗';
const ASCII_TOP = '|____/ \\___|\\__,_|_|';
const EMBLEM = '( <> )';

const TMP = mkdtempSync(join(tmpdir(), 'pretty-sweep-'));
const jsonFiles = (d) => (existsSync(join(TV, d)) ? readdirSync(join(TV, d)).filter((f) => f.endsWith('.json')).sort() : []);

const cases = [];
for (const kind of ['valid', 'invalid']) {
  for (const f of jsonFiles(kind)) {
    const p = join(TV, kind, f);
    cases.push([`${kind}/${f} pinned`, p, ['--key', ATT_KEY]]);
    cases.push([`${kind}/${f} integrity-only`, p, ['--integrity-only']]);
  }
  for (const f of jsonFiles(`action/${kind}`)) {
    const p = join(TV, 'action', kind, f);
    cases.push([`action/${kind}/${f} pinned`, p, ['--profile', 'action-1', '--key', ACT_KEY]]);
    cases.push([`action/${kind}/${f} integrity-only`, p, ['--profile', 'action-1', '--integrity-only']]);
  }
  for (const f of jsonFiles(`acceptance/${kind}`)) {
    cases.push([`acceptance/${kind}/${f}`, join(TV, 'acceptance', kind, f), ['--key', ACC_KEY]]);
  }
}
for (const kind of ['pass', 'fail', 'incomplete']) {
  for (const profile of ['chain', 'complete', 'witnessed']) {
    for (const f of jsonFiles(`${profile}/${kind}`)) {
      const v = JSON.parse(readFileSync(join(TV, profile, kind, f), 'utf8'));
      const bundle = join(TMP, `${profile}-${kind}-${f}`);
      writeFileSync(bundle, JSON.stringify(v.bundle));
      const a = ['--profile', profile, '--key', profile === 'chain' ? CHAIN_KEY : E79_KEY];
      if (profile === 'chain' && v.approver_keys != null) a.push('--approver-keys', v.approver_keys.join(','));
      if (profile === 'complete') {
        if (v.review_from != null) a.push('--review-from', v.review_from);
        if (v.review_to != null) a.push('--review-to', v.review_to);
        if (v.executor_keys != null) a.push('--executor-keys', v.executor_keys.join(','));
      }
      if (profile === 'witnessed') {
        if (v.witness_keys != null) a.push('--witness-keys', v.witness_keys.join(','));
        if (Number.isInteger(v.tolerance_seconds) && v.tolerance_seconds >= 0) a.push('--tolerance', String(v.tolerance_seconds));
      }
      cases.push([`${profile}/${kind}/${f}`, bundle, a]);
    }
  }
}
for (const f of readdirSync(join(TV, 'bytes')).filter((n) => n.endsWith('.bin')).sort()) {
  cases.push([`bytes/${f}`, join(TV, 'bytes', f), ['--key', ATT_KEY]]);
}

function run(cmd, args, env) {
  return new Promise((resolve) => {
    execFile(cmd, args, { env, encoding: 'buffer', maxBuffer: 1 << 24 }, (err, stdout, stderr) => {
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, out: stdout.toString('utf8'), err: stderr.toString('utf8') });
    });
  });
}
const ts = (args, env) => run('node', [TS_CLI, ...args], env);
const py = (args, env) => run(PY, ['-m', 'aqta_verify_receipt', ...args], env);

async function pool(items, n, fn) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  }));
  return results;
}

const cpWidth = (cp) => (cp >= 0x10000 || (cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0xa4cf) ||
  (cp >= 0xac00 && cp <= 0xd7a3) || (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0xfe30 && cp <= 0xfe4f) ||
  (cp >= 0xff00 && cp <= 0xff60) || (cp >= 0xffe0 && cp <= 0xffe6) ? 2 : 1);
const width = (s) => Array.from(s).reduce((w, ch) => w + cpWidth(ch.codePointAt(0)), 0);

const problems = [];
let tolerated = 0;
// Everything after the compact line.
const card = (out) => out.split('\n').slice(1).join('\n');
// The card with its Reason row (and that row's continuation lines) removed.
function withoutReason(text) {
  const out = [];
  let skipping = false;
  for (const line of text.split('\n')) {
    if (line.startsWith('| Reason ')) { skipping = true; continue; }
    if (skipping && /^\| {17}\| /.test(line)) continue;
    skipping = false;
    out.push(line);
  }
  return out.join('\n');
}
function shape(label, envName, text, { card }) {
  const lines = text.replace(/\n$/, '').split('\n');
  // The compact line carries receipt values as before; only the card and the
  // help are held to the width limit.
  for (const l of card ? lines.slice(1) : lines) {
    if (width(l) > 78) problems.push(`${label} [${envName}]: line wider than 78 columns: ${JSON.stringify(l)}`);
  }
  if (text.includes('\x1b')) problems.push(`${label} [${envName}]: ANSI escape on a pipe`);
  if (/[\u2013\u2014]/.test(text)) problems.push(`${label} [${envName}]: en or em dash in output`);
  if (envName !== 'utf8' && /[^\x00-\x7f]/.test(text)) problems.push(`${label} [${envName}]: non-ASCII in a fallback mode`);
  if (text.includes(EMBLEM)) problems.push(`${label} [${envName}]: the old emblem is back`);
  const want = envName === 'utf8' ? BLOCK_TOP : ASCII_TOP;
  const avoid = envName === 'utf8' ? ASCII_TOP : BLOCK_TOP;
  if (!text.includes(want) || text.includes(avoid)) problems.push(`${label} [${envName}]: wrong header for this mode`);
}

const jobs = [];
for (const envName of Object.keys(MODES)) for (const c of cases) jobs.push([envName, ...c]);

let compared = 0;
await pool(jobs, 4, async ([envName, label, file, baseArgs]) => {
  const { env, extra } = MODES[envName];
  const args = [...baseArgs, ...extra];
  const [tsPretty, pyPretty, tsPlain, pyPlain, tsJson, pyJson] = await Promise.all([
    ts([file, ...args, '--pretty'], env), py([file, ...args, '--pretty'], env),
    ts([file, ...args], env), py([file, ...args], env),
    ts([file, ...args, '--json'], env), py([file, ...args, '--json'], env),
  ]);
  compared++;
  const where = `${label} [${envName}]`;
  const reasonOf = (r) => { try { return JSON.parse(r.out).reason ?? null; } catch { return null; } };
  const libraryReasonsDiffer = reasonOf(tsJson) !== reasonOf(pyJson);
  const tsCard = card(tsPretty.out);
  const pyCard = card(pyPretty.out);
  if (tsCard !== pyCard) {
    const same = libraryReasonsDiffer && withoutReason(tsCard) === withoutReason(pyCard);
    if (same) tolerated++;
    else problems.push(`${where}: --pretty card differs\n--- ts\n${tsCard}\n--- py\n${pyCard}`);
  }
  if (tsPretty.code !== pyPretty.code) problems.push(`${where}: --pretty exit ts=${tsPretty.code} py=${pyPretty.code}`);
  for (const [name, pretty, plain] of [['ts', tsPretty, tsPlain], ['py', pyPretty, pyPlain]]) {
    if (pretty.code !== plain.code) problems.push(`${where}: ${name} exit ${plain.code} plain, ${pretty.code} with --pretty`);
    if (plain.out !== '' && pretty.out.split('\n')[0] !== plain.out.split('\n')[0]) {
      problems.push(`${where}: ${name} first --pretty line is not the compact line`);
    }
  }
  if (tsPretty.code !== 2) shape(where, envName, tsPretty.out, { card: true });
});

for (const envName of Object.keys(MODES)) {
  const { env, extra } = MODES[envName];
  const tsHelp = await ts(['--help', ...extra], env);
  const pyHelp = await py(['--help', ...extra], env);
  compared++;
  if (tsHelp.err !== pyHelp.out) problems.push(`--help [${envName}]: text differs\n--- ts\n${tsHelp.err}--- py\n${pyHelp.out}`);
  if (tsHelp.code !== 2 || pyHelp.code !== 0) problems.push(`--help [${envName}]: exit ts=${tsHelp.code} py=${pyHelp.code}`);
  shape('--help', envName, tsHelp.err, { card: false });
}

for (const p of problems) console.log(`  ${p}`);
console.log(`\n${cases.length} vectors x ${Object.keys(MODES).length} output modes, ${compared} comparisons` +
  ` (${tolerated} cards differ only in a Reason row the libraries already word differently)`);
console.log(problems.length === 0
  ? 'PRETTY SWEEP CLEAN: both CLIs print the same --pretty card and --help, byte for byte, apart from the reasons counted above'
  : `${problems.length} PROBLEMS`);
process.exit(problems.length === 0 ? 0 : 1);
