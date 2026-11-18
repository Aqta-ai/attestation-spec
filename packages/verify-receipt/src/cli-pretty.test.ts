/**
 * The --pretty card and --help. Presentation only, so these tests pin what it
 * must never do: change the compact first line or the exit code, overrun an
 * 80-column terminal, emit ANSI on a pipe, or say more than a signature shows.
 * Byte equality with the Python CLI is checked by scripts/pretty-interop-sweep.mjs.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const CLI = join(__dirname, 'cli.js');
const TV = join(__dirname, '..', '..', '..', 'test-vectors');
const KEY = 'alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E';
const UTF8 = { ...process.env, LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8' };
const ASCII = { ...process.env, LANG: 'C', LC_ALL: 'C' };
delete (UTF8 as Record<string, string | undefined>).NO_COLOR;

function cli(args: string[], env = UTF8) {
  const r = spawnSync('node', [CLI, ...args], { env, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

function assertShape(text: string) {
  for (const line of text.split('\n')) assert.ok(Array.from(line).length <= 78, `too wide: ${line}`);
  assert.ok(!text.includes('\x1b'), 'ANSI escape on a pipe');
  assert.ok(!/[\u2013\u2014]/.test(text), 'en or em dash');
}

test('--pretty starts with the default compact line and keeps the exit code', () => {
  for (const [file, args, code] of [
    ['valid/002-blocked.json', ['--key', KEY], 0],
    ['valid/001-allowed.json', ['--integrity-only'], 0],
    ['invalid/002-tampered-outcome.json', ['--key', KEY], 1],
  ] as const) {
    const plain = cli([join(TV, file), ...args]);
    const pretty = cli([join(TV, file), ...args, '--pretty']);
    assert.equal(plain.code, code);
    assert.equal(pretty.code, code);
    assert.equal(plain.out.split('\n').length, 2, 'default output is one line');
    assert.equal(pretty.out.split('\n')[0] + '\n', plain.out);
    assertShape(pretty.out.split('\n').slice(1).join('\n'));
  }
});

test('a pinned valid card says what the signature proves and what it does not', () => {
  const out = cli([join(TV, 'valid/002-blocked.json'), '--key', KEY, '--pretty']).out;
  assert.match(out, /\| Seal receipt +VALID \|/);
  assert.match(out, /\| Decision +\| BLOCKED +\|/);
  assert.match(out, /signed these exact bytes/);
  assert.match(out, /invoice is genuine/);
  assert.match(out, /payment settled/);
  assert.match(out, /issuer is honest/);
  assert.match(out, /offline receipt check · by Aqta/);
});

test('an integrity-only card warns that anyone can self-sign', () => {
  const out = cli([join(TV, 'valid/001-allowed.json'), '--integrity-only', '--pretty']).out;
  assert.match(out, /embedded, untrusted/);
  assert.match(out, /anyone can self-sign/);
});

test('an invalid card says not to rely on the receipt and shows no claimed decision', () => {
  const out = cli([join(TV, 'invalid/002-tampered-outcome.json'), '--key', KEY, '--pretty']).out;
  assert.match(out, /INVALID \|/);
  assert.match(out, /\| Reason +\| signature check failed/);
  assert.match(out, /do not rely on this receipt/);
  assert.doesNotMatch(out, /\| Decision /);
});

test('outside a UTF-8 locale the card and help are plain ASCII', () => {
  const out = cli([join(TV, 'valid/007-non-ascii-policy.json'), '--key', KEY, '--pretty'], ASCII).out;
  assert.ok(/^[\x00-\x7f]*$/.test(out));
  const help = cli(['--help'], ASCII);
  assert.ok(/^[\x00-\x7f]*$/.test(help.err));
});

test('--help keeps every option and the contract, within 78 columns', () => {
  const help = cli(['--help']);
  assert.equal(help.code, 2);
  assert.equal(help.out, '');
  for (const flag of ['--key', '--integrity-only', '--envelope', '--profile', '--approver-keys', '--review-from',
    '--review-to', '--executor-keys', '--witness-keys', '--tolerance', '--no-strict', '--json', '--pretty',
    '-q, --quiet', 'exit 0 valid', '3 INCOMPLETE', 'default stdout is one compact line',
    '--pretty never changes the exit code']) {
    assert.ok(help.err.includes(flag), `help lost ${flag}`);
  }
  assertShape(help.err);
});

test('receipt values cannot inject terminal control sequences into the card', () => {
  const r = spawnSync('node', [CLI, '-', '--integrity-only', '--pretty'], {
    env: UTF8, encoding: 'utf8',
    input: JSON.stringify({ attestation_id: 'x\x1b[2Jy', outcome: 'ALLOWED', timestamp: '\x1b]0;t\x07' }),
  });
  const card = r.stdout.split('\n').slice(1).join('\n');
  assert.ok(!card.includes('\x1b'));
  assert.equal(r.status, 1);
});

const BLOCK_HEADER = [
  '███████╗███████╗ █████╗ ██╗',
  '██╔════╝██╔════╝██╔══██╗██║',
  '███████╗█████╗  ███████║██║',
  '╚════██║██╔══╝  ██╔══██║██║',
  '███████║███████╗██║  ██║███████╗',
  '╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝',
  '  offline receipt check · by Aqta',
].join('\n');
const ASCII_HEADER = [
  ' ____             _',
  '/ ___|  ___  __ _| |',
  '\\___ \\ / _ \\/ _` | |',
  ' ___) |  __/ (_| | |',
  '|____/ \\___|\\__,_|_|',
  'offline receipt check - by Aqta',
].join('\n');

test('UTF-8 output carries the block-letter header and no emblem', () => {
  const out = cli([join(TV, 'valid/002-blocked.json'), '--key', KEY, '--pretty']).out;
  assert.ok(out.includes(`\n\n${BLOCK_HEADER}\n\n.`), 'block header between the compact line and the card');
  assert.ok(!out.includes('( <> )'), 'old emblem');
  const help = cli(['--help']).err;
  assert.ok(help.startsWith(`${BLOCK_HEADER}\n`));
});

test('the block letters are aligned: every glyph column is one cell', () => {
  const rows = BLOCK_HEADER.split('\n').slice(0, 6);
  assert.deepEqual(rows.map((r) => Array.from(r).length), [27, 27, 27, 27, 32, 32]);
  // S, E, A and L are 8 cells each; the shadow row closes every letter.
  assert.equal(rows[5], '╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝');
});

test('--ascii, NO_UNICODE and a C locale fall back to the plain ASCII letters', () => {
  const file = join(TV, 'valid/007-non-ascii-policy.json');
  for (const [args, env] of [
    [['--ascii'], UTF8],
    [[], { ...UTF8, NO_UNICODE: '1' }],
    [[], ASCII],
  ] as const) {
    const r = cli([file, '--key', KEY, '--pretty', ...args], env);
    assert.equal(r.code, 0);
    assert.ok(/^[\x00-\x7f]*$/.test(r.out), 'pure ASCII');
    assert.ok(r.out.includes(`\n\n${ASCII_HEADER}\n\n.`), 'ASCII header');
    assert.ok(!r.out.includes('( <> )'), 'old emblem');
    const help = cli(['--help', ...args], env);
    assert.ok(help.err.startsWith(`${ASCII_HEADER}\n`));
  }
});

test('--ascii never changes the exit code or the verdict', () => {
  for (const [file, code] of [['valid/002-blocked.json', 0], ['invalid/002-tampered-outcome.json', 1]] as const) {
    const plain = cli([join(TV, file), '--key', KEY, '--json']);
    const ascii = cli([join(TV, file), '--key', KEY, '--json', '--ascii']);
    const pretty = cli([join(TV, file), '--key', KEY, '--pretty', '--ascii']);
    assert.equal(plain.code, code);
    assert.equal(ascii.code, code);
    assert.equal(pretty.code, code);
    assert.equal(ascii.out, plain.out);
  }
});
