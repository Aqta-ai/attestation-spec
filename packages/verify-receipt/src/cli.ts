#!/usr/bin/env node
/**
 * aqta-verify-receipt CLI.
 *
 * Offline check of an ATTESTATION-v1 receipt. No account. No network by
 * default. Exit 0 if the signature verifies, 1 if not, 2 on usage/IO errors.
 *
 *   npx aqta-verify-receipt receipt.json --key <base64url-ed25519-key>
 *   curl -sS https://api.aqta.ai/r/REC_ID | npx aqta-verify-receipt - --key <key>
 *   npx aqta-verify-receipt receipt.json --integrity-only
 */
import { readFileSync } from 'fs';
import { verifyReceipt, AttestationReceipt } from './index';

const PUB_KEY_HINT =
  'https://api.aqta.ai/v1/attestation/public-key';

/**
 * Human-facing stamp on stderr, TTY only, so piped runs still see exactly the
 * machine line on stdout. A small mark, aligned rows, and a single coloured
 * verdict token: green when the signature holds, red when it does not. No
 * block art, no flood of colour. This is a tool an auditor runs.
 */
function stamp(
  receipt: AttestationReceipt,
  valid: boolean,
  reason: string | undefined,
  trust: string
): void {
  if (!process.stderr.isTTY) return;

  const utf8 = /UTF-?8/i.test(
    process.env.LC_ALL || process.env.LC_CTYPE || process.env.LANG || ''
  );
  const MARK = utf8 ? '•ᴥ•' : 'o.o';
  const DOT = utf8 ? '·' : '-';
  const ELL = utf8 ? '…' : '...';
  const OK = utf8 ? '✓' : '+';
  const NO = utf8 ? '✗' : 'x';

  const ESC = String.fromCharCode(27);
  const colour = process.env.NO_COLOR === undefined;
  const paint = (code: string, s: string): string =>
    colour ? ESC + '[' + code + 'm' + s + ESC + '[0m' : s;
  const dim = (s: string): string => paint('2', s);

  const r = receipt as unknown as Record<string, unknown>;
  const str = (v: unknown): string => (typeof v === 'string' ? v : '?');
  const mid = (v: unknown, head = 8, tail = 6): string => {
    const s = str(v);
    return s.length > head + tail + 1 ? s.slice(0, head) + ELL + s.slice(-tail) : s;
  };
  const policies =
    Array.isArray(r.policy_applied) && r.policy_applied.length
      ? (r.policy_applied as unknown[]).map(str).join(' ' + DOT + ' ')
      : '';

  const rows: Array<[string, string]> = [
    ['outcome', str(r.outcome)],
    ['model', str(r.model)],
  ];
  if (policies) rows.push(['rules', policies]);
  rows.push(['key', trust]);
  rows.push(['request', mid(r.request_hash)]);
  rows.push(['id', mid(r.attestation_id, 8, 4)]);

  const out = ['', '  ' + dim(MARK + ' Seal ' + DOT + ' ATTESTATION-v1'), ''];
  for (const [k, v] of rows) out.push('  ' + dim(k.padEnd(8)) + v);
  out.push('');
  out.push(
    valid
      ? '  ' + paint('32', OK + ' sealed') + '   ' + dim('signature valid, checked offline')
      : '  ' + paint('31', NO + ' broken') + '   ' + dim(reason ?? 'signature does not match the key')
  );
  out.push('');
  process.stderr.write(out.join('\n') + '\n');
}

function usage(): never {
  console.error(`aqta-verify-receipt - offline check for ATTESTATION-v1 (Seal)

Usage:
  aqta-verify-receipt <receipt.json | -> --key <base64url> [--no-strict] [-q]
  aqta-verify-receipt <receipt.json | -> --integrity-only [--no-strict] [-q]

Options:
  --key <key>        pin the issuer public key (required for counsel-grade)
  --integrity-only   check signature vs embedded key only (anyone can self-sign)
  --no-strict        allow unknown top-level fields
  -q, --quiet        exit code only

Pin the production key once from ${PUB_KEY_HINT}
(field public_key). Do not re-fetch on every verify.
`);
  process.exit(2);
}

function main(): void {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) usage();

  let file = '';
  let trustedKey: string | undefined;
  let integrityOnly = false;
  let strict = true;
  let quiet = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--key') {
      trustedKey = args[++i];
      if (!trustedKey) usage();
    } else if (a === '--integrity-only') {
      integrityOnly = true;
    } else if (a === '--no-strict') {
      strict = false;
    } else if (a === '--quiet' || a === '-q') {
      quiet = true;
    } else if (!file) {
      file = a;
    } else {
      usage();
    }
  }
  if (!file) usage();
  if (!trustedKey && !integrityOnly) {
    console.error(
      'aqta-verify-receipt: pass --key <pinned> (or --integrity-only for embedded-key checks)'
    );
    process.exit(2);
  }
  if (trustedKey && integrityOnly) {
    console.error('aqta-verify-receipt: use --key or --integrity-only, not both');
    process.exit(2);
  }

  let raw: string;
  try {
    raw = file === '-' ? readFileSync(0, 'utf8') : readFileSync(file, 'utf8');
  } catch {
    console.error(`aqta-verify-receipt: cannot read ${file === '-' ? 'stdin' : file}`);
    process.exit(2);
  }

  let receipt: AttestationReceipt;
  try {
    receipt = JSON.parse(raw);
  } catch {
    console.error('aqta-verify-receipt: input is not valid JSON');
    process.exit(2);
  }

  const result = verifyReceipt(receipt, {
    trustedPublicKey: trustedKey,
    allowUntrustedEmbeddedKey: integrityOnly,
    strictFields: strict,
  });

  if (!quiet) {
    const trust =
      result.keySource === 'pinned'
        ? 'pinned key'
        : 'untrusted embedded key (integrity only)';
    stamp(receipt, result.valid, result.reason, trust);

    // One machine-readable line, emitted only when stdout is not a terminal,
    // so an interactive run shows just the stamp and `... | tool` still parses.
    if (!process.stdout.isTTY) {
      const id = typeof receipt.attestation_id === 'string' ? receipt.attestation_id : '?';
      const outcome = typeof receipt.outcome === 'string' ? receipt.outcome : '?';
      if (result.valid) {
        console.log(`ok  ${outcome}  ${id}  ${trust}`);
      } else {
        console.log(`fail  ${result.reason ?? 'verification failed'}  ${id}`);
      }
    }
  }
  process.exit(result.valid ? 0 : 1);
}

main();
