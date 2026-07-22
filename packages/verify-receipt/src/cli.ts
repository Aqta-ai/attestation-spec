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
 * The Seal mark, traced from the brand artwork: head up, snout right,
 * one eye (the notch in the head). Half blocks give twice the vertical
 * resolution per line; plain ASCII is the fallback for non UTF-8 terminals.
 */
const SEAL_BLOCK = [
  '      ▄▄▄▄▄▄',
  '    ▄██████████▄',
  '   ███▀███████████▄',
  '  ██████████████████████▄',
  ' ████████████████████████▙',
  ' █████████████████████████',
  '  ▀███████████████████▛▀▜██',
  '    ▀▀▀████████▀▀▀   ▀▙▄▟▀',
];

const SEAL_ASCII = [
  '      ++++++',
  '    +@@@@@@@@@@+',
  '   @@@o@@@@@@@@@@@@+',
  '  @@@@@@@@@@@@@@@@@@@@@@+',
  ' @@@@@@@@@@@@@@@@@@@@@@@@%',
  ' @@@@@@@@@@@@@@@@@@@@@@@@@',
  '  +@@@@@@@@@@@@@@@@@@@@%+%@@',
  '    +++@@@@@@@@+++   +%+%+',
];

/**
 * Human-facing stamp: an intact seal when the signature verifies, a sheared
 * one when it does not, so the shape carries the answer before the word.
 *
 * stderr only, TTY only, so piped runs still see exactly the verdict line.
 */
function stamp(valid: boolean): void {
  if (!process.stderr.isTTY) return;

  const utf8 = /UTF-?8/i.test(
    process.env.LC_ALL || process.env.LC_CTYPE || process.env.LANG || ''
  );
  const ESC = String.fromCharCode(27);
  const colour = process.env.NO_COLOR === undefined;
  const body = colour ? ESC + '[' + (valid ? '32' : '31') + 'm' : '';
  const off = colour ? ESC + '[0m' : '';

  // A failed check shears the mark along its midline: the seal is broken.
  const base = utf8 ? SEAL_BLOCK : SEAL_ASCII;
  const half = Math.ceil(base.length / 2);
  const art = valid ? base : base.map((l, i) => (i < half ? l : '  ' + l));
  const painted = art.map((l) => body + l + off);
  painted.push(body + (valid ? '   sealed' : '   broken') + off);
  process.stderr.write(painted.join('\n') + '\n');
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
    stamp(result.valid);
    const id = typeof receipt.attestation_id === 'string' ? receipt.attestation_id : '?';
    const outcome = typeof receipt.outcome === 'string' ? receipt.outcome : '?';
    if (result.valid) {
      const trust =
        result.keySource === 'pinned'
          ? 'pinned key'
          : 'untrusted embedded key (integrity only)';
      console.log(`ok  ${outcome}  ${id}  ${trust}`);
    } else {
      console.log(`fail  ${result.reason ?? 'verification failed'}  ${id}`);
    }
  }
  process.exit(result.valid ? 0 : 1);
}

main();
