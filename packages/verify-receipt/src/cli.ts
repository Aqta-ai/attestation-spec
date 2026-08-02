#!/usr/bin/env node
/**
 * aqta-verify-receipt CLI.
 *
 * Offline check of an ATTESTATION-v1 receipt. No account. No network by
 * default. Exit 0 if the signature verifies, 1 if not, 2 on usage/IO errors.
 *
 * Default output is one compact, scriptable line on stdout. Colour is
 * presentation only (NO_COLOR / non-TTY disables it). --pretty adds a short
 * human flourish; it is never the verification contract.
 *
 *   npx aqta-verify-receipt receipt.json --key <base64url-ed25519-key>
 *   curl -sS https://api.aqta.ai/r/REC_ID | npx aqta-verify-receipt - --key <key>
 *   npx aqta-verify-receipt receipt.json --key <key> --json
 *   npx aqta-verify-receipt receipt.json --key <key> --pretty
 */
import { readFileSync } from 'fs';
import { verifyReceipt, AttestationReceipt } from './index';

const PUB_KEY_HINT = 'https://api.aqta.ai/v1/attestation/public-key';

function useUtf8(): boolean {
  return /UTF-?8/i.test(
    process.env.LC_ALL || process.env.LC_CTYPE || process.env.LANG || ''
  );
}

function useColour(): boolean {
  return (
    process.stdout.isTTY === true &&
    process.env.NO_COLOR === undefined &&
    process.env.TERM !== 'dumb'
  );
}

function paint(code: string, s: string): string {
  if (!useColour()) return s;
  return `\x1b[${code}m${s}\x1b[0m`;
}

function mid(s: string, head = 4, tail = 6): string {
  const ell = useUtf8() ? '…' : '...';
  return s.length > head + tail + 1 ? `${s.slice(0, head)}${ell}${s.slice(-tail)}` : s;
}

function usage(): never {
  process.stderr.write(`aqta-verify-receipt - offline check for ATTESTATION-v1 (Seal)

Usage:
  aqta-verify-receipt <receipt.json | -> --key <base64url> [options]
  aqta-verify-receipt <receipt.json | -> --integrity-only [options]

Options:
  --key <key>        pin the issuer public key (required for counsel-grade)
  --integrity-only   check signature vs embedded key only (anyone can self-sign)
  --no-strict        allow unknown top-level fields
  --json             machine JSON on stdout (one object)
  --pretty           optional human flourish after the compact line
  -q, --quiet        exit code only

Contract:
  exit 0 valid · exit 1 invalid · exit 2 usage/IO
  default stdout is one compact line (words carry meaning; colour is optional)
  --pretty never changes the exit code or the verify result

Pin the production key once from ${PUB_KEY_HINT}
(field public_key). Do not re-fetch on every verify.
`);
  process.exit(2);
}

function compactLine(
  valid: boolean,
  outcome: string,
  id: string,
  trustOrReason: string
): string {
  const utf8 = useUtf8();
  const ok = utf8 ? '✓' : '+';
  const no = utf8 ? '✕' : 'x';
  if (valid) {
    return `${paint('32', `${ok} valid`)}  ${outcome}  ${mid(id)}  ${trustOrReason}`;
  }
  return `${paint('31', `${no} invalid`)}  ${trustOrReason}  ${mid(id)}`;
}

function prettyExtra(valid: boolean): string {
  const utf8 = useUtf8();
  const mark = utf8 ? '◈' : '*';
  const dot = utf8 ? '·' : '-';
  if (valid) {
    return `${mark} seal intact ${dot} verified offline`;
  }
  return `${mark} seal broken ${dot} do not trust this receipt`;
}

function main(): void {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) usage();

  let file = '';
  let trustedKey: string | undefined;
  let integrityOnly = false;
  let strict = true;
  let quiet = false;
  let asJson = false;
  let pretty = false;
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
    } else if (a === '--json') {
      asJson = true;
    } else if (a === '--pretty') {
      pretty = true;
    } else if (!file) {
      file = a;
    } else {
      usage();
    }
  }
  if (!file) usage();
  if (!trustedKey && !integrityOnly) {
    process.stderr.write(
      'aqta-verify-receipt: pass --key <pinned> (or --integrity-only for embedded-key checks)\n'
    );
    process.exit(2);
  }
  if (trustedKey && integrityOnly) {
    process.stderr.write('aqta-verify-receipt: use --key or --integrity-only, not both\n');
    process.exit(2);
  }
  if (quiet && (asJson || pretty)) {
    process.stderr.write('aqta-verify-receipt: -q cannot be combined with --json or --pretty\n');
    process.exit(2);
  }

  let raw: string;
  try {
    raw = file === '-' ? readFileSync(0, 'utf8') : readFileSync(file, 'utf8');
  } catch {
    process.stderr.write(
      `aqta-verify-receipt: cannot read ${file === '-' ? 'stdin' : file}\n`
    );
    process.exit(2);
  }

  let receipt: AttestationReceipt;
  try {
    receipt = JSON.parse(raw);
  } catch {
    process.stderr.write('aqta-verify-receipt: input is not valid JSON\n');
    process.exit(2);
  }

  const result = verifyReceipt(receipt, {
    trustedPublicKey: trustedKey,
    allowUntrustedEmbeddedKey: integrityOnly,
    strictFields: strict,
  });

  const id = typeof receipt.attestation_id === 'string' ? receipt.attestation_id : '?';
  const outcome = typeof receipt.outcome === 'string' ? receipt.outcome : '?';
  const trust =
    result.keySource === 'pinned'
      ? 'pinned issuer key'
      : 'untrusted embedded key (integrity only)';

  if (!quiet) {
    if (asJson) {
      process.stdout.write(
        JSON.stringify({
          valid: result.valid,
          outcome,
          attestation_id: id,
          key_source: result.keySource ?? null,
          reason: result.valid ? null : result.reason ?? 'verification failed',
        }) + '\n'
      );
    } else {
      const detail = result.valid ? trust : result.reason ?? 'verification failed';
      process.stdout.write(compactLine(result.valid, outcome, id, detail) + '\n');
      if (pretty) {
        process.stdout.write(prettyExtra(result.valid) + '\n');
      }
    }
  }
  process.exit(result.valid ? 0 : 1);
}

main();
