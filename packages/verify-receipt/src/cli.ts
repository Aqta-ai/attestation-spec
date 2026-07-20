#!/usr/bin/env node
/**
 * aqta-verify-receipt CLI.
 *
 * Offline check of an ATTESTATION-v1 receipt. No account. No network by
 * default. Exit 0 if the signature verifies, 1 if not, 2 on usage/IO errors.
 *
 *   npx aqta-verify-receipt receipt.json
 *   npx aqta-verify-receipt receipt.json --key <base64url-ed25519-key>
 *   curl -sS https://api.aqta.ai/r/REC_ID | npx aqta-verify-receipt -
 */
import { readFileSync } from 'fs';
import { verifyReceipt, AttestationReceipt } from './index';

const PUB_KEY_HINT =
  'https://api.aqta.ai/v1/attestation/public-key';

function usage(): never {
  console.error(`aqta-verify-receipt — offline check for ATTESTATION-v1 (Seal)

Usage:
  aqta-verify-receipt <receipt.json | -> [--key <base64url>] [--no-strict] [-q]

Options:
  --key <key>   pin the issuer public key (recommended for counsel checks)
  --no-strict   allow unknown top-level fields
  -q, --quiet   exit code only

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
  let strict = true;
  let quiet = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--key') {
      trustedKey = args[++i];
      if (!trustedKey) usage();
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
    trustedPublicKey: trustedKey ?? receipt.public_key,
    strictFields: strict,
  });

  if (!quiet) {
    const id = typeof receipt.attestation_id === 'string' ? receipt.attestation_id : '?';
    const outcome = typeof receipt.outcome === 'string' ? receipt.outcome : '?';
    if (result.valid) {
      const trust = trustedKey
        ? 'pinned key'
        : 'embedded key (integrity only; pass --key to bind issuer identity)';
      console.log(`ok  ${outcome}  ${id}  ${trust}`);
    } else {
      console.log(`fail  ${result.reason ?? 'verification failed'}  ${id}`);
    }
  }
  process.exit(result.valid ? 0 : 1);
}

main();
