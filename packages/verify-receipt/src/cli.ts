#!/usr/bin/env node
/**
 * aqta-verify-receipt CLI. Free for everyone, by design: verification must
 * never require an account. Reads a receipt JSON file (or stdin), verifies
 * offline, exits 0 on valid and 1 otherwise.
 *
 *   npx aqta-verify-receipt receipt.json
 *   npx aqta-verify-receipt receipt.json --key <base64url-ed25519-key>
 *   cat receipt.json | npx aqta-verify-receipt -
 */
import { readFileSync } from 'fs';
import { verifyReceipt, AttestationReceipt } from './index';

function usage(): never {
  console.error('usage: aqta-verify-receipt <receipt.json | -> [--key <trusted-public-key>] [--no-strict] [--quiet]');
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
    if (a === '--key') { trustedKey = args[++i]; if (!trustedKey) usage(); }
    else if (a === '--no-strict') strict = false;
    else if (a === '--quiet' || a === '-q') quiet = true;
    else if (!file) file = a;
    else usage();
  }
  if (!file) usage();

  let raw: string;
  try {
    raw = file === '-' ? readFileSync(0, 'utf8') : readFileSync(file, 'utf8');
  } catch (e) {
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
    trustedPublicKey: trustedKey ?? (receipt as { public_key?: string }).public_key,
    strictFields: strict,
  });

  if (!quiet) {
    if (result.valid) {
      const pinned = trustedKey ? 'pinned key' : 'embedded key (integrity only; pass --key to check identity)';
      console.log(`valid: signature verifies against the ${pinned}`);
    } else {
      console.log(`invalid: ${result.reason ?? 'verification failed'}`);
    }
  }
  process.exit(result.valid ? 0 : 1);
}

main();
