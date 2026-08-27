#!/usr/bin/env node
/**
 * aqta-verify-proof
 *
 * Checks a transparency proof offline. Separate from aqta-verify-receipt
 * because the questions are different: a receipt asks "did the issuer assert
 * this", a proof asks "is this entry in the issuer's log, and has that log
 * only ever grown". Conflating them into one command invites a reader to think
 * a valid signature answered the second question. It does not.
 *
 *   aqta-verify-proof inclusion.json
 *   aqta-verify-proof consistency.json
 *   aqta-verify-proof sth.json --key <published key>
 *   curl -s https://api.aqta.ai/v1/public/transparency/proof/<id> | aqta-verify-proof -
 *
 * Exit 0 valid, 1 invalid, 2 usage or IO.
 */
import { readFileSync } from 'fs';
import {
  verifyConsistencyProof,
  verifyInclusionProof,
  verifySignedTreeHead,
} from './transparency.js';

const USAGE = `aqta-verify-proof <file|-> [--key <base64url>] [--json] [-q]

  Detects the document type from its fields:
    audit_path        an RFC 6962 inclusion proof
    consistency_path  an RFC 6962 consistency proof
    signature         a signed tree head, which needs --key

  A proof establishes that what you were shown is in the log. It does not
  establish that what you were not shown is irrelevant.
`;

function main(): void {
  const args = process.argv.slice(2);
  let file = '';
  let key: string | undefined;
  let asJson = false;
  let quiet = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--key') key = args[++i];
    else if (a === '--json') asJson = true;
    else if (a === '-q' || a === '--quiet') quiet = true;
    else if (a === '-h' || a === '--help') {
      process.stdout.write(USAGE);
      process.exit(0);
    } else if (!file) file = a;
    else {
      process.stderr.write(`aqta-verify-proof: unexpected argument ${a}\n`);
      process.exit(2);
    }
  }
  if (!file) {
    process.stderr.write(USAGE);
    process.exit(2);
  }

  let raw: string;
  try {
    raw = file === '-' ? readFileSync(0, 'utf8') : readFileSync(file, 'utf8');
  } catch {
    process.stderr.write(`aqta-verify-proof: cannot read ${file === '-' ? 'stdin' : file}\n`);
    process.exit(2);
  }

  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(raw);
  } catch {
    process.stderr.write('aqta-verify-proof: input is not valid JSON\n');
    process.exit(2);
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    process.stderr.write('aqta-verify-proof: input must be a JSON object\n');
    process.exit(2);
  }

  // Some endpoints wrap the proof in an envelope; accept either shape.
  const inner = (doc.proof ?? doc.inclusion_proof ?? doc.consistency_proof ?? doc) as Record<string, unknown>;

  let kind: string;
  let result: { valid: boolean; reason?: string };

  if ('audit_path' in inner) {
    kind = 'inclusion proof';
    result = verifyInclusionProof(inner);
  } else if ('consistency_path' in inner) {
    kind = 'consistency proof';
    result = verifyConsistencyProof(inner);
  } else if ('signature' in inner && 'root_hash' in inner) {
    kind = 'signed tree head';
    if (!key) {
      process.stderr.write('aqta-verify-proof: a signed tree head needs --key <published key>\n');
      process.exit(2);
    }
    result = verifySignedTreeHead(inner, key);
  } else {
    process.stderr.write(
      'aqta-verify-proof: unrecognised document: expected audit_path, consistency_path, or a signed tree head\n'
    );
    process.exit(2);
  }

  if (!quiet) {
    if (asJson) {
      process.stdout.write(
        JSON.stringify({
          valid: result.valid,
          kind,
          reason: result.valid ? null : result.reason ?? 'verification failed',
        }) + '\n'
      );
    } else {
      const mark = result.valid ? '✓ valid' : '✕ invalid';
      const detail = result.valid ? kind : `${kind}: ${result.reason ?? 'verification failed'}`;
      process.stdout.write(`${mark}  ${detail}\n`);
    }
  }
  process.exit(result.valid ? 0 : 1);
}

main();
