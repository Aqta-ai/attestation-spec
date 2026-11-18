#!/usr/bin/env node
/**
 * aqta-verify-receipt CLI.
 *
 * Offline check of an ATTESTATION-v1 receipt. No account. No network by
 * default. Exit 0 if the signature verifies, 1 if not, 2 on usage/IO errors.
 *
 * Default output is one compact, scriptable line on stdout. Colour is
 * presentation only (NO_COLOR / non-TTY disables it). --pretty prints that
 * same line first, then a boxed human-readable card; it is never the
 * verification contract.
 *
 *   npx aqta-verify-receipt receipt.json --key <base64url-ed25519-key>
 *   curl -sS https://api.aqta.ai/v1/receipts/REC_ID/public | npx aqta-verify-receipt - --key <key>
 *   npx aqta-verify-receipt receipt.json --key <key> --json
 *   npx aqta-verify-receipt receipt.json --key <key> --pretty
 *   npx aqta-verify-receipt receipt.json --key <key> --pretty --ascii
 */
import { readFileSync } from 'fs';
import { verifyReceipt, AttestationReceipt, EnvelopeFormat } from './index';
import { verifyChain } from './chain';
import { verifyComplete } from './complete';
import { verifyWitnessed } from './witnessed';

const PUB_KEY_HINT = 'https://api.aqta.ai/v1/attestation/public-key';

// --ascii, set from the raw arguments before anything is printed (so it also
// covers --help, which is handled before the arguments are parsed).
let asciiOnly = false;

/**
 * True when output may use characters outside ASCII: a UTF-8 locale, no
 * NO_UNICODE in the environment and no --ascii. Otherwise every mark, the
 * header and the card fall back to plain ASCII.
 */
function useUtf8(): boolean {
  if (asciiOnly || process.env.NO_UNICODE !== undefined) return false;
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

// The header and help text are shared with the Python CLI byte for byte
// (scripts/pretty-interop-sweep.mjs compares them). With UTF-8 output the
// header is block letters; otherwise it is the plain ASCII letters. The middle
// dot falls back to '-' outside UTF-8, as the compact line's marks do.
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
  'offline receipt check · by Aqta',
].join('\n');

function header(): string {
  return useUtf8() ? BLOCK_HEADER : ASCII_HEADER;
}

const HELP = `
Checks Seal records offline: ATTESTATION-v1 receipts for what an AI decided,
ACTION-v1 records for what an agent was allowed to do. No account, no network.

Usage
  aqta-verify-receipt <receipt.json | -> --key <base64url> [options]
  aqta-verify-receipt <receipt.json | -> --integrity-only [options]

Trust
  --key <key>            pin the issuer public key (required unless
                         --integrity-only)
  --integrity-only       check signature vs embedded key only (anyone can
                         self-sign)
  --no-strict            allow unknown top-level fields

Record type
  --envelope <name>      opt in to a non-ATTESTATION-v1 envelope (e.g.
                         anchor-v1); ATTESTATION-v1 rules do not apply to it
  --profile <name>       verify under a named profile: action-1 (ACTION-v1
                         records), chain (GRANT-v1 + USE-v1 + ACTION-v1
                         bundle, draft), complete (records against
                         CHECKPOINT-v1 checkpoints and an EXECUTION-v1 log,
                         draft) or witnessed (records against WITNESS-v1
                         statements, draft); not with --envelope

Profile options
  --approver-keys <k,k>  chain only: approver keys the relying party
                         designates; without it an authorised action is
                         INCOMPLETE, never PASS
  --review-from <t>      complete only: start of the review window (RFC 3339,
                         with an offset)
  --review-to <t>        complete only: end of the review window
  --executor-keys <k,k>  complete only: executor keys the relying party
                         designates
  --witness-keys <k,k>   witnessed only: time-authority keys the relying
                         party designates
  --tolerance <s>        witnessed only: seconds an honest record may lag
                         (default 3600)

Output
  (default)              one compact line on stdout
  --json                 machine JSON on stdout (one object)
  --pretty               the compact line, then a human-readable card
  --ascii                plain ASCII output (also when the terminal is not
                         UTF-8, or NO_UNICODE is set)
  -q, --quiet            exit code only
  -h, --help             this help

Contract
  exit 0 valid · exit 1 invalid · exit 2 usage/IO
  --profile chain|complete|witnessed:
    exit 0 PASS · 1 FAIL · 3 INCOMPLETE · 2 usage/IO
  default stdout is one compact line (words carry meaning; colour is optional)
  --pretty never changes the exit code or the verify result

Pin the production key once from
  ${PUB_KEY_HINT}
(field public_key). Do not re-fetch on every verify.
`;

/** Replace the middle dot when the terminal is not UTF-8, as the marks do. */
function localDots(s: string): string {
  return useUtf8() ? s : s.split('·').join('-');
}

function helpText(): string {
  return localDots(`${header()}\n${HELP}`);
}

function usage(): never {
  process.stderr.write(helpText());
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

/*
 * The --pretty card. Presentation only: it is printed after the compact line,
 * never instead of it, and never changes the exit code or the verify result.
 *
 * Must stay byte-identical to the card in the Python CLI; the comparison runs
 * in scripts/pretty-interop-sweep.mjs over every vector. Widths are counted in
 * code points (wide East Asian and non-BMP characters count as two), so both
 * implementations wrap and pad at the same places. The frame is plain ASCII.
 */
const CARD_WIDTH = 76; // outer width; every line fits an 80-column terminal
const LABEL_WIDTH = 16;
const VALUE_WIDTH = CARD_WIDTH - 4 - LABEL_WIDTH - 3;

const NOT_PROVEN = 'that an invoice is genuine, that a payment settled, or that the issuer is honest.';

type Row = [string, string, boolean?]; // label, value, wrap (else truncate)
type Card = { title: string; verdict: string; colour: string; facts: Row[]; meaning: Row[] };

function cpWidth(cp: number): number {
  if (
    cp >= 0x10000 ||
    (cp >= 0x1100 && cp <= 0x115f) ||
    (cp >= 0x2e80 && cp <= 0xa4cf) ||
    (cp >= 0xac00 && cp <= 0xd7a3) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xfe30 && cp <= 0xfe4f) ||
    (cp >= 0xff00 && cp <= 0xff60) ||
    (cp >= 0xffe0 && cp <= 0xffe6)
  ) {
    return 2;
  }
  return 1;
}

function textWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += cpWidth(ch.codePointAt(0) as number);
  return w;
}

/**
 * Receipt values are untrusted. Control characters (which could move the
 * cursor or recolour the terminal) and lone surrogates become '?', and so does
 * anything outside ASCII when the terminal is not UTF-8.
 */
function safeText(s: string): string {
  const utf8 = useUtf8();
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    const bad =
      cp < 0x20 ||
      (cp >= 0x7f && cp <= 0x9f) ||
      (cp >= 0xd800 && cp <= 0xdfff) ||
      (!utf8 && cp > 0x7e);
    out += bad ? '?' : ch;
  }
  return out;
}

function fitText(s: string, width: number): string {
  if (textWidth(s) <= width) return s;
  const ell = useUtf8() ? '…' : '...';
  const room = width - textWidth(ell);
  let out = '';
  let w = 0;
  for (const ch of s) {
    const cw = cpWidth(ch.codePointAt(0) as number);
    if (w + cw > room) break;
    out += ch;
    w += cw;
  }
  return out + ell;
}

function wrapText(s: string, width: number): string[] {
  const lines: string[] = [];
  let line = '';
  for (let word of s.split(' ').filter((x) => x !== '')) {
    while (textWidth(word) > width) {
      if (line !== '') {
        lines.push(line);
        line = '';
      }
      let head = '';
      let w = 0;
      const chars = Array.from(word);
      let i = 0;
      while (i < chars.length && w + cpWidth(chars[i].codePointAt(0) as number) <= width) {
        w += cpWidth(chars[i].codePointAt(0) as number);
        head += chars[i];
        i += 1;
      }
      lines.push(head);
      word = chars.slice(i).join('');
    }
    if (word === '') continue;
    if (line === '') line = word;
    else if (textWidth(line) + 1 + textWidth(word) <= width) line += ' ' + word;
    else {
      lines.push(line);
      line = word;
    }
  }
  if (line !== '' || lines.length === 0) lines.push(line);
  return lines;
}

function pad(s: string, width: number): string {
  return s + ' '.repeat(Math.max(0, width - textWidth(s)));
}

function cardRows(rows: Row[]): string[] {
  const out: string[] = [];
  for (const [label, value, wrap] of rows) {
    const text = safeText(value);
    const parts = wrap ? wrapText(text, VALUE_WIDTH) : [fitText(text, VALUE_WIDTH)];
    parts.forEach((part, i) => {
      out.push(`| ${pad(i === 0 ? label : '', LABEL_WIDTH)} | ${pad(part, VALUE_WIDTH)} |`);
    });
  }
  return out;
}

function renderCard(card: Card): string {
  const dash = '-'.repeat(CARD_WIDTH - 2);
  const inner = CARD_WIDTH - 4;
  const gap = ' '.repeat(Math.max(1, inner - textWidth(card.title) - textWidth(card.verdict)));
  const lines = [
    '',
    header(),
    '',
    `.${dash}.`,
    `| ${card.title}${gap}${paint(card.colour, card.verdict)} |`,
    `|${dash}|`,
    ...cardRows(card.facts),
    `|${dash}|`,
    ...cardRows(card.meaning),
    `'${dash}'`,
  ];
  return localDots(lines.join('\n'));
}

function keyCount(keys: string[] | null): string {
  if (keys === null || keys.length === 0) return 'none given';
  return keys.length === 1 ? '1 designated' : `${keys.length} designated`;
}

/** Card for an ATTESTATION-v1 receipt or an ACTION-v1 record. */
function recordCard(
  receipt: Record<string, unknown>,
  valid: boolean,
  keySource: string | undefined,
  reason: string,
  format: string,
  trustedKey: string | undefined
): string {
  const str = (v: unknown): string => (typeof v === 'string' ? v : '?');
  const isAction = format === 'ACTION-v1';
  const id = str(isAction ? receipt.action_id : receipt.attestation_id);
  const keyRow: Row = trustedKey !== undefined
    ? ['Issuer key', `${mid(trustedKey)} (pinned)`]
    : ['Issuer key', `${mid(str(receipt.public_key))} (embedded, untrusted)`];
  if (!valid) {
    return renderCard({
      title: isAction ? 'Seal action record' : 'Seal receipt',
      verdict: 'INVALID',
      colour: '31',
      facts: [['Reason', reason, true], ['Record', mid(id)], ['Format', format], ['Checked against', keyRow[1]]],
      meaning: [
        ['What this means', 'seal broken: do not rely on this receipt. These bytes are not what the issuer signed.', true],
      ],
    });
  }
  const facts: Row[] = [['Decision', str(receipt.outcome)]];
  if (isAction) facts.push(['Tool', str(receipt.tool)]);
  facts.push(['Issued', str(receipt.timestamp)], keyRow, ['Record', mid(id)], ['Format', format]);
  const limits = isAction ? NOT_PROVEN : `which model actually ran, ${NOT_PROVEN}`;
  const meaning: Row[] = keySource === 'pinned'
    ? [
        ['What this proves', 'seal intact: the issuer signed these exact bytes and no one has altered them since. Checked offline, nothing was sent to Aqta.', true],
        ['What it does not', limits, true],
      ]
    : [
        ['What this proves', 'the signature checks out against a key this receipt supplied itself, so the file is only internally consistent.', true],
        ['Warning', 'anyone can self-sign. Pin the issuer key with --key before you rely on it.', true],
        ['What it does not', `who signed it, ${limits}`, true],
      ];
  return renderCard({ title: isAction ? 'Seal action record' : 'Seal receipt', verdict: 'VALID', colour: '32', facts, meaning });
}

/** Card for the chain, complete and witnessed profiles (drafts). */
function profileCard(
  profile: string,
  verdict: string,
  reason: string | null,
  trustedKey: string | undefined,
  extraRows: Row[]
): string {
  const facts: Row[] = [['Profile', `${profile} (draft)`], ['Issuer key', `${mid(trustedKey ?? '?')} (pinned)`], ...extraRows];
  if (reason) facts.push(['Reason', reason, true]);
  const meaning: Row[] =
    verdict === 'PASS'
      ? [['What this proves', 'every check this draft profile defines passed against the pinned issuer key, offline.', true]]
      : verdict === 'FAIL'
        ? [['What this means', 'a check failed: do not rely on this bundle.', true]]
        : [['What this means', 'the bundle could not be fully checked. INCOMPLETE is never a pass.', true]];
  meaning.push(['What it does not', NOT_PROVEN, true]);
  const colour = verdict === 'PASS' ? '32' : verdict === 'FAIL' ? '31' : '33';
  return renderCard({ title: `Seal ${profile} bundle`, verdict, colour, facts, meaning });
}

function main(): void {
  const args = process.argv.slice(2);
  asciiOnly = args.includes('--ascii');
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) usage();

  let file = '';
  let trustedKey: string | undefined;
  let integrityOnly = false;
  let envelope: EnvelopeFormat | undefined;
  let profile: string | undefined;
  let strict = true;
  let quiet = false;
  let asJson = false;
  let pretty = false;
  let approverKeys: string | undefined;
  const extra: Record<string, string | undefined> = {};
  const EXTRA_FLAGS: Record<string, string> = {
    '--review-from': 'complete', '--review-to': 'complete', '--executor-keys': 'complete',
    '--witness-keys': 'witnessed', '--tolerance': 'witnessed',
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--key') {
      trustedKey = args[++i];
      if (!trustedKey) usage();
    } else if (a === '--integrity-only') {
      integrityOnly = true;
    } else if (a === '--envelope') {
      envelope = args[++i] as EnvelopeFormat;
      if (!envelope) usage();
    } else if (a === '--profile') {
      profile = args[++i];
      if (!profile) usage();
    } else if (a in EXTRA_FLAGS) {
      extra[a] = args[++i];
      if (extra[a] === undefined) usage();
    } else if (a === '--approver-keys') {
      approverKeys = args[++i];
      if (approverKeys === undefined) usage();
    } else if (a === '--no-strict') {
      strict = false;
    } else if (a === '--quiet' || a === '-q') {
      quiet = true;
    } else if (a === '--json') {
      asJson = true;
    } else if (a === '--pretty') {
      pretty = true;
    } else if (a === '--ascii') {
      // read before parsing, see asciiOnly
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
  // The flag takes the wire tag ("action-1"), the library takes the profile
  // name ("ACTION-v1"); the mapping is fixed here and nowhere else.
  if (profile !== undefined && !['action-1', 'chain', 'complete', 'witnessed'].includes(profile)) {
    process.stderr.write(`aqta-verify-receipt: unknown profile ${profile} (only: action-1, chain, complete, witnessed)\n`);
    process.exit(2);
  }
  for (const [flag, owner] of Object.entries(EXTRA_FLAGS)) {
    if (extra[flag] !== undefined && profile !== owner) {
      process.stderr.write(`aqta-verify-receipt: ${flag} applies only to --profile ${owner}\n`);
      process.exit(2);
    }
  }
  const draftProfile = profile === 'complete' || profile === 'witnessed';
  if (draftProfile && (integrityOnly || !strict)) {
    process.stderr.write(`aqta-verify-receipt: --profile ${profile} needs --key and takes no --integrity-only or --no-strict\n`);
    process.exit(2);
  }
  const chainProfile = profile === 'chain';
  if (approverKeys !== undefined && !chainProfile) {
    process.stderr.write('aqta-verify-receipt: --approver-keys applies only to --profile chain\n');
    process.exit(2);
  }
  if (chainProfile && (integrityOnly || !strict)) {
    process.stderr.write('aqta-verify-receipt: --profile chain needs --key and takes no --integrity-only or --no-strict\n');
    process.exit(2);
  }
  if (profile !== undefined && envelope !== undefined) {
    process.stderr.write('aqta-verify-receipt: use --profile or --envelope, not both\n');
    process.exit(2);
  }
  if (quiet && (asJson || pretty)) {
    process.stderr.write('aqta-verify-receipt: -q cannot be combined with --json or --pretty\n');
    process.exit(2);
  }

  let raw: string;
  try {
    // Bytes first, then a fatal decoder. readFileSync(…, 'utf8') replaced invalid
    // sequences with U+FFFD, so a file that was never signed could decode back onto
    // the signed payload and verify. ignoreBOM keeps a BOM in the text so JSON.parse
    // rejects it, as Python does. Reported under the bounty, 12 September 2026.
    const bytes = file === '-' ? readFileSync(0) : readFileSync(file);
    raw = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch (err) {
    if (err instanceof TypeError) {
      process.stderr.write(`aqta-verify-receipt: cannot read ${file === '-' ? 'stdin' : file}: not valid UTF-8\n`);
      process.exit(2);
    }
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

  // Bare `null` parses fine and then crashed the display code below with an
  // uncaught TypeError and a Node stack trace, including on the documented
  // `curl ... | aqta-verify-receipt -` path. Matches the Python message and
  // exit code.
  if (typeof receipt !== 'object' || receipt === null || Array.isArray(receipt)) {
    process.stderr.write('aqta-verify-receipt: receipt must be a JSON object\n');
    process.exit(2);
  }

  // ATTESTATION-v1 canonicalises a parsed object, so a receipt carrying the same
  // member name twice has no single canonical payload: a parser keeping the first
  // value and one keeping the last compute different signed bytes from identical
  // input. RFC 8259 leaves that choice to the implementation, so the format
  // rejects the receipt. JSON.parse silently keeps the last value, so the check
  // has to run over the raw text.
  const duplicate = findDuplicateMemberName(raw);
  if (duplicate !== null) {
    process.stderr.write(
      `aqta-verify-receipt: duplicate member name: ${duplicate}\n`
    );
    process.exit(2);
  }

  if (draftProfile) {
    const keys = (v: string | undefined) => (v === undefined ? null : v.split(',').map((k) => k.trim()).filter((k) => k !== ''));
    let res;
    if (profile === 'complete') {
      res = verifyComplete(receipt, { trustedPublicKey: trustedKey, reviewFrom: extra['--review-from'],
        reviewTo: extra['--review-to'], executorKeys: keys(extra['--executor-keys']) });
    } else {
      const tol = extra['--tolerance'];
      if (tol !== undefined && !/^[0-9]+$/.test(tol)) {
        process.stderr.write('aqta-verify-receipt: --tolerance takes whole seconds\n');
        process.exit(2);
      }
      res = verifyWitnessed(receipt, { trustedPublicKey: trustedKey, witnessKeys: keys(extra['--witness-keys']),
        ...(tol === undefined ? {} : { toleranceSeconds: Number(tol) }) });
    }
    if (!quiet) {
      if (asJson) {
        process.stdout.write(JSON.stringify({ verdict: res.verdict, profile, reason: res.reason }) + '\n');
      } else {
        process.stdout.write(`${res.verdict} ${profile}` + (res.reason ? ` (${res.reason})` : ', pinned issuer key') + '\n');
        if (pretty) {
          const rows: Row[] = profile === 'complete'
            ? [
                ['Review window', `${extra['--review-from'] ?? 'not given'} to ${extra['--review-to'] ?? 'not given'}`, true],
                ['Executor keys', keyCount(keys(extra['--executor-keys']))],
              ]
            : [
                ['Witness keys', keyCount(keys(extra['--witness-keys']))],
                ['Tolerance', extra['--tolerance'] === undefined ? '3600 seconds (default)' : `${extra['--tolerance']} seconds`],
              ];
          process.stdout.write(profileCard(profile as string, res.verdict, res.reason, trustedKey, rows) + '\n');
        }
      }
    }
    process.exit(res.verdict === 'PASS' ? 0 : res.verdict === 'FAIL' ? 1 : 3);
  }

  if (chainProfile) {
    const approvers = approverKeys === undefined
      ? null
      : approverKeys.split(',').map((k) => k.trim()).filter((k) => k !== '');
    const res = verifyChain(receipt, { trustedPublicKey: trustedKey, approverKeys: approvers });
    if (!quiet) {
      if (asJson) {
        process.stdout.write(JSON.stringify({ verdict: res.verdict, profile: 'chain', reason: res.reason }) + '\n');
      } else {
        process.stdout.write(`${res.verdict} chain` + (res.reason ? ` (${res.reason})` : ', pinned issuer key') + '\n');
        if (pretty) {
          process.stdout.write(profileCard('chain', res.verdict, res.reason, trustedKey, [['Approver keys', keyCount(approvers)]]) + '\n');
        }
      }
    }
    process.exit(res.verdict === 'PASS' ? 0 : res.verdict === 'FAIL' ? 1 : 3);
  }

  const actionProfile = profile === 'action-1';
  const result = verifyReceipt(receipt, {
    trustedPublicKey: trustedKey,
    allowUntrustedEmbeddedKey: integrityOnly,
    envelope,
    strictFields: strict,
    profile: actionProfile ? 'ACTION-v1' : undefined,
  });

  const idField = actionProfile
    ? (receipt as unknown as Record<string, unknown>).action_id
    : receipt.attestation_id;
  const id = typeof idField === 'string' ? idField : '?';
  const outcome = typeof receipt.outcome === 'string' ? receipt.outcome : '?';
  const trust =
    result.keySource === 'pinned'
      ? 'pinned issuer key'
      : 'untrusted embedded key (integrity only)';

  if (!quiet) {
    if (asJson) {
      process.stdout.write(
        JSON.stringify(
          actionProfile
            ? {
                valid: result.valid,
                outcome,
                action_id: id,
                key_source: result.keySource ?? null,
                profile: 'ACTION-v1',
                reason: result.valid ? null : result.reason ?? 'verification failed',
              }
            : {
                valid: result.valid,
                outcome,
                attestation_id: id,
                key_source: result.keySource ?? null,
                envelope: result.envelope ?? null,
                reason: result.valid ? null : result.reason ?? 'verification failed',
              }
        ) + '\n'
      );
    } else {
      let detail = result.valid ? trust : result.reason ?? 'verification failed';
      // Name the profile or envelope when it is not the default, so a valid
      // line never leaves the reader assuming ATTESTATION-v1 rules were
      // applied.
      if (result.valid && actionProfile) {
        detail = `${detail}, profile ACTION-v1`;
      } else if (result.valid && result.envelope && result.envelope !== 'ATTESTATION-v1') {
        detail = `${detail}, envelope ${result.envelope}`;
      }
      process.stdout.write(compactLine(result.valid, outcome, id, detail) + '\n');
      if (pretty) {
        const format = actionProfile ? 'ACTION-v1' : envelope ?? 'ATTESTATION-v1';
        process.stdout.write(
          recordCard(
            receipt as unknown as Record<string, unknown>,
            result.valid,
            result.keySource,
            result.reason ?? 'verification failed',
            format,
            trustedKey
          ) + '\n'
        );
      }
    }
  }
  process.exit(result.valid ? 0 : 1);
}

main();

/**
 * Returns the first member name that appears twice within the same object, or
 * null. Walks the raw text because JSON.parse has already collapsed duplicates
 * by the time a reviver runs.
 */
function findDuplicateMemberName(raw: string): string | null {
  const stack: Array<Set<string>> = [];
  let i = 0;
  const readString = (): string => {
    let out = '';
    i += 1; // opening quote
    while (i < raw.length) {
      const ch = raw[i];
      if (ch === '\\') {
        out += raw.slice(i, i + 2);
        i += 2;
        continue;
      }
      if (ch === '"') {
        i += 1;
        // Decode escapes before comparing. Comparing raw source spelling made
        // the check escape-blind, so "outcome" was not seen as a duplicate
        // of "outcome" and the ambiguous receipt verified here while Python
        // rejected it. `out` is a valid JSON string body by construction.
        try {
          return JSON.parse('"' + out + '"');
        } catch {
          return out;
        }
      }
      out += ch;
      i += 1;
    }
    return out;
  };
  while (i < raw.length) {
    const ch = raw[i];
    if (ch === '"') {
      const value = readString();
      // A string is a member name only if the next non-space character is a colon
      // and we are directly inside an object.
      let j = i;
      while (j < raw.length && /\s/.test(raw[j])) j += 1;
      if (raw[j] === ':' && stack.length > 0) {
        const names = stack[stack.length - 1];
        if (names.has(value)) return value;
        names.add(value);
      }
      continue;
    }
    if (ch === '{') stack.push(new Set());
    else if (ch === '}') stack.pop();
    i += 1;
  }
  return null;
}
