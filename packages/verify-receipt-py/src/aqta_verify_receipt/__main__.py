"""aqta-verify-receipt CLI.

Offline check of an ATTESTATION-v1 (Seal) receipt. No account. No network by
default. Exit 0 if valid, 1 if not, 2 on usage or IO errors.

Default output is one compact, scriptable line on stdout. Colour is
presentation only (NO_COLOR / non-TTY disables it). --pretty prints that same
line first, then a boxed human-readable card; it is never the verification
contract.

    aqta-verify-receipt receipt.json --key <base64url>
    curl -sS https://api.aqta.ai/v1/receipts/ID/public | aqta-verify-receipt - --key <base64url>
    aqta-verify-receipt receipt.json --key <base64url> --json
    aqta-verify-receipt receipt.json --key <base64url> --pretty
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .chain import verify_chain
from .complete import verify_complete
from .witnessed import verify_witnessed
from .verifier import verify_receipt

PUB_KEY_HINT = "https://api.aqta.ai/v1/attestation/public-key"


def _utf8() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc


def _colour() -> bool:
    return (
        sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
    )


def _paint(code: str, s: str) -> str:
    if not _colour():
        return s
    return f"\x1b[{code}m{s}\x1b[0m"


def _mid(s: str, head: int = 4, tail: int = 6) -> str:
    ell = "…" if _utf8() else "..."
    if len(s) > head + tail + 1:
        return s[:head] + ell + s[-tail:]
    return s


def _compact_line(valid: bool, outcome: str, rid: str, detail: str) -> str:
    ok = "✓" if _utf8() else "+"
    no = "✕" if _utf8() else "x"
    if valid:
        return f"{_paint('32', ok + ' valid')}  {outcome}  {_mid(rid)}  {detail}"
    return f"{_paint('31', no + ' invalid')}  {detail}  {_mid(rid)}"


# The wordmark and help text are shared with the TypeScript CLI byte for byte
# (scripts/pretty-interop-sweep.mjs compares them). Pure ASCII apart from the
# middle dot, which falls back to '-' outside a UTF-8 locale, as the compact
# line's marks do.
WORDMARK = "\n".join([
    '   .-""-.     ____             _',
    "  / .--. \\   / ___|  ___  __ _| |",
    " | ( <> ) |  \\___ \\ / _ \\/ _` | |",
    "  \\ '--' /    ___) |  __/ (_| | |",
    "   '-..-'    |____/ \\___|\\__,_|_|",
    "             offline receipt check · by Aqta",
])

HELP = f"""
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
  -q, --quiet            exit code only
  -h, --help             this help

Contract
  exit 0 valid · exit 1 invalid · exit 2 usage/IO
  --profile chain|complete|witnessed:
    exit 0 PASS · 1 FAIL · 3 INCOMPLETE · 2 usage/IO
  default stdout is one compact line (words carry meaning; colour is optional)
  --pretty never changes the exit code or the verify result

Pin the production key once from
  {PUB_KEY_HINT}
(field public_key). Do not re-fetch on every verify.
"""


def _local_dots(s: str) -> str:
    """Replace the middle dot when the terminal is not UTF-8, as the marks do."""
    return s if _utf8() else s.replace("·", "-")


def _help_text() -> str:
    return _local_dots(f"{WORDMARK}\n{HELP}")


# The --pretty card. Presentation only: it is printed after the compact line,
# never instead of it, and never changes the exit code or the verify result.
#
# Must stay byte-identical to the card in the TypeScript CLI; the comparison
# runs in scripts/pretty-interop-sweep.mjs over every vector. Widths are
# counted in code points (wide East Asian and non-BMP characters count as
# two), so both implementations wrap and pad at the same places. The frame is
# plain ASCII.
CARD_WIDTH = 76  # outer width; every line fits an 80-column terminal
LABEL_WIDTH = 16
VALUE_WIDTH = CARD_WIDTH - 4 - LABEL_WIDTH - 3

NOT_PROVEN = "that an invoice is genuine, that a payment settled, or that the issuer is honest."


def _cp_width(cp: int) -> int:
    if (
        cp >= 0x10000
        or 0x1100 <= cp <= 0x115F
        or 0x2E80 <= cp <= 0xA4CF
        or 0xAC00 <= cp <= 0xD7A3
        or 0xF900 <= cp <= 0xFAFF
        or 0xFE30 <= cp <= 0xFE4F
        or 0xFF00 <= cp <= 0xFF60
        or 0xFFE0 <= cp <= 0xFFE6
    ):
        return 2
    return 1


def _text_width(s: str) -> int:
    return sum(_cp_width(ord(ch)) for ch in s)


def _safe_text(s: str) -> str:
    """Receipt values are untrusted. Control characters (which could move the
    cursor or recolour the terminal) and lone surrogates become '?', and so
    does anything outside ASCII when the terminal is not UTF-8."""
    utf8 = _utf8()
    out = []
    for ch in s:
        cp = ord(ch)
        bad = cp < 0x20 or 0x7F <= cp <= 0x9F or 0xD800 <= cp <= 0xDFFF or (not utf8 and cp > 0x7E)
        out.append("?" if bad else ch)
    return "".join(out)


def _fit_text(s: str, width: int) -> str:
    if _text_width(s) <= width:
        return s
    ell = "…" if _utf8() else "..."
    room = width - _text_width(ell)
    out = ""
    w = 0
    for ch in s:
        cw = _cp_width(ord(ch))
        if w + cw > room:
            break
        out += ch
        w += cw
    return out + ell


def _wrap_text(s: str, width: int) -> list[str]:
    lines: list[str] = []
    line = ""
    for word in [x for x in s.split(" ") if x != ""]:
        while _text_width(word) > width:
            if line != "":
                lines.append(line)
                line = ""
            head = ""
            w = 0
            i = 0
            while i < len(word) and w + _cp_width(ord(word[i])) <= width:
                w += _cp_width(ord(word[i]))
                head += word[i]
                i += 1
            lines.append(head)
            word = word[i:]
        if word == "":
            continue
        if line == "":
            line = word
        elif _text_width(line) + 1 + _text_width(word) <= width:
            line += " " + word
        else:
            lines.append(line)
            line = word
    if line != "" or not lines:
        lines.append(line)
    return lines


def _pad(s: str, width: int) -> str:
    return s + " " * max(0, width - _text_width(s))


def _card_rows(rows: list) -> list[str]:
    out = []
    for row in rows:
        label, value = row[0], row[1]
        wrap = len(row) > 2 and row[2]
        text = _safe_text(value)
        parts = _wrap_text(text, VALUE_WIDTH) if wrap else [_fit_text(text, VALUE_WIDTH)]
        for i, part in enumerate(parts):
            out.append(f"| {_pad(label if i == 0 else '', LABEL_WIDTH)} | {_pad(part, VALUE_WIDTH)} |")
    return out


def _render_card(title: str, verdict: str, colour: str, facts: list, meaning: list) -> str:
    dash = "-" * (CARD_WIDTH - 2)
    inner = CARD_WIDTH - 4
    gap = " " * max(1, inner - _text_width(title) - _text_width(verdict))
    lines = [
        "",
        WORDMARK,
        "",
        f".{dash}.",
        f"| {title}{gap}{_paint(colour, verdict)} |",
        f"|{dash}|",
        *_card_rows(facts),
        f"|{dash}|",
        *_card_rows(meaning),
        f"'{dash}'",
    ]
    return _local_dots("\n".join(lines))


def _key_count(keys) -> str:
    if not keys:
        return "none given"
    return "1 designated" if len(keys) == 1 else f"{len(keys)} designated"


def _record_card(receipt: dict, valid: bool, key_source, reason: str, fmt: str, trusted_key) -> str:
    """Card for an ATTESTATION-v1 receipt or an ACTION-v1 record."""
    def s(v):
        return v if isinstance(v, str) else "?"

    is_action = fmt == "ACTION-v1"
    rid = s(receipt.get("action_id" if is_action else "attestation_id"))
    title = "Seal action record" if is_action else "Seal receipt"
    if trusted_key is not None:
        key_row = ["Issuer key", f"{_mid(trusted_key)} (pinned)"]
    else:
        key_row = ["Issuer key", f"{_mid(s(receipt.get('public_key')))} (embedded, untrusted)"]
    if not valid:
        return _render_card(
            title, "INVALID", "31",
            [["Reason", reason, True], ["Record", _mid(rid)], ["Format", fmt], ["Checked against", key_row[1]]],
            [["What this means",
              "seal broken: do not rely on this receipt. These bytes are not what the issuer signed.", True]],
        )
    facts = [["Decision", s(receipt.get("outcome"))]]
    if is_action:
        facts.append(["Tool", s(receipt.get("tool"))])
    facts += [["Issued", s(receipt.get("timestamp"))], key_row, ["Record", _mid(rid)], ["Format", fmt]]
    limits = NOT_PROVEN if is_action else f"which model actually ran, {NOT_PROVEN}"
    if key_source == "pinned":
        meaning = [
            ["What this proves",
             "seal intact: the issuer signed these exact bytes and no one has altered them since. "
             "Checked offline, nothing was sent to Aqta.", True],
            ["What it does not", limits, True],
        ]
    else:
        meaning = [
            ["What this proves",
             "the signature checks out against a key this receipt supplied itself, "
             "so the file is only internally consistent.", True],
            ["Warning", "anyone can self-sign. Pin the issuer key with --key before you rely on it.", True],
            ["What it does not", f"who signed it, {limits}", True],
        ]
    return _render_card(title, "VALID", "32", facts, meaning)


def _profile_card(profile: str, verdict: str, reason, trusted_key, extra_rows: list) -> str:
    """Card for the chain, complete and witnessed profiles (drafts)."""
    facts = [["Profile", f"{profile} (draft)"],
             ["Issuer key", f"{_mid(trusted_key if trusted_key is not None else '?')} (pinned)"], *extra_rows]
    if reason:
        facts.append(["Reason", reason, True])
    if verdict == "PASS":
        meaning = [["What this proves",
                    "every check this draft profile defines passed against the pinned issuer key, offline.", True]]
    elif verdict == "FAIL":
        meaning = [["What this means", "a check failed: do not rely on this bundle.", True]]
    else:
        meaning = [["What this means", "the bundle could not be fully checked. INCOMPLETE is never a pass.", True]]
    meaning.append(["What it does not", NOT_PROVEN, True])
    colour = "32" if verdict == "PASS" else "31" if verdict == "FAIL" else "33"
    return _render_card(f"Seal {profile} bundle", verdict, colour, facts, meaning)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aqta-verify-receipt",
        description=(
            "Offline check for Seal ATTESTATION-v1 receipts. "
            f"Pin the issuer key from {PUB_KEY_HINT}."
        ),
        epilog=(
            "Contract: exit 0 valid, 1 invalid, 2 usage/IO. "
            "Default stdout is one compact line. Words carry meaning; "
            "colour is optional. --pretty never changes the exit code."
        ),
        add_help=False,
    )

    class _Help(argparse.Action):
        # The help text is shared with the TypeScript CLI byte for byte, so it
        # is printed from HELP rather than generated by argparse. Same stream
        # and exit code as argparse's own --help: stdout, exit 0.
        def __call__(self, parser, namespace, values, option_string=None):
            sys.stdout.write(_help_text())
            parser.exit(0)

    parser.add_argument("-h", "--help", action=_Help, nargs=0, help="show this help and exit")
    parser.add_argument("file", help="receipt JSON file, or - for stdin")
    parser.add_argument(
        "--key",
        dest="key",
        help="trusted Ed25519 public key (base64url); pins the issuer",
    )
    parser.add_argument(
        "--integrity-only",
        action="store_true",
        help="check signature vs embedded key only (anyone can self-sign)",
    )
    parser.add_argument(
        "--no-strict",
        action="store_true",
        help="allow unknown top-level fields",
    )
    parser.add_argument(
        "--envelope",
        metavar="NAME",
        default=None,
        help="opt in to a non-ATTESTATION-v1 envelope (e.g. anchor-v1); "
        "ATTESTATION-v1 rules do not apply to it",
    )
    parser.add_argument(
        "--profile",
        metavar="NAME",
        default=None,
        help="verify under an explicit profile: action-1 (ACTION-v1 action "
        "records), chain (a GRANT-v1, USE-v1 and ACTION-v1 bundle), complete "
        "(records against CHECKPOINT-v1 checkpoints and an EXECUTION-v1 log) or "
        "witnessed (records against WITNESS-v1 statements); the last three are "
        "drafts, exit 0 PASS, 1 FAIL, 3 INCOMPLETE. Cannot be combined with "
        "--envelope",
    )
    parser.add_argument("--review-from", metavar="TIME", default=None,
                        help="complete profile only: start of the review window, RFC 3339 with an offset")
    parser.add_argument("--review-to", metavar="TIME", default=None,
                        help="complete profile only: end of the review window, RFC 3339 with an offset")
    parser.add_argument("--executor-keys", metavar="KEYS", default=None,
                        help="complete profile only: comma-separated executor keys the relying party designates")
    parser.add_argument("--witness-keys", metavar="KEYS", default=None,
                        help="witnessed profile only: comma-separated time-authority keys the relying party designates")
    parser.add_argument("--tolerance", metavar="SECONDS", default=None,
                        help="witnessed profile only: how late an honest record may enter the log (default 3600)")
    parser.add_argument(
        "--approver-keys",
        metavar="KEYS",
        default=None,
        help="chain profile only: comma-separated base64url approver keys the "
        "relying party designates. Without it an authorised action is "
        "INCOMPLETE, never PASS",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="machine JSON on stdout (one object)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="optional human-readable summary after the compact line",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="no output, exit code only",
    )
    args = parser.parse_args(argv)

    if not args.key and not args.integrity_only:
        print(
            "aqta-verify-receipt: pass --key <pinned> "
            "(or --integrity-only for embedded-key checks)",
            file=sys.stderr,
        )
        return 2
    if args.key and args.integrity_only:
        print(
            "aqta-verify-receipt: use --key or --integrity-only, not both",
            file=sys.stderr,
        )
        return 2
    if args.quiet and (args.json or args.pretty):
        print(
            "aqta-verify-receipt: -q cannot be combined with --json or --pretty",
            file=sys.stderr,
        )
        return 2
    if args.profile is not None and args.envelope is not None:
        print(
            "aqta-verify-receipt: use --profile or --envelope, not both",
            file=sys.stderr,
        )
        return 2
    if args.profile is not None and args.profile not in ("action-1", "chain", "complete", "witnessed"):
        print(
            f"aqta-verify-receipt: unknown profile: {args.profile} "
            "(accepted values: action-1, chain, complete, witnessed)",
            file=sys.stderr,
        )
        return 2
    chain_profile = args.profile == "chain"
    for flag, value, owner in (("--review-from", args.review_from, "complete"), ("--review-to", args.review_to, "complete"),
                               ("--executor-keys", args.executor_keys, "complete"),
                               ("--witness-keys", args.witness_keys, "witnessed"), ("--tolerance", args.tolerance, "witnessed")):
        if value is not None and args.profile != owner:
            print(f"aqta-verify-receipt: {flag} applies only to --profile {owner}", file=sys.stderr)
            return 2
    if args.profile in ("complete", "witnessed") and (args.integrity_only or args.no_strict):
        print(f"aqta-verify-receipt: --profile {args.profile} needs --key and takes no --integrity-only or --no-strict",
              file=sys.stderr)
        return 2
    if args.approver_keys is not None and not chain_profile:
        print(
            "aqta-verify-receipt: --approver-keys applies only to --profile chain",
            file=sys.stderr,
        )
        return 2
    if chain_profile and (args.integrity_only or args.no_strict):
        print(
            "aqta-verify-receipt: --profile chain needs --key and takes no "
            "--integrity-only or --no-strict",
            file=sys.stderr,
        )
        return 2

    try:
        if args.file == "-":
            raw = sys.stdin.read()
        else:
            with open(args.file, encoding="utf-8") as fh:
                raw = fh.read()
    except UnicodeDecodeError:
        # Subclasses ValueError, not OSError, so it used to escape as a
        # traceback. A file that is not UTF-8 is malformed input, which is
        # exit 2, the same answer the TypeScript CLI gives.
        print(
            f"aqta-verify-receipt: cannot read {args.file}: not valid UTF-8",
            file=sys.stderr,
        )
        return 2
    except OSError:
        print(
            f"aqta-verify-receipt: cannot read {'stdin' if args.file == '-' else args.file}",
            file=sys.stderr,
        )
        return 2

    def _no_duplicate_names(pairs):
        # ATTESTATION-v1 canonicalises a parsed object, so a receipt carrying the
        # same member name twice has no single canonical payload: parsers that
        # keep the first value and parsers that keep the last would compute
        # different signed bytes from identical input. RFC 8259 leaves the choice
        # to the implementation, so the format rejects the receipt instead.
        seen = set()
        for key, value in pairs:
            if key in seen:
                raise ValueError(f"duplicate member name: {key}")
            seen.add(key)
        return dict(pairs)

    def _no_json5_constants(token):
        # RFC 8259 has no NaN or Infinity. Python's json accepts all three as an
        # extension, so without this the two reference verifiers disagree on
        # whether a receipt is even JSON, and NaN reaches the number handling
        # and raises there instead of being rejected as malformed input.
        raise ValueError(f"not valid JSON: {token}")

    try:
        receipt = json.loads(
            raw,
            object_pairs_hook=_no_duplicate_names,
            parse_constant=_no_json5_constants,
        )
    except ValueError as exc:
        if isinstance(exc, json.JSONDecodeError):
            print("aqta-verify-receipt: input is not valid JSON", file=sys.stderr)
        else:
            print(f"aqta-verify-receipt: {exc}", file=sys.stderr)
        return 2

    if not isinstance(receipt, dict):
        print("aqta-verify-receipt: receipt must be a JSON object", file=sys.stderr)
        return 2

    if args.profile in ("complete", "witnessed"):
        def keys(v):
            return None if v is None else [k.strip() for k in v.split(",") if k.strip()]
        if args.profile == "complete":
            res = verify_complete(receipt, trusted_public_key=args.key, review_from=args.review_from,
                                  review_to=args.review_to, executor_keys=keys(args.executor_keys))
        else:
            kw = {}
            if args.tolerance is not None:
                if not args.tolerance.isascii() or not args.tolerance.isdigit():
                    print("aqta-verify-receipt: --tolerance takes whole seconds", file=sys.stderr)
                    return 2
                kw["tolerance_seconds"] = int(args.tolerance)
            res = verify_witnessed(receipt, trusted_public_key=args.key, witness_keys=keys(args.witness_keys), **kw)
        if not args.quiet:
            if args.json:
                print(json.dumps({"verdict": res.verdict, "profile": args.profile, "reason": res.reason}))
            else:
                print(f"{res.verdict} {args.profile}" + (f" ({res.reason})" if res.reason else ", pinned issuer key"))
                if args.pretty:
                    if args.profile == "complete":
                        frm = args.review_from if args.review_from is not None else "not given"
                        to = args.review_to if args.review_to is not None else "not given"
                        rows = [["Review window", f"{frm} to {to}", True],
                                ["Executor keys", _key_count(keys(args.executor_keys))]]
                    else:
                        tol = "3600 seconds (default)" if args.tolerance is None else f"{args.tolerance} seconds"
                        rows = [["Witness keys", _key_count(keys(args.witness_keys))], ["Tolerance", tol]]
                    print(_profile_card(args.profile, res.verdict, res.reason, args.key, rows))
        return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 3}[res.verdict]

    if chain_profile:
        approvers = None
        if args.approver_keys is not None:
            approvers = [k.strip() for k in args.approver_keys.split(",") if k.strip()]
        res = verify_chain(receipt, trusted_public_key=args.key, approver_keys=approvers)
        if not args.quiet:
            if args.json:
                print(json.dumps({"verdict": res.verdict, "profile": "chain", "reason": res.reason}))
            else:
                print(f"{res.verdict} chain" + (f" ({res.reason})" if res.reason else ", pinned issuer key"))
                if args.pretty:
                    print(_profile_card("chain", res.verdict, res.reason, args.key,
                                        [["Approver keys", _key_count(approvers)]]))
        return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 3}[res.verdict]

    action_profile = args.profile == "action-1"
    result = verify_receipt(
        receipt,
        trusted_public_key=args.key,
        allow_untrusted_embedded_key=args.integrity_only,
        strict_fields=not args.no_strict,
        envelope=args.envelope,
        profile="ACTION-v1" if action_profile else None,
    )

    rid = receipt.get("action_id" if action_profile else "attestation_id", "?")
    if not isinstance(rid, str):
        rid = "?"
    outcome = receipt.get("outcome", "?")
    if not isinstance(outcome, str):
        outcome = "?"
    trust = (
        "pinned issuer key"
        if result.key_source == "pinned"
        else "untrusted embedded key (integrity only)"
    )

    if not args.quiet:
        if args.json:
            if action_profile:
                out = {
                    "valid": result.valid,
                    "outcome": outcome,
                    "action_id": rid,
                    "key_source": result.key_source,
                    "profile": "ACTION-v1",
                    "reason": None if result.valid else (result.reason or "verification failed"),
                }
            else:
                out = {
                    "valid": result.valid,
                    "outcome": outcome,
                    "attestation_id": rid,
                    "key_source": result.key_source,
                    "envelope": result.envelope,
                    "reason": None if result.valid else (result.reason or "verification failed"),
                }
            print(json.dumps(out, separators=(",", ":"), ensure_ascii=False))
        else:
            detail = trust if result.valid else (result.reason or "verification failed")
            # Name the envelope when it is not the default, so a valid line
            # never leaves the reader assuming ATTESTATION-v1 rules were applied.
            # Under --profile the caller has already named the rules, so no
            # suffix is added there.
            if (
                result.valid
                and not action_profile
                and result.envelope
                and result.envelope != "ATTESTATION-v1"
            ):
                detail = f"{detail}, envelope {result.envelope}"
            print(_compact_line(result.valid, outcome, rid, detail))
            if args.pretty:
                fmt = "ACTION-v1" if action_profile else (args.envelope if args.envelope is not None else "ATTESTATION-v1")
                print(_record_card(receipt, result.valid, result.key_source,
                                   result.reason or "verification failed", fmt, args.key))
    return 0 if result.valid else 1


if __name__ == "__main__":
    # A closed downstream pipe turned a valid receipt into exit 120 at
    # interpreter shutdown, which is outside the documented {0,1,2} contract.
    # Redirecting stdout to devnull before exit stops the flush from raising.
    try:
        _code = main()
    except BrokenPipeError:
        _code = 0
    try:
        sys.stdout.flush()
    except (BrokenPipeError, ValueError):
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    raise SystemExit(_code)
