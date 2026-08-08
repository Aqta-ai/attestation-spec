"""aqta-verify-receipt CLI.

Offline check of an ATTESTATION-v1 (Seal) receipt. No account. No network by
default. Exit 0 if valid, 1 if not, 2 on usage or IO errors.

Default output is one compact, scriptable line on stdout. Colour is
presentation only (NO_COLOR / non-TTY disables it). --pretty adds a short
human flourish; it is never the verification contract.

    aqta-verify-receipt receipt.json --key <base64url>
    curl -sS https://api.aqta.ai/r/ID | aqta-verify-receipt - --key <base64url>
    aqta-verify-receipt receipt.json --key <base64url> --json
    aqta-verify-receipt receipt.json --key <base64url> --pretty
"""
from __future__ import annotations

import argparse
import json
import os
import sys

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


def _pretty_extra(valid: bool) -> str:
    mark = "◈" if _utf8() else "*"
    dot = "·" if _utf8() else "-"
    if valid:
        return f"{mark} seal intact {dot} verified offline"
    return f"{mark} seal broken {dot} do not trust this receipt"


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
    )
    parser.add_argument("file", help="receipt JSON file, or - for stdin")
    parser.add_argument(
        "--key",
        dest="key",
        help="trusted Ed25519 public key (base64url); required for counsel-grade",
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
        "--json",
        action="store_true",
        help="machine JSON on stdout (one object)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="optional human flourish after the compact line",
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

    result = verify_receipt(
        receipt,
        trusted_public_key=args.key,
        allow_untrusted_embedded_key=args.integrity_only,
        strict_fields=not args.no_strict,
        envelope=args.envelope,
    )

    rid = receipt.get("attestation_id", "?")
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
            print(
                json.dumps(
                    {
                        "valid": result.valid,
                        "outcome": outcome,
                        "attestation_id": rid,
                        "key_source": result.key_source,
                        "envelope": result.envelope,
                        "reason": None if result.valid else (result.reason or "verification failed"),
                    },
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            )
        else:
            detail = trust if result.valid else (result.reason or "verification failed")
            # Name the envelope when it is not the default, so a valid line
            # never leaves the reader assuming ATTESTATION-v1 rules were applied.
            if result.valid and result.envelope and result.envelope != "ATTESTATION-v1":
                detail = f"{detail}, envelope {result.envelope}"
            print(_compact_line(result.valid, outcome, rid, detail))
            if args.pretty:
                print(_pretty_extra(result.valid))
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
