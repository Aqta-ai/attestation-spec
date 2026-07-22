"""aqta-verify-receipt CLI.

Offline check of an ATTESTATION-v1 (Seal) receipt. No account. No network by
default. Exit 0 if valid, 1 if not, 2 on usage or IO errors.

    aqta-verify-receipt receipt.json --key <base64url>
    curl -sS https://api.aqta.ai/r/ID | aqta-verify-receipt - --key <base64url>
    aqta-verify-receipt receipt.json --integrity-only
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .verifier import verify_receipt

PUB_KEY_HINT = "https://api.aqta.ai/v1/attestation/public-key"


# The Seal mark, traced from the brand artwork: head up, snout right, one
# eye (the notch in the head). Half blocks double the vertical resolution;
# plain ASCII is the fallback for non UTF-8 terminals.
_SEAL_BLOCK = [
    "           ▄▄▄▄▄▄▄▄",
    "         ▄███████▀████▄▄",
    "       ▄████████████████",
    "       ██████████████▀▀",
    "      █████████████▀",
    "     ▄█████████████",
    "    ▄██████████████",
    "  ▄█████████████████",
    "▄███████████████████",
    "████████████████████         ▄",
    "██████████████▀ ████      ▄▀",
    " ▀▀█████████▀   ███▀  ▄▄▀▀",
    "     ▀▀▀██▄▄▄▄▄▄██▀ ▀▀",
]

_SEAL_ASCII = [
    "         +%@@@@%+",
    "       %@@@@@@oo@@@@@",
    "      @@@@@@@@@@@@@@+",
    "     +@@@@@@@@@@@+",
    "     @@@@@@@@@@@",
    "   +@@@@@@@@@@@@%",
    "  @@@@@@@@@@@@@@@",
    "@@@@@@@@@@@@@@@@@%",
    "@@@@@@@@@@@@@%@@@%",
    "+%@@@@@@@@@+  @@@",
    "    +%@@%+    @@+",
]


def _stamp(valid: bool) -> None:
    """Print the Seal mark for a human.

    stderr only, and only when stderr is a TTY, so piped and scripted runs
    still see exactly the verdict line on stdout. A failed check shears the
    mark along its midline: the seal is broken.
    """
    if not sys.stderr.isatty():
        return

    enc = (sys.stderr.encoding or '').lower()
    utf8 = 'utf' in enc
    esc = chr(27)
    colour = os.environ.get('NO_COLOR') is None
    body = (esc + '[' + ('32' if valid else '31') + 'm') if colour else ''
    off = (esc + '[0m') if colour else ''

    base = _SEAL_BLOCK if utf8 else _SEAL_ASCII
    half = (len(base) + 1) // 2
    art = base if valid else [
        l if i < half else '  ' + l for i, l in enumerate(base)
    ]
    painted = [body + l + off for l in art]
    painted.append(body + ('   sealed' if valid else '   broken') + off)
    print(chr(10).join(painted), file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aqta-verify-receipt",
        description=(
            "Offline check for Seal ATTESTATION-v1 receipts. "
            f"Pin the issuer key from {PUB_KEY_HINT}."
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

    try:
        if args.file == "-":
            raw = sys.stdin.read()
        else:
            with open(args.file, encoding="utf-8") as fh:
                raw = fh.read()
    except OSError:
        print(
            f"aqta-verify-receipt: cannot read {'stdin' if args.file == '-' else args.file}",
            file=sys.stderr,
        )
        return 2

    try:
        receipt = json.loads(raw)
    except json.JSONDecodeError:
        print("aqta-verify-receipt: input is not valid JSON", file=sys.stderr)
        return 2

    if not isinstance(receipt, dict):
        print("aqta-verify-receipt: receipt must be a JSON object", file=sys.stderr)
        return 2

    result = verify_receipt(
        receipt,
        trusted_public_key=args.key,
        allow_untrusted_embedded_key=args.integrity_only,
        strict_fields=not args.no_strict,
    )

    if not args.quiet:
        _stamp(result.valid)
        rid = receipt.get("attestation_id", "?")
        outcome = receipt.get("outcome", "?")
        if result.valid:
            trust = (
                "pinned key"
                if result.key_source == "pinned"
                else "untrusted embedded key (integrity only)"
            )
            print(f"ok  {outcome}  {rid}  {trust}")
        else:
            print(f"fail  {result.reason or 'verification failed'}  {rid}")
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
