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


def _stamp(receipt: dict, valid: bool, reason, trust: str) -> None:
    """Compact human stamp for a TTY.

    stderr only, and only when stderr is a TTY, so piped and scripted runs
    still see exactly the machine line on stdout. A small mark, aligned rows,
    and a single coloured verdict token: green when the signature holds, red
    when it does not. No block art, no flood of colour.
    """
    if not sys.stderr.isatty():
        return

    enc = (sys.stderr.encoding or "").lower()
    utf8 = "utf" in enc
    mark = "•ᴥ•" if utf8 else "o.o"
    dot = "·" if utf8 else "-"
    ell = "…" if utf8 else "..."
    ok = "✓" if utf8 else "+"
    no = "✗" if utf8 else "x"

    esc = chr(27)
    colour = os.environ.get("NO_COLOR") is None

    def paint(code: str, s: str) -> str:
        return (esc + "[" + code + "m" + s + esc + "[0m") if colour else s

    def dim(s: str) -> str:
        return paint("2", s)

    def field(key: str) -> str:
        v = receipt.get(key)
        return v if isinstance(v, str) else "?"

    def mid(v, head: int = 8, tail: int = 6) -> str:
        s = v if isinstance(v, str) else "?"
        return (s[:head] + ell + s[-tail:]) if len(s) > head + tail + 1 else s

    pol = receipt.get("policy_applied")
    rules = (" " + dot + " ").join(str(x) for x in pol) if isinstance(pol, list) and pol else ""

    rows = [("outcome", field("outcome")), ("model", field("model"))]
    if rules:
        rows.append(("rules", rules))
    rows.append(("key", trust))
    rows.append(("request", mid(receipt.get("request_hash"))))
    rows.append(("id", mid(receipt.get("attestation_id"), 8, 4)))

    lines = ["", "  " + dim(mark + " Seal " + dot + " ATTESTATION-v1"), ""]
    for key, value in rows:
        lines.append("  " + dim(key.ljust(8)) + value)
    lines.append("")
    if valid:
        lines.append("  " + paint("32", ok + " sealed") + "   " + dim("signature valid, checked offline"))
    else:
        lines.append("  " + paint("31", no + " broken") + "   " + dim(reason or "signature does not match the key"))
    lines.append("")
    print(chr(10).join(lines), file=sys.stderr)


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
        trust = (
            "pinned key"
            if result.key_source == "pinned"
            else "untrusted embedded key (integrity only)"
        )
        _stamp(receipt, result.valid, result.reason, trust)

        # One machine-readable line, only when stdout is not a terminal, so an
        # interactive run shows just the stamp and `... | tool` still parses.
        if not sys.stdout.isatty():
            rid = receipt.get("attestation_id", "?")
            outcome = receipt.get("outcome", "?")
            if result.valid:
                print(f"ok  {outcome}  {rid}  {trust}")
            else:
                print(f"fail  {result.reason or 'verification failed'}  {rid}")
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
