"""aqta-verify-receipt CLI. Free for everyone: verification never needs an account.

    aqta-verify-receipt receipt.json
    aqta-verify-receipt receipt.json --key <base64url-ed25519-key>
    cat receipt.json | aqta-verify-receipt -
"""
from __future__ import annotations

import argparse
import json
import sys

from .verifier import verify_receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aqta-verify-receipt",
        description="Verify an ATTESTATION-v1 receipt offline. Exit 0 if valid, 1 if not.",
    )
    parser.add_argument("file", help="receipt JSON file, or - for stdin")
    parser.add_argument("--key", dest="key", help="trusted Ed25519 public key (base64url); omit to check integrity against the receipt's own embedded key")
    parser.add_argument("--no-strict", action="store_true", help="allow unknown top-level fields")
    parser.add_argument("-q", "--quiet", action="store_true", help="no output, exit code only")
    args = parser.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
    except OSError:
        print(f"aqta-verify-receipt: cannot read {'stdin' if args.file == '-' else args.file}", file=sys.stderr)
        return 2

    try:
        receipt = json.loads(raw)
    except json.JSONDecodeError:
        print("aqta-verify-receipt: input is not valid JSON", file=sys.stderr)
        return 2

    trusted = args.key or receipt.get("public_key")
    result = verify_receipt(receipt, trusted_public_key=trusted, strict_fields=not args.no_strict)

    if not args.quiet:
        if result.valid:
            pinned = "pinned key" if args.key else "embedded key (integrity only; pass --key to check identity)"
            print(f"valid: signature verifies against the {pinned}")
        else:
            print(f"invalid: {result.reason or 'verification failed'}")
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
