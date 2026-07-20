"""aqta-verify-receipt CLI.

Offline check of an ATTESTATION-v1 (Seal) receipt. No account. No network by
default. Exit 0 if valid, 1 if not, 2 on usage or IO errors.

    aqta-verify-receipt receipt.json --key <base64url>
    curl -sS https://api.aqta.ai/r/ID | aqta-verify-receipt - --key <base64url>
"""
from __future__ import annotations

import argparse
import json
import sys

from .verifier import verify_receipt

PUB_KEY_HINT = "https://api.aqta.ai/v1/attestation/public-key"


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
        help="trusted Ed25519 public key (base64url); omit for integrity-only vs embedded key",
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

    trusted = args.key or receipt.get("public_key")
    result = verify_receipt(
        receipt,
        trusted_public_key=trusted,
        strict_fields=not args.no_strict,
    )

    if not args.quiet:
        rid = receipt.get("attestation_id", "?")
        outcome = receipt.get("outcome", "?")
        if result.valid:
            trust = (
                "pinned key"
                if args.key
                else "embedded key (integrity only; pass --key to bind issuer identity)"
            )
            print(f"ok  {outcome}  {rid}  {trust}")
        else:
            print(f"fail  {result.reason or 'verification failed'}  {rid}")
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
