"""aqta-verify-proof: check a transparency proof offline.

Separate from `aqta-verify-receipt` because the questions are different. A
receipt asks "did the issuer assert this". A proof asks "is this entry in the
issuer's log, and has that log only ever grown". Conflating them into one
command invites a reader to think a valid signature answered the second
question. It does not.

    aqta-verify-proof inclusion.json
    aqta-verify-proof consistency.json
    aqta-verify-proof sth.json --key <published key>
    curl -s https://api.aqta.ai/v1/public/transparency/proof/<id> | aqta-verify-proof -

Verdicts, exit codes and the document sniffing match the TypeScript command of
the same name byte for byte, because a bounty class nobody outside can exercise
in both languages is not a bounty class.

Exit 0 valid, 1 invalid, 2 usage or IO.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Mapping, Optional

from .transparency import (
    verify_consistency_proof,
    verify_inclusion_proof,
    verify_signed_tree_head,
)

USAGE = """aqta-verify-proof <file|-> [--key <base64url>] [--json] [-q]

  Detects the document type from its fields:
    audit_path        an RFC 6962 inclusion proof
    consistency_path  an RFC 6962 consistency proof
    signature         a signed tree head, which needs --key

  A proof establishes that what you were shown is in the log. It does not
  establish that what you were not shown is irrelevant.
"""


def main(argv: Optional[list] = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    file = ""
    key: Optional[str] = None
    as_json = False
    quiet = False

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--key":
            i += 1
            key = args[i] if i < len(args) else None
        elif a == "--json":
            as_json = True
        elif a in ("-q", "--quiet"):
            quiet = True
        elif a in ("-h", "--help"):
            sys.stdout.write(USAGE)
            raise SystemExit(0)
        elif not file:
            file = a
        else:
            sys.stderr.write(f"aqta-verify-proof: unexpected argument {a}\n")
            raise SystemExit(2)
        i += 1

    if not file:
        sys.stderr.write(USAGE)
        raise SystemExit(2)

    try:
        raw = sys.stdin.read() if file == "-" else open(file, "r", encoding="utf-8").read()
    except OSError:
        where = "stdin" if file == "-" else file
        sys.stderr.write(f"aqta-verify-proof: cannot read {where}\n")
        raise SystemExit(2)

    try:
        doc: Any = json.loads(raw)
    except ValueError:
        sys.stderr.write("aqta-verify-proof: input is not valid JSON\n")
        raise SystemExit(2)
    if not isinstance(doc, Mapping):
        sys.stderr.write("aqta-verify-proof: input must be a JSON object\n")
        raise SystemExit(2)

    # Some endpoints wrap the proof in an envelope; accept either shape.
    inner = doc.get("proof") or doc.get("inclusion_proof") or doc.get("consistency_proof") or doc
    if not isinstance(inner, Mapping):
        sys.stderr.write("aqta-verify-proof: input must be a JSON object\n")
        raise SystemExit(2)

    if "audit_path" in inner:
        kind = "inclusion proof"
        result = verify_inclusion_proof(inner)
    elif "consistency_path" in inner:
        kind = "consistency proof"
        result = verify_consistency_proof(inner)
    elif "signature" in inner and "root_hash" in inner:
        kind = "signed tree head"
        if not key:
            sys.stderr.write(
                "aqta-verify-proof: a signed tree head needs --key <published key>\n"
            )
            raise SystemExit(2)
        result = verify_signed_tree_head(inner, key)
    else:
        sys.stderr.write(
            "aqta-verify-proof: unrecognised document: expected audit_path, "
            "consistency_path, or a signed tree head\n"
        )
        raise SystemExit(2)

    if not quiet:
        if as_json:
            sys.stdout.write(
                json.dumps(
                    {
                        "valid": result.valid,
                        "kind": kind,
                        "reason": None if result.valid else (result.reason or "verification failed"),
                    },
                    # Compact separators so this is byte-identical to the
                    # TypeScript command's JSON.stringify output. Two commands
                    # that disagree on whitespace are two commands to diff.
                    separators=(",", ":"),
                )
                + "\n"
            )
        else:
            mark = "✓ valid" if result.valid else "✕ invalid"
            detail = kind if result.valid else f"{kind}: {result.reason or 'verification failed'}"
            sys.stdout.write(f"{mark}  {detail}\n")

    raise SystemExit(0 if result.valid else 1)


if __name__ == "__main__":
    main()
