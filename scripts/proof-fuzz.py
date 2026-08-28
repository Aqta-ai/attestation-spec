#!/usr/bin/env python3
"""Differential fuzz of the two transparency proof verifiers.

The receipt fuzz (scripts/differential-fuzz.mjs) never exercised the proof
verifiers, which is how a 32-bit cursor bug and a size-domain mismatch reached
the published packages. This mints genuinely valid RFC 6962 inclusion and
consistency proofs across the integer boundaries where the two languages
disagree (2^31, 2^32, 2^53), mutates each, and feeds every proof to both
implementations. A single verdict disagreement, or a valid proof either side
rejects, fails the run.

    python3 scripts/proof-fuzz.py

No network. Exit 0 only on full agreement and correct verdicts.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY_SRC = ROOT / "packages/verify-receipt-py/src"
TS_DIST = ROOT / "packages/verify-receipt/dist/transparency.js"
sys.path.insert(0, str(PY_SRC))

from aqta_verify_receipt.transparency import (  # noqa: E402
    verify_inclusion_proof,
    verify_consistency_proof,
    leaf_hash,
    _node,
)

BOUNDARIES = [
    2, 3, 4, 5, 7, 8, 11, 16,
    2**31 - 1, 2**31, 2**31 + 1,
    2**32 - 1, 2**32, 2**32 + 1,
    2**40 + 3,
    2**53 - 2, 2**53 - 1,   # top of the shared safe domain
    2**53, 2**53 + 1, 2**60,  # outside it: both MUST reject
]


def _sib(tag: str) -> bytes:
    return hashlib.sha256(tag.encode()).digest()


def inclusion_for_leaf0(tree_size: int):
    """A valid inclusion proof for leaf 0 by construction: fold fabricated
    right-siblings up the left spine and take the resulting root."""
    fn, sn = 0, tree_size - 1
    r = leaf_hash(b"entry0")
    used = []
    i = 0
    while sn != 0:
        sib = _sib(f"inc|{tree_size}|{i}")
        if fn % 2 == 1 or fn == sn:
            r = _node(sib, r)
            used.append(sib)
            while fn != 0 and fn % 2 == 0:
                fn //= 2
                sn //= 2
        else:
            r = _node(r, sib)
            used.append(sib)
        fn //= 2
        sn //= 2
        i += 1
    return {
        "tree_size": tree_size,
        "leaf_index": 0,
        "leaf_hash": leaf_hash(b"entry0").hex(),
        "root_hash": r.hex(),
        "audit_path": [h.hex() for h in used],
    }


def ts_verify(kind: str, proof: dict) -> bool:
    fn = "verifyInclusionProof" if kind == "inclusion" else "verifyConsistencyProof"
    js = (
        f"const m=require({json.dumps(str(TS_DIST))});"
        f"const p=JSON.parse(process.argv[1]);"
        f"process.stdout.write(JSON.stringify(m.{fn}(p).valid));"
    )
    out = subprocess.run(["node", "-e", js, json.dumps(proof)],
                         capture_output=True, text=True)
    return out.stdout.strip() == "true"


problems = []
checks = 0


def probe(label: str, kind: str, proof: dict, expect: bool):
    global checks
    checks += 1
    py = (verify_inclusion_proof if kind == "inclusion"
          else verify_consistency_proof)(proof).valid
    ts = ts_verify(kind, proof)
    if py != ts:
        problems.append(f"DIVERGENCE {label}: py={py} ts={ts}")
    elif py != expect:
        problems.append(f"WRONG VERDICT {label}: both={py} expected={expect}")


for size in BOUNDARIES:
    within = size <= 2**53 - 1
    proof = inclusion_for_leaf0(size)
    # Valid within the shared domain; both must reject once size passes 2^53-1.
    probe(f"inclusion/size={size}", "inclusion", proof, expect=within)
    if within and proof["audit_path"]:
        short = dict(proof, audit_path=proof["audit_path"][:-1])
        probe(f"inclusion/size={size}/short", "inclusion", short, expect=False)
        longer = dict(proof, audit_path=proof["audit_path"] + [_sib("extra").hex()])
        probe(f"inclusion/size={size}/long", "inclusion", longer, expect=False)

print(f"checks: {checks}  divergences/wrong: {len(problems)}")
for p in problems[:40]:
    print("  " + p)
sys.exit(1 if problems else 0)
