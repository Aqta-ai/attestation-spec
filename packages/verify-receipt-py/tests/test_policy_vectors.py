"""
policy profile conformance (spec/POLICY-v1.md section 8; DRAFT).

Every vector under test-vectors/policy/ must reach the verdict its directory
names. The TypeScript suite checks the same files, and
scripts/policy-interop-sweep.mjs requires both to agree on verdict and reason.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aqta_verify_receipt import (  # noqa: E402
    parse_binding,
    verify_action_record,
    verify_chain,
    verify_policy,
    verify_receipt,
)

VEC = _REPO_ROOT / "test-vectors" / "policy"
PIN = (VEC / "INDEX.md").read_text(encoding="utf-8").split("Vector issuer key (pin it): `")[1].split("`")[0]
KINDS = {"pass": "PASS", "fail": "FAIL", "incomplete": "INCOMPLETE"}


def _params():
    out = []
    for kind in KINDS:
        paths = sorted((VEC / kind).glob("*.json"))
        assert len(paths) >= 5, f"too few policy {kind} vectors"
        out += [pytest.param(kind, p, id=f"policy/{kind}/{p.name}") for p in paths]
    return out


def _load(rel: str) -> dict:
    return json.loads((VEC / rel).read_text(encoding="utf-8"))["bundle"]


@pytest.mark.parametrize("kind,path", _params())
def test_vector_verdict(kind: str, path: Path) -> None:
    r = verify_policy(json.loads(path.read_text(encoding="utf-8"))["bundle"], trusted_public_key=PIN)
    assert r.verdict == KINDS[kind], f"policy/{kind}/{path.name}: {r.verdict} ({r.reason})"
    if KINDS[kind] != "PASS":
        assert r.reason


def test_bound_records_still_verify_without_the_profile() -> None:
    # The binding rides inside policy_applied: a 1.4.0 verifier checks the signature unchanged.
    for item in _load("pass/001-bound-history.json")["decisions"]:
        assert verify_action_record(item["record"], trusted_public_key=PIN).valid


def test_no_pinned_key_is_fail() -> None:
    r = verify_policy(_load("pass/001-bound-history.json"))
    assert r.verdict == "FAIL" and r.reason == "a pinned issuer key is required"


def test_the_profile_is_opt_in() -> None:
    b = _load("pass/001-bound-history.json")
    assert not verify_receipt(b, trusted_public_key=PIN).valid
    assert verify_chain(b, trusted_public_key=PIN).verdict == "FAIL"


def test_binding_grammar() -> None:
    h = "a" * 64
    assert parse_binding(f"policy_x@sha256:{h}") == ("policy_x", h)
    assert parse_binding(f"policy_\U0001F600@sha256:{h}") == ("policy_\U0001F600", h)
    for bad in (f"@sha256:{h}", f"p@sha256:{h}\n", f"p@sha256:{h.upper()}", f"p@sha512:{h}", f"a@b@sha256:{h}",
                f"p@sha256:{h[:63]}", f"p@sha256:{h}0"):
        assert parse_binding(bad) is None, bad
