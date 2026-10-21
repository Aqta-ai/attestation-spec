"""
chain profile conformance (spec/USE-v1.md section 9; DRAFT).

Every vector under test-vectors/chain/ must reach the verdict its directory
names. The TypeScript suite checks the same files, and
scripts/chain-interop-sweep.mjs requires both to agree on verdict and reason.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aqta_verify_receipt import verify_chain, verify_receipt  # noqa: E402

PIN = "VZh1DjZPXa6voCmlv7MU7APjSr-HFxrG2WSqDm-eBGE"
DIR = _REPO_ROOT / "test-vectors" / "chain"
KINDS = {"pass": "PASS", "fail": "FAIL", "incomplete": "INCOMPLETE"}


def _params():
    out = []
    for kind in KINDS:
        paths = sorted((DIR / kind).glob("*.json"))
        assert paths, f"no chain {kind} vectors"
        out += [pytest.param(kind, p, id=f"{kind}/{p.name}") for p in paths]
    return out


@pytest.mark.parametrize("kind,path", _params())
def test_chain_vector_verdict(kind: str, path: Path) -> None:
    v = json.loads(path.read_text(encoding="utf-8"))
    r = verify_chain(v["bundle"], trusted_public_key=PIN, approver_keys=v["approver_keys"])
    assert r.verdict == KINDS[kind], f"{kind}/{path.name}: {r.verdict} ({r.reason})"
    if KINDS[kind] != "PASS":
        assert r.reason


def _honest():
    return json.loads((DIR / "pass" / "001-single-use.json").read_text(encoding="utf-8"))


def test_incomplete_is_never_pass() -> None:
    v = _honest()
    assert verify_chain(v["bundle"], trusted_public_key=PIN, approver_keys=v["approver_keys"]).verdict == "PASS"
    assert verify_chain(v["bundle"], trusted_public_key=PIN).verdict == "INCOMPLETE"


def test_no_pinned_key_is_fail() -> None:
    v = _honest()
    assert verify_chain(v["bundle"], approver_keys=v["approver_keys"]).verdict == "FAIL"


def test_chain_is_opt_in_a_bundle_is_not_a_receipt() -> None:
    v = _honest()
    assert not verify_receipt(v["bundle"], trusted_public_key=PIN).valid
    assert not verify_receipt(v["bundle"], trusted_public_key=PIN, profile="ACTION-v1").valid


def test_cli_exit_codes(tmp_path: Path) -> None:
    v = _honest()
    keys = ",".join(v["approver_keys"])
    f = tmp_path / "b.json"
    f.write_text(json.dumps(v["bundle"]))
    src = str(Path(__file__).parent.parent / "src")

    def run(*extra):
        return subprocess.run([sys.executable, "-m", "aqta_verify_receipt", str(f), "--key", PIN, "--profile", "chain",
                               "-q", *extra], env={"PYTHONPATH": src}, capture_output=True).returncode

    assert run("--approver-keys", keys) == 0
    assert run() == 3
    over = json.loads((DIR / "fail" / "007-use-index-over-limit.json").read_text(encoding="utf-8"))
    f.write_text(json.dumps(over["bundle"]))
    assert run("--approver-keys", keys) == 1
