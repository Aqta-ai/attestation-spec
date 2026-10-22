"""
complete and witnessed profile conformance (spec/CHECKPOINT-v1.md section 8,
spec/WITNESS-v1.md section 7; DRAFTS).

Every vector under test-vectors/complete/ and test-vectors/witnessed/ must reach
the verdict its directory names. The TypeScript suite checks the same files, and
scripts/e79-interop-sweep.mjs requires both to agree on verdict and reason.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aqta_verify_receipt import (  # noqa: E402
    verify_chain,
    verify_complete,
    verify_receipt,
    verify_witnessed,
)

VEC = _REPO_ROOT / "test-vectors"
PIN = (VEC / "complete" / "INDEX.md").read_text(encoding="utf-8").split("Vector issuer key (pin it): `")[1].split("`")[0]
KINDS = {"pass": "PASS", "fail": "FAIL", "incomplete": "INCOMPLETE"}


def _run(profile: str, v: dict):
    if profile == "complete":
        return verify_complete(v["bundle"], trusted_public_key=PIN, review_from=v["review_from"],
                               review_to=v["review_to"], executor_keys=v["executor_keys"])
    return verify_witnessed(v["bundle"], trusted_public_key=PIN, witness_keys=v["witness_keys"],
                            tolerance_seconds=v["tolerance_seconds"])


def _params():
    out = []
    for profile in ("complete", "witnessed"):
        for kind in KINDS:
            paths = sorted((VEC / profile / kind).glob("*.json"))
            assert paths, f"no {profile} {kind} vectors"
            out += [pytest.param(profile, kind, p, id=f"{profile}/{kind}/{p.name}") for p in paths]
    return out


@pytest.mark.parametrize("profile,kind,path", _params())
def test_vector_verdict(profile: str, kind: str, path: Path) -> None:
    v = json.loads(path.read_text(encoding="utf-8"))
    r = _run(profile, v)
    assert r.verdict == KINDS[kind], f"{profile}/{kind}/{path.name}: {r.verdict} ({r.reason})"
    if KINDS[kind] != "PASS":
        assert r.reason


def _load(profile: str, rel: str) -> dict:
    return json.loads((VEC / profile / rel).read_text(encoding="utf-8"))


def test_withheld_record_is_never_pass_and_the_honest_bundle_is() -> None:
    honest = _load("complete", "pass/001-complete-with-executor-log.json")
    assert _run("complete", honest).verdict == "PASS"
    withheld = _load("complete", "incomplete/001-record-withheld.json")
    assert _run("complete", withheld).verdict == "INCOMPLETE"


def test_no_executor_set_with_a_log_is_incomplete_not_pass() -> None:
    v = _load("complete", "pass/001-complete-with-executor-log.json")
    r = verify_complete(v["bundle"], trusted_public_key=PIN, review_from=v["review_from"], review_to=v["review_to"])
    assert r.verdict == "INCOMPLETE" and r.reason == "no executor key set was supplied"


def test_no_witness_set_is_incomplete_not_pass() -> None:
    v = _load("witnessed", "pass/001-honest-history.json")
    assert verify_witnessed(v["bundle"], trusted_public_key=PIN).verdict == "INCOMPLETE"


def test_tolerance_is_the_line() -> None:
    """The boundary vector passes at 3600 and fails at 3599: a check that cannot fail is not a check."""
    v = _load("witnessed", "pass/002-exactly-at-the-tolerance.json")
    ok = verify_witnessed(v["bundle"], trusted_public_key=PIN, witness_keys=v["witness_keys"], tolerance_seconds=3600)
    tight = verify_witnessed(v["bundle"], trusted_public_key=PIN, witness_keys=v["witness_keys"], tolerance_seconds=3599)
    assert ok.verdict == "PASS"
    assert tight.verdict == "FAIL" and "logged more than 3599 seconds late" in tight.reason


def test_no_pinned_key_is_fail() -> None:
    v = _load("complete", "pass/001-complete-with-executor-log.json")
    assert verify_complete(v["bundle"], review_from=v["review_from"], review_to=v["review_to"]).verdict == "FAIL"
    w = _load("witnessed", "pass/001-honest-history.json")
    assert verify_witnessed(w["bundle"], witness_keys=w["witness_keys"]).verdict == "FAIL"


def test_profiles_are_opt_in_a_bundle_is_nothing_else() -> None:
    for profile, rel in (("complete", "pass/001-complete-with-executor-log.json"),
                         ("witnessed", "pass/001-honest-history.json")):
        b = _load(profile, rel)["bundle"]
        assert not verify_receipt(b, trusted_public_key=PIN).valid
        assert not verify_receipt(b, trusted_public_key=PIN, profile="ACTION-v1").valid
        assert verify_chain(b, trusted_public_key=PIN).verdict == "FAIL"
    w = _load("witnessed", "pass/001-honest-history.json")["bundle"]
    assert verify_complete(w, trusted_public_key=PIN, review_from="2026-10-20T10:00:00+00:00",
                           review_to="2026-10-20T13:00:00+00:00").verdict == "FAIL"


def test_cli_exit_codes(tmp_path: Path) -> None:
    import subprocess

    src = str(Path(__file__).parent.parent / "src")

    def run(profile: str, rel: str, *extra: str) -> int:
        v = _load(profile, rel)
        f = tmp_path / "b.json"
        f.write_text(json.dumps(v["bundle"]))
        return subprocess.run([sys.executable, "-m", "aqta_verify_receipt", str(f), "--key", PIN, "--profile", profile,
                               "-q", *extra], env={"PYTHONPATH": src}, capture_output=True).returncode

    c = _load("complete", "pass/001-complete-with-executor-log.json")
    window = ("--review-from", c["review_from"], "--review-to", c["review_to"])
    ek = ",".join(c["executor_keys"])
    assert run("complete", "pass/001-complete-with-executor-log.json", *window, "--executor-keys", ek) == 0
    assert run("complete", "pass/001-complete-with-executor-log.json", *window) == 3
    assert run("complete", "fail/016-executed-action-never-recorded.json", *window, "--executor-keys", ek) == 1
    wk = ",".join(_load("witnessed", "pass/001-honest-history.json")["witness_keys"])
    assert run("witnessed", "pass/001-honest-history.json", "--witness-keys", wk) == 0
    assert run("witnessed", "pass/001-honest-history.json") == 3
    assert run("witnessed", "fail/001-backdated.json", "--witness-keys", wk) == 1
    assert run("witnessed", "pass/002-exactly-at-the-tolerance.json", "--witness-keys", wk, "--tolerance", "3599") == 1
    assert run("complete", "pass/001-complete-with-executor-log.json", "--tolerance", "1") == 2
