"""The --pretty card and --help.

Presentation only, so these tests pin what it must never do: change the
compact first line or the exit code, overrun an 80-column terminal, emit ANSI
on a pipe, or say more than a signature shows. Byte equality with the
TypeScript CLI is checked by scripts/pretty-interop-sweep.mjs.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_TV = _ROOT / "test-vectors"
_SRC = Path(__file__).resolve().parent.parent / "src"
_KEY = "alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E"


def _env(utf8: bool = True) -> dict:
    env = {k: v for k, v in os.environ.items() if k != "NO_COLOR"}
    env["PYTHONPATH"] = str(_SRC)
    env["PYTHONHASHSEED"] = "0"
    if utf8:
        env.update(LANG="en_US.UTF-8", LC_ALL="en_US.UTF-8", PYTHONIOENCODING="utf-8")
    else:
        env.update(LANG="C", LC_ALL="C", PYTHONIOENCODING="ascii")
    return env


def _cli(args, utf8=True, stdin=None):
    r = subprocess.run([sys.executable, "-m", "aqta_verify_receipt", *args], capture_output=True,
                       env=_env(utf8), input=stdin)
    return r.returncode, r.stdout.decode("utf-8"), r.stderr.decode("utf-8")


def _assert_shape(text: str) -> None:
    for line in text.split("\n"):
        assert len(line) <= 78, f"too wide: {line}"
    assert "\x1b" not in text
    assert "\u2013" not in text and "\u2014" not in text


@pytest.mark.parametrize("name,args,code", [
    ("valid/002-blocked.json", ["--key", _KEY], 0),
    ("valid/001-allowed.json", ["--integrity-only"], 0),
    ("invalid/002-tampered-outcome.json", ["--key", _KEY], 1),
])
def test_pretty_starts_with_the_compact_line_and_keeps_the_exit_code(name, args, code):
    plain_code, plain, _ = _cli([str(_TV / name), *args])
    pretty_code, pretty, _ = _cli([str(_TV / name), *args, "--pretty"])
    assert plain_code == pretty_code == code
    assert plain.count("\n") == 1
    assert pretty.split("\n")[0] + "\n" == plain
    _assert_shape("\n".join(pretty.split("\n")[1:]))


def test_pinned_valid_card_says_what_it_proves_and_what_it_does_not():
    _, out, _ = _cli([str(_TV / "valid/002-blocked.json"), "--key", _KEY, "--pretty"])
    assert "| Seal receipt" in out and "VALID |" in out
    assert "signed these exact bytes" in out
    for phrase in ("invoice is genuine", "payment settled", "issuer is honest"):
        assert phrase in out
    assert "offline receipt check · by Aqta" in out


def test_integrity_only_card_warns_anyone_can_self_sign():
    _, out, _ = _cli([str(_TV / "valid/001-allowed.json"), "--integrity-only", "--pretty"])
    assert "embedded, untrusted" in out
    assert "anyone can self-sign" in out


def test_invalid_card_says_do_not_rely_and_shows_no_claimed_decision():
    _, out, _ = _cli([str(_TV / "invalid/002-tampered-outcome.json"), "--key", _KEY, "--pretty"])
    assert "INVALID |" in out
    assert "do not rely on this receipt" in out
    assert "| Decision " not in out


def test_ascii_locale_gives_plain_ascii():
    _, out, _ = _cli([str(_TV / "valid/007-non-ascii-policy.json"), "--key", _KEY, "--pretty"], utf8=False)
    assert out.isascii()
    code, help_text, _ = _cli(["--help"], utf8=False)
    assert code == 0 and help_text.isascii()


def test_help_keeps_every_option_and_the_contract():
    code, out, err = _cli(["--help"])
    assert code == 0 and err == ""
    for flag in ("--key", "--integrity-only", "--envelope", "--profile", "--approver-keys", "--review-from",
                 "--review-to", "--executor-keys", "--witness-keys", "--tolerance", "--no-strict", "--json",
                 "--pretty", "-q, --quiet", "exit 0 valid", "3 INCOMPLETE",
                 "default stdout is one compact line", "--pretty never changes the exit code"):
        assert flag in out, f"help lost {flag}"
    _assert_shape(out)


def test_receipt_values_cannot_inject_control_sequences_into_the_card():
    receipt = {"attestation_id": "x\x1b[2Jy", "outcome": "ALLOWED", "timestamp": "\x1b]0;t\x07"}
    code, out, _ = _cli(["-", "--integrity-only", "--pretty"], stdin=json.dumps(receipt).encode())
    assert code == 1
    assert "\x1b" not in "\n".join(out.split("\n")[1:])
