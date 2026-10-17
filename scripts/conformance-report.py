#!/usr/bin/env python3
"""Run every published vector through both verifiers and emit CONFORMANCE-REPORT.md.

Generated, never hand-written: a hand-written conformance claim goes stale the
first time a vector is added, and a stale conformance claim is worse than none.
Run on every release, commit the output.
"""
import subprocess, glob, json, os, sys, datetime, collections, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
os.environ["PYTHONPATH"] = "packages/verify-receipt-py/src"
TS = ["node", "packages/verify-receipt/dist/cli.js"]
PY = [sys.executable, "-m", "aqta_verify_receipt"]
KEY = json.load(open("test-vectors/valid/001-allowed.json"))["public_key"]
ACTION_KEY = json.load(open("test-vectors/action/valid/001-allowed.json"))["public_key"]

# what each adversarial vector is actually testing, for the categories table
CATEGORY = {
    "tampered-signature": "Signature tampering", "tampered-outcome": "Field tampering",
    "tampered-public-key": "Key substitution", "missing-field": "Schema violation",
    "unknown-field": "Schema violation", "wrong-version": "Version violation",
    "bad-request-hash": "Digest violation", "invalid-outcome": "Enum violation",
    "policy-not-sorted": "Canonical ordering", "policy-not-strings": "Type violation",
    "timestamp-no-offset": "Timestamp violation", "timestamp-not-datetime": "Timestamp violation",
    "negative-cost": "Range violation", "boolean-version": "Type violation",
    "signature-padded": "Encoding violation",
    "signature-standard-base64-alphabet": "Encoding violation",
    "uncoerced-integer-float": "Number canonicalisation",
    "request-hash-trailing-newline": "Digest violation",
    "timestamp-trailing-newline": "Timestamp violation",
    "signature-trailing-newline": "Encoding violation",
    "timestamp-non-ascii-digits": "Timestamp violation",
    "outcome-not-a-string": "Type violation",
    "policy-lone-surrogate": "Unicode handling",
    "action-v1-record": "Record-type confusion", "action-version-tag": "Record-type confusion",
    "accept-v1-record": "Record-type confusion", "accept-version-tag": "Record-type confusion",
}

def run(cmd, f, key=KEY, extra=()):
    return subprocess.run(cmd + list(extra) + ["--key", key, "-q", f],
                          capture_output=True, text=True, timeout=90).returncode

rows, cats = [], collections.Counter()
for kind in ("valid", "invalid"):
    for f in sorted(glob.glob(f"test-vectors/{kind}/*.json")):
        name = os.path.basename(f)
        ts, py = run(TS, f), run(PY, f)
        expect = 0 if kind == "valid" else 1
        rows.append({"vector": name, "class": kind, "ts": ts, "py": py,
                     "agree": ts == py, "correct": ts == expect and py == expect})
        if kind == "invalid":
            stem = name.split("-", 1)[1].rsplit(".", 1)[0]
            cats[CATEGORY.get(stem, "Other")] += 1

# ACTION-v1 records, verified under the explicit action-1 profile.
action_rows = []
for kind in ("valid", "invalid"):
    for f in sorted(glob.glob(f"test-vectors/action/{kind}/*.json")):
        prof = ("--profile", "action-1")
        ts, py = run(TS, f, ACTION_KEY, prof), run(PY, f, ACTION_KEY, prof)
        expect = 0 if kind == "valid" else 1
        action_rows.append({"vector": os.path.basename(f), "class": kind, "ts": ts, "py": py,
                            "agree": ts == py, "correct": ts == expect and py == expect})

# Argument-object member-name order (test-vectors/action/args): the anchor-v1
# envelope signed over the UTF-16 code-unit bytes must verify, and the one
# signed over code-point bytes must not wherever the two orders differ.
args_rows = []
with tempfile.TemporaryDirectory() as tmp:
    for f in sorted(glob.glob("test-vectors/action/args/*.json")):
        v = json.load(open(f))
        for label, env, expect in (("code unit", v["envelope"], 0),
                                   ("code point", v["envelope_code_point_order"],
                                    1 if v["orders_differ"] else 0)):
            path = os.path.join(tmp, "envelope.json")
            with open(path, "w", encoding="utf-8") as out:
                json.dump(env, out)
            ext = ("--envelope", "anchor-v1")
            ts, py = run(TS, path, ACTION_KEY, ext), run(PY, path, ACTION_KEY, ext)
            args_rows.append({"vector": f"{os.path.basename(f)} ({label})",
                              "class": "valid" if expect == 0 else "invalid",
                              "ts": ts, "py": py, "agree": ts == py,
                              "correct": ts == expect and py == expect})

valid = [r for r in rows if r["class"] == "valid"]
inval = [r for r in rows if r["class"] == "invalid"]
everything = rows + action_rows + args_rows
agree = sum(r["agree"] for r in everything)
ok    = sum(r["correct"] for r in everything)
ver   = json.load(open("packages/verify-receipt/package.json"))["version"]
today = datetime.date.today().isoformat()

lines = [
 "# Conformance report", "",
 "**Generated by `scripts/conformance-report.py`. Do not edit by hand.**", "",
 f"| | |", "|---|---|", f"| Release | {ver} |", f"| Generated | {today} |",
 f"| Vectors | {len(rows)} ({len(valid)} valid, {len(inval)} adversarial) |",
 f"| ACTION-v1 vectors | {len(action_rows)} |",
 f"| Argument-order envelopes | {len(args_rows)} |",
 f"| Implementations agree | **{agree}/{len(everything)}** |",
 f"| Verdicts match specification | **{ok}/{len(everything)}** |", "",
 "Two separately written verifiers, TypeScript (npm) and Python (PyPI), run",
 "against the same published vectors with the same pinned key.", "",
 ("> Both implementations produced identical verdicts for every published vector."
  if agree == len(everything) else
  "> **The implementations disagree on at least one vector; see the tables below.**"), "",
 "## What the adversarial vectors cover", "",
 "| Failure class | Vectors |", "|---|---:|",
]
for c, n in sorted(cats.items(), key=lambda x: (-x[1], x[0])):
    lines.append(f"| {c} | {n} |")
lines += ["", "## Every vector", "", "| Vector | Class | TypeScript | Python | Agree |", "|---|---|---|---|---|"]
verdict = lambda c: "accept" if c == 0 else ("reject" if c == 1 else f"error({c})")
for r in rows:
    lines.append(f"| `{r['vector']}` | {r['class']} | {verdict(r['ts'])} | {verdict(r['py'])} | {'yes' if r['agree'] else '**NO**'} |")
lines += ["", "## ACTION-v1 vectors", "",
 "`test-vectors/action/`, verified with `--profile action-1` and the action vector key.", "",
 "| Vector | Class | TypeScript | Python | Agree |", "|---|---|---|---|---|"]
for r in action_rows:
    lines.append(f"| `{r['vector']}` | {r['class']} | {verdict(r['ts'])} | {verdict(r['py'])} | {'yes' if r['agree'] else '**NO**'} |")
lines += ["", "## Argument member-name order", "",
 "`test-vectors/action/args/`, each object as an `anchor-v1` envelope verified with",
 "`--envelope anchor-v1`. Member names sort by UTF-16 code unit (RFC 8785 section",
 "3.2.3). The envelope signed over code-point order must be refused wherever the",
 "two orders differ.", "",
 "| Vector | Expected | TypeScript | Python | Agree |", "|---|---|---|---|---|"]
for r in args_rows:
    lines.append(f"| `{r['vector']}` | {r['class']} | {verdict(r['ts'])} | {verdict(r['py'])} | {'yes' if r['agree'] else '**NO**'} |")
lines += ["", "## Reproducing this", "", "```", "python3 scripts/conformance-report.py", "```", "",
 "Both verifiers require an explicit `--key`. Neither will verify a receipt",
 "against the public key carried inside that same receipt unless",
 "`--integrity-only` is passed, because a signature checked against a key the",
 "receipt supplies proves only that whoever held that key signed it.", ""]

open("CONFORMANCE-REPORT.md", "w").write("\n".join(lines))
print(f"CONFORMANCE-REPORT.md: {len(everything)} checks, agree {agree}/{len(everything)}, correct {ok}/{len(everything)}")
sys.exit(0 if agree == len(everything) == ok else 1)
