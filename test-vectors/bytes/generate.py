"""
Byte-level conformance vectors for ATTESTATION-v1.

The vectors in ../valid and ../invalid are JSON documents, and every harness
that reads them decodes text first. That is exactly the layer this directory
exercises: what a verifier does with BYTES that are not valid UTF-8 at all.
A JavaScript string cannot hold an invalid byte, so these cannot be expressed
as .json files and are written as .bin with a manifest of expected exit codes.

Verdict is the CLI exit code: 0 valid, 1 invalid, 2 malformed. Both reference
verifiers must return the SAME code for every file here, and it must match
expected.json. Found through the standing bounty, 12 September 2026: the
TypeScript CLI decoded with replacement, so 000 mutated into 001 verified as
valid while the Python CLI rejected it as not UTF-8.

    python3 test-vectors/bytes/generate.py
"""
from __future__ import annotations
import hashlib, importlib.util, json, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ri", ROOT / "examples" / "reference-issuer.py")
ri = importlib.util.module_from_spec(spec); spec.loader.exec_module(ri)

# Same seed and therefore the same pinned key as ../README.md.
ISSUER = ri.ReferenceIssuer.from_seed(hashlib.sha256(b"attestation-spec/test-vectors/v1").digest())
COMMON = dict(trace_id="trace-bytes-0001", org_id="org-vectors",
              request_hash="8f3a7e2b9c4d5f6a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
              outcome="ALLOWED", policy_applied=["budget_guard", "loop_guard"], cost_prevented_eur=0.0,
              attestation_id="00000000-0000-0000-0000-00000000b001",
              timestamp="2026-09-12T02:00:00.000000+00:00")

def receipt_bytes(model: str) -> bytes:
    # ensure_ascii=False so the file carries real multi-byte sequences to mutate.
    return json.dumps(ISSUER.sign(model=model, **COMMON), ensure_ascii=False).encode("utf-8")

OUT = pathlib.Path(__file__).parent
fffd = receipt_bytes("�")            # signed model is U+FFFD (EF BF BD)
plain = receipt_bytes("gpt-4o")
assert fffd.count(b"\xef\xbf\xbd") == 1 and plain.count(b'"gpt-4o"') == 1

vectors = {
    # name: (bytes, expected exit code, note)
    "000-clean-non-ascii":            (fffd, 0, "control: signed U+FFFD as a valid three-byte sequence; must verify"),
    "001-invalid-continuation-byte":  (fffd.replace(b"\xef\xbf\xbd", b"\x80"), 2,
                                       "the reported case: EF BF BD replaced by lone 0x80; a replacing decoder maps it back onto the signed payload"),
    "002-utf8-bom":                   (b"\xef\xbb\xbf" + plain, 2, "BOM before the document; a decoder that strips it accepts, one that keeps it rejects"),
    "003-truncated-multibyte":        (fffd.replace(b"\xef\xbf\xbd", b"\xef\xbf"), 2, "three-byte sequence cut short"),
    "004-overlong-encoding":          (plain.replace(b'"gpt-4o"', b'"gpt-4\xc0\xaf"'), 2, "overlong form of U+002F, forbidden by RFC 3629"),
    "005-surrogate-in-utf8":          (plain.replace(b'"gpt-4o"', b'"gpt-4\xed\xa0\x80"'), 2, "UTF-16 surrogate D800 encoded in UTF-8, forbidden"),
    "006-invalid-byte-in-ascii-value":(plain.replace(b'"gpt-4o"', b'"gpt-4\x80"'), 2, "invalid byte where the signed value was ASCII; both must say malformed, not one invalid and one malformed"),
}
manifest = {}
for name, (data, code, note) in vectors.items():
    (OUT / f"{name}.bin").write_bytes(data)
    manifest[f"{name}.bin"] = {"expected_exit": code, "sha256": hashlib.sha256(data).hexdigest(), "note": note}
    try: data.decode("utf-8"); ok = True
    except UnicodeDecodeError: ok = False
    assert ok == (code == 0) or name == "002-utf8-bom", name   # BOM is valid UTF-8 but not valid JSON
(OUT / "expected.json").write_text(json.dumps({"trusted_public_key": ISSUER.public_key_b64, "vectors": manifest}, indent=2) + "\n")
print(f"wrote {len(vectors)} vectors, key {ISSUER.public_key_b64}")
