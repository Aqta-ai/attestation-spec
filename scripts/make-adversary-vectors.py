"""Generate adversary-class history bundles for test-vectors/transparency/adversary.

Each bundle is what a reviewer holds after a dispute: signed heads obtained at
different times, consistency proofs between them, inclusion proofs for the
records in question with the time each record claims. The primitives are
checked one object at a time by the valid/invalid vectors; the adversary
classes in ISSUER-ADVERSARY.md only show across objects, and these are the
vectors for that.

Heads are signed with a deterministic throwaway key (private bytes 0..31) so
the bundles are stable across runs. The public half travels in each bundle as
trusted_public_key; nothing here is secret.

Before writing, every bundle is assessed with the published Python verifier
and must produce its expected verdict, so the corpus cannot drift from the
implementation that generated it. The interop sweep then holds the TypeScript
verifier to the same verdicts.

  PYTHONPATH=packages/verify-receipt-py/src python3 scripts/make-adversary-vectors.py
"""
import base64
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "packages" / "verify-receipt-py" / "src"))
from make_transparency_vectors_lib import consistency_path, inclusion_path, leaf_hash, merkle_root  # noqa: E402
from aqta_verify_receipt.transparency import assess_history  # noqa: E402

OUT = HERE.parent / "test-vectors" / "transparency" / "adversary"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUB = base64.urlsafe_b64encode(KEY.public_key().public_bytes_raw()).decode().rstrip("=")


def ts(minute: int) -> str:
    return f"2026-09-12T18:{minute:02d}:00Z"


def head(leaves, minute):
    root = merkle_root(leaves)
    signed = b"aqta-sth-public-v1|" + str(len(leaves)).encode() + b"|" + root + b"|" + ts(minute).encode()
    return {
        "v": 1, "log": "public", "tree_size": len(leaves), "root_hash": root.hex(),
        "timestamp": ts(minute),
        "signature": base64.urlsafe_b64encode(KEY.sign(signed)).decode().rstrip("="),
    }


def consistency(leaves, old, new, old_root=None, new_root=None):
    return {
        "old_size": old, "new_size": new,
        "old_root": (old_root or merkle_root(leaves[:old])).hex(),
        "new_root": (new_root or merkle_root(leaves[:new])).hex(),
        "consistency_path": [h.hex() for h in consistency_path(leaves, old, new)],
    }


def inclusion(leaves, index, record_minute=None):
    proof = {
        "leaf_index": index, "tree_size": len(leaves),
        "leaf_hash": leaves[index].hex(), "root_hash": merkle_root(leaves).hex(),
        "audit_path": [h.hex() for h in inclusion_path(leaves, index)],
    }
    entry = {"proof": proof}
    if record_minute is not None:
        entry["record_timestamp"] = ts(record_minute)
    return entry


def write(name, cls, note, expect, **parts):
    bundle = {"_note": note, "_class": cls, "trusted_public_key": PUB, **parts, "expect": {"verdict": expect}}
    got = assess_history(bundle, PUB)
    assert got.verdict == expect, f"{name}: python says {got.verdict} ({got.reason}), expected {expect}"
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    print(f"  adversary/{name}  -> {expect}")


def main():
    honest = [leaf_hash(f"receipt-{i:04d}".encode()) for i in range(11)]
    # A tree with one leaf replaced, and one with two leaves swapped.
    replaced = list(honest); replaced[3] = leaf_hash(b"receipt-0003-rewritten")
    swapped = list(honest); swapped[2], swapped[3] = swapped[3], swapped[2]
    side6 = honest[:6]; side6 = [side6[0], leaf_hash(b"receipt-0001-side"), *side6[2:]]

    # ---- valid baselines --------------------------------------------------
    write("a1-consistent-growth.json", "A1",
          "two heads obtained at different times, the later one an append-only extension of the first; "
          "a record included at size 11 claims a time before that head",
          "consistent",
          heads=[head(honest[:5], 5), head(honest, 11)],
          consistency=[consistency(honest, 5, 11)],
          inclusions=[inclusion(honest, 2, record_minute=2)])

    # ---- A1 equivocation ----------------------------------------------------
    write("a1-equivocation-same-size.json", "A1",
          "two heads, both correctly signed, both at size 11, different roots: the issuer showed two "
          "different logs. Every signature verifies; only holding both heads reveals it",
          "equivocation",
          heads=[head(honest, 11), head(replaced, 12)])

    write("a1-fork-no-extension.json", "A1",
          "a head at 7 and a head at 11 whose tree does not contain the first seven entries as they "
          "were: the consistency proof cannot rebuild the earlier root",
          "fork",
          heads=[head(honest[:7], 7), head(replaced, 11)],
          consistency=[consistency(replaced, 7, 11, old_root=merkle_root(honest[:7]))])

    # ---- A3 backdating: the sound half, and the honest limit -------------------
    write("a3-included-before-head-time.json", "A3",
          "a record claiming 18:04 is included in a head signed at 18:11: consistent, the head bounds "
          "the record's existence from above",
          "consistent",
          heads=[head(honest, 11)],
          inclusions=[inclusion(honest, 4, record_minute=4)])

    write("a3-claims-time-after-including-head.json", "A3",
          "a record claiming 18:30 is included in a head signed at 18:11. A record cannot be created "
          "after a head that already contains it: one of the two timestamps is false",
          "timestamp_contradiction",
          heads=[head(honest, 11)],
          inclusions=[inclusion(honest, 4, record_minute=30)])

    write("a3-lag-is-not-backdating.json", "A3",
          "a record claiming 18:03 sits at index 8, so it is absent from the head at size 5 signed at "
          "18:05. That is NOT evidence of backdating: log order is submission order, and a record can be "
          "created before a head and submitted after it. A verifier that flags this is wrong",
          "consistent",
          heads=[head(honest[:5], 5), head(honest, 11)],
          consistency=[consistency(honest, 5, 11)],
          inclusions=[inclusion(honest, 8, record_minute=3)])

    strict = inclusion(honest, 4)
    strict["record_timestamp"] = "2026-09-12T18:04:00.000000+00:00"
    write("a3-timestamp-grammar-is-strict.json", "A3",
          "a record_timestamp carrying fractional seconds and an offset. The bundle grammar is "
          "YYYY-MM-DDTHH:MM:SSZ, deliberately narrower than RFC 3339, so the two implementations never "
          "depend on a date parser agreeing. Builders convert to UTC and floor to the second, which can "
          "only make a record look earlier and so cannot manufacture a contradiction; the signed value "
          "travels beside it. A verifier that parses this instead of refusing it is wrong",
          "invalid_proof",
          heads=[head(honest, 11)],
          inclusions=[strict])

    # ---- A4 retrospective reordering ---------------------------------------
    write("a4-reordered-history.json", "A4",
          "a pinned head at 5, then a head at 11 over the same entries with two of them swapped. The "
          "inclusion proof for the moved record verifies on its own against the new head; only the "
          "consistency proof from the pinned head catches the reordering",
          "fork",
          heads=[head(honest[:5], 5), head(swapped, 11)],
          consistency=[consistency(swapped, 5, 11, old_root=merkle_root(honest[:5]))],
          inclusions=[inclusion(swapped, 3)])

    # ---- A6 selective disclosure: the pack head must be a prefix of the live log
    write("a6-pack-head-is-prefix.json", "A6",
          "a pack head at 6 obtained from the issuer and a live head at 11 fetched independently; the "
          "pack head is a prefix of the live log and every pack proof verifies against it",
          "consistent",
          heads=[head(honest[:6], 6), head(honest, 11)],
          consistency=[consistency(honest, 6, 11)],
          inclusions=[inclusion(honest[:6], 1, record_minute=1), inclusion(honest[:6], 5, record_minute=5)])

    write("a6-side-head.json", "A6",
          "a pack head at 6, correctly signed, over a tree the live log never contained: the pack's "
          "proofs verify against it, and the live head does not extend it. A side history built for "
          "one reviewer",
          "fork",
          heads=[head(side6, 6), head(honest, 11)],
          consistency=[consistency(honest, 6, 11, old_root=merkle_root(side6))],
          inclusions=[inclusion(side6, 1)])

    # ---- malformed bundles must not pass as consistent ------------------------
    write("invalid-head-signature.json", "A5",
          "one head carries a signature that does not verify under the trusted key: nothing below it "
          "can be relied on, whatever the proofs say",
          "invalid_head",
          heads=[head(honest[:5], 5), {**head(honest, 11), "signature": head(replaced, 11)["signature"]}],
          consistency=[consistency(honest, 5, 11)])

    unsigned = inclusion(honest[:9], 2)
    write("unsigned-root-target.json", "A6",
          "an inclusion proof that verifies, against a root no head in the bundle signed: a proof "
          "about a tree that is not in evidence",
          "unsigned_root",
          heads=[head(honest, 11)],
          inclusions=[unsigned])

    print(f"\nwrote {len(list(OUT.glob('*.json')))} bundles to {OUT}")


if __name__ == "__main__":
    main()
