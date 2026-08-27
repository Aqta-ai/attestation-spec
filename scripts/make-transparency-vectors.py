"""Generate transparency conformance vectors from a real Merkle tree.

Builds a tree over deterministic leaves, emits genuine inclusion and
consistency proofs, then derives adversarial variants that a verifier must
reject. Adversarial vectors are derived by mutating a genuine proof, so each
one differs from a valid proof in exactly one respect and the reason a
verifier rejects it is unambiguous.

  python3 scripts/make-transparency-vectors.py

Writes test-vectors/transparency/{valid,invalid}/*.json.
"""
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "test-vectors" / "transparency"

LEAF, NODE = b"\x00", b"\x01"


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(LEAF + entry).digest()


def node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE + left + right).digest()


def k_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = k_below(len(leaves))
    return node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_path(leaves, index):
    n = len(leaves)
    if n == 1:
        return []
    k = k_below(n)
    if index < k:
        return inclusion_path(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_path(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def consistency_path(leaves, old, new, start=True):
    if old == new:
        return [] if start else [merkle_root(leaves[:new])]
    k = k_below(new)
    if old <= k:
        return consistency_path(leaves, old, k, start) + [merkle_root(leaves[k:new])]
    # RFC 6962 2.1.2: SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k]).
    # The recursive subproof comes first and the left-subtree root is appended
    # after it. Emitting them the other way round produces a path that no
    # conformant verifier accepts, which is exactly what the sweep caught.
    return consistency_path(leaves[k:], old - k, new - k, False) + [merkle_root(leaves[:k])]


def write(kind, name, payload, note):
    d = OUT / kind
    d.mkdir(parents=True, exist_ok=True)
    payload = {"_note": note, **payload}
    (d / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"  {kind}/{name}")


def main():
    # Eleven leaves: not a power of two, so the tree is unbalanced and the
    # proofs exercise the awkward paths rather than the tidy ones.
    leaves = [leaf_hash(f"receipt-{i:04d}".encode()) for i in range(11)]
    root = merkle_root(leaves)

    print("valid:")
    for index in (0, 5, 10):
        write("valid", f"inclusion-{index:02d}.json", {
            "leaf_index": index,
            "tree_size": len(leaves),
            "leaf_hash": leaves[index].hex(),
            "root_hash": root.hex(),
            "audit_path": [h.hex() for h in inclusion_path(leaves, index)],
        }, f"genuine inclusion proof for leaf {index} of {len(leaves)}")

    for old in (1, 4, 7):
        write("valid", f"consistency-{old:02d}-to-11.json", {
            "old_size": old,
            "new_size": len(leaves),
            "old_root": merkle_root(leaves[:old]).hex(),
            "new_root": root.hex(),
            "consistency_path": [h.hex() for h in consistency_path(leaves, old, len(leaves))],
        }, f"genuine append-only extension from {old} to {len(leaves)} entries")

    write("valid", "consistency-unchanged.json", {
        "old_size": 11, "new_size": 11,
        "old_root": root.hex(), "new_root": root.hex(),
        "consistency_path": [],
    }, "nothing appended: identical roots and an empty path")

    print("invalid:")
    good = {
        "leaf_index": 5, "tree_size": 11,
        "leaf_hash": leaves[5].hex(), "root_hash": root.hex(),
        "audit_path": [h.hex() for h in inclusion_path(leaves, 5)],
    }
    write("invalid", "inclusion-wrong-leaf.json",
          {**good, "leaf_hash": leaves[6].hex()},
          "a different leaf, claimed at index 5: the log does not contain this entry here")
    write("invalid", "inclusion-truncated-path.json",
          {**good, "audit_path": good["audit_path"][:-1]},
          "audit path one node short: must not be tolerated")
    write("invalid", "inclusion-extra-node.json",
          {**good, "audit_path": good["audit_path"] + [root.hex()]},
          "audit path one node too long: must not be tolerated")
    write("invalid", "inclusion-index-out-of-tree.json",
          {**good, "leaf_index": 11},
          "leaf_index equal to tree_size: outside the tree")
    write("invalid", "inclusion-swapped-siblings.json",
          {**good, "audit_path": list(reversed(good["audit_path"]))},
          "audit path in the wrong order: the tree is ordered and so is the proof")
    write("invalid", "inclusion-forged-root.json",
          {**good, "root_hash": merkle_root(leaves[:10]).hex()},
          "a genuine path checked against a root it does not produce")

    cgood = {
        "old_size": 7, "new_size": 11,
        "old_root": merkle_root(leaves[:7]).hex(), "new_root": root.hex(),
        "consistency_path": [h.hex() for h in consistency_path(leaves, 7, 11)],
    }
    write("invalid", "consistency-rewritten-history.json",
          {**cgood, "old_root": merkle_root(leaves[:6]).hex()},
          "the earlier head does not match what the later tree contains: history was rewritten")
    write("invalid", "consistency-shrunk.json",
          {**cgood, "old_size": 11, "new_size": 7},
          "new_size smaller than old_size: a log that shrank is not append-only")
    write("invalid", "consistency-unchanged-roots-differ.json",
          {"old_size": 11, "new_size": 11,
           "old_root": root.hex(), "new_root": merkle_root(leaves[:10]).hex(),
           "consistency_path": []},
          "same size but a different root: the head was equivocated")
    write("invalid", "consistency-truncated-path.json",
          {**cgood, "consistency_path": cgood["consistency_path"][:-1]},
          "consistency path one node short")

    print(f"\nwrote vectors to {OUT}")


if __name__ == "__main__":
    main()
