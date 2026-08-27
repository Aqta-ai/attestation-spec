"""Transparency proof verification: RFC 6962 inclusion and consistency.

A receipt signature answers "did this issuer assert this". It cannot answer
"is this one of the entries the issuer committed to, and has that commitment
only ever grown". Those are log questions, and answering them needs a signed
tree head plus a proof, checked without holding the log.

Nothing here contacts a server. Written from RFC 6962 rather than ported from
the TypeScript module, for the same reason the two receipt verifiers are
written separately: two implementations that agree are evidence, and one
implementation translated twice is not.

What these proofs do NOT establish: that the entries you were not shown are
irrelevant. Inclusion proves that what you were shown is in the log. Omission
stays open, and is documented as open.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_HEX = re.compile(r"^[0-9a-f]*$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass
class ProofResult:
    """Outcome of a proof check. Never raises; a malformed proof is invalid."""

    valid: bool
    reason: Optional[str] = None


def leaf_hash(entry: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || entry)."""
    return hashlib.sha256(_LEAF_PREFIX + entry).digest()


def _node(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _unhex(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) % 2 or not _HEX.match(value):
        raise ValueError("not lowercase hex")
    return bytes.fromhex(value)


def _is_size(value: Any) -> bool:
    # bool is an int subclass in Python, so exclude it explicitly or True
    # would pass as the integer 1 and a tree could have a size of "true".
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def verify_inclusion_proof(proof: Mapping[str, Any]) -> ProofResult:
    """Verify that a leaf is in a tree of the stated size with the stated root.

    RFC 6962 section 2.1.1. The audit path must be consumed exactly: a path
    with a node to spare, or one that ends early, is rejected rather than
    tolerated, because a verifier that accepts a loose proof accepts a forged
    one constructed the same way.
    """
    if not isinstance(proof, Mapping):
        return ProofResult(False, "proof is not an object")
    if not _is_size(proof.get("tree_size")) or proof["tree_size"] < 1:
        return ProofResult(False, "tree_size must be a positive integer")
    if not _is_size(proof.get("leaf_index")) or proof["leaf_index"] >= proof["tree_size"]:
        return ProofResult(False, "leaf_index must be an integer inside the tree")
    if not isinstance(proof.get("audit_path"), Sequence) or isinstance(proof["audit_path"], (str, bytes)):
        return ProofResult(False, "audit_path must be an array")

    try:
        leaf = _unhex(proof.get("leaf_hash"))
        root = _unhex(proof.get("root_hash"))
        path = [_unhex(h) for h in proof["audit_path"]]
    except ValueError:
        return ProofResult(False, "hashes must be lowercase hex")
    if len(leaf) != 32 or len(root) != 32 or any(len(n) != 32 for n in path):
        return ProofResult(False, "every hash must be 32 bytes")

    fn = proof["leaf_index"]
    sn = proof["tree_size"] - 1
    r = leaf

    for sibling in path:
        if sn == 0:
            return ProofResult(False, "audit_path is longer than the tree allows")
        if fn % 2 == 1 or fn == sn:
            r = _node(sibling, r)
            while fn != 0 and fn % 2 == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node(r, sibling)
        fn >>= 1
        sn >>= 1

    if sn != 0:
        return ProofResult(False, "audit_path is shorter than the tree requires")
    if r != root:
        return ProofResult(False, "computed root does not match root_hash")
    return ProofResult(True)


def verify_consistency_proof(proof: Mapping[str, Any]) -> ProofResult:
    """Verify that a later tree is an append-only extension of an earlier one.

    RFC 6962 section 2.1.2. This is the check that makes a log a log: without
    it an issuer can publish one head, then publish another that quietly drops
    or reorders what came before.
    """
    if not isinstance(proof, Mapping):
        return ProofResult(False, "proof is not an object")
    if not _is_size(proof.get("old_size")) or proof["old_size"] < 1:
        return ProofResult(False, "old_size must be a positive integer")
    if not _is_size(proof.get("new_size")) or proof["new_size"] < proof["old_size"]:
        return ProofResult(False, "new_size must be an integer at least old_size")
    if not isinstance(proof.get("consistency_path"), Sequence) or isinstance(
        proof["consistency_path"], (str, bytes)
    ):
        return ProofResult(False, "consistency_path must be an array")

    try:
        old_root = _unhex(proof.get("old_root"))
        new_root = _unhex(proof.get("new_root"))
        nodes = [_unhex(h) for h in proof["consistency_path"]]
    except ValueError:
        return ProofResult(False, "hashes must be lowercase hex")
    if len(old_root) != 32 or len(new_root) != 32 or any(len(n) != 32 for n in nodes):
        return ProofResult(False, "every hash must be 32 bytes")

    old_size = proof["old_size"]
    new_size = proof["new_size"]

    if old_size == new_size:
        # Nothing was appended, so the roots must match and a path would be noise.
        if nodes:
            return ProofResult(False, "no consistency_path is expected when the tree has not grown")
        if old_root != new_root:
            return ProofResult(False, "tree did not grow but roots differ")
        return ProofResult(True)

    # An old_size that is an exact power of two has its own root as the first
    # node; RFC 6962 omits it because the verifier already holds it.
    if old_size & (old_size - 1) == 0:
        nodes = [old_root] + nodes
    if not nodes:
        return ProofResult(False, "consistency_path is empty")

    fn = old_size - 1
    sn = new_size - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1

    fr = nodes[0]
    sr = nodes[0]

    for node in nodes[1:]:
        if sn == 0:
            return ProofResult(False, "consistency_path is longer than the trees allow")
        if fn % 2 == 1 or fn == sn:
            fr = _node(node, fr)
            sr = _node(node, sr)
            while fn != 0 and fn % 2 == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _node(sr, node)
        fn >>= 1
        sn >>= 1

    if sn != 0:
        return ProofResult(False, "consistency_path is shorter than the trees require")
    if fr != old_root:
        return ProofResult(False, "computed old root does not match old_root")
    if sr != new_root:
        return ProofResult(False, "computed new root does not match new_root")
    return ProofResult(True)


def verify_signed_tree_head(head: Mapping[str, Any], trusted_public_key: str) -> ProofResult:
    """Verify the Ed25519 signature on a signed tree head.

    The head is signed over a fixed byte string rather than JSON, so there is
    no canonicalisation question here, and none of the encoding-level
    divergence that JSON payloads invite.
    """
    if not isinstance(head, Mapping):
        return ProofResult(False, "head is not an object")
    if not isinstance(head.get("org_id"), str) or not _is_size(head.get("tree_size")):
        return ProofResult(False, "head must carry org_id and an integer tree_size")
    if not isinstance(head.get("root_hash"), str) or not isinstance(head.get("signature"), str):
        return ProofResult(False, "head must carry root_hash and signature")
    if not _B64URL.match(head["signature"]) or not _B64URL.match(trusted_public_key or ""):
        return ProofResult(False, "signature and key must be base64url without padding")

    try:
        root = _unhex(head["root_hash"])
    except ValueError:
        return ProofResult(False, "root_hash must be lowercase hex")
    if len(root) != 32:
        return ProofResult(False, "root_hash must be 32 bytes")

    signed = b"aqta-sth-v1|" + head["org_id"].encode("utf-8") + b"|" + str(head["tree_size"]).encode() + b"|" + root

    import base64

    def b64url(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    try:
        sig = b64url(head["signature"])
        pub = b64url(trusted_public_key)
    except Exception:
        return ProofResult(False, "signature decode error")
    if len(sig) != 64:
        return ProofResult(False, "signature length != 64 bytes")
    if len(pub) != 32:
        return ProofResult(False, "public key length != 32 bytes")

    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, signed)
    except InvalidSignature:
        return ProofResult(False, "tree head signature check failed")
    except Exception as exc:
        return ProofResult(False, f"verification error: {exc}")
    return ProofResult(True)
