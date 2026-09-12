"""Importable view of the tree helpers in make-transparency-vectors.py.

That script's filename has hyphens, so it cannot be imported by name. This
shim loads it as a module so make-adversary-vectors.py shares one Merkle
implementation with the primitive vectors rather than carrying a second copy.
"""
import importlib.util
import pathlib

_p = pathlib.Path(__file__).resolve().parent / "make-transparency-vectors.py"
_spec = importlib.util.spec_from_file_location("make_transparency_vectors", _p)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)

leaf_hash = _m.leaf_hash
node = _m.node
merkle_root = _m.merkle_root
inclusion_path = _m.inclusion_path
consistency_path = _m.consistency_path
