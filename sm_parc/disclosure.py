"""Selective disclosure — reveal a few receipts from a large ledger, provably.

As an agent transacts across trust domains its Receipts Ledger grows without bound,
and handing the whole history to every gate is neither private nor scalable. PARC
already commits the ledger as a ``behavioral_merkle_root``; this module lets a holder
reveal only the *receipts worth showing* plus a **Merkle inclusion proof** for each, so
a verifier confirms every revealed receipt sits under the signed root **without ever
seeing the rest of the ledger**.

The proof is the dual of recomputation: where ``sm_parc.admit`` recomputes the whole root,
:func:`verify_inclusion` folds one leaf up its authentication path to the same root.
Pure SHA-256 over the *identical* leaf/tree construction as
``sm_arp.vrp.behavioral_merkle_root`` (leaves sorted by ``issued_at`` then
``receipt_id``; node = ``SHA-256(left || right)``; an odd node is duplicated). No new
crypto, no zero-knowledge — just the commitment PARC already carries.

Scope: this discloses *which receipts happened* (the transactions). It does NOT
recompute the reputation score — that is an aggregate over the whole graph (collusion
severance needs every edge), so the score stays the signed value over the full root.
The two are deliberately separate layers; see ``THREATMODEL.md``.
"""

from __future__ import annotations

import hashlib
from typing import Any, TypedDict

import jcs


class InclusionStep(TypedDict):
    sibling: str  # hex of the sibling node hash
    position: str  # "left" if the sibling is the left input, else "right"


class InclusionProof(TypedDict):
    leaf_index: int  # index of the receipt in canonical (sorted) order
    leaf_count: int  # total leaves committed (lets a verifier sanity-check scope)
    path: list[InclusionStep]


def _leaf_hash(receipt: dict[str, Any]) -> bytes:
    """SHA-256 of the receipt's JCS bytes — the identical leaf as the VRP root."""
    return hashlib.sha256(jcs.canonicalize(receipt)).digest()


def _ordered_leaves(receipts: list[dict[str, Any]]) -> list[bytes]:
    ordered = sorted(receipts, key=lambda r: (r.get("issued_at", ""), r.get("receipt_id", "")))
    return [_leaf_hash(r) for r in ordered]


def inclusion_proof(receipts: list[dict[str, Any]], *, receipt: dict[str, Any]) -> InclusionProof:
    """Build a Merkle inclusion proof that ``receipt`` is committed in ``receipts``.

    Returns the leaf index, the total leaf count, and the authentication path (each
    step is a sibling hash + which side it sits on). Raises ``ValueError`` if the
    receipt is not in the ledger. The proof verifies against the SAME
    ``behavioral_merkle_root`` the credential signs over — see :func:`verify_inclusion`.
    """
    leaves = _ordered_leaves(receipts)
    target = _leaf_hash(receipt)
    try:
        index = leaves.index(target)
    except ValueError as exc:
        raise ValueError("receipt is not present in the ledger") from exc

    path: list[InclusionStep] = []
    level = leaves
    i = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = [*level, level[-1]]  # duplicate the final node (matches the root)
        sibling = i ^ 1
        # If the node is the left input (even index), its sibling is on the right.
        position = "right" if i % 2 == 0 else "left"
        path.append({"sibling": level[sibling].hex(), "position": position})
        level = [hashlib.sha256(level[j] + level[j + 1]).digest() for j in range(0, len(level), 2)]
        i //= 2

    return {"leaf_index": index, "leaf_count": len(leaves), "path": path}


def verify_inclusion(receipt: dict[str, Any], proof: InclusionProof, root: str) -> bool:
    """True iff ``receipt`` folds up ``proof.path`` to ``root`` (a ``sha256:<hex>``).

    The verifier recomputes only the revealed receipt's leaf and walks the path — it
    never needs the other receipts. A wrong receipt, a tampered path, or a mismatched
    root all yield False.
    """
    if not isinstance(root, str) or not root.startswith("sha256:"):
        return False
    node = _leaf_hash(receipt)
    for step in proof.get("path", []):
        try:
            sibling = bytes.fromhex(step["sibling"])
        except (ValueError, KeyError, TypeError):
            return False
        if step.get("position") == "left":
            node = hashlib.sha256(sibling + node).digest()
        else:
            node = hashlib.sha256(node + sibling).digest()
    return "sha256:" + node.hex() == root


__all__ = ["InclusionProof", "InclusionStep", "inclusion_proof", "verify_inclusion"]
