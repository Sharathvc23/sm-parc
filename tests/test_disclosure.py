"""Selective disclosure — behavioural spec for Merkle inclusion proofs.

The guarantee: a holder reveals a few receipts from a large ledger, and a verifier
confirms each sits under the credential's signed ``behavioral_merkle_root`` WITHOUT
seeing the rest. Pins that the proof folds to the *identical* root the VRP layer
commits (so it composes with a signed PARC), across every ledger size including the
odd-count duplicate rule, and that tampering is caught.
"""

from __future__ import annotations

import hashlib

import pytest
from sm_arp.vrp import behavioral_merkle_root, cosign_receipt, did_from_sk

from sm_parc import inclusion_proof, verify_inclusion


def _sk(label: bytes) -> bytes:
    return hashlib.sha256(label).digest()


def _receipt(n: int) -> dict:
    """A deterministic, corroborated ARP receipt (distinct counterparty per receipt)."""
    issuer = _sk(b"disclosure-issuer-%d" % n)
    cp = _sk(b"disclosure-cp-%d" % n)
    receipt: dict = {
        "version": "arp/0.1",
        "receipt_id": f"{n:08d}-1111-4111-8111-111111111111",
        "issuer_did": did_from_sk(issuer),
        "issued_at": f"2026-06-07T00:{n // 60:02d}:{n % 60:02d}Z",
        "action": {
            "category": "purchase",
            "human_summary": f"purchase #{n}",
            "counterparty_did": did_from_sk(cp),
        },
        "signature": "AA==",
    }
    receipt["evidence"] = {
        "witness_signatures": [
            cosign_receipt(receipt, signing_key_bytes=cp, witness_did=did_from_sk(cp))
        ]
    }
    return receipt


def _ledger(size: int) -> list[dict]:
    return [_receipt(i) for i in range(size)]


# Odd sizes (3, 5, 7, 41) exercise the duplicate-the-final-node rule; 1 is the
# single-leaf root; powers of two are the clean case.
@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 40, 41])
def test_every_receipt_proves_against_the_real_vrp_root(size: int) -> None:
    receipts = _ledger(size)
    root = behavioral_merkle_root(receipts)
    assert root is not None
    for r in receipts:
        proof = inclusion_proof(receipts, receipt=r)
        assert proof["leaf_count"] == size
        assert verify_inclusion(r, proof, root), f"size={size} receipt={r['receipt_id']}"


def test_reveal_subset_without_the_rest_of_the_ledger() -> None:
    """The point of the mechanism: verification needs only the revealed receipt +
    proof + root — never the other receipts."""
    receipts = _ledger(40)
    root = behavioral_merkle_root(receipts)
    assert root is not None
    revealed = [receipts[3], receipts[17], receipts[39]]
    proofs = [inclusion_proof(receipts, receipt=r) for r in revealed]
    # Verify with ONLY (receipt, proof, root) in scope — the ledger is not passed.
    assert all(verify_inclusion(r, p, root) for r, p in zip(revealed, proofs, strict=True))


def test_wrong_receipt_with_a_valid_proof_is_rejected() -> None:
    receipts = _ledger(40)
    root = behavioral_merkle_root(receipts)
    assert root is not None
    proof = inclusion_proof(receipts, receipt=receipts[7])
    assert not verify_inclusion(receipts[8], proof, root)


def test_tampered_path_is_rejected() -> None:
    receipts = _ledger(40)
    root = behavioral_merkle_root(receipts)
    assert root is not None
    proof = inclusion_proof(receipts, receipt=receipts[7])
    tampered = {**proof, "path": [{**proof["path"][0], "sibling": "00" * 32}, *proof["path"][1:]]}
    assert not verify_inclusion(receipts[7], tampered, root)


def test_mismatched_root_is_rejected() -> None:
    receipts = _ledger(40)
    proof = inclusion_proof(receipts, receipt=receipts[7])
    assert not verify_inclusion(receipts[7], proof, "sha256:" + "00" * 32)
    assert not verify_inclusion(receipts[7], proof, "not-a-hash")


def test_receipt_not_in_ledger_raises() -> None:
    receipts = _ledger(10)
    with pytest.raises(ValueError, match="not present"):
        inclusion_proof(receipts, receipt=_receipt(999))


def test_single_receipt_root_is_its_leaf() -> None:
    receipts = _ledger(1)
    root = behavioral_merkle_root(receipts)
    assert root is not None
    proof = inclusion_proof(receipts, receipt=receipts[0])
    assert proof["path"] == []
    assert verify_inclusion(receipts[0], proof, root)
