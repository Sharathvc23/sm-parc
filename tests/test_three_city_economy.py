"""Three-city economy — behavioural spec for the A→B→C showcase.

Pins the four claims the demo rests on: portability compounds across the three
domains, accumulated reputation is load-bearing (cold traveler rejected at the
enterprise), self-dealing is rejected at the lowest bar, and the enterprise admits on
the signed aggregate while spot-checking a revealed subset via inclusion proofs —
without the full ledger.
"""

from __future__ import annotations

from examples.three_city_economy import (
    CITIES,
    PHASE_A,
    REVEALED_INDICES,
    TOTAL,
    admit_with_disclosure,
    always_valid,
    build_fixture,
    home_issues,
    traveler_receipts,
    wash_receipts,
)
from sm_parc import inclusion_proof, verify_inclusion


def test_portability_compounds_across_three_domains() -> None:
    fx = build_fixture()
    stops = fx["journey"]
    assert [s["city"] for s in stops] == ["A", "B", "C"]
    assert [s["admitted"] for s in stops] == [True, True, True]
    # score strictly compounds as the ledger grows
    scores = [s["reputation_score"] for s in stops]
    assert scores == sorted(scores) and len(set(scores)) == 3
    assert scores == [60.0, 130.0, 200.0]


def test_cold_traveler_is_rejected_at_the_enterprise() -> None:
    """Accumulated reputation is the key: the community-only ledger fails C's bar."""
    fx = build_fixture()
    cf = fx["counterfactual"]
    assert not cf["admitted"] and cf["reason"] == "below_threshold"
    assert cf["reputation_score"] < cf["bar"]


def test_wash_trader_rejected_at_the_lowest_bar() -> None:
    fx = build_fixture()
    sec = fx["security"]
    assert not sec["admitted"] and sec["reason"] == "below_threshold"
    # the whole point: its NAIVE score would clear the bar; the corroborated one is 0
    assert sec["naive_0_1_score"] > sec["bar"]
    assert sec["reputation_score"] == 0.0


def test_enterprise_admits_on_signed_aggregate_without_full_ledger() -> None:
    """The selective-disclosure path: admit on the signed score (no recomputation) +
    verify the revealed receipts by inclusion proof — the 40-receipt ledger is never
    handed over."""
    receipts = traveler_receipts()
    artifact = home_issues(subject_did=receipts[0]["issuer_did"], receipts=receipts, cred_id="t")
    revealed = [receipts[i] for i in REVEALED_INDICES]
    proofs = [inclusion_proof(receipts, receipt=r) for r in revealed]
    result, disclosed_ok = admit_with_disclosure(
        bar=float(CITIES["C"]["bar"]), vc=artifact["vc"], revealed=revealed, proofs=proofs
    )
    assert result.ok and result.stage == "admitted"
    assert disclosed_ok


def test_revealed_receipts_prove_inclusion_and_tampering_fails() -> None:
    receipts = traveler_receipts()
    artifact = home_issues(subject_did=receipts[0]["issuer_did"], receipts=receipts, cred_id="t")
    root = artifact["vc"]["credentialSubject"]["behavioral_merkle_root"]
    for i in REVEALED_INDICES:
        proof = inclusion_proof(receipts, receipt=receipts[i])
        assert verify_inclusion(receipts[i], proof, root)
        # a receipt NOT actually at that position is rejected with the same proof
        other = receipts[(i + 1) % TOTAL]
        assert not verify_inclusion(other, proof, root)


def test_disclosure_reveals_strict_subset() -> None:
    fx = build_fixture()
    disc = fx["journey"][2]["disclosure"]
    assert disc["presented_receipts"] == len(REVEALED_INDICES)
    assert disc["total_receipts"] == TOTAL
    assert disc["presented_receipts"] < disc["total_receipts"]
    assert disc["all_inclusion_proofs_verify"]


def test_wash_ledger_is_self_dealt() -> None:
    """Sanity: the wash receipts really are self-cosigned (no distinct counterparty)."""
    wash = wash_receipts()
    assert len(wash) == PHASE_A
    for r in wash:
        assert r["action"]["counterparty_did"] == r["issuer_did"]
    assert always_valid(wash[0])  # the signatures are valid; only corroboration fails
