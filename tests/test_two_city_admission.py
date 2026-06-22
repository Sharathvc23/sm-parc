"""Two-city admission demo — behavioural spec for the cross-city PARC flow.

Asserts the four guarantees the demo headline ("reputation that travels, collusion
that can't") rests on:

  1. ``honest-visitor`` is admitted by City B's nanda-rep/0.2 gate;
  2. ``wash-visitor`` is rejected with stage ``below_threshold``;
  3. City B's decision is reproducible from the agent's PRESENTED artifact alone
     (credential + inline receipts) — City B never touches a City A object. We prove
     this structurally: B only ever sees a JSON string, and re-running B on a
     freshly round-tripped artifact yields the identical decision;
  4. the load-bearing 0.1-vs-0.2 contrast: the wash agent clears the threshold under
     the naive nanda-rep/0.1 score (would be admitted) but is severed to ~0 under
     nanda-rep/0.2.
"""

from __future__ import annotations

import json

from sm_arp.vrp import reputation_score, reputation_score_v2

from examples.two_city_admission import (
    HONEST_DID,
    MIN_SCORE,
    WASH_DID,
    always_valid,
    city_a_issues,
    city_b_admits,
    demonstrate_naive_gate_would_admit,
    honest_receipts,
    wash_receipts,
)


def _present(*, subject_did: str, receipts: list[dict], cred_id: str) -> str:
    """City A issues, then the artifact is serialized to the wire (JSON string)."""
    artifact = city_a_issues(subject_did=subject_did, receipts=receipts, cred_id=cred_id)
    return json.dumps(artifact, sort_keys=True)


def test_honest_visitor_admitted() -> None:
    presented = _present(
        subject_did=HONEST_DID, receipts=honest_receipts(), cred_id="urn:uuid:parc-honest"
    )
    result = city_b_admits(presented)
    assert result.ok
    assert result.stage == "admitted"


def test_wash_visitor_rejected_below_threshold() -> None:
    presented = _present(
        subject_did=WASH_DID, receipts=wash_receipts(), cred_id="urn:uuid:parc-wash"
    )
    result = city_b_admits(presented)
    assert not result.ok
    assert result.stage == "below_threshold"


def test_city_b_decides_from_presented_artifact_only() -> None:
    """B's input is a JSON string — it holds no reference to any City A object.

    The decision must be reproducible from that string alone: round-tripping the
    presented artifact through JSON again (a second independent "wire copy") yields
    the identical decision. City A's in-memory ledger is never reachable from
    ``city_b_admits``; its only argument is the serialized presentation.
    """
    presented = _present(
        subject_did=HONEST_DID, receipts=honest_receipts(), cred_id="urn:uuid:parc-honest"
    )
    first = city_b_admits(presented)

    # A second, independent wire copy (what a different verifier would receive) —
    # no shared mutable object, no City A handle.
    rewired = json.dumps(json.loads(presented), sort_keys=True)
    second = city_b_admits(rewired)

    assert (first.ok, first.stage) == (second.ok, second.stage)
    # And the artifact B saw really is credential + inline receipts, nothing more.
    artifact = json.loads(presented)
    assert set(artifact) == {"vc", "ledger"}
    assert artifact["ledger"]["receipts"], "inline receipts must travel with the agent"


def test_wash_tampering_with_receipts_fails_recompute() -> None:
    """If the wash agent presents inflated receipts, the signed root/count catch it.

    This is why B can recompute from agent-presented receipts without trusting them:
    the credential pins ``behavioral_merkle_root`` + ``receipt_count``.
    """
    artifact = city_a_issues(
        subject_did=WASH_DID, receipts=honest_receipts(), cred_id="urn:uuid:parc-wash"
    )
    # The wash agent swaps in different receipts after A signed — recompute breaks.
    artifact["ledger"]["receipts"] = wash_receipts()
    tampered = json.dumps(artifact, sort_keys=True)
    result = city_b_admits(tampered)
    assert not result.ok
    assert result.stage in {"root_mismatch", "count_mismatch", "score_mismatch"}


def test_naive_0_1_gate_would_admit_wash() -> None:
    """The load-bearing contrast: 0.1 admits the wash agent, 0.2 rejects it."""
    presented = _present(
        subject_did=WASH_DID, receipts=wash_receipts(), cred_id="urn:uuid:parc-wash"
    )
    naive = demonstrate_naive_gate_would_admit(presented)
    real = city_b_admits(presented)

    assert naive.ok and naive.stage == "admitted"
    assert not real.ok and real.stage == "below_threshold"


def test_scores_show_the_contrast_directly() -> None:
    """The wash agent's 0.1 score clears the bar; its 0.2 score is severed to ~0.

    And the honest agent scores identically under 0.1 — so 0.1 cannot tell them
    apart, which is exactly why admitting on 0.1 is unsafe.
    """
    honest = honest_receipts()
    wash = wash_receipts()

    wash_01 = reputation_score(wash, is_valid=always_valid)
    wash_02 = reputation_score_v2(wash, is_valid=always_valid)
    honest_01 = reputation_score(honest, is_valid=always_valid)
    honest_02 = reputation_score_v2(honest, is_valid=always_valid)

    # Naive 0.1 cannot distinguish honest from wash.
    assert wash_01 == honest_01
    # Wash 0.1 would clear City B's threshold...
    assert wash_01 >= MIN_SCORE
    # ...but 0.2 severs it below threshold while keeping the honest score.
    assert wash_02 < MIN_SCORE
    assert honest_02 >= MIN_SCORE
