"""Two-city PARC admission demo — "reputation that travels, collusion that can't".

Two cities, two different ``did:key`` identities, no shared infrastructure:

  * **City A** is the *issuer*. It watches two visiting agents earn ARP receipts,
    builds a ``nanda-rep/0.2`` Receipts Ledger for each, and mints a signed
    ``parc/0.1`` ReputationCredential (a W3C VC) over it.
  * **City B** is the *verifier*. It trusts A's ``did:key`` but has **zero access
    to A's receipts store, ledger objects, or live server**. All it ever sees is the
    portable artifact the agent carries — the signed credential plus the inline
    receipts presented *by the agent*. B verifies A's Ed25519 signature, recomputes
    the corroborated ``nanda-rep/0.2`` facet from the inline receipts, and applies
    its own threshold.

The two visitors:

  * ``honest-visitor`` — every receipt is co-signed by a **distinct** counterparty
    (real corroboration). ``nanda-rep/0.2`` credits it → high score.
  * ``wash-visitor`` — self-dealing: it co-signs its *own* receipts (counterparty ==
    witness == itself). The signatures are cryptographically valid, so the naive
    ``nanda-rep/0.1`` score is just as high as the honest agent's. But no *distinct*
    party corroborates anything, so ``nanda-rep/0.2`` severs it to ~0.

The load-bearing contrast (``demonstrate_naive_gate_would_admit`` below): a *naive*
City B that admitted on ``nanda-rep/0.1`` would let ``wash-visitor`` straight in —
its signed 0.1 score clears the bar. City B's 0.2 gate rejects it. Same agent, same
receipts, same threshold; only the scoring method differs.

Run:  python examples/two_city_admission.py
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sm_arp.vrp import (
    SCORING_METHOD_V2,
    build_ledger,
    cosign_receipt,
    did_from_sk,
    reputation_score,
)

from sm_parc import AdmissionPolicy, AdmissionResult, admit, build_reputation_credential
from sm_parc.credential import did_from_private_key

# --- fixed identities (deterministic: sha256 of a stable label) --------------
# Two cities with DIFFERENT did:key identities, and one did:key per agent +
# the honest visitor's distinct counterparty. No uuids, no wall-clock.
CITY_A_SK = hashlib.sha256(b"two-city-demo:city-A-issuer").digest()
CITY_B_SK = hashlib.sha256(b"two-city-demo:city-B-verifier").digest()
HONEST_SK = hashlib.sha256(b"two-city-demo:honest-visitor").digest()
WASH_SK = hashlib.sha256(b"two-city-demo:wash-visitor").digest()
COUNTERPARTY_SK = hashlib.sha256(b"two-city-demo:honest-counterparty").digest()

CITY_A_DID = did_from_private_key(CITY_A_SK)
CITY_B_DID = did_from_private_key(CITY_B_SK)
HONEST_DID = did_from_sk(HONEST_SK)
WASH_DID = did_from_sk(WASH_SK)
COUNTERPARTY_DID = did_from_sk(COUNTERPARTY_SK)

# Fixed validity window + recompute clock (caller-supplied; the lib takes no clock).
VALID_FROM = "2026-06-07T00:00:00Z"
VALID_UNTIL = "2026-07-07T00:00:00Z"
NOW = "2026-06-08T00:00:00Z"

# City B's threshold. The honest 0.2 score (15.0) clears it; the wash 0.2 score
# (0.0) does not. Crucially the wash 0.1 score (15.0) WOULD clear it — that is the
# whole demo.
MIN_SCORE = 1.0


def always_valid(_receipt: dict[str, Any]) -> bool:
    """Stand-in for the ARP verifier — here every receipt's signature is valid."""
    return True


def _receipt(
    *,
    n: int,
    subject_did: str,
    counterparty_did: str,
    cosign_sk: bytes,
    cosign_did: str,
) -> dict[str, Any]:
    """One ARP receipt for ``subject_did``, co-signed by ``cosign_did``.

    For the honest visitor ``counterparty_did`` / ``cosign_did`` are a DISTINCT
    third party. For the wash visitor they are the subject itself (self-dealing):
    the co-signature verifies, but ``nanda-rep/0.2`` only credits a co-sign from a
    counterparty *distinct* from the subject, so it is not corroboration.
    """
    action: dict[str, Any] = {
        "category": "purchase",
        "human_summary": f"purchase #{n}",
        "outcome": "completed",
        "counterparty_did": counterparty_did,
    }
    receipt: dict[str, Any] = {
        "version": "arp/0.1",
        "receipt_id": f"{n:08d}-1111-4111-8111-111111111111",
        "issuer_did": subject_did,
        "principal_did": subject_did,
        "issued_at": f"2026-06-07T00:00:0{n}Z",
        "action": action,
        "signature": "AA==",
    }
    receipt["evidence"] = {
        "witness_signatures": [
            cosign_receipt(receipt, signing_key_bytes=cosign_sk, witness_did=cosign_did)
        ]
    }
    return receipt


def honest_receipts() -> list[dict[str, Any]]:
    """Three receipts, each co-signed by a DISTINCT counterparty (corroborated)."""
    return [
        _receipt(
            n=i,
            subject_did=HONEST_DID,
            counterparty_did=COUNTERPARTY_DID,
            cosign_sk=COUNTERPARTY_SK,
            cosign_did=COUNTERPARTY_DID,
        )
        for i in range(3)
    ]


def wash_receipts() -> list[dict[str, Any]]:
    """Three SELF-DEALT receipts: the agent is its own counterparty + witness.

    The co-signatures verify, but the counterparty is not distinct from the
    subject, so nanda-rep/0.2 does not count any of them as corroboration.
    """
    return [
        _receipt(
            n=i,
            subject_did=WASH_DID,
            counterparty_did=WASH_DID,
            cosign_sk=WASH_SK,
            cosign_did=WASH_DID,
        )
        for i in range(3)
    ]


def city_a_issues(
    *, subject_did: str, receipts: list[dict[str, Any]], cred_id: str
) -> dict[str, Any]:
    """City A: build a nanda-rep/0.2 ledger + mint a signed PARC over it.

    Returns the portable artifact ``{"vc": ..., "ledger": ...}`` the visiting agent
    carries to City B. (The ledger here is the inline-receipts ledger that travels
    WITH the agent — it is not a handle into A's store.)
    """
    ledger = build_ledger(
        subject=subject_did,
        receipts=receipts,
        is_valid=always_valid,
        as_of=VALID_FROM,
        method="nanda-rep/0.2",
    )
    vc = build_reputation_credential(
        ledger=ledger,
        issuer_sk=CITY_A_SK,
        issuer_did=CITY_A_DID,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        credential_id=cred_id,
    )
    return {"vc": vc, "ledger": ledger}


def city_b_admits(presented_artifact_json: str) -> AdmissionResult:
    """City B: decide admission from the agent's PRESENTED artifact only.

    ``presented_artifact_json`` is a JSON string the agent hands over — City B has
    no other channel to City A. We ``json.loads`` it here so this function holds NO
    reference to any of City A's in-memory objects; it can only read what was on the
    wire. Recomputation runs over the inline receipts the agent presented; the signed
    ``behavioral_merkle_root`` + ``receipt_count`` pin them, so tampering fails.
    """
    artifact = json.loads(presented_artifact_json)
    policy = AdmissionPolicy(
        trusted_issuers={CITY_A_DID},
        required_scoring_method=SCORING_METHOD_V2,  # nanda-rep/0.2 only
        min_reputation_score=MIN_SCORE,
        require_recomputation=True,
    )
    return admit(
        artifact["vc"],
        policy=policy,
        ledger=artifact["ledger"],
        is_valid=always_valid,
        now=NOW,
    )


def demonstrate_naive_gate_would_admit(presented_artifact_json: str) -> AdmissionResult:
    """The load-bearing contrast: a NAIVE City B admitting on nanda-rep/0.1.

    A naive verifier trusts the un-corroborated 0.1 score and (like every chapter
    that does not recompute) skips recomputation. We re-issue the SAME receipts as a
    0.1-method credential and run that naive gate. The wash agent's 0.1 score is just
    as high as an honest agent's, so the naive gate ADMITS it — exactly the hole that
    nanda-rep/0.2 closes.
    """
    artifact = json.loads(presented_artifact_json)
    receipts = artifact["ledger"]["receipts"]
    subject = artifact["vc"]["credentialSubject"]["id"]
    naive_ledger = build_ledger(
        subject=subject,
        receipts=receipts,
        is_valid=always_valid,
        as_of=VALID_FROM,
        method="nanda-rep/0.1",
    )
    naive_vc = build_reputation_credential(
        ledger=naive_ledger,
        issuer_sk=CITY_A_SK,
        issuer_did=CITY_A_DID,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        credential_id="urn:uuid:naive-0.1-credential",
    )
    naive_policy = AdmissionPolicy(
        trusted_issuers={CITY_A_DID},
        required_scoring_method="nanda-rep/0.1",
        min_reputation_score=MIN_SCORE,
        require_recomputation=False,  # the naive chapter does not recompute
    )
    return admit(naive_vc, policy=naive_policy, now=NOW)


def _score_01(receipts: list[dict[str, Any]]) -> float:
    """The naive nanda-rep/0.1 score (no corroboration) — for the contrast column."""
    return reputation_score(receipts, is_valid=always_valid)


def build_fixture() -> dict[str, Any]:
    """Build the full, deterministic demo state for a Python-free frontend.

    The fixture carries everything a browser needs to render the demo AND
    re-verify the Ed25519 signatures itself: the full signed PARC per agent, the
    recomputed facet (both 0.2 and the naive 0.1 score, for the contrast), sample
    receipts, and City B's per-agent decision. Stable across runs (fixed seeds).
    """
    agents: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    visitors = [
        ("honest-visitor", HONEST_DID, honest_receipts(), "urn:uuid:parc-honest", True),
        ("wash-visitor", WASH_DID, wash_receipts(), "urn:uuid:parc-wash", False),
    ]
    for persona, subject_did, receipts, cred_id, corroborated in visitors:
        artifact = city_a_issues(subject_did=subject_did, receipts=receipts, cred_id=cred_id)
        presented = json.dumps(artifact, sort_keys=True)
        result = city_b_admits(presented)

        subj = artifact["vc"]["credentialSubject"]
        score_02 = float(subj["reputation_score"])
        score_01 = _score_01(receipts)
        agents.append(
            {
                "id": subject_did,
                "persona": persona,
                "self_dealing": not corroborated,
                "credential": artifact["vc"],  # the full signed PARC (re-verifiable)
                "facet": {
                    "behavioral_merkle_root": subj["behavioral_merkle_root"],
                    "scoring_method": subj["scoring_method"],
                    "reputation_score": score_02,
                    "reputation_score_0_1": score_01,
                    "corroboration_rate": float(subj["corroboration_rate"]),
                    "validity_rate": float(subj["validity_rate"]),
                    "receipt_count": int(subj["receipt_count"]),
                },
                "sample_receipts": receipts,
            }
        )

        if result.ok:
            line = (
                f"{persona} admitted: corroborated nanda-rep/0.2 "
                f"score {score_02:.1f} >= {MIN_SCORE}"
            )
        else:
            line = (
                f"{persona} rejected ({result.stage}): nanda-rep/0.2 score {score_02:.1f} "
                f"< {MIN_SCORE} -- its high 0.1 score ({score_01:.1f}) is un-corroborated "
                f"self-dealing"
            )
        decisions.append(
            {
                "agent": subject_did,
                "persona": persona,
                "admitted": result.ok,
                "reason": result.stage,
                "threshold": MIN_SCORE,
                "scoring_method": SCORING_METHOD_V2,
                "human": line,
            }
        )

    return {
        "demo": "two-city PARC admission",
        "headline": "reputation that travels, collusion that can't",
        "wire": "parc/0.1",
        "now": NOW,
        "cities": {
            "A": {"did": CITY_A_DID, "role": "issuer"},
            "B": {
                "did": CITY_B_DID,
                "role": "verifier",
                "policy": {
                    "trusted_issuers": [CITY_A_DID],
                    "required_scoring_method": SCORING_METHOD_V2,
                    "min_reputation_score": MIN_SCORE,
                    "require_recomputation": True,
                },
            },
        },
        "agents": agents,
        "decisions": decisions,
    }


def main() -> None:
    visitors = [
        ("honest-visitor", HONEST_DID, honest_receipts(), "urn:uuid:parc-honest"),
        ("wash-visitor", WASH_DID, wash_receipts(), "urn:uuid:parc-wash"),
    ]

    print("headline: reputation that travels, collusion that can't")
    print(f"City A (issuer)  : {CITY_A_DID}")
    print(f"City B (verifier): {CITY_B_DID}")
    print(f"City B policy    : trust={{A}}  method=nanda-rep/0.2  min_score={MIN_SCORE}")
    print()
    print("City B admission decisions (from credential + inline receipts only):")
    header = (
        f"{'agent':<15} {'issuer=A':<8} {'0.2-score':>9} {'0.1-score':>9} "
        f"{'corrob':>6}  {'decision':<9} {'reason':<18}"
    )
    print(header)
    print("-" * len(header))

    for persona, subject_did, receipts, cred_id in visitors:
        artifact = city_a_issues(subject_did=subject_did, receipts=receipts, cred_id=cred_id)
        # Serialize, sever the in-memory link, and present to City B.
        presented = json.dumps(artifact, sort_keys=True)
        result = city_b_admits(presented)

        subj = artifact["vc"]["credentialSubject"]
        score_02 = float(subj["reputation_score"])
        score_01 = _score_01(receipts)
        corrob = float(subj["corroboration_rate"])
        decision = "ADMIT" if result.ok else "REJECT"
        print(
            f"{persona:<15} {'yes':<8} {score_02:>9.1f} {score_01:>9.1f} "
            f"{corrob:>6.2f}  {decision:<9} {result.stage:<18}"
        )

    # --- the load-bearing assertion ------------------------------------------
    print()
    wash_artifact = city_a_issues(
        subject_did=WASH_DID, receipts=wash_receipts(), cred_id="urn:uuid:parc-wash"
    )
    wash_presented = json.dumps(wash_artifact, sort_keys=True)

    real = city_b_admits(wash_presented)
    naive = demonstrate_naive_gate_would_admit(wash_presented)
    naive_decision = "ADMIT" if naive.ok else "REJECT"
    real_decision = "ADMIT" if real.ok else "REJECT"
    print("load-bearing contrast for wash-visitor (same receipts, same threshold):")
    print(f"  naive City B' on nanda-rep/0.1 : {naive_decision} ({naive.stage})")
    print(f"  real  City B  on nanda-rep/0.2 : {real_decision} ({real.stage})")

    assert naive.ok and naive.stage == "admitted", "naive 0.1 gate must admit wash"
    assert not real.ok and real.stage == "below_threshold", "0.2 gate must reject wash"

    # honest visitor is admitted by the real gate
    honest_artifact = city_a_issues(
        subject_did=HONEST_DID, receipts=honest_receipts(), cred_id="urn:uuid:parc-honest"
    )
    honest_res = city_b_admits(json.dumps(honest_artifact, sort_keys=True))
    assert honest_res.ok and honest_res.stage == "admitted", "honest must be admitted"

    print()
    print("OK: honest admitted; wash rejected by 0.2 but would be admitted by 0.1.")


if __name__ == "__main__":
    main()
