"""Three-city economy demo — "one passport, three worlds".

A single agent earns reputation transacting across three *different kinds* of trust
domain and carries one PARC through all of them:

  * **City A — community chapter** (low admission bar)
  * **City B — marketplace** (medium bar)
  * **City C — enterprise / regulated gate** (high bar)

The three things this shows at once:

  * **Transactions** — the traveler accumulates cross-domain ARP receipts; its ledger
    grows from 12 → 26 → 40 as it moves A → B → C.
  * **Portability** — the *same* corroborated ``nanda-rep/0.2`` reputation compounds
    (60 → 130 → 200) and is what unlocks the enterprise gate. Shown cold would never
    work: the traveler's community-only ledger (60) is **rejected** at City C's bar of
    180. Accumulated reputation is the key.
  * **Security** — a **wash-trader** that self-deals to a high naive score is severed
    to 0 and rejected at the *lowest* bar (City A). You cannot fake your way in.

And the answer to "what happens when the ledger gets too big": at the enterprise gate
the 40-receipt ledger is **not** handed over. The traveler presents the signed PARC
(score + root) and **reveals only 3 receipts + Merkle inclusion proofs**; City C
confirms those 3 sit under the signed root WITHOUT seeing the other 37 (selective
disclosure, ``sm_parc.disclosure``).

The honest layer-split: the *score* is the signed aggregate over the whole committed
root (collusion severance needs the whole graph); the *revealed subset* proves which
transactions happened. The two are separate — see ``THREATMODEL.md``.

Run:  python examples/three_city_economy.py
"""

from __future__ import annotations

import hashlib
from typing import Any

from sm_arp.vrp import (
    SCORING_METHOD_V2,
    build_ledger,
    cosign_receipt,
    did_from_sk,
    reputation_score,
)

from sm_parc import (
    AdmissionPolicy,
    AdmissionResult,
    admit,
    build_reputation_credential,
    inclusion_proof,
    verify_inclusion,
)
from sm_parc.credential import did_from_private_key

# --- fixed identities (deterministic: sha256 of a stable label) --------------
CITY_A_SK = hashlib.sha256(b"3city:city-A-community").digest()
CITY_B_SK = hashlib.sha256(b"3city:city-B-marketplace").digest()
CITY_C_SK = hashlib.sha256(b"3city:city-C-enterprise").digest()
TRAVELER_SK = hashlib.sha256(b"3city:traveler").digest()
WASH_SK = hashlib.sha256(b"3city:wash-trader").digest()

CITY_A_DID = did_from_private_key(CITY_A_SK)
CITY_B_DID = did_from_private_key(CITY_B_SK)
CITY_C_DID = did_from_private_key(CITY_C_SK)
TRAVELER_DID = did_from_sk(TRAVELER_SK)
WASH_DID = did_from_sk(WASH_SK)

VALID_FROM = "2026-06-07T00:00:00Z"
VALID_UNTIL = "2026-07-07T00:00:00Z"
NOW = "2026-06-08T00:00:00Z"

# The journey: the ledger the traveler presents at each city, and that city's bar.
# Receipts 0-11 are earned in the community, 12-25 in the marketplace, 26-39 at the
# enterprise — so the ledger the traveler carries grows as it travels.
PHASE_A, PHASE_B, TOTAL = 12, 26, 40
VENUES = ["community", "marketplace", "enterprise"]

CITIES = {
    "A": {"name": "community chapter", "did": CITY_A_DID, "bar": 10.0, "ledger_size": PHASE_A},
    "B": {"name": "marketplace", "did": CITY_B_DID, "bar": 100.0, "ledger_size": PHASE_B},
    "C": {"name": "enterprise gate", "did": CITY_C_DID, "bar": 180.0, "ledger_size": TOTAL},
}

# Which 3 of the 40 receipts the traveler chooses to reveal at the enterprise gate —
# one representative deal from each venue.
REVEALED_INDICES = [5, 20, 35]


def always_valid(_receipt: dict[str, Any]) -> bool:
    """Stand-in for the ARP verifier — here every receipt's signature is valid."""
    return True


def _venue_for(n: int) -> str:
    return VENUES[0] if n < PHASE_A else VENUES[1] if n < PHASE_B else VENUES[2]


def _receipt(
    *, n: int, subject_did: str, counterparty_sk: bytes, counterparty_did: str
) -> dict[str, Any]:
    """One ARP receipt for ``subject_did`` co-signed by ``counterparty_did``."""
    receipt: dict[str, Any] = {
        "version": "arp/0.1",
        "receipt_id": f"{n:08d}-1111-4111-8111-111111111111",
        "issuer_did": subject_did,
        "principal_did": subject_did,
        "issued_at": f"2026-06-07T00:{n // 60:02d}:{n % 60:02d}Z",
        "action": {
            "category": "purchase",
            "human_summary": f"purchase #{n} in the {_venue_for(n)}",
            "outcome": "completed",
            "counterparty_did": counterparty_did,
        },
        "signature": "AA==",
    }
    receipt["evidence"] = {
        "witness_signatures": [
            cosign_receipt(receipt, signing_key_bytes=counterparty_sk, witness_did=counterparty_did)
        ]
    }
    return receipt


def traveler_receipts() -> list[dict[str, Any]]:
    """40 corroborated receipts, each co-signed by a DISTINCT cross-domain counterparty."""
    out: list[dict[str, Any]] = []
    for n in range(TOTAL):
        cp_sk = hashlib.sha256(b"3city:counterparty:%d" % n).digest()
        out.append(
            _receipt(
                n=n,
                subject_did=TRAVELER_DID,
                counterparty_sk=cp_sk,
                counterparty_did=did_from_sk(cp_sk),
            )
        )
    return out


def wash_receipts() -> list[dict[str, Any]]:
    """12 SELF-DEALT receipts: the wash-trader is its own counterparty + witness."""
    return [
        _receipt(n=n, subject_did=WASH_DID, counterparty_sk=WASH_SK, counterparty_did=WASH_DID)
        for n in range(PHASE_A)
    ]


def home_issues(
    *, subject_did: str, receipts: list[dict[str, Any]], cred_id: str
) -> dict[str, Any]:
    """The traveler's home community (City A) signs a nanda-rep/0.2 PARC over its ledger."""
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


def admit_full(*, bar: float, vc: dict[str, Any], ledger: dict[str, Any]) -> AdmissionResult:
    """An early-stage gate (community, marketplace): the small ledger is presented in
    full and the gate recomputes it."""
    policy = AdmissionPolicy(
        trusted_issuers={CITY_A_DID},
        required_scoring_method=SCORING_METHOD_V2,
        min_reputation_score=bar,
        require_recomputation=True,
    )
    return admit(vc, policy=policy, ledger=ledger, is_valid=always_valid, now=NOW)


def admit_with_disclosure(
    *, bar: float, vc: dict[str, Any], revealed: list[dict[str, Any]], proofs: list[dict[str, Any]]
) -> tuple[AdmissionResult, bool]:
    """The enterprise gate: the 40-receipt ledger is NOT presented. The gate admits on
    the signed aggregate score (no recomputation) and spot-checks the revealed receipts
    via Merkle inclusion proofs against the credential's signed root.

    Returns the admission result and whether every revealed receipt proved inclusion.
    """
    policy = AdmissionPolicy(
        trusted_issuers={CITY_A_DID},
        required_scoring_method=SCORING_METHOD_V2,
        min_reputation_score=bar,
        require_recomputation=False,  # selective disclosure: no full ledger handed over
    )
    result = admit(vc, policy=policy, now=NOW)
    root = vc["credentialSubject"]["behavioral_merkle_root"]
    disclosed_ok = all(verify_inclusion(r, p, root) for r, p in zip(revealed, proofs, strict=True))
    return result, disclosed_ok


def _score_01(receipts: list[dict[str, Any]]) -> float:
    return reputation_score(receipts, is_valid=always_valid)


def build_fixture() -> dict[str, Any]:
    """Deterministic demo state for a Python-free frontend: the journey, the compounding
    score, the wash-trader rejection, the cold-at-C counterfactual, and the selective
    disclosure at the enterprise gate (revealed receipts + inclusion proofs)."""
    receipts = traveler_receipts()

    # --- the A -> B -> C journey -----------------------------------------------
    journey: list[dict[str, Any]] = []
    for key in ("A", "B", "C"):
        city = CITIES[key]
        size = int(city["ledger_size"])
        artifact = home_issues(
            subject_did=TRAVELER_DID, receipts=receipts[:size], cred_id=f"urn:uuid:3city-{key}"
        )
        score = float(artifact["vc"]["credentialSubject"]["reputation_score"])
        if key == "C":
            revealed = [receipts[i] for i in REVEALED_INDICES]
            proofs = [inclusion_proof(receipts[:size], receipt=r) for r in revealed]
            result, disclosed_ok = admit_with_disclosure(
                bar=float(city["bar"]), vc=artifact["vc"], revealed=revealed, proofs=proofs
            )
            disclosure = {
                "presented_receipts": len(revealed),
                "total_receipts": size,
                "all_inclusion_proofs_verify": disclosed_ok,
                "revealed": [
                    {
                        "receipt_id": r["receipt_id"],
                        "summary": r["action"]["human_summary"],
                        "venue": _venue_for(REVEALED_INDICES[j]),
                        "proof": proofs[j],
                        # the full receipt travels so a browser can recompute the leaf
                        # hash and verify the inclusion proof client-side.
                        "receipt": r,
                    }
                    for j, r in enumerate(revealed)
                ],
                "behavioral_merkle_root": artifact["vc"]["credentialSubject"][
                    "behavioral_merkle_root"
                ],
            }
        else:
            result = admit_full(
                bar=float(city["bar"]), vc=artifact["vc"], ledger=artifact["ledger"]
            )
            disclosure = None
        journey.append(
            {
                "city": key,
                "name": city["name"],
                "did": city["did"],
                "bar": float(city["bar"]),
                "ledger_size": size,
                "reputation_score": score,
                "admitted": result.ok,
                "reason": result.stage,
                "credential": artifact["vc"],
                "disclosure": disclosure,
            }
        )

    # --- counterfactual: the traveler shown COLD at the enterprise -------------
    cold = home_issues(
        subject_did=TRAVELER_DID, receipts=receipts[:PHASE_A], cred_id="urn:uuid:3city-cold"
    )
    cold_result = admit_full(bar=float(CITIES["C"]["bar"]), vc=cold["vc"], ledger=cold["ledger"])

    # --- security: the wash-trader at the LOWEST bar ---------------------------
    wash = wash_receipts()
    wash_artifact = home_issues(subject_did=WASH_DID, receipts=wash, cred_id="urn:uuid:3city-wash")
    wash_result = admit_full(
        bar=float(CITIES["A"]["bar"]), vc=wash_artifact["vc"], ledger=wash_artifact["ledger"]
    )

    return {
        "demo": "three-city economy",
        "headline": "one passport, three worlds",
        "wire": "parc/0.1",
        "now": NOW,
        "cities": {
            k: {"name": v["name"], "did": v["did"], "bar": v["bar"]} for k, v in CITIES.items()
        },
        "traveler": TRAVELER_DID,
        "journey": journey,
        "counterfactual": {
            "label": "traveler shown cold at the enterprise (community-only ledger)",
            "ledger_size": PHASE_A,
            "reputation_score": float(cold["vc"]["credentialSubject"]["reputation_score"]),
            "bar": float(CITIES["C"]["bar"]),
            "admitted": cold_result.ok,
            "reason": cold_result.stage,
        },
        "security": {
            "label": "wash-trader rejected at the lowest bar (community)",
            "naive_0_1_score": _score_01(wash),
            "reputation_score": float(wash_artifact["vc"]["credentialSubject"]["reputation_score"]),
            "bar": float(CITIES["A"]["bar"]),
            "admitted": wash_result.ok,
            "reason": wash_result.stage,
        },
    }


def main() -> None:
    fx = build_fixture()
    print("headline: one passport, three worlds")
    print(f"traveler: {TRAVELER_DID}")
    print()
    header = f"{'stop':<22} {'bar':>6} {'ledger':>7} {'score':>7}  {'decision':<8} {'reason'}"
    print(header)
    print("-" * len(header))
    for stop in fx["journey"]:
        decision = "ADMIT" if stop["admitted"] else "REJECT"
        label = f"{stop['city']} · {stop['name']}"
        print(
            f"{label:<22} {stop['bar']:>6.0f} {stop['ledger_size']:>7} "
            f"{stop['reputation_score']:>7.0f}  {decision:<8} {stop['reason']}"
        )

    cf, sec = fx["counterfactual"], fx["security"]
    print()
    print(
        f"portability is load-bearing: same agent shown COLD at the enterprise "
        f"(score {cf['reputation_score']:.0f} < {cf['bar']:.0f}) -> "
        f"{'ADMIT' if cf['admitted'] else 'REJECT'} ({cf['reason']})"
    )
    print(
        f"security: wash-trader naive 0.1 score {sec['naive_0_1_score']:.0f} but "
        f"corroborated 0.2 score {sec['reputation_score']:.0f} < {sec['bar']:.0f} -> "
        f"{'ADMIT' if sec['admitted'] else 'REJECT'} ({sec['reason']})"
    )

    disc = fx["journey"][2]["disclosure"]
    print(
        f"selective disclosure at the enterprise: revealed {disc['presented_receipts']} of "
        f"{disc['total_receipts']} receipts; all inclusion proofs verify = "
        f"{disc['all_inclusion_proofs_verify']}"
    )

    # --- load-bearing assertions ----------------------------------------------
    assert [s["admitted"] for s in fx["journey"]] == [True, True, True], "traveler admitted A,B,C"
    assert fx["journey"][2]["disclosure"]["all_inclusion_proofs_verify"], "disclosed receipts prove"
    assert not cf["admitted"] and cf["reason"] == "below_threshold", "cold traveler rejected at C"
    assert not sec["admitted"] and sec["reason"] == "below_threshold", "wash-trader rejected at A"
    assert sec["naive_0_1_score"] > sec["bar"], (
        "wash 0.1 score WOULD clear the bar (the whole point)"
    )
    print()
    print("OK: portability compounds A->B->C; cold rejected; wash rejected; 3-of-40 disclosed.")


if __name__ == "__main__":
    main()
