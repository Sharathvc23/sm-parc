"""Mint + admit a PARC credential over a corroborated nanda-rep/0.2 facet.

End to end:

  1. an agent earns corroborated ARP receipts (each co-signed by a distinct
     counterparty — the nanda-rep/0.2 corroboration signal);
  2. a chapter builds a ``nanda-rep/0.2`` Receipts Ledger and mints a ``parc/0.1``
     ReputationCredential (a W3C VC) over it;
  3. a *different* chapter admits the agent by verifying the issuer signature and
     recomputing the corroborated 0.2 score itself — never trusting the issuer's
     server.

Then the same demo shows the gate rejecting an un-corroborated (wash-trading)
agent whose 0.2 score is severed to zero.

Run:  python examples/mint_and_admit.py
"""

from __future__ import annotations

import hashlib
from typing import Any

from sm_arp.vrp import build_ledger, cosign_receipt, did_from_sk

from sm_parc import AdmissionPolicy, admit, build_reputation_credential, did_from_private_key

CHAPTER_SK = hashlib.sha256(b"issuing-chapter").digest()
CHAPTER_DID = did_from_private_key(CHAPTER_SK)
AGENT_SK = hashlib.sha256(b"acting-agent").digest()
AGENT_DID = did_from_sk(AGENT_SK)
COUNTERPARTY_SK = hashlib.sha256(b"a-distinct-counterparty").digest()
COUNTERPARTY_DID = did_from_sk(COUNTERPARTY_SK)


def always_valid(_receipt: dict[str, Any]) -> bool:
    """Stand-in for the ARP verifier (verify_receipt) — here every receipt is valid."""
    return True


def receipt(n: int, *, corroborated: bool) -> dict[str, Any]:
    action: dict[str, Any] = {
        "category": "purchase",
        "human_summary": f"purchase #{n}",
        "outcome": "completed",
    }
    if corroborated:
        action["counterparty_did"] = COUNTERPARTY_DID
    r: dict[str, Any] = {
        "version": "arp/0.1",
        "receipt_id": f"{n:08d}-1111-4111-8111-111111111111",
        "issuer_did": AGENT_DID,
        "principal_did": AGENT_DID,
        "issued_at": f"2026-06-07T00:00:0{n}Z",
        "action": action,
        "signature": "AA==",
    }
    if corroborated:
        r["evidence"] = {
            "witness_signatures": [cosign_receipt(r, signing_key_bytes=COUNTERPARTY_SK)]
        }
    return r


def mint(*, corroborated: bool) -> dict[str, Any]:
    ledger = build_ledger(
        subject=AGENT_DID,
        receipts=[receipt(i, corroborated=corroborated) for i in range(3)],
        is_valid=always_valid,
        as_of="2026-06-07T00:00:00Z",
        method="nanda-rep/0.2",
    )
    vc = build_reputation_credential(
        ledger=ledger,
        issuer_sk=CHAPTER_SK,
        valid_from="2026-06-07T00:00:00Z",
        valid_until="2026-07-07T00:00:00Z",
        credential_id="urn:uuid:demo-parc-1",
    )
    return {"ledger": ledger, "vc": vc}


def main() -> None:
    # The admitting chapter trusts the issuer's did (in practice via an sm-conformance
    # badge) and requires a real corroborated score.
    policy = AdmissionPolicy(trusted_issuers={CHAPTER_DID}, min_reputation_score=1.0)

    honest = mint(corroborated=True)
    res = admit(
        honest["vc"],
        policy=policy,
        ledger=honest["ledger"],
        is_valid=always_valid,
        now="2026-06-08T00:00:00Z",
    )
    print("wire id          : parc/0.1")
    print("scoring method   :", honest["vc"]["credentialSubject"]["scoring_method"])
    print("honest agent     : score", honest["ledger"]["reputation_score"], end=" ")
    print("corroboration", honest["ledger"]["corroboration_rate"])
    print("  -> admission   :", res.stage, "(ok)" if res.ok else "(REJECTED)")
    assert res.ok and res.stage == "admitted"

    # A wash-trading agent issues the same receipts with NO distinct corroboration.
    # nanda-rep/0.2 severs the un-corroborated score to 0, so it fails the gate.
    wash = mint(corroborated=False)
    res = admit(
        wash["vc"],
        policy=policy,
        ledger=wash["ledger"],
        is_valid=always_valid,
        now="2026-06-08T00:00:00Z",
    )
    print("wash-trade agent : score", wash["ledger"]["reputation_score"], end=" ")
    print("corroboration", wash["ledger"]["corroboration_rate"])
    print("  -> admission   :", res.stage, "(ok)" if res.ok else "(REJECTED)")
    assert not res.ok and res.stage == "below_threshold"


if __name__ == "__main__":
    main()
