"""Pointer-mode PARC admission demo — "the gate severs the ring itself".

The companion to ``two_city_admission.py``. That demo is INLINE mode: a credential
carries the subject's own receipts, City B recomputes them offline, and self-dealing
is severed by the corroboration filter. But an inline credential is single-subject —
its corroboration graph is a star, never a strongly-connected ring — so it
*structurally cannot* show an N-party Sybil ring. Severance is a property of the
whole community graph, and the inline credential never carries that graph.

POINTER mode closes that gap. The credential names a **published community ledger**
(``credentialSubject.ledger_uri``) hosted by a third party; City B FETCHES it,
checks it hashes to the credential's signed ``behavioral_merkle_root`` (so the host
cannot serve a different ledger than the issuer committed to), and then **re-runs the
collusion severance over the full graph itself** — the gate derives the subject's
severed score (:func:`sm_parc.subject_severed_score`), it does not trust an attested one.

Three cases, with the SAME ring member ``R0`` carrying the load:

  * ``honest-visitor`` (an anchor member) over City A's complete ledger →
    survives severance → **admitted**.
  * ``ring-visitor`` (``R0``, a member of an isolated dense ring) over City A's
    complete ledger → the gate, seeing the honest anchor the ring is isolated from,
    **severs the ring to 0** → **rejected**. City B never trusted A's number; it
    re-derived it.
  * ``laundered-visitor`` (the SAME ``R0``, same receipts) over a *colluding* issuer
    City C's **curated** ledger that publishes the ring WITHOUT the anchor → the ring
    is now the largest component, nothing is severed, the gate recomputes HIGH →
    **admitted (wrongly)**.

The honest residual, shown not asserted: ``ring-visitor`` and ``laundered-visitor``
are the identical agent with identical receipts. The ONLY difference is which ledger
the issuer published. Pointer mode catches a lazy-but-honest issuer; it cannot catch
a colluding one who curates what it publishes. The gate sees the published ledger,
never what was left out of it. That is the ``ledger completeness`` residual — and the
reason the notary / multi-issuer-attestation layer exists. See ``THREATMODEL.md``.

Run:  python examples/published_ledger_admission.py
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
    reputation_score_v2,
)

from sm_parc import (
    AdmissionPolicy,
    AdmissionResult,
    admit_over_published_ledger,
    build_reputation_credential,
    subject_severed_score,
)
from sm_parc.credential import did_from_private_key

# --- fixed identities (deterministic: sha256 of a stable label) --------------
# Two issuers with DIFFERENT did:key identities (A honest, C colluding), a
# verifier B, a 4-member honest anchor, and a 3-member isolated ring.
CITY_A_SK = hashlib.sha256(b"pub-ledger-demo:city-A-honest-issuer").digest()
CITY_B_SK = hashlib.sha256(b"pub-ledger-demo:city-B-verifier").digest()
CITY_C_SK = hashlib.sha256(b"pub-ledger-demo:city-C-colluding-issuer").digest()

CITY_A_DID = did_from_private_key(CITY_A_SK)
CITY_B_DID = did_from_private_key(CITY_B_SK)
CITY_C_DID = did_from_private_key(CITY_C_SK)

ANCHOR_SEEDS = [f"pub-ledger-demo:anchor-{i}".encode() for i in range(4)]
RING_SEEDS = [f"pub-ledger-demo:ring-{i}".encode() for i in range(3)]

ANCHOR_SK = {s: hashlib.sha256(s).digest() for s in ANCHOR_SEEDS}
RING_SK = {s: hashlib.sha256(s).digest() for s in RING_SEEDS}
ANCHOR_DID = {s: did_from_sk(ANCHOR_SK[s]) for s in ANCHOR_SEEDS}
RING_DID = {s: did_from_sk(RING_SK[s]) for s in RING_SEEDS}

# The honest visitor is an anchor member; the ring/laundered visitor is ring member 0.
HONEST_DID = ANCHOR_DID[ANCHOR_SEEDS[0]]
RING_VISITOR_DID = RING_DID[RING_SEEDS[0]]

# Published-ledger URIs (the third-party host City B fetches from).
COMMUNITY_URI = "https://city-a.example/ledgers/community"
CURATED_URI = "https://city-c.example/ledgers/curated"

VALID_FROM = "2026-06-07T00:00:00Z"
VALID_UNTIL = "2026-07-07T00:00:00Z"
NOW = "2026-06-08T00:00:00Z"

# City B's threshold. An anchor member's severed score is 15.0 (3 purchases x 5.0);
# a ring member's severed score over the COMPLETE ledger is 0.0; over the CURATED
# (anchor-less) ledger it is 10.0 (2 purchases x 5.0). 5.0 separates all three.
MIN_SCORE = 5.0


def always_valid(_receipt: dict[str, Any]) -> bool:
    """Stand-in for the ARP verifier — here every receipt's signature is valid."""
    return True


def _clique(
    seeds: list[bytes],
    sk_map: dict[bytes, bytes],
    did_map: dict[bytes, str],
    start: int,
) -> tuple[list[dict[str, Any]], int]:
    """Receipts for a complete corroboration clique among ``seeds`` (every ordered
    pair co-signs), numbered from ``start``. Returns the receipts and the next index.
    """
    out: list[dict[str, Any]] = []
    n = start
    for a in seeds:
        for b in seeds:
            if a == b:
                continue
            r = {
                "version": "arp/0.1",
                "receipt_id": f"{n:08d}-1111-4111-8111-111111111111",
                "issuer_did": did_map[a],
                "principal_did": did_map[a],
                "issued_at": f"2026-06-07T00:{(n // 60) % 60:02d}:{n % 60:02d}Z",
                "action": {
                    "category": "purchase",
                    "human_summary": f"purchase #{n}",
                    "outcome": "completed",
                    "counterparty_did": did_map[b],
                },
                "signature": "AA==",
            }
            r["evidence"] = {
                "witness_signatures": [
                    cosign_receipt(r, signing_key_bytes=sk_map[b], witness_did=did_map[b])
                ]
            }
            out.append(r)
            n += 1
    return out, n


def anchor_receipts() -> list[dict[str, Any]]:
    """The honest anchor: a complete 4-clique of mutually-corroborating members."""
    receipts, _ = _clique(ANCHOR_SEEDS, ANCHOR_SK, ANCHOR_DID, start=0)
    return receipts


def ring_receipts() -> list[dict[str, Any]]:
    """The isolated Sybil ring: a complete 3-clique that corroborates ONLY itself.

    No receipt crosses to the anchor, so over the complete community ledger the ring
    is an isolated dense component and ``nanda-rep/0.2`` severs it.
    """
    receipts, _ = _clique(RING_SEEDS, RING_SK, RING_DID, start=1000)
    return receipts


def community_ledger() -> dict[str, Any]:
    """City A's COMPLETE community ledger: honest anchor + isolated ring."""
    return build_ledger(
        subject=HONEST_DID,
        receipts=anchor_receipts() + ring_receipts(),
        is_valid=always_valid,
        as_of=VALID_FROM,
        method="nanda-rep/0.2",
    )


def curated_ledger() -> dict[str, Any]:
    """City C's CURATED ledger: the SAME ring, published WITHOUT the anchor.

    Severance treats the largest strongly-connected component as the honest core, so
    with no anchor present the ring is never severed — it recomputes HIGH. This is the
    completeness residual: the gate faithfully recomputes what was published; it cannot
    see what was withheld.
    """
    return build_ledger(
        subject=RING_VISITOR_DID,
        receipts=ring_receipts(),
        is_valid=always_valid,
        as_of=VALID_FROM,
        method="nanda-rep/0.2",
    )


def issue_pointer_credential(
    *,
    issuer_sk: bytes,
    issuer_did: str,
    subject_did: str,
    receipts: list[dict[str, Any]],
    ledger_uri: str,
    cred_id: str,
) -> dict[str, Any]:
    """Mint a signed POINTER-mode PARC for ``subject_did`` over ``receipts``.

    The credential's facet names ``ledger_uri`` (the published ledger the verifier
    fetches) and commits the root over ``receipts``; the receipts are NOT inlined. We
    build a per-subject ledger so ``credentialSubject.id`` is the visitor — the root is
    over the receipts only, so it matches the published ledger regardless of which
    subject label that copy carries.
    """
    ledger = build_ledger(
        subject=subject_did,
        receipts=receipts,
        is_valid=always_valid,
        as_of=VALID_FROM,
        method="nanda-rep/0.2",
    )
    return build_reputation_credential(
        ledger=ledger,
        issuer_sk=issuer_sk,
        issuer_did=issuer_did,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        credential_id=cred_id,
        ledger_uri=ledger_uri,
    )


def published_store() -> dict[str, dict[str, Any]]:
    """The third-party ledger host City B fetches from: URI → published ledger."""
    return {COMMUNITY_URI: community_ledger(), CURATED_URI: curated_ledger()}


def city_b_admits(vc: dict[str, Any], store: dict[str, dict[str, Any]]) -> AdmissionResult:
    """City B: fetch the named ledger, re-verify + re-sever it, decide admission.

    City B trusts the did:key of BOTH issuers (A and the colluding C) — the laundering
    happens *inside* the allowlist, which is the whole point of the residual.
    """
    policy = AdmissionPolicy(
        trusted_issuers={CITY_A_DID, CITY_C_DID},
        required_scoring_method=SCORING_METHOD_V2,
        min_reputation_score=MIN_SCORE,
    )
    return admit_over_published_ledger(
        vc, policy=policy, fetch=lambda uri: store[uri], is_valid=always_valid, now=NOW
    )


def _cases() -> list[dict[str, Any]]:
    """Demo cases. Receipts are pulled from the published store by ``ledger_uri`` at
    use-time, so the credential commits the exact root the gate will fetch."""
    return [
        {
            "case": "honest-visitor",
            "subject": HONEST_DID,
            "issuer_did": CITY_A_DID,
            "issuer_sk": CITY_A_SK,
            "ledger_uri": COMMUNITY_URI,
            "cred_id": "urn:uuid:parc-pub-honest",
            "note": "anchor member, complete ledger",
        },
        {
            "case": "ring-visitor",
            "subject": RING_VISITOR_DID,
            "issuer_did": CITY_A_DID,
            "issuer_sk": CITY_A_SK,
            "ledger_uri": COMMUNITY_URI,
            "cred_id": "urn:uuid:parc-pub-ring",
            "note": "ring member, complete ledger — gate severs the ring",
        },
        {
            "case": "laundered-visitor",
            "subject": RING_VISITOR_DID,
            "issuer_did": CITY_C_DID,
            "issuer_sk": CITY_C_SK,
            "ledger_uri": CURATED_URI,
            "cred_id": "urn:uuid:parc-pub-laundered",
            "note": "SAME ring member, curated anchor-less ledger — residual",
        },
    ]


def build_fixture() -> dict[str, Any]:
    """Deterministic demo state for a Python-free frontend: the signed pointer PARC
    per case, the published ledger it points at, the gate's derived severed score, and
    the admission decision. Stable across runs (fixed seeds)."""
    store = published_store()
    cases: list[dict[str, Any]] = []
    for c in _cases():
        published = store[c["ledger_uri"]]
        receipts = published["receipts"]
        vc = issue_pointer_credential(
            issuer_sk=c["issuer_sk"],
            issuer_did=c["issuer_did"],
            subject_did=c["subject"],
            receipts=receipts,
            ledger_uri=c["ledger_uri"],
            cred_id=c["cred_id"],
        )
        result = city_b_admits(vc, store)
        severed = subject_severed_score(receipts, subject=c["subject"], is_valid=always_valid)
        # The naive 0.1 score over the subject's own receipts — high for every case,
        # which is exactly why the ledger-wide severance (not the per-agent total) is
        # what tells them apart.
        own = [r for r in receipts if r.get("issuer_did") == c["subject"]]
        cases.append(
            {
                "case": c["case"],
                "subject": c["subject"],
                "issuer": c["issuer_did"],
                "note": c["note"],
                "credential": vc,
                "ledger_uri": c["ledger_uri"],
                "published_ledger": {
                    "behavioral_merkle_root": published["behavioral_merkle_root"],
                    "receipt_count": int(published["receipt_count"]),
                    "ledger_wide_reputation_score": float(published["reputation_score"]),
                    "receipts": receipts,
                },
                "gate": {
                    "subject_severed_score": severed,
                    "subject_naive_0_1_score": reputation_score(own, is_valid=always_valid),
                    "threshold": MIN_SCORE,
                    "admitted": result.ok,
                    "reason": result.stage,
                },
            }
        )

    return {
        "demo": "pointer-mode PARC admission",
        "headline": "the gate severs the ring itself — and shows where it can't",
        "wire": "parc/0.1",
        "now": NOW,
        "issuers": {
            "A": {"did": CITY_A_DID, "role": "honest issuer (complete ledger)"},
            "C": {"did": CITY_C_DID, "role": "colluding issuer (curated ledger)"},
        },
        "verifier": {
            "did": CITY_B_DID,
            "policy": {
                "trusted_issuers": [CITY_A_DID, CITY_C_DID],
                "required_scoring_method": SCORING_METHOD_V2,
                "min_reputation_score": MIN_SCORE,
                "mode": "fetch published ledger, re-run severance, derive subject score",
            },
        },
        "cases": cases,
    }


def main() -> None:
    store = published_store()

    print("headline: the gate severs the ring itself — and shows where it can't")
    print(f"City A (honest issuer)   : {CITY_A_DID}")
    print(f"City C (colluding issuer): {CITY_C_DID}")
    print(f"City B (verifier)        : {CITY_B_DID}")
    print(f"City B policy            : trust={{A, C}}  method=nanda-rep/0.2  min_score={MIN_SCORE}")
    print()
    header = (
        f"{'case':<18} {'issuer':<8} {'severed':>8} {'naive0.1':>9}  {'decision':<8} {'reason':<16}"
    )
    print("City B fetches each published ledger, re-runs severance, then decides:")
    print(header)
    print("-" * len(header))

    results: dict[str, AdmissionResult] = {}
    for c in _cases():
        receipts = store[c["ledger_uri"]]["receipts"]
        vc = issue_pointer_credential(
            issuer_sk=c["issuer_sk"],
            issuer_did=c["issuer_did"],
            subject_did=c["subject"],
            receipts=receipts,
            ledger_uri=c["ledger_uri"],
            cred_id=c["cred_id"],
        )
        result = city_b_admits(vc, store)
        results[c["case"]] = result
        severed = subject_severed_score(receipts, subject=c["subject"], is_valid=always_valid)
        own = [r for r in receipts if r.get("issuer_did") == c["subject"]]
        naive = reputation_score(own, is_valid=always_valid)
        issuer_tag = "A" if c["issuer_did"] == CITY_A_DID else "C"
        decision = "ADMIT" if result.ok else "REJECT"
        print(
            f"{c['case']:<18} {issuer_tag:<8} {severed:>8.1f} {naive:>9.1f}  "
            f"{decision:<8} {result.stage:<16}"
        )

    # --- load-bearing assertions ---------------------------------------------
    print()
    print("load-bearing facts:")
    print("  * ring-visitor and laundered-visitor are the SAME agent + SAME receipts;")
    print("    only the published ledger differs (complete vs anchor-less curated).")
    print("  * the gate DERIVES the severed score — it never trusts an attested number.")

    assert results["honest-visitor"].ok, "anchor member must be admitted"
    assert not results["ring-visitor"].ok and results["ring-visitor"].stage == "below_threshold", (
        "ring member must be severed to 0 and rejected over the complete ledger"
    )
    assert results["laundered-visitor"].ok, (
        "curated anchor-less ledger must be (wrongly) admitted — the completeness residual"
    )

    # The severance is real: assert the ring is severed in the complete ledger and
    # NOT severed in the curated one (the construction is fiddly — a stray cross-edge
    # or sub-dense ring would silently un-sever; pin it).
    full_receipts = community_ledger()["receipts"]
    curated_receipts = curated_ledger()["receipts"]
    full_ring = subject_severed_score(
        full_receipts, subject=RING_VISITOR_DID, is_valid=always_valid
    )
    curated_ring = subject_severed_score(
        curated_receipts, subject=RING_VISITOR_DID, is_valid=always_valid
    )
    assert full_ring == 0.0, "ring member is severed to 0 in the complete ledger"
    assert curated_ring > 0.0, "ring member survives in the anchor-less curated ledger"
    # And the ledger-wide score really does drop the ring in the complete ledger.
    assert (
        reputation_score_v2(full_receipts, is_valid=always_valid)
        == subject_severed_score(full_receipts, subject=HONEST_DID, is_valid=always_valid) * 4
    ), "complete-ledger score is the 4 anchor members only; the ring is severed out"

    print()
    print("OK: honest admitted; ring severed+rejected; curated-anchor-less wrongly admitted.")


if __name__ == "__main__":
    main()
