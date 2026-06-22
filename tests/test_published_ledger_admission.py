"""Pointer-mode admission — behavioural spec for the published-ledger PARC flow.

The companion spec to ``test_two_city_admission.py`` (inline mode). It pins the
guarantees the headline ("the gate severs the ring itself — and shows where it
can't") rests on:

  1. ``honest-visitor`` (anchor member) is admitted;
  2. ``ring-visitor`` (an isolated-ring member) is rejected ``below_threshold`` —
     the gate fetches the full community ledger and SEVERS the ring itself, landing
     the subject's score at 0 without ever trusting an attested number;
  3. ``laundered-visitor`` — the SAME ring member + SAME receipts — is (wrongly)
     ADMITTED when a colluding issuer publishes the ring WITHOUT the anchor. This is
     the completeness residual, shown rather than asserted;
  4. the gate genuinely derives the score: it does NOT catch a ring from a single
     subject's receipts (that is structurally a star), and it rejects tampering /
     withholding / a mis-attested ledger-wide score.
"""

from __future__ import annotations

from typing import Any

from sm_arp.vrp import SCORING_METHOD_V2, build_ledger, did_from_sk

from examples.published_ledger_admission import (
    CITY_A_DID,
    CITY_A_SK,
    CITY_C_DID,
    CITY_C_SK,
    COMMUNITY_URI,
    CURATED_URI,
    HONEST_DID,
    MIN_SCORE,
    NOW,
    RING_VISITOR_DID,
    VALID_FROM,
    VALID_UNTIL,
    always_valid,
    anchor_receipts,
    city_b_admits,
    issue_pointer_credential,
    published_store,
    ring_receipts,
)
from sm_parc import (
    AdmissionPolicy,
    admit,
    admit_over_published_ledger,
    build_reputation_credential,
    subject_severed_score,
)


def _store() -> dict[str, dict[str, Any]]:
    return published_store()


def _issue(case: str) -> dict[str, Any]:
    """Issue the signed pointer credential for a named demo case over the store."""
    store = _store()
    cfg = {
        "honest-visitor": (CITY_A_SK, CITY_A_DID, HONEST_DID, COMMUNITY_URI),
        "ring-visitor": (CITY_A_SK, CITY_A_DID, RING_VISITOR_DID, COMMUNITY_URI),
        "laundered-visitor": (CITY_C_SK, CITY_C_DID, RING_VISITOR_DID, CURATED_URI),
    }[case]
    issuer_sk, issuer_did, subject_did, uri = cfg
    return issue_pointer_credential(
        issuer_sk=issuer_sk,
        issuer_did=issuer_did,
        subject_did=subject_did,
        receipts=store[uri]["receipts"],
        ledger_uri=uri,
        cred_id=f"urn:uuid:test-{case}",
    )


# --- the three headline outcomes --------------------------------------------


def test_honest_anchor_member_is_admitted() -> None:
    result = city_b_admits(_issue("honest-visitor"), _store())
    assert result.ok and result.stage == "admitted"


def test_ring_member_is_severed_and_rejected() -> None:
    result = city_b_admits(_issue("ring-visitor"), _store())
    assert not result.ok
    assert result.stage == "below_threshold"


def test_laundered_curated_ledger_is_wrongly_admitted() -> None:
    """The completeness residual: a colluding issuer that omits the anchor gets in."""
    result = city_b_admits(_issue("laundered-visitor"), _store())
    assert result.ok and result.stage == "admitted"


def test_same_agent_opposite_outcome_only_ledger_differs() -> None:
    """ring-visitor and laundered-visitor are the identical DID + identical receipts;
    only the published ledger's completeness flips the decision."""
    ring = city_b_admits(_issue("ring-visitor"), _store())
    laundered = city_b_admits(_issue("laundered-visitor"), _store())
    assert not ring.ok and laundered.ok


# --- the gate derives the score (it is not attested) ------------------------


def test_subject_severed_score_is_per_subject_over_full_graph() -> None:
    full = anchor_receipts() + ring_receipts()
    ring_only = ring_receipts()
    # The ring member: severed to 0 with the anchor present; survives without it.
    assert subject_severed_score(full, subject=RING_VISITOR_DID, is_valid=always_valid) == 0.0
    assert subject_severed_score(ring_only, subject=RING_VISITOR_DID, is_valid=always_valid) > 0.0
    # An anchor member scores identically in both — only severance is graph-dependent.
    assert subject_severed_score(full, subject=HONEST_DID, is_valid=always_valid) == 15.0


def test_inline_single_subject_credential_cannot_show_a_ring() -> None:
    """Why pointer mode exists: a ring member's OWN receipts form a star, so severance
    never fires on them — the ring is invisible without the full community graph."""
    own = [r for r in ring_receipts() if r.get("issuer_did") == RING_VISITOR_DID]
    # Over only its own receipts the ring member looks perfectly corroborated.
    assert subject_severed_score(own, subject=RING_VISITOR_DID, is_valid=always_valid) > 0.0


# --- adversarial paths -------------------------------------------------------


def _policy() -> AdmissionPolicy:
    return AdmissionPolicy(
        trusted_issuers={CITY_A_DID, CITY_C_DID},
        required_scoring_method=SCORING_METHOD_V2,
        min_reputation_score=MIN_SCORE,
    )


def test_tampered_fetched_ledger_fails_root() -> None:
    """The host serving a different ledger than the issuer signed is caught by root."""
    vc = _issue("honest-visitor")
    store = _store()
    tampered = dict(store[COMMUNITY_URI])
    receipts = [dict(r) for r in tampered["receipts"]]
    receipts[0] = {**receipts[0], "receipt_id": "deadbeef-0000-4000-8000-000000000000"}
    tampered["receipts"] = receipts
    store[COMMUNITY_URI] = tampered
    result = admit_over_published_ledger(
        vc, policy=_policy(), fetch=lambda uri: store[uri], is_valid=always_valid, now=NOW
    )
    assert not result.ok and result.stage == "root_mismatch"


def test_withheld_receipt_fails_count_or_root() -> None:
    vc = _issue("honest-visitor")
    store = _store()
    short = dict(store[COMMUNITY_URI])
    short["receipts"] = short["receipts"][:-1]
    store[COMMUNITY_URI] = short
    result = admit_over_published_ledger(
        vc, policy=_policy(), fetch=lambda uri: store[uri], is_valid=always_valid, now=NOW
    )
    assert not result.ok and result.stage in {"count_mismatch", "root_mismatch"}


def test_mis_attested_ledger_wide_score_fails() -> None:
    """An issuer that signs a ledger-wide reputation_score the receipts do not produce
    is caught by the anti-withholding recompute (step 4)."""
    store = _store()
    receipts = store[COMMUNITY_URI]["receipts"]
    # Build a ledger, then inflate its signed score before signing the credential.
    ledger = build_ledger(
        subject=HONEST_DID,
        receipts=receipts,
        is_valid=always_valid,
        as_of=VALID_FROM,
        method="nanda-rep/0.2",
    )
    ledger["reputation_score"] = float(ledger["reputation_score"]) + 999.0
    vc = build_reputation_credential(
        ledger=ledger,
        issuer_sk=CITY_A_SK,
        issuer_did=CITY_A_DID,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        ledger_uri=COMMUNITY_URI,
    )
    result = admit_over_published_ledger(
        vc, policy=_policy(), fetch=lambda uri: store[uri], is_valid=always_valid, now=NOW
    )
    assert not result.ok and result.stage == "score_mismatch"


def test_untrusted_issuer_rejected() -> None:
    vc = _issue("honest-visitor")
    policy = AdmissionPolicy(
        trusted_issuers={did_from_sk(b"\x01" * 32)},
        required_scoring_method=SCORING_METHOD_V2,
        min_reputation_score=MIN_SCORE,
    )
    store = _store()
    result = admit_over_published_ledger(
        vc, policy=policy, fetch=lambda uri: store[uri], is_valid=always_valid, now=NOW
    )
    assert not result.ok and result.stage == "untrusted_issuer"


def test_inline_credential_rejected_by_pointer_gate() -> None:
    """An inline credential (no ledger_uri) cannot be admitted through the pointer gate."""
    ledger = build_ledger(
        subject=HONEST_DID,
        receipts=anchor_receipts(),
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
    )  # no ledger_uri
    result = admit_over_published_ledger(
        vc, policy=_policy(), fetch=lambda uri: {}, is_valid=always_valid, now=NOW
    )
    assert not result.ok and result.stage == "wrong_mode"


def test_pointer_credential_rejected_by_inline_gate() -> None:
    """The dangerous pairing the gate MUST refuse: inline admit() on a pointer
    credential would threshold the ledger-WIDE score and re-admit the ring member.
    The inline gate refuses pointer credentials outright (wrong_mode)."""
    store = _store()
    ring_vc = _issue("ring-visitor")
    result = admit(
        ring_vc,
        policy=AdmissionPolicy(trusted_issuers={CITY_A_DID}, min_reputation_score=MIN_SCORE),
        ledger=store[COMMUNITY_URI],
        is_valid=always_valid,
        now=NOW,
    )
    assert not result.ok and result.stage == "wrong_mode"


def test_private_effective_receipts_symbol_is_importable() -> None:
    """sm_parc.admission depends on sm_arp.vrp._effective_receipts (a private symbol).
    Pin it: a sm-arp patch release that moves/renames it must fail loudly here, not at
    runtime inside admit_over_published_ledger."""
    from sm_arp.vrp import _effective_receipts

    assert callable(_effective_receipts)


def test_stale_credential_rejected() -> None:
    vc = _issue("honest-visitor")
    store = _store()
    result = admit_over_published_ledger(
        vc,
        policy=_policy(),
        fetch=lambda uri: store[uri],
        is_valid=always_valid,
        now="2030-01-01T00:00:00Z",
    )
    assert not result.ok and result.stage == "stale"


# --- v0.1 hardening: required anchors + execution budget --------------------


def _policy_with(**kw: object) -> AdmissionPolicy:
    base: dict[str, object] = {
        "trusted_issuers": {CITY_A_DID, CITY_C_DID},
        "required_scoring_method": SCORING_METHOD_V2,
        "min_reputation_score": MIN_SCORE,
    }
    base.update(kw)
    return AdmissionPolicy(**base)  # type: ignore[arg-type]


def test_required_anchor_rejects_curated_ledger() -> None:
    """Omitted-anchor stopgap: a curated ledger that involves no known anchor is
    rejected as incomplete (anchor_absent) — defeating 'publish my ring, no anchor'."""
    store = _store()
    result = admit_over_published_ledger(
        _issue("laundered-visitor"),
        policy=_policy_with(required_anchors={HONEST_DID}),
        fetch=lambda uri: store[uri],
        is_valid=always_valid,
        now=NOW,
    )
    assert not result.ok and result.stage == "anchor_absent"


def test_required_anchor_passes_complete_ledger() -> None:
    """A complete ledger (which involves the anchor) clears the anchor check; the ring
    member is then still rejected on severance — not anchor_absent."""
    store = _store()
    result = admit_over_published_ledger(
        _issue("ring-visitor"),
        policy=_policy_with(required_anchors={HONEST_DID}),
        fetch=lambda uri: store[uri],
        is_valid=always_valid,
        now=NOW,
    )
    assert not result.ok and result.stage == "below_threshold"


def test_required_anchor_disabled_by_default() -> None:
    """No required_anchors set → the check is skipped (laundered still admitted)."""
    store = _store()
    result = admit_over_published_ledger(
        _issue("laundered-visitor"),
        policy=_policy_with(),
        fetch=lambda uri: store[uri],
        is_valid=always_valid,
        now=NOW,
    )
    assert result.ok  # the residual the anchor list is meant to close


def test_max_ledger_receipts_rejects_oversized() -> None:
    """Execution budget: a fetched ledger larger than the cap is rejected before the
    expensive severance recomputation runs."""
    store = _store()
    result = admit_over_published_ledger(
        _issue("honest-visitor"),
        policy=_policy_with(max_ledger_receipts=2),
        fetch=lambda uri: store[uri],
        is_valid=always_valid,
        now=NOW,
    )
    assert not result.ok and result.stage == "ledger_too_large"
