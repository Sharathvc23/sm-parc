"""PARC behavioural suite — the credential + the admission gate.

Per GOVERNANCE: the test suite is the authoritative behavioural spec. Every
guarantee ("verifiable, recomputable, admitted without trusting the issuer's
server", "bound to the corroborated nanda-rep/0.2 score") gets a happy path;
every adversarial claim gets a hostile-path test.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sm_arp.vrp import build_ledger, cosign_receipt, did_from_sk

from sm_parc import (
    AdmissionPolicy,
    AdmissionResult,
    build_reputation_credential,
    did_from_private_key,
    verify_credential_proof,
)
from sm_parc import admit as _gate

CHAPTER_SK = hashlib.sha256(b"parc-issuer-chapter").digest()
CHAPTER_DID = did_from_private_key(CHAPTER_SK)
SUBJECT_SK = hashlib.sha256(b"parc-subject-agent").digest()
SUBJECT_DID = did_from_sk(SUBJECT_SK)
COUNTERPARTY_SK = hashlib.sha256(b"parc-counterparty").digest()
COUNTERPARTY_DID = did_from_sk(COUNTERPARTY_SK)
VALID_FROM, VALID_UNTIL = "2026-06-07T00:00:00Z", "2026-07-07T00:00:00Z"
# A fixed clock inside the window. The gate defaults to the REAL wall clock (so the
# fixtures above would be stale by the time you read this); every test injects NOW
# unless it is testing the clock itself.
NOW = "2026-06-08T00:00:00Z"


def _always(_r: dict[str, Any]) -> bool:
    return True


def admit(vc: dict[str, Any], **kw: Any) -> AdmissionResult:
    """The gate with this suite's defaults: the subject presents its own credential at
    the fixed in-window clock. Tests override either to exercise the checks."""
    kw.setdefault("presenter_did", SUBJECT_DID)
    kw.setdefault("now", NOW)
    return _gate(vc, **kw)


def _receipt(n: int, *, corroborated: bool = True, category: str = "purchase") -> dict[str, Any]:
    """An ARP-shaped receipt issued by the subject. When ``corroborated`` it names
    a distinct counterparty and carries that counterparty's co-signature — the
    nanda-rep/0.2 gate that distinguishes earned reputation from self-dealing."""
    action: dict[str, Any] = {
        "category": category,
        "human_summary": f"a{n}",
        "outcome": "completed",
    }
    if corroborated:
        action["counterparty_did"] = COUNTERPARTY_DID
    receipt: dict[str, Any] = {
        "version": "arp/0.1",
        "receipt_id": f"{n:08d}-1111-4111-8111-111111111111",
        "issuer_did": SUBJECT_DID,
        "principal_did": SUBJECT_DID,
        "issued_at": f"2026-06-07T00:00:0{n}Z",
        "action": action,
        "signature": "AA==",
    }
    if corroborated:
        cosig = cosign_receipt(receipt, signing_key_bytes=COUNTERPARTY_SK)
        receipt["evidence"] = {"witness_signatures": [cosig]}
    return receipt


def _ledger(
    n: int = 3, *, corroborated: bool = True, method: str = "nanda-rep/0.2"
) -> dict[str, Any]:
    return build_ledger(
        subject=SUBJECT_DID,
        receipts=[_receipt(i, corroborated=corroborated) for i in range(n)],
        is_valid=_always,
        as_of="2026-06-07T00:00:00Z",
        method=method,
    )


def _vc(**overrides: Any) -> dict[str, Any]:
    kw: dict[str, Any] = {
        "ledger": _ledger(),
        "issuer_sk": CHAPTER_SK,
        "valid_from": VALID_FROM,
        "valid_until": VALID_UNTIL,
    }
    kw.update(overrides)
    return build_reputation_credential(**kw)


def _resign(vc: dict[str, Any], sk: bytes) -> dict[str, Any]:
    body = {k: v for k, v in vc.items() if k != "proof"}
    vc["proof"]["proofValue"] = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(sk).sign(jcs.canonicalize(body))
    ).decode()
    return vc


def _policy(**kw: Any) -> AdmissionPolicy:
    kw.setdefault("trusted_issuers", {CHAPTER_DID})
    return AdmissionPolicy(**kw)


# ── credential ─────────────────────────────────────────────────────


def test_credential_proof_verifies() -> None:
    assert verify_credential_proof(_vc()) is True


def test_credential_subject_mirrors_v2_ledger() -> None:
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    s = vc["credentialSubject"]
    assert s["id"] == SUBJECT_DID
    assert s["scoring_method"] == "nanda-rep/0.2"
    assert s["behavioral_merkle_root"] == ledger["behavioral_merkle_root"]
    assert s["reputation_score"] == ledger["reputation_score"]
    # the 0.2 facet carries the corroboration rate (1.0 — all receipts co-signed)
    assert s["corroboration_rate"] == ledger["corroboration_rate"] == 1.0
    assert vc["issuer"] == CHAPTER_DID


def test_tampered_credential_fails_proof() -> None:
    vc = _vc()
    vc["credentialSubject"]["reputation_score"] = 9999  # tamper without re-signing
    assert verify_credential_proof(vc) is False


# ── admission (nanda-rep/0.2) ──────────────────────────────────────


def test_admit_corroborated_agent() -> None:
    # A corroborated agent (every receipt co-signed by a distinct counterparty) has
    # a non-zero nanda-rep/0.2 score and is admitted.
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always, now="2026-06-08T00:00:00Z")
    assert res.ok and res.stage == "admitted"
    assert res.warnings == ["anchor_check_disabled"]  # no anchors configured — said out loud


def test_v01_facet_rejected_at_gate() -> None:
    # A credential carrying the un-corroborated nanda-rep/0.1 score is rejected: the
    # gate admits only on the collusion-resistant 0.2 score.
    ledger = _ledger(method="nanda-rep/0.1")
    vc = _vc(ledger=ledger)
    assert vc["credentialSubject"]["scoring_method"] == "nanda-rep/0.1"
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "scoring_method_unsupported"


def test_uncorroborated_score_severed_below_threshold() -> None:
    # A wash-trading agent whose receipts are NOT corroborated: its nanda-rep/0.2
    # score is severed to 0 (uncorroborated receipts earn nothing), so it fails the
    # threshold even though it presents a self-consistent 0.2 credential.
    ledger = _ledger(corroborated=False)
    assert ledger["reputation_score"] == 0.0  # 0.2 severs the uncorroborated score
    assert ledger["corroboration_rate"] == 0.0
    vc = _vc(ledger=ledger)
    res = admit(vc, policy=_policy(min_reputation_score=1.0), ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "below_threshold"


def test_untrusted_issuer_rejected() -> None:
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    res = admit(
        vc,
        policy=AdmissionPolicy(trusted_issuers={"did:key:zSomeoneElse"}),
        ledger=ledger,
        is_valid=_always,
    )
    assert not res.ok and res.stage == "untrusted_issuer"


def test_auditor_attested_admissible_when_trusted() -> None:
    # "Both" trust model: an auditor-signed credential is admissible when the
    # auditor did is in trusted_issuers — recomputation still required.
    auditor_sk = hashlib.sha256(b"parc-auditor").digest()
    auditor_did = did_from_private_key(auditor_sk)
    ledger = _ledger()
    vc = _vc(ledger=ledger, issuer_sk=auditor_sk)
    res = admit(vc, policy=_policy(trusted_issuers={auditor_did}), ledger=ledger, is_valid=_always)
    assert res.ok and res.stage == "admitted"


def test_tampered_ledger_root_mismatch() -> None:
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    ledger["receipts"][0]["action"]["human_summary"] = "swapped after the credential was signed"
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "root_mismatch"


def test_score_mismatch_when_vc_inflated() -> None:
    # Issuer inflates the claimed score and re-signs: proof verifies, but the gate
    # recomputes the 0.2 score from the honest ledger and rejects.
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    vc["credentialSubject"]["reputation_score"] = 9999.0
    _resign(vc, CHAPTER_SK)
    assert verify_credential_proof(vc) is True  # signature is valid…
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "score_mismatch"  # …but recomputation catches it


def test_corroboration_rate_mismatch_when_inflated() -> None:
    # Inflating the signed corroboration_rate while presenting the honest ledger is
    # caught by the 0.2 recompute too.
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    vc["credentialSubject"]["corroboration_rate"] = 0.0  # claim no corroboration…
    _resign(vc, CHAPTER_SK)
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "score_mismatch"


def test_below_threshold_rejected() -> None:
    ledger = _ledger()  # 3 corroborated purchases x 5 = 15
    vc = _vc(ledger=ledger)
    res = admit(vc, policy=_policy(min_reputation_score=100.0), ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "below_threshold"


def test_stale_credential_rejected() -> None:
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always, now="2099-01-01T00:00:00Z")
    assert not res.ok and res.stage == "stale"


def test_revoked_credential_rejected() -> None:
    ledger = _ledger()
    vc = _vc(ledger=ledger, credential_id="urn:uuid:revoked-1")
    res = admit(
        vc, policy=_policy(revocation={"urn:uuid:revoked-1"}), ledger=ledger, is_valid=_always
    )
    assert not res.ok and res.stage == "revoked"


def test_refs_only_ledger_not_recomputable() -> None:
    inline = _ledger()
    vc = _vc(ledger=inline)
    refs = build_ledger(
        subject=SUBJECT_DID,
        receipts=[_receipt(i) for i in range(3)],
        is_valid=_always,
        as_of="2026-06-07T00:00:00Z",
        method="nanda-rep/0.2",
        inline=False,
    )
    res = admit(vc, policy=_policy(), ledger=refs, is_valid=_always)
    assert not res.ok and res.stage == "root_mismatch"


def test_not_yet_valid_rejected() -> None:
    ledger = _ledger()
    vc = _vc(ledger=ledger)  # validFrom = 2026-06-07
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always, now="2026-01-01T00:00:00Z")
    assert not res.ok and res.stage == "not_yet_valid"


def test_count_mismatch_when_receipts_withheld() -> None:
    ledger = _ledger(3)
    vc = _vc(ledger=ledger)  # signed credentialSubject.receipt_count == 3
    ledger["receipts"].pop()  # present only 2 of the 3 committed receipts
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "count_mismatch"


# ── anchor rule (0.2.2) ─────────────────────────────

ANCHOR_SK = hashlib.sha256(b"parc-anchor").digest()
ANCHOR_DID = did_from_sk(ANCHOR_SK)
SYBIL_CP_SK = hashlib.sha256(b"parc-sybil-cp").digest()
SYBIL_CP_DID = did_from_sk(SYBIL_CP_SK)


def _cp_receipt(n: int, cp_did: str, cp_sk: bytes | None) -> dict[str, Any]:
    """A receipt naming ``cp_did``; genuinely co-signed iff ``cp_sk`` is given,
    else carrying a junk witness signature (the pre-0.2.2 mention-only bypass)."""
    receipt: dict[str, Any] = {
        "version": "arp/0.1",
        "receipt_id": f"{n:08d}-2222-4222-8222-222222222222",
        "issuer_did": SUBJECT_DID,
        "principal_did": SUBJECT_DID,
        "issued_at": f"2026-06-07T00:00:0{n}Z",
        "action": {
            "category": "purchase",
            "human_summary": f"anchor-case {n}",
            "outcome": "completed",
            "counterparty_did": cp_did,
        },
        "signature": "AA==",
    }
    if cp_sk is not None:
        cosig = cosign_receipt(receipt, signing_key_bytes=cp_sk)
    else:
        cosig = {"witness_did": cp_did, "signature": "QUFBQQ=="}
    receipt["evidence"] = {"witness_signatures": [cosig]}
    return receipt


def _anchor_ledger(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    return build_ledger(
        subject=SUBJECT_DID,
        receipts=receipts,
        is_valid=_always,
        as_of="2026-06-07T00:00:00Z",
        method="nanda-rep/0.2",
    )


def test_anchor_verified_cosignature_admits() -> None:
    """History genuinely co-signed by an anchor clears the anchor rule."""
    ledger = _anchor_ledger([_cp_receipt(i, ANCHOR_DID, ANCHOR_SK) for i in range(3)])
    vc = _vc(ledger=ledger)
    res = admit(
        vc,
        policy=_policy(required_anchors={ANCHOR_DID}, min_reputation_score=1.0),
        ledger=ledger,
        is_valid=_always,
    )
    assert res.ok, (res.stage, res.detail)


def test_anchor_absent_for_sybil_counterparties() -> None:
    """A recompute-clean, bar-clearing history of freshly minted counterparties
    is refused: nothing in it verifiably touches an anchor. This is the sybil
    case the inline path silently waved through before 0.2.2."""
    ledger = _anchor_ledger([_cp_receipt(i, SYBIL_CP_DID, SYBIL_CP_SK) for i in range(3)])
    vc = _vc(ledger=ledger)
    res = admit(
        vc,
        policy=_policy(required_anchors={ANCHOR_DID}, min_reputation_score=1.0),
        ledger=ledger,
        is_valid=_always,
    )
    assert not res.ok and res.stage == "anchor_absent"


def test_anchor_mention_without_cosignature_rejected() -> None:
    """A junk receipt merely NAMING an anchor (broken witness signature) counts
    for nothing — the pre-0.2.2 mention-only bypass is closed."""
    receipts = [_cp_receipt(i, SYBIL_CP_DID, SYBIL_CP_SK) for i in range(3)]
    receipts.append(_cp_receipt(3, ANCHOR_DID, None))  # names the anchor, junk co-sig
    ledger = _anchor_ledger(receipts)
    vc = _vc(ledger=ledger)
    res = admit(
        vc,
        policy=_policy(required_anchors={ANCHOR_DID}, min_reputation_score=1.0),
        ledger=ledger,
        is_valid=_always,
    )
    assert not res.ok and res.stage == "anchor_absent"


def test_anchor_issued_by_anchor_admits() -> None:
    """The other verified involvement: the anchor itself ISSUED a receipt."""
    receipts = [_cp_receipt(i, SYBIL_CP_DID, SYBIL_CP_SK) for i in range(3)]
    anchor_issued = dict(_cp_receipt(4, SYBIL_CP_DID, SYBIL_CP_SK))
    anchor_issued["issuer_did"] = ANCHOR_DID
    receipts.append(anchor_issued)
    # subject binding: ledger.subject must equal credentialSubject.id, and the
    # anchor-issued receipt belongs to the anchor — so this ledger is invalid
    # for the SUBJECT's credential. The check still demonstrates the helper:
    from sm_parc.admission import _involves_anchor

    assert _involves_anchor(receipts, {ANCHOR_DID}, is_valid=_always)


def test_anchor_fail_closed_without_recomputation() -> None:
    """required_anchors with require_recomputation=False must refuse, not
    silently skip (anchor contact is only checkable from a presented ledger)."""
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    res = admit(
        vc,
        policy=_policy(required_anchors={ANCHOR_DID}, require_recomputation=False),
    )
    assert not res.ok and res.stage == "anchor_absent"


def test_involves_anchor_rejects_invalid_receipt() -> None:
    """Even an anchor-issued receipt counts only if it verifies."""
    from sm_parc.admission import _involves_anchor

    junk = _cp_receipt(5, ANCHOR_DID, ANCHOR_SK)
    assert _involves_anchor([junk], {ANCHOR_DID}, is_valid=lambda _r: False) is False


# ── audit 2026-11: clock, presenter, subject-bound ledger, id, cap, malformed ──

OTHER_SK = hashlib.sha256(b"parc-other-agent").digest()
OTHER_DID = did_from_sk(OTHER_SK)


def _strip_and_resign(vc: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Apply top-level ``changes`` (``None`` deletes the key) and re-sign as the
    issuer, so the proof verifies and the envelope check under test is what fires."""
    for key, value in changes.items():
        if value is None:
            vc.pop(key, None)
        else:
            vc[key] = value
    return _resign(vc, CHAPTER_SK)


# 1. expiry is enforced against the real clock, as instants ------------------


def test_default_clock_rejects_expired_credential() -> None:
    """``now`` omitted → the UTC wall clock. The fixture window (June to July 2026) is
    in the past, so the credential is stale WITHOUT any caller cooperation."""
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    res = _gate(vc, policy=_policy(), presenter_did=SUBJECT_DID, ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "stale"


def test_window_compared_as_instants_not_strings() -> None:
    """validUntil is 2026-07-07T00:00:00Z. A ``now`` of 20:00 on the 6th at UTC-5 is
    01:00Z on the 7th — AFTER expiry — yet sorts lexically BEFORE the bound. The
    string comparison admitted it; instant comparison rejects it."""
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    assert VALID_UNTIL > "2026-07-06T20:00:00-05:00"  # the lexical trap
    res = admit(
        vc, policy=_policy(), ledger=ledger, is_valid=_always, now="2026-07-06T20:00:00-05:00"
    )
    assert not res.ok and res.stage == "stale"
    # ...and an offset instant INSIDE the window is admitted: 04:00+05:00 = 23:00Z on the 6th.
    res = admit(
        vc, policy=_policy(), ledger=ledger, is_valid=_always, now="2026-07-07T04:00:00+05:00"
    )
    assert res.ok, (res.stage, res.detail)


def test_aware_datetime_now_is_accepted() -> None:
    from datetime import UTC, datetime

    ledger = _ledger()
    vc = _vc(ledger=ledger)
    res = admit(
        vc,
        policy=_policy(),
        ledger=ledger,
        is_valid=_always,
        now=datetime(2026, 6, 8, tzinfo=UTC),
    )
    assert res.ok


def test_naive_or_unparseable_now_is_malformed() -> None:
    from datetime import datetime

    ledger = _ledger()
    vc = _vc(ledger=ledger)
    for bad_now in ("2026-06-08T00:00:00", "2026-06-08", "tomorrow", datetime(2026, 6, 8)):
        res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always, now=bad_now)
        assert not res.ok and res.stage == "malformed", (bad_now, res)


def test_naive_or_missing_window_bounds_are_malformed() -> None:
    """A credential whose bounds are offset-less, or absent, names no instant and is
    refused — not silently treated as unbounded (the pre-0.3 behaviour)."""
    ledger = _ledger()
    cases: list[dict[str, Any]] = [
        {"validFrom": "2026-06-07T00:00:00"},  # naive
        {"validUntil": "2026-07-07"},  # date only
        {"validUntil": None},  # missing → unbounded, refused
        {"validFrom": None},
        {"validUntil": 1783468800},  # epoch int
    ]
    for changes in cases:
        vc = _strip_and_resign(_vc(ledger=ledger), **changes)
        assert verify_credential_proof(vc)
        res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
        assert not res.ok and res.stage == "malformed", (changes, res)


def test_builder_refuses_window_that_names_no_instant() -> None:
    import pytest

    ledger = _ledger()
    with pytest.raises(ValueError):
        _vc(ledger=ledger, valid_from="2026-06-07T00:00:00")  # naive
    with pytest.raises(ValueError):
        _vc(ledger=ledger, valid_until="2026-07-07")  # date only
    with pytest.raises(ValueError):
        _vc(ledger=ledger, valid_from=VALID_UNTIL, valid_until=VALID_FROM)  # inverted


# 2. presenter binding ---------------------------------------------------------


def test_presenter_mismatch_rejected() -> None:
    """A copied credential + ledger is public bytes; only its subject is admitted on it."""
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always, presenter_did=OTHER_DID)
    assert not res.ok and res.stage == "presenter_mismatch"
    assert SUBJECT_DID in res.detail and OTHER_DID in res.detail


def test_subject_without_id_is_malformed() -> None:
    ledger = _ledger()
    vc = _vc(ledger=ledger)
    del vc["credentialSubject"]["id"]
    _resign(vc, CHAPTER_SK)
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "malformed"


# 3. inline ledger must be the subject's OWN history ---------------------------


def _foreign_receipt(n: int) -> dict[str, Any]:
    """A fully corroborated receipt issued by ANOTHER agent (OTHER_DID)."""
    r = _receipt(n)
    r["issuer_did"] = r["principal_did"] = OTHER_DID
    r["evidence"] = {"witness_signatures": [cosign_receipt(r, signing_key_bytes=COUNTERPARTY_SK)]}
    return r


def test_ledger_of_another_agent_rejected() -> None:
    """The issuer honestly signs over Y's receipts labelled with X's subject. The root,
    count and scores all recompute — and X would have been admitted on Y's history.
    Every inline receipt MUST be issued by the subject."""
    foreign = [_foreign_receipt(i) for i in range(3)]
    ledger = build_ledger(
        subject=SUBJECT_DID,
        receipts=foreign,
        is_valid=_always,
        as_of="2026-06-07T00:00:00Z",
        method="nanda-rep/0.2",
    )
    assert ledger["reputation_score"] > 0
    vc = _vc(ledger=ledger)
    res = admit(vc, policy=_policy(min_reputation_score=1.0), ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "ledger_subject_mismatch"
    assert OTHER_DID in res.detail


def test_single_foreign_receipt_among_own_rejected() -> None:
    receipts = [_receipt(i) for i in range(3)] + [_foreign_receipt(3)]
    ledger = build_ledger(
        subject=SUBJECT_DID,
        receipts=receipts,
        is_valid=_always,
        as_of="2026-06-07T00:00:00Z",
        method="nanda-rep/0.2",
    )
    vc = _vc(ledger=ledger)
    res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
    assert not res.ok and res.stage == "ledger_subject_mismatch"
    assert "1 receipt(s)" in res.detail


# 4. a credential always has an id, and the gate requires one ------------------


def test_builder_always_emits_an_id() -> None:
    vc = _vc()  # no credential_id supplied
    assert isinstance(vc["id"], str) and vc["id"].startswith("urn:uuid:")
    assert vc["id"] != _vc()["id"]  # fresh per mint
    assert verify_credential_proof(vc)  # the id is under the signature
    assert _vc(credential_id="urn:uuid:given")["id"] == "urn:uuid:given"


def test_builder_refuses_empty_id() -> None:
    import pytest

    with pytest.raises(ValueError):
        _vc(credential_id="")


def test_credential_without_id_rejected_as_unrevocable() -> None:
    """A verifier keys revocation on vc.id; an id-less credential could never be
    revoked, so it is refused outright (before the revocation lookup)."""
    ledger = _ledger()
    for bad_id in (None, "", 42):
        vc = _strip_and_resign(_vc(ledger=ledger), id=bad_id)
        if bad_id is None:
            assert "id" not in vc
        assert verify_credential_proof(vc)
        res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
        assert not res.ok and res.stage == "missing_id", (bad_id, res)


# 5. execution budget applies inline too ---------------------------------------


def test_inline_ledger_over_cap_rejected_before_recomputation() -> None:
    ledger = _ledger(3)
    vc = _vc(ledger=ledger)
    calls = 0

    def counting_is_valid(r: dict[str, Any]) -> bool:
        nonlocal calls
        calls += 1
        return True

    res = admit(
        vc, policy=_policy(max_ledger_receipts=2), ledger=ledger, is_valid=counting_is_valid
    )
    assert not res.ok and res.stage == "ledger_too_large"
    assert "3 receipts > max 2" in res.detail
    assert calls == 0  # nothing was recomputed
    # at the cap exactly is fine
    res = admit(vc, policy=_policy(max_ledger_receipts=3), ledger=ledger, is_valid=_always)
    assert res.ok


# 6. the disabled sybil defence is announced -----------------------------------


def test_anchor_warning_present_iff_no_anchors_configured() -> None:
    from sm_parc import WARNING_ANCHOR_CHECK_DISABLED

    ledger = _anchor_ledger([_cp_receipt(i, ANCHOR_DID, ANCHOR_SK) for i in range(3)])
    vc = _vc(ledger=ledger)
    loud = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
    assert loud.ok and loud.warnings == [WARNING_ANCHOR_CHECK_DISABLED]
    quiet = admit(
        vc, policy=_policy(required_anchors={ANCHOR_DID}), ledger=ledger, is_valid=_always
    )
    assert quiet.ok and quiet.warnings == []
    # rejections carry the warning too — the operator sees it regardless of outcome
    rejected = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always, presenter_did=OTHER_DID)
    assert not rejected.ok and rejected.warnings == [WARNING_ANCHOR_CHECK_DISABLED]


# 8. a non-numeric facet is malformed, not a crash -----------------------------


def test_non_numeric_scores_are_malformed() -> None:
    """``float("15.0")`` would silently coerce and ``float(None)`` / ``float([..])``
    would raise out of the gate; a bool is an int in Python. All are refused."""
    ledger = _ledger()
    for key in ("reputation_score", "validity_rate", "corroboration_rate"):
        for bad in ("15.0", None, True, [15.0], {"value": 15.0}):
            vc = _vc(ledger=ledger)
            vc["credentialSubject"][key] = bad
            _resign(vc, CHAPTER_SK)
            res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
            assert not res.ok and res.stage == "malformed", (key, bad, res)


def test_non_finite_scores_cannot_pass() -> None:
    """NaN is the dangerous one: ``abs(nan - x) > tol`` and ``nan < min`` are both
    False, so a NaN facet would sail through recompute AND threshold. JCS (RFC 8785)
    has no encoding for NaN/Infinity, so such a credential cannot carry a verifying
    proof — the gate rejects it (signature) without raising. The explicit finite
    check in the envelope is defence in depth behind that."""
    from sm_parc.admission import _is_finite_number

    ledger = _ledger()
    for bad in (float("nan"), float("inf"), -float("inf")):
        assert not _is_finite_number(bad)
        vc = _vc(ledger=ledger)
        vc["credentialSubject"]["reputation_score"] = bad
        res = admit(vc, policy=_policy(), ledger=ledger, is_valid=_always)
        assert not res.ok and res.stage == "signature", (bad, res)
