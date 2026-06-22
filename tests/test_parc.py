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
    admit,
    build_reputation_credential,
    did_from_private_key,
    verify_credential_proof,
)

CHAPTER_SK = hashlib.sha256(b"parc-issuer-chapter").digest()
CHAPTER_DID = did_from_private_key(CHAPTER_SK)
SUBJECT_SK = hashlib.sha256(b"parc-subject-agent").digest()
SUBJECT_DID = did_from_sk(SUBJECT_SK)
COUNTERPARTY_SK = hashlib.sha256(b"parc-counterparty").digest()
COUNTERPARTY_DID = did_from_sk(COUNTERPARTY_SK)
VALID_FROM, VALID_UNTIL = "2026-06-07T00:00:00Z", "2026-07-07T00:00:00Z"


def _always(_r: dict[str, Any]) -> bool:
    return True


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
