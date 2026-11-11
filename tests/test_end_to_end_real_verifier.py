"""End to end with the REAL verifier — no ``is_valid=_always``, no ``"AA=="`` signatures.

Every other module in this suite stubs receipt validity. That exercises the gate's
arithmetic but never the composition PARC actually ships: ARP receipts signed by the
acting agent, co-signed by real counterparties (``sm_arp.vrp.cosign_receipt``),
scored by ``build_ledger`` under the real ``sm_arp.verify_receipt``, wrapped in a
signed credential, and admitted with ``is_valid=lambda r: verify_receipt(r).ok``.
This module pins that path — on sm-arp 0.4.0, whose canonical bytes exclude
``evidence.witness_signatures`` so a receipt stays verifiable after it is co-signed.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sm_arp import Identity, build_action, issue_receipt, verify_receipt
from sm_arp.vrp import build_ledger, cosign_receipt, did_from_sk, is_corroborated

from sm_parc import (
    AdmissionPolicy,
    AdmissionResult,
    admit,
    build_reputation_credential,
    did_from_private_key,
    verify_credential_proof,
)

CHAPTER_SK = hashlib.sha256(b"e2e:issuing-chapter").digest()
CHAPTER_DID = did_from_private_key(CHAPTER_SK)
AGENT = Identity.from_seed(hashlib.sha256(b"e2e:acting-agent").digest())
OTHER = Identity.from_seed(hashlib.sha256(b"e2e:other-agent").digest())
COUNTERPARTY_SKS = [hashlib.sha256(b"e2e:counterparty:%d" % i).digest() for i in range(3)]
VALID_FROM, VALID_UNTIL = "2026-06-07T00:00:00Z", "2026-07-07T00:00:00Z"
NOW = "2026-06-08T00:00:00Z"
AS_OF = "2026-06-07T00:00:00Z"


def real_is_valid(receipt: dict[str, Any]) -> bool:
    """The production predicate: the ARP verifier (structure + issuer signature)."""
    return verify_receipt(receipt).ok


def _receipt(agent: Identity, n: int) -> dict[str, Any]:
    """A real ARP receipt issued by ``agent`` and co-signed by a real counterparty."""
    cp_sk = COUNTERPARTY_SKS[n % len(COUNTERPARTY_SKS)]
    action = build_action(
        category="purchase",
        human_summary=f"purchase #{n}",
        outcome="completed",
        counterparty_did=did_from_sk(cp_sk),
    )
    r = issue_receipt(
        agent,
        principal_did=agent.did,
        action=action,
        receipt_id=f"{n:08d}-e2e0-4e2e-8e2e-{n:012d}",
        issued_at=f"2026-06-07T00:00:{n:02d}Z",
    )
    r["evidence"] = {"witness_signatures": [cosign_receipt(r, signing_key_bytes=cp_sk)]}
    return r


def _ledger(agent: Identity, n: int = 3, *, subject: str | None = None) -> dict[str, Any]:
    return build_ledger(
        subject=subject or agent.did,
        receipts=[_receipt(agent, i) for i in range(n)],
        is_valid=real_is_valid,
        as_of=AS_OF,
        method="nanda-rep/0.2",
    )


def _vc(ledger: dict[str, Any], **kw: Any) -> dict[str, Any]:
    kw.setdefault("issuer_sk", CHAPTER_SK)
    kw.setdefault("valid_from", VALID_FROM)
    kw.setdefault("valid_until", VALID_UNTIL)
    return build_reputation_credential(ledger=ledger, **kw)


def _resign(vc: dict[str, Any], sk: bytes = CHAPTER_SK) -> dict[str, Any]:
    body = {k: v for k, v in vc.items() if k != "proof"}
    vc["proof"]["proofValue"] = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(sk).sign(jcs.canonicalize(body))
    ).decode()
    return vc


def _admit(vc: dict[str, Any], ledger: dict[str, Any], **kw: Any) -> AdmissionResult:
    kw.setdefault(
        "policy", AdmissionPolicy(trusted_issuers={CHAPTER_DID}, min_reputation_score=1.0)
    )
    kw.setdefault("presenter_did", AGENT.did)
    kw.setdefault("now", NOW)
    return admit(vc, ledger=ledger, is_valid=real_is_valid, **kw)


# --- the fixtures really are real --------------------------------------------


def test_fixture_receipts_verify_and_are_corroborated() -> None:
    ledger = _ledger(AGENT)
    for r in ledger["receipts"]:
        assert r["signature"] != "AA=="
        assert verify_receipt(r).ok, verify_receipt(r)
        assert is_corroborated(r)
    assert ledger["reputation_score"] == 15.0  # 3 corroborated purchases x 5.0
    assert ledger["validity_rate"] == 1.0 and ledger["corroboration_rate"] == 1.0


# --- the eight outcomes --------------------------------------------------------


def test_trusted_issuer_real_receipts_admitted() -> None:
    ledger = _ledger(AGENT)
    res = _admit(_vc(ledger), ledger)
    assert res.ok and res.stage == "admitted", (res.stage, res.detail)


def test_untrusted_issuer_rejected() -> None:
    ledger = _ledger(AGENT)
    res = _admit(
        _vc(ledger),
        ledger,
        policy=AdmissionPolicy(trusted_issuers={OTHER.did}, min_reputation_score=1.0),
    )
    assert not res.ok and res.stage == "untrusted_issuer"


def test_tampered_score_rejected() -> None:
    ledger = _ledger(AGENT)
    # tampered without re-signing → the proof fails
    vc = _vc(ledger)
    vc["credentialSubject"]["reputation_score"] = 9999.0
    assert not verify_credential_proof(vc)
    assert _admit(vc, ledger).stage == "signature"
    # tampered AND re-signed by the (trusted) issuer → the real recompute catches it
    _resign(vc)
    assert verify_credential_proof(vc)
    res = _admit(vc, ledger)
    assert not res.ok and res.stage == "score_mismatch"


def test_proof_removed_rejected() -> None:
    ledger = _ledger(AGENT)
    vc = _vc(ledger)
    del vc["proof"]
    res = _admit(vc, ledger)
    assert not res.ok and res.stage == "signature"


def test_expired_with_default_clock_rejected() -> None:
    """No ``now`` injected: the gate reads the wall clock, and a June-2026 credential is
    stale. The credential is otherwise perfect — this is the check that used to be
    opt-in."""
    ledger = _ledger(AGENT)
    res = admit(
        _vc(ledger),
        policy=AdmissionPolicy(trusted_issuers={CHAPTER_DID}, min_reputation_score=1.0),
        presenter_did=AGENT.did,
        ledger=ledger,
        is_valid=real_is_valid,
    )
    assert not res.ok and res.stage == "stale"


def test_wrong_presenter_rejected() -> None:
    ledger = _ledger(AGENT)
    res = _admit(_vc(ledger), ledger, presenter_did=OTHER.did)
    assert not res.ok and res.stage == "presenter_mismatch"


def test_ledger_of_another_agent_rejected() -> None:
    """OTHER's genuinely-signed, genuinely-corroborated history, labelled with AGENT's
    subject and honestly signed over by the chapter. Root/count/scores recompute;
    the gate still refuses — the receipts were not issued by the subject."""
    ledger = _ledger(OTHER, subject=AGENT.did)
    assert ledger["reputation_score"] == 15.0
    vc = _vc(ledger)
    assert vc["credentialSubject"]["id"] == AGENT.did
    res = _admit(vc, ledger)
    assert not res.ok and res.stage == "ledger_subject_mismatch"


def test_over_cap_rejected() -> None:
    ledger = _ledger(AGENT, 3)
    res = _admit(
        _vc(ledger),
        ledger,
        policy=AdmissionPolicy(
            trusted_issuers={CHAPTER_DID}, min_reputation_score=1.0, max_ledger_receipts=2
        ),
    )
    assert not res.ok and res.stage == "ledger_too_large"


# --- the real verifier matters: a forged receipt changes the outcome ----------


def test_forged_receipt_signature_is_caught_by_the_real_verifier() -> None:
    """Swap one receipt's issuer signature for junk AFTER the ledger was built. Under
    ``_always`` nothing would change; under ``verify_receipt`` that receipt is
    invalid, so validity_rate and the score no longer recompute to the signed facet.
    (The root still matches: the signature is part of the committed leaf, so we also
    re-sign the facet over the forged ledger to isolate the verifier's contribution.)"""
    ledger = _ledger(AGENT)
    vc = _vc(ledger)
    forged = ledger["receipts"][0]
    forged["signature"] = base64.b64encode(b"\x00" * 64).decode()
    assert not verify_receipt(forged).ok
    # Re-commit the facet to the forged receipts so ONLY the validity verdict differs.
    vc["credentialSubject"]["behavioral_merkle_root"] = build_ledger(
        subject=AGENT.did,
        receipts=ledger["receipts"],
        is_valid=lambda _r: True,
        as_of=AS_OF,
        method="nanda-rep/0.2",
    )["behavioral_merkle_root"]
    _resign(vc)
    res = _admit(vc, ledger)
    assert not res.ok and res.stage == "score_mismatch"
    assert "validity_rate" in res.detail or "reputation_score" in res.detail
