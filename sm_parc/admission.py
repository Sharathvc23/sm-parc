"""The admission gate — verify a ReputationCredential at chapter admission.

The point of PARC: a chapter admits (or rejects) an agent on the strength of a
reputation credential it can verify *without trusting the issuing chapter's live
server*. The gate trusts two things only — the issuer's signature and its OWN
recomputation of the ledger:

  1. the VC proof verifies under the issuer did;
  2. the issuer is trusted by policy (a chapter OR a credentialed auditor);
  3. the credential is not revoked and is inside its validity window
     (``validFrom`` ≤ now ≤ ``validUntil``);
  4. the credential's ``scoring_method`` is the corroborated, collusion-resistant
     ``nanda-rep/0.2`` — a credential carrying the un-corroborated ``nanda-rep/0.1``
     score is rejected (``scoring_method_unsupported``);
  5. the presented ledger is recomputable and its receipt count matches the
     credential's signed ``receipt_count`` (no withholding);
  6. the ledger recomputes to the VC's ``behavioral_merkle_root`` and the
     ``nanda-rep/0.2`` ``reputation_score`` / ``validity_rate`` / ``corroboration_rate``;
  7. the scores clear the policy thresholds.

Why bind admission to ``nanda-rep/0.2`` (step 4 + the v2 recompute in step 6): the
0.2 score counts only receipts that are ARP-valid AND corroborated by a distinct
counterparty AND not part of a severed collusion component. A wash-trading ring
that mutually co-signs its own receipts is severed to a score of ~0, so its
credential FAILS the gate at the threshold. The un-corroborated ``nanda-rep/0.1``
score has no such defence, so the gate refuses to admit on it.

Step 5-6 recomputation is ``sm_arp.vrp``. Pure: receipts' validity is supplied
by the caller as ``is_valid`` (normally the ARP verifier), and ``now`` is supplied
by the caller (no wall-clock here).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from sm_arp.vrp import (
    DEFAULT_CATEGORY_WEIGHTS,
    SCORING_METHOD_V2,
    _effective_receipts,
    behavioral_merkle_root,
    corroboration_rate,
    reputation_score_v2,
    validity_rate,
)

from .credential import verify_credential_proof

IsValid = Callable[[dict[str, Any]], bool]
Fetch = Callable[[str], dict[str, Any]]


@dataclass
class AdmissionPolicy:
    """What an admitting chapter requires of a reputation credential."""

    trusted_issuers: set[str] = field(default_factory=set)
    min_reputation_score: float = 0.0
    min_validity_rate: float = 0.0
    require_recomputation: bool = True
    revocation: set[str] = field(default_factory=set)
    score_tolerance: float = 1e-9
    # The scoring method the gate will admit on. Defaults to the corroborated,
    # collusion-resistant nanda-rep/0.2 — a credential carrying any other method
    # (notably the un-corroborated nanda-rep/0.1) is rejected before recomputation.
    required_scoring_method: str = SCORING_METHOD_V2
    # Pointer-mode stopgap for the curated-ledger residual (until a notary layer
    # exists): a local allowlist of known-honest "anchor" dids. A fetched ledger that
    # does NOT involve at least one of these anchors is treated as incomplete and
    # rejected (anchor_absent) — it defeats the trivial "publish my ring with no anchor"
    # laundering. Empty set = check disabled. See THREATMODEL.md for the residual that
    # remains (an attacker who wires one real edge to an anchor still evades severance).
    required_anchors: set[str] = field(default_factory=set)
    # Deterministic execution budget: the gate runs SCC severance over the whole
    # fetched ledger, so a hostile issuer could publish an enormous graph to exhaust
    # the verifier. A fetched ledger with more than this many receipts is rejected
    # (ledger_too_large) BEFORE the expensive recomputation. None = unbounded.
    max_ledger_receipts: int | None = None


@dataclass
class AdmissionResult:
    ok: bool
    # signature | untrusted_issuer | revoked | not_yet_valid | stale |
    # scoring_method_unsupported | wrong_mode | ledger_too_large | count_mismatch |
    # root_mismatch | anchor_absent | score_mismatch | below_threshold | admitted
    stage: str
    detail: str

    @classmethod
    def admitted(cls) -> AdmissionResult:
        return cls(True, "admitted", "credential verifies and clears policy")


def _check_envelope(
    vc: dict[str, Any], *, policy: AdmissionPolicy, now: str | None
) -> AdmissionResult | None:
    """Shared envelope checks for both admission modes: proof, trusted issuer,
    revocation, validity window, and the required scoring method.

    Returns the failing :class:`AdmissionResult`, or ``None`` if the envelope is
    sound (in which case the caller proceeds to its mode-specific recomputation).
    """
    if not verify_credential_proof(vc):
        return AdmissionResult(False, "signature", "credential proof does not verify")

    issuer = vc.get("issuer", "")
    if issuer not in policy.trusted_issuers:
        return AdmissionResult(
            False, "untrusted_issuer", f"issuer {issuer} not in policy.trusted_issuers"
        )

    cred_id = vc.get("id")
    if cred_id is not None and cred_id in policy.revocation:
        return AdmissionResult(False, "revoked", f"credential {cred_id} is revoked")

    # Not-yet-valid: a credential's window has a lower bound too.
    valid_from = vc.get("validFrom")
    if now is not None and isinstance(valid_from, str) and now < valid_from:
        return AdmissionResult(
            False, "not_yet_valid", f"credential not valid until {valid_from} (now {now})"
        )

    valid_until = vc.get("validUntil")
    if now is not None and isinstance(valid_until, str) and now > valid_until:
        return AdmissionResult(False, "stale", f"credential expired at {valid_until} (now {now})")

    # The credential MUST carry the corroborated, collusion-resistant scoring method.
    # A credential whose facet is the un-corroborated nanda-rep/0.1 score is rejected
    # here: that score lets a wash-trading ring inflate itself, so the gate refuses to
    # admit on it (corroboration_required).
    subject = vc.get("credentialSubject") or {}
    scoring_method = subject.get("scoring_method")
    if scoring_method != policy.required_scoring_method:
        return AdmissionResult(
            False,
            "scoring_method_unsupported",
            f"scoring_method {scoring_method!r} != required "
            f"{policy.required_scoring_method!r} (corroboration_required)",
        )
    return None


def subject_severed_score(
    receipts: Sequence[dict[str, Any]],
    *,
    subject: str,
    is_valid: IsValid,
    weights: dict[str, float] = DEFAULT_CATEGORY_WEIGHTS,
) -> float:
    """The subject's OWN collusion-severed reputation within a *full* community ledger.

    Severance (Tarjan SCC over the corroboration graph) is run over the WHOLE
    ``receipts`` set, so an isolated dense ring is severed only when the ledger also
    carries the honest anchor it is isolated from. Then only the subject's own
    receipts (``issuer_did == subject``) that SURVIVE severance are scored.

    A ring member's receipts are all severed → 0; an anchor member's survive → its
    real score. This is the per-subject number the pointer-mode gate derives ITSELF
    from a fetched ledger — it is deliberately NOT carried in the credential, so the
    gate does the collusion analysis rather than trusting an attested number.

    Why this catches what :func:`admit` (inline mode) cannot: a single-subject
    credential's corroboration graph is a star (the subject → its counterparties),
    never a strongly-connected ring, so severance can never fire on it. Severance is
    a property of the *whole* graph; only a credential that points at the full
    community ledger lets the gate see — and sever — an N-party ring.
    """
    effective = _effective_receipts(receipts, is_valid=is_valid)
    return sum(
        weights.get((r.get("action") or {}).get("category", ""), 0.0)
        for r in effective
        if r.get("issuer_did") == subject
    )


def admit(
    vc: dict[str, Any],
    *,
    policy: AdmissionPolicy,
    ledger: dict[str, Any] | None = None,
    is_valid: IsValid | None = None,
    now: str | None = None,
) -> AdmissionResult:
    """Decide admission for ``vc`` under ``policy`` (INLINE, self-contained mode).

    The credential carries the subject's OWN receipts inline; the gate recomputes the
    facet from them. This is fully offline and leaks nothing but the subject's own
    history — but a single-subject credential's corroboration graph is a star, so this
    mode catches *self-dealing* (the corroboration filter) but structurally CANNOT see
    an N-party Sybil ring. For that, see :func:`admit_over_published_ledger`.

    ``ledger`` (the agent's presented Receipts Ledger) + ``is_valid`` are required
    when ``policy.require_recomputation`` is True (the default and recommended
    posture). ``now`` (RFC 3339) enables the validity-window checks against both
    ``validFrom`` and ``validUntil``. Under recomputation the credential's signed
    ``receipt_count`` must also match the presented ledger (anti-withholding), and
    the recomputed nanda-rep/0.2 ``reputation_score`` / ``validity_rate`` /
    ``corroboration_rate`` must match the signed facet.
    """
    envelope = _check_envelope(vc, policy=policy, now=now)
    if envelope is not None:
        return envelope

    subject = vc.get("credentialSubject") or {}

    # Mode pairing: a pointer credential carries a ledger-wide score in
    # ``reputation_score`` and a ``ledger_uri``. Admitting it here would threshold the
    # WHOLE-community score (not the subject's severed score) and silently re-admit a
    # ring member. Refuse — pointer credentials MUST go through
    # admit_over_published_ledger, which derives the per-subject severed score.
    if subject.get("ledger_uri") is not None:
        return AdmissionResult(
            False, "wrong_mode", "pointer credential; use admit_over_published_ledger"
        )

    if policy.require_recomputation:
        if ledger is None or is_valid is None:
            return AdmissionResult(
                False, "root_mismatch", "recomputation required but ledger/is_valid not provided"
            )
        receipts = ledger.get("receipts")
        if not isinstance(receipts, list) or any("action" not in r for r in receipts):
            return AdmissionResult(
                False, "root_mismatch", "presented ledger is not recomputable (refs-only)"
            )
        # 6a. The credential's signed receipt_count MUST match the presented ledger —
        # a presenter cannot withhold receipts to change the recomputed scores.
        if subject.get("receipt_count") != len(receipts):
            return AdmissionResult(
                False,
                "count_mismatch",
                f"count {subject.get('receipt_count')} != {len(receipts)} presented",
            )
        if behavioral_merkle_root(receipts) != subject.get("behavioral_merkle_root"):
            return AdmissionResult(
                False, "root_mismatch", "ledger does not recompute to the credential root"
            )
        # 6b. Recompute the nanda-rep/0.2 facet (corroborated + collusion-severed)
        # and confirm it matches the signed credentialSubject — a signed-but-inflated
        # score is caught here, and a SELF-DEALT receipt (self-cosigned, no distinct
        # counterparty) earns 0 via the corroboration filter. Note: this inline path
        # canNOT sever an N-party ring — the subject's own receipts form a star, not a
        # strongly-connected component. Ring severance needs the full community graph;
        # that is admit_over_published_ledger, not this function.
        recomputed_score = reputation_score_v2(receipts, is_valid=is_valid)
        recomputed_validity = validity_rate(receipts, is_valid=is_valid)
        recomputed_corroboration = corroboration_rate(receipts, is_valid=is_valid)
        if (
            abs(recomputed_score - float(subject.get("reputation_score", 0)))
            > policy.score_tolerance
        ):
            return AdmissionResult(False, "score_mismatch", "reputation_score does not recompute")
        if (
            abs(recomputed_validity - float(subject.get("validity_rate", 0)))
            > policy.score_tolerance
        ):
            return AdmissionResult(False, "score_mismatch", "validity_rate does not recompute")
        if (
            abs(recomputed_corroboration - float(subject.get("corroboration_rate", 0)))
            > policy.score_tolerance
        ):
            return AdmissionResult(False, "score_mismatch", "corroboration_rate does not recompute")

    if float(subject.get("reputation_score", 0)) < policy.min_reputation_score:
        return AdmissionResult(False, "below_threshold", "reputation_score below policy minimum")
    if float(subject.get("validity_rate", 0)) < policy.min_validity_rate:
        return AdmissionResult(False, "below_threshold", "validity_rate below policy minimum")

    return AdmissionResult.admitted()


def _involves_anchor(receipts: list[dict[str, Any]], anchors: set[str]) -> bool:
    """True iff any receipt is issued by, or transacted with, a required anchor did."""
    for r in receipts:
        if r.get("issuer_did") in anchors:
            return True
        if (r.get("action") or {}).get("counterparty_did") in anchors:
            return True
    return False


def admit_over_published_ledger(
    vc: dict[str, Any],
    *,
    policy: AdmissionPolicy,
    fetch: Fetch,
    is_valid: IsValid,
    now: str | None = None,
) -> AdmissionResult:
    """Decide admission for ``vc`` in POINTER mode — the credential names a published
    community ledger (``credentialSubject.ledger_uri``) and the gate FETCHES it and
    re-runs the collusion analysis itself.

    Where :func:`admit` (inline) verifies a self-contained, single-subject credential
    offline, this path trades that for collusion-resistance the inline mode cannot
    have. The facet describes the LEDGER (root + ledger-wide scores); the gate:

      1. verifies the envelope (proof, trusted issuer, window, ``nanda-rep/0.2``);
      2. ``fetch``-es the full ledger named by ``ledger_uri`` (caller supplies the
         resolver — no network here);
      3. checks the fetched ledger hashes to the credential's SIGNED
         ``behavioral_merkle_root`` (tamper-evidence: the host cannot serve a
         different ledger than the one the issuer committed to);
      4. checks the ledger-wide ``reputation_score`` recomputes from those receipts
         (anti-withholding / anti-substitution of the published ledger);
      5. **derives the subject's own collusion-severed score** over the full graph
         via :func:`subject_severed_score` and applies the threshold. An isolated
         N-party Sybil ring is severed to 0 HERE, by the gate — not trusted from an
         attested number.

    Honest residual — the trust this does NOT remove: severance is only as good as
    the ledger's COMPLETENESS. A *colluding* issuer that publishes its ring WITHOUT
    the honest anchor (so the ring is the largest SCC and is never severed), or that
    injects a single cross-edge to the anchor, yields a ledger that recomputes HIGH
    and is admitted — and the gate, seeing only the published ledger, cannot tell.
    Pointer mode catches a LAZY-but-honest issuer; the colluding issuer is the notary
    / multi-issuer-attestation layer's problem. See ``THREATMODEL.md``.
    """
    envelope = _check_envelope(vc, policy=policy, now=now)
    if envelope is not None:
        return envelope

    subject = vc.get("credentialSubject") or {}
    ledger_uri = subject.get("ledger_uri")
    if not isinstance(ledger_uri, str):
        return AdmissionResult(False, "wrong_mode", "inline credential (no ledger_uri); use admit")

    ledger = fetch(ledger_uri)
    receipts = ledger.get("receipts")
    if not isinstance(receipts, list) or any("action" not in r for r in receipts):
        return AdmissionResult(
            False, "root_mismatch", "fetched ledger is refs-only (not recomputable)"
        )

    # 2a. Execution budget: reject an oversized ledger BEFORE any O(n) hashing or the
    # severance recomputation, so a hostile issuer cannot exhaust the verifier.
    if policy.max_ledger_receipts is not None and len(receipts) > policy.max_ledger_receipts:
        return AdmissionResult(
            False,
            "ledger_too_large",
            f"fetched ledger has {len(receipts)} receipts > max {policy.max_ledger_receipts}",
        )

    # 3. Tamper-evidence: the fetched ledger MUST hash to the credential's signed root.
    if behavioral_merkle_root(receipts) != subject.get("behavioral_merkle_root"):
        return AdmissionResult(
            False, "root_mismatch", "fetched ledger does not match the signed root"
        )
    # 4. Anti-withholding: the signed ledger-wide score must recompute from the fetched
    # receipts (the issuer cannot publish a ledger that differs from what it attested).
    if subject.get("receipt_count") != len(receipts):
        return AdmissionResult(
            False,
            "count_mismatch",
            f"count {subject.get('receipt_count')} != {len(receipts)} fetched",
        )
    # 4a. Curated-ledger stopgap: the fetched ledger MUST involve at least one
    # known-honest anchor, else it is treated as incomplete (defeats the trivial
    # "publish my ring with no honest anchor" laundering). Disabled when the policy
    # carries no anchors.
    if policy.required_anchors and not _involves_anchor(receipts, policy.required_anchors):
        return AdmissionResult(
            False, "anchor_absent", "fetched ledger involves no required anchor (incomplete)"
        )
    ledger_wide = reputation_score_v2(receipts, is_valid=is_valid)
    if abs(ledger_wide - float(subject.get("reputation_score", 0))) > policy.score_tolerance:
        return AdmissionResult(
            False, "score_mismatch", "ledger-wide reputation_score does not recompute"
        )

    # 5. The gate DERIVES the subject's severed score over the full graph — an
    # isolated ring member lands at 0 here, computed by the gate, not attested.
    subject_did = subject.get("id")
    if not isinstance(subject_did, str):
        return AdmissionResult(False, "root_mismatch", "credentialSubject has no subject id")
    severed = subject_severed_score(receipts, subject=subject_did, is_valid=is_valid)
    if severed < policy.min_reputation_score:
        return AdmissionResult(
            False,
            "below_threshold",
            f"subject's collusion-severed score {severed:g} < {policy.min_reputation_score:g}",
        )

    return AdmissionResult.admitted()


__all__ = [
    "AdmissionPolicy",
    "AdmissionResult",
    "admit",
    "admit_over_published_ledger",
    "subject_severed_score",
]
