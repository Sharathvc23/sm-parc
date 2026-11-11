"""The admission gate — verify a ReputationCredential at chapter admission.

The point of PARC: a chapter admits (or rejects) an agent on the strength of a
reputation credential it can verify *without trusting the issuing chapter's live
server*. The gate trusts two things only — the issuer's signature and its OWN
recomputation of the ledger:

  1. the VC proof verifies under the issuer did;
  2. the issuer is trusted by policy (a chapter OR a credentialed auditor);
  3. the credential carries an ``id`` (so it CAN be revoked), is not revoked, and is
     inside its validity window (``validFrom`` ≤ now ≤ ``validUntil``, compared as
     instants against the real clock unless the caller injects ``now``);
  4. the credential is bound to the agent presenting it
     (``credentialSubject.id == presenter_did``) — a public credential + ledger
     cannot be replayed by a third party;
  5. the credential's ``scoring_method`` is the corroborated, collusion-resistant
     ``nanda-rep/0.2`` — a credential carrying the un-corroborated ``nanda-rep/0.1``
     score is rejected (``scoring_method_unsupported``);
  6. the presented ledger is within the execution budget, recomputable, its receipt
     count matches the credential's signed ``receipt_count`` (no withholding), and
     every receipt was issued BY the subject (inline mode — a ledger earned by
     another agent cannot be attached to this subject's credential);
  7. the ledger recomputes to the VC's ``behavioral_merkle_root`` and the
     ``nanda-rep/0.2`` ``reputation_score`` / ``validity_rate`` / ``corroboration_rate``;
  8. the scores clear the policy thresholds.

Why bind admission to ``nanda-rep/0.2`` (step 5 + the v2 recompute in step 7): the
0.2 score counts only receipts that are ARP-valid AND corroborated by a distinct
counterparty AND not part of a severed collusion component. A wash-trading ring
that mutually co-signs its own receipts is severed to a score of ~0, so its
credential FAILS the gate at the threshold. The un-corroborated ``nanda-rep/0.1``
score has no such defence, so the gate refuses to admit on it.

Step 6-7 recomputation is ``sm_arp.vrp``. Receipts' validity is supplied by the
caller as ``is_valid`` (normally the ARP verifier, ``sm_arp.verify_receipt``).
``now`` defaults to the UTC wall clock and is injectable for tests.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sm_arp.vrp import (
    DEFAULT_CATEGORY_WEIGHTS,
    SCORING_METHOD_V2,
    _effective_receipts,
    behavioral_merkle_root,
    corroboration_rate,
    is_corroborated,
    reputation_score_v2,
    validity_rate,
)

from .credential import parse_rfc3339_instant, verify_credential_proof

IsValid = Callable[[dict[str, Any]], bool]
Fetch = Callable[[str], dict[str, Any]]

# The numeric facet fields the gate reads. Each MUST be a finite real number when
# present: a non-numeric value used to raise ``TypeError``/``ValueError`` out of the
# gate, and a NaN would pass BOTH the tolerance comparison (``abs(nan - x) > tol`` is
# False) and the threshold (``nan < min`` is False) — i.e. be admitted.
_FACET_NUMBERS = ("reputation_score", "validity_rate", "corroboration_rate")

# Structured policy warnings (``AdmissionResult.warnings``). They never change the
# decision; they tell the operator which defence the policy has left switched off.
WARNING_ANCHOR_CHECK_DISABLED = "anchor_check_disabled"


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
    # Anchor rule (both admission modes since 0.2.2): a local allowlist of
    # known-honest "anchor" dids. The presented/fetched ledger must VERIFIABLY
    # involve at least one anchor — issued by it, or carrying its verifying
    # co-signature — else the credential is rejected (anchor_absent). This is
    # the sybil defense: free-to-mint counterparty dids can corroborate their
    # own receipts, so a recomputable score alone proves arithmetic, not
    # honesty. Empty set = check DISABLED, and every result then carries the
    # ``anchor_check_disabled`` warning: three fresh dids can forge a
    # bar-clearing, recompute-clean credential. Production policies MUST set
    # anchors. See THREATMODEL.md for the residual that remains even with them
    # (one real corroborated edge from an anchor still evades).
    required_anchors: set[str] = field(default_factory=set)
    # Deterministic execution budget (both admission modes since 0.3.0): the gate
    # hashes and severs the whole presented/fetched ledger, so a hostile presenter or
    # issuer could hand over an enormous graph to exhaust the verifier. A ledger with
    # more than this many receipts is rejected (ledger_too_large) BEFORE the
    # expensive recomputation. None = unbounded.
    max_ledger_receipts: int | None = None


@dataclass
class AdmissionResult:
    ok: bool
    # signature | untrusted_issuer | missing_id | revoked | malformed | not_yet_valid |
    # stale | presenter_mismatch | scoring_method_unsupported | wrong_mode |
    # ledger_too_large | count_mismatch | ledger_subject_mismatch | root_mismatch |
    # anchor_absent | score_mismatch | below_threshold | admitted
    stage: str
    detail: str
    # Policy warnings — defences the policy left disabled (see
    # ``WARNING_ANCHOR_CHECK_DISABLED``). Informational: never changes ``ok``.
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def admitted(cls) -> AdmissionResult:
        return cls(True, "admitted", "credential verifies and clears policy")


def _policy_warnings(policy: AdmissionPolicy) -> list[str]:
    warnings: list[str] = []
    if not policy.required_anchors:
        warnings.append(WARNING_ANCHOR_CHECK_DISABLED)
    return warnings


def _resolve_now(now: str | datetime | None) -> datetime | None:
    """The instant the gate evaluates the validity window at.

    ``None`` → the UTC wall clock (production). A string is parsed as an RFC 3339
    instant; a :class:`datetime` must be offset-aware. Returns ``None`` when the
    injected value does not name an instant (the caller then gets ``malformed``).
    """
    if now is None:
        return datetime.now(UTC)
    if isinstance(now, datetime):
        return now if now.utcoffset() is not None else None
    return parse_rfc3339_instant(now)


def _is_finite_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def _check_envelope(
    vc: dict[str, Any],
    *,
    policy: AdmissionPolicy,
    presenter_did: str,
    now: str | datetime | None,
) -> AdmissionResult | None:
    """Shared envelope checks for both admission modes: proof, trusted issuer,
    mandatory id + revocation, validity window (as instants), presenter binding,
    facet well-formedness, and the required scoring method.

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

    # Revocation is keyed on vc.id. A credential without one can never be revoked, so
    # the gate refuses it outright rather than admitting an unrevocable credential.
    cred_id = vc.get("id")
    if not isinstance(cred_id, str) or not cred_id:
        return AdmissionResult(False, "missing_id", "credential has no id; it cannot be revoked")
    if cred_id in policy.revocation:
        return AdmissionResult(False, "revoked", f"credential {cred_id} is revoked")

    # Validity window — compared as INSTANTS, never as strings. Both bounds are
    # required: a credential with no window is unbounded, and an offset other than
    # "Z" would defeat a lexical comparison. ``now`` defaults to the wall clock.
    instant = _resolve_now(now)
    if instant is None:
        return AdmissionResult(False, "malformed", f"now {now!r} is not an RFC 3339 instant")
    valid_from = parse_rfc3339_instant(vc.get("validFrom"))
    if valid_from is None:
        return AdmissionResult(
            False, "malformed", f"validFrom {vc.get('validFrom')!r} is not an RFC 3339 instant"
        )
    valid_until = parse_rfc3339_instant(vc.get("validUntil"))
    if valid_until is None:
        return AdmissionResult(
            False, "malformed", f"validUntil {vc.get('validUntil')!r} is not an RFC 3339 instant"
        )
    if instant < valid_from:
        return AdmissionResult(
            False,
            "not_yet_valid",
            f"credential not valid until {vc['validFrom']} (now {instant.isoformat()})",
        )
    if instant > valid_until:
        return AdmissionResult(
            False, "stale", f"credential expired at {vc['validUntil']} (now {instant.isoformat()})"
        )

    subject = vc.get("credentialSubject")
    if not isinstance(subject, dict):
        return AdmissionResult(False, "malformed", "credentialSubject is not an object")
    subject_did = subject.get("id")
    if not isinstance(subject_did, str) or not subject_did:
        return AdmissionResult(False, "malformed", "credentialSubject has no subject id")

    # Presenter binding: the credential is for ONE agent, and only that agent may be
    # admitted on it. Without this, anyone holding a (public) credential + ledger
    # could replay it. ``presenter_did`` is the did the verifier has AUTHENTICATED
    # for the connecting agent — never read from the credential or the ledger.
    if subject_did != presenter_did:
        return AdmissionResult(
            False,
            "presenter_mismatch",
            f"credential subject {subject_did} is not the presenter {presenter_did}",
        )

    for key in _FACET_NUMBERS:
        if key in subject and not _is_finite_number(subject[key]):
            return AdmissionResult(
                False,
                "malformed",
                f"credentialSubject.{key} {subject[key]!r} is not a finite number",
            )

    # The credential MUST carry the corroborated, collusion-resistant scoring method.
    # A credential whose facet is the un-corroborated nanda-rep/0.1 score is rejected
    # here: that score lets a wash-trading ring inflate itself, so the gate refuses to
    # admit on it (corroboration_required).
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


def _with_warnings(result: AdmissionResult, policy: AdmissionPolicy) -> AdmissionResult:
    result.warnings = _policy_warnings(policy)
    return result


def admit(
    vc: dict[str, Any],
    *,
    policy: AdmissionPolicy,
    presenter_did: str,
    ledger: dict[str, Any] | None = None,
    is_valid: IsValid | None = None,
    now: str | datetime | None = None,
) -> AdmissionResult:
    """Decide admission for ``vc`` under ``policy`` (INLINE, self-contained mode).

    The credential carries the subject's OWN receipts inline; the gate recomputes the
    facet from them. This is fully offline and leaks nothing but the subject's own
    history — but a single-subject credential's corroboration graph is a star, so this
    mode catches *self-dealing* (the corroboration filter) but structurally CANNOT see
    an N-party Sybil ring. For that, see :func:`admit_over_published_ledger`.

    ``presenter_did`` (required) is the did the verifier has authenticated for the
    agent presenting the credential — e.g. the key that signed the admission request.
    The credential is admitted only for its own subject (``presenter_mismatch``).

    ``ledger`` (the agent's presented Receipts Ledger) + ``is_valid`` are required
    when ``policy.require_recomputation`` is True (the default and recommended
    posture). ``now`` defaults to the UTC wall clock; inject an RFC 3339 string or an
    offset-aware :class:`datetime` for deterministic tests. The window is checked
    against both ``validFrom`` and ``validUntil`` as instants. Under recomputation the
    presented ledger must be within ``policy.max_ledger_receipts``, its signed
    ``receipt_count`` must match (anti-withholding), every receipt must have been
    issued by the subject (``ledger_subject_mismatch``), and the recomputed
    nanda-rep/0.2 ``reputation_score`` / ``validity_rate`` / ``corroboration_rate``
    must match the signed facet.

    Every result carries ``warnings`` naming the defences the policy left disabled —
    notably ``anchor_check_disabled`` when ``required_anchors`` is empty.
    """
    return _with_warnings(
        _admit_inline(
            vc,
            policy=policy,
            presenter_did=presenter_did,
            ledger=ledger,
            is_valid=is_valid,
            now=now,
        ),
        policy,
    )


def _admit_inline(
    vc: dict[str, Any],
    *,
    policy: AdmissionPolicy,
    presenter_did: str,
    ledger: dict[str, Any] | None,
    is_valid: IsValid | None,
    now: str | datetime | None,
) -> AdmissionResult:
    envelope = _check_envelope(vc, policy=policy, presenter_did=presenter_did, now=now)
    if envelope is not None:
        return envelope

    subject: dict[str, Any] = vc["credentialSubject"]
    subject_did: str = subject["id"]

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
        if not isinstance(receipts, list):
            return AdmissionResult(
                False, "root_mismatch", "presented ledger is not recomputable (no receipts)"
            )
        # 6a. Execution budget: reject an oversized ledger BEFORE any O(n) hashing or
        # the recomputation, so a hostile presenter cannot exhaust the verifier.
        if policy.max_ledger_receipts is not None and len(receipts) > policy.max_ledger_receipts:
            return AdmissionResult(
                False,
                "ledger_too_large",
                f"presented ledger has {len(receipts)} receipts > max {policy.max_ledger_receipts}",
            )
        if any("action" not in r for r in receipts):
            return AdmissionResult(
                False, "root_mismatch", "presented ledger is not recomputable (refs-only)"
            )
        # 6b. The credential's signed receipt_count MUST match the presented ledger —
        # a presenter cannot withhold receipts to change the recomputed scores.
        if subject.get("receipt_count") != len(receipts):
            return AdmissionResult(
                False,
                "count_mismatch",
                f"count {subject.get('receipt_count')} != {len(receipts)} presented",
            )
        # 6c. Subject binding: an inline ledger is the subject's OWN history, so every
        # receipt MUST have been issued by the subject. Without this, a ledger earned
        # by agent Y (and honestly signed over by the issuer) could be presented under
        # agent X's credential — X would be admitted on Y's reputation.
        foreign = [r.get("issuer_did") for r in receipts if r.get("issuer_did") != subject_did]
        if foreign:
            return AdmissionResult(
                False,
                "ledger_subject_mismatch",
                f"{len(foreign)} receipt(s) not issued by subject {subject_did} "
                f"(e.g. {foreign[0]!r})",
            )
        if behavioral_merkle_root(receipts) != subject.get("behavioral_merkle_root"):
            return AdmissionResult(
                False, "root_mismatch", "ledger does not recompute to the credential root"
            )
        # 6d. Anchor rule (sybil defense): dids are free to mint, so a
        # recomputable corroborated score alone is forgeable — an attacker
        # co-signs its own receipts with fresh "counterparties". When the policy
        # names anchors, the subject's history must VERIFIABLY involve one
        # (issued by an anchor, or carrying an anchor's verifying co-signature).
        if policy.required_anchors and not _involves_anchor(
            receipts, policy.required_anchors, is_valid=is_valid
        ):
            return AdmissionResult(
                False, "anchor_absent", "no verified receipt involves a required anchor"
            )
        # 7. Recompute the nanda-rep/0.2 facet (corroborated + collusion-severed)
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

    if not policy.require_recomputation and policy.required_anchors:
        # Fail closed: anchor contact can only be established from a presented,
        # recomputable ledger. Silently skipping the check (the pre-0.2.2
        # behavior for the inline path) turned a configured defense into a
        # no-op.
        return AdmissionResult(
            False,
            "anchor_absent",
            "required_anchors needs require_recomputation (a presented ledger)",
        )

    if float(subject.get("reputation_score", 0)) < policy.min_reputation_score:
        return AdmissionResult(False, "below_threshold", "reputation_score below policy minimum")
    if float(subject.get("validity_rate", 0)) < policy.min_validity_rate:
        return AdmissionResult(False, "below_threshold", "validity_rate below policy minimum")

    return AdmissionResult.admitted()


def _involves_anchor(
    receipts: list[dict[str, Any]], anchors: set[str], *, is_valid: IsValid
) -> bool:
    """True iff some receipt VERIFIABLY involves a required anchor did.

    Verifiably, not nominally: a receipt merely *naming* an anchor counts for
    nothing (an attacker can insert one junk receipt naming an anchor into an
    otherwise-laundered ledger). An anchor is involved iff either

    * the anchor **issued** the receipt and the receipt passes ``is_valid``
      (the anchor itself signed it), or
    * the anchor is the receipt's **counterparty**, the receipt passes
      ``is_valid``, and the anchor's co-signature verifies
      (:func:`sm_arp.vrp.is_corroborated`) — the anchor genuinely attested
      the interaction.
    """
    for r in receipts:
        if r.get("issuer_did") in anchors and is_valid(r):
            return True
        if (
            (r.get("action") or {}).get("counterparty_did") in anchors
            and is_valid(r)
            and is_corroborated(r)
        ):
            return True
    return False


def admit_over_published_ledger(
    vc: dict[str, Any],
    *,
    policy: AdmissionPolicy,
    presenter_did: str,
    fetch: Fetch,
    is_valid: IsValid,
    now: str | datetime | None = None,
) -> AdmissionResult:
    """Decide admission for ``vc`` in POINTER mode — the credential names a published
    community ledger (``credentialSubject.ledger_uri``) and the gate FETCHES it and
    re-runs the collusion analysis itself.

    Where :func:`admit` (inline) verifies a self-contained, single-subject credential
    offline, this path trades that for collusion-resistance the inline mode cannot
    have. The facet describes the LEDGER (root + ledger-wide scores); the gate:

      1. verifies the envelope (proof, trusted issuer, id + revocation, window as
         instants, presenter binding — ``presenter_did`` MUST equal
         ``credentialSubject.id`` — and ``nanda-rep/0.2``);
      2. ``fetch``-es the full ledger named by ``ledger_uri`` (caller supplies the
         resolver — no network here) and bounds it by ``policy.max_ledger_receipts``;
      3. checks the fetched ledger hashes to the credential's SIGNED
         ``behavioral_merkle_root`` (tamper-evidence: the host cannot serve a
         different ledger than the one the issuer committed to);
      4. checks the ledger-wide ``reputation_score`` recomputes from those receipts
         (anti-withholding / anti-substitution of the published ledger);
      5. **derives the subject's own collusion-severed score** over the full graph
         via :func:`subject_severed_score` and applies the threshold. An isolated
         N-party Sybil ring is severed to 0 HERE, by the gate — not trusted from an
         attested number.

    A community ledger is MULTI-issuer by design (the anchor's and the ring's receipts
    all live in it), so unlike inline mode there is no "every receipt issued by the
    subject" rule here; subject binding is step 5 — only receipts the subject itself
    issued are scored.

    Honest residual — the trust this does NOT remove: severance is only as good as
    the ledger's COMPLETENESS. A *colluding* issuer that publishes its ring WITHOUT
    the honest anchor (so the ring is the largest SCC and is never severed), or that
    injects a single cross-edge to the anchor, yields a ledger that recomputes HIGH
    and is admitted — and the gate, seeing only the published ledger, cannot tell.
    Pointer mode catches a LAZY-but-honest issuer; the colluding issuer is the notary
    / multi-issuer-attestation layer's problem. See ``THREATMODEL.md``.
    """
    return _with_warnings(
        _admit_pointer(
            vc, policy=policy, presenter_did=presenter_did, fetch=fetch, is_valid=is_valid, now=now
        ),
        policy,
    )


def _admit_pointer(
    vc: dict[str, Any],
    *,
    policy: AdmissionPolicy,
    presenter_did: str,
    fetch: Fetch,
    is_valid: IsValid,
    now: str | datetime | None,
) -> AdmissionResult:
    envelope = _check_envelope(vc, policy=policy, presenter_did=presenter_did, now=now)
    if envelope is not None:
        return envelope

    subject: dict[str, Any] = vc["credentialSubject"]
    subject_did: str = subject["id"]
    ledger_uri = subject.get("ledger_uri")
    if not isinstance(ledger_uri, str):
        return AdmissionResult(False, "wrong_mode", "inline credential (no ledger_uri); use admit")

    ledger = fetch(ledger_uri)
    receipts = ledger.get("receipts")
    if not isinstance(receipts, list):
        return AdmissionResult(
            False, "root_mismatch", "fetched ledger is not recomputable (no receipts)"
        )

    # 2a. Execution budget: reject an oversized ledger BEFORE any O(n) hashing or the
    # severance recomputation, so a hostile issuer cannot exhaust the verifier.
    if policy.max_ledger_receipts is not None and len(receipts) > policy.max_ledger_receipts:
        return AdmissionResult(
            False,
            "ledger_too_large",
            f"fetched ledger has {len(receipts)} receipts > max {policy.max_ledger_receipts}",
        )
    if any("action" not in r for r in receipts):
        return AdmissionResult(
            False, "root_mismatch", "fetched ledger is refs-only (not recomputable)"
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
    # carries no anchors (and the result then says so: anchor_check_disabled).
    if policy.required_anchors and not _involves_anchor(
        receipts, policy.required_anchors, is_valid=is_valid
    ):
        return AdmissionResult(
            False, "anchor_absent", "fetched ledger involves no verified required anchor"
        )
    ledger_wide = reputation_score_v2(receipts, is_valid=is_valid)
    if abs(ledger_wide - float(subject.get("reputation_score", 0))) > policy.score_tolerance:
        return AdmissionResult(
            False, "score_mismatch", "ledger-wide reputation_score does not recompute"
        )

    # 5. The gate DERIVES the subject's severed score over the full graph — an
    # isolated ring member lands at 0 here, computed by the gate, not attested.
    severed = subject_severed_score(receipts, subject=subject_did, is_valid=is_valid)
    if severed < policy.min_reputation_score:
        return AdmissionResult(
            False,
            "below_threshold",
            f"subject's collusion-severed score {severed:g} < {policy.min_reputation_score:g}",
        )

    return AdmissionResult.admitted()


__all__ = [
    "WARNING_ANCHOR_CHECK_DISABLED",
    "AdmissionPolicy",
    "AdmissionResult",
    "admit",
    "admit_over_published_ledger",
    "subject_severed_score",
]
