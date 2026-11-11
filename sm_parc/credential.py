"""The reputation credential — build + verify a W3C VC over a VRP ledger.

A ReputationCredential wraps a VRP Receipts Ledger's commitment + scores
(``behavioral_merkle_root`` + the ``nanda-rep/0.2`` ``reputation_score`` /
``validity_rate`` / ``corroboration_rate``) as a W3C Verifiable Credential, signed
by the originating chapter or a credentialed auditor. The proof is Ed25519 over the
JCS-canonical VC sans-``proof`` — the same canonical signing path as ARP receipts
and DATs, so the whole stack verifies signatures one way.

The credential is the *portable* form: an agent carries it to a new chapter, which
verifies the proof and recomputes the ledger (see ``sm_parc.admission``) without
trusting the issuing chapter's live server. The default scoring method is the
corroborated, collusion-resistant ``nanda-rep/0.2`` — a wash-trading ring's score
is severed to ~0, so it cannot buy its way past the gate.
"""

from __future__ import annotations

import base64
import re
import uuid
from datetime import datetime
from typing import Any

import base58
import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sm_arp.vrp import SCORING_METHOD_V2

from .context import CONTEXT_V2, CREDENTIAL_TYPE, PARC_CONTEXT, PROOF_TYPE

_DID_PREFIX = b"\xed\x01"

# RFC 3339 `date-time`: full date, "T", full time (optional fraction), and a MANDATORY
# offset ("Z" or ±hh:mm). Stricter than ``datetime.fromisoformat`` on purpose: that
# parser also accepts a bare date, a space separator and an offset-less (naive) time,
# none of which name an instant.
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)


def parse_rfc3339_instant(value: object) -> datetime | None:
    """Parse ``value`` as an RFC 3339 ``date-time`` naming a definite instant.

    Returns an offset-aware :class:`datetime` (comparable across offsets, so
    ``2026-07-07T05:00:00+05:00`` and ``2026-07-07T00:00:00Z`` are the same instant),
    or ``None`` when ``value`` is not a string, does not match the RFC 3339 grammar,
    carries no offset, or is otherwise unparseable. The gate compares instants, never
    strings: a string comparison is defeated by any offset other than ``Z``.
    """
    if not isinstance(value, str) or not _RFC3339_RE.match(value):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.utcoffset() is None:  # pragma: no cover - the regex forces an offset
        return None
    return parsed


def did_from_private_key(sk_bytes: bytes) -> str:
    """did:key for a 32-byte Ed25519 seed."""
    pk = Ed25519PrivateKey.from_private_bytes(sk_bytes).public_key().public_bytes_raw()
    return "did:key:z" + base58.b58encode(_DID_PREFIX + pk).decode("ascii")


def _pubkey_from_did(did_key: str) -> Ed25519PublicKey:
    if not did_key.startswith("did:key:z"):
        raise ValueError(f"unsupported DID method: {did_key!r}")
    decoded = base58.b58decode(did_key[len("did:key:z") :])
    if len(decoded) != 34 or decoded[:2] != _DID_PREFIX:
        raise ValueError("not a did:key Ed25519 record")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def _canonical_bytes_for_signing(vc: dict[str, Any]) -> bytes:
    """JCS-canonical bytes of the VC with the ``proof`` removed."""
    return bytes(jcs.canonicalize({k: v for k, v in vc.items() if k != "proof"}))


def build_reputation_credential(
    *,
    ledger: dict[str, Any],
    issuer_sk: bytes,
    issuer_did: str | None = None,
    valid_from: str,
    valid_until: str,
    credential_id: str | None = None,
    ledger_uri: str | None = None,
) -> dict[str, Any]:
    """Build + sign a ReputationCredential over ``ledger``.

    The credential ALWAYS carries an ``id``: ``credential_id`` when supplied (a
    non-empty string), else a freshly generated ``urn:uuid:<uuid4>``. Revocation at
    the gate is keyed on ``vc.id`` (``policy.revocation``), so an id-less credential
    would be unrevocable — the gate rejects one (``missing_id``), and this builder
    never mints one.

    Pass ``ledger_uri`` to mint a POINTER-mode credential: the facet then carries a
    handle to a published community ledger instead of expecting the subject's receipts
    to be presented inline. A pointer credential is what
    :func:`sm_parc.admit_over_published_ledger` consumes — the verifier fetches that
    ledger and re-runs collusion severance itself (see ``THREATMODEL.md``).

    ``credentialSubject`` IS the VRP facet: the ledger's
    ``behavioral_merkle_root`` + nanda-rep scores + subject + ledger pointer. The
    facet mirrors the ledger's own ``scoring_method`` (defaulting to the
    corroborated ``nanda-rep/0.2``); when the ledger is ``nanda-rep/0.2`` the facet
    also carries its ``corroboration_rate`` (the 0.2 collusion-resistance signal).
    The issuer (``issuer_did``, defaulting to the key's own did) is the chapter
    (self-attested) or an auditor. ``valid_from`` / ``valid_until`` are RFC 3339
    ``date-time`` strings WITH an offset (caller-supplied; this module takes no
    wall-clock) and ``valid_from`` MUST NOT be after ``valid_until``; anything else
    raises ``ValueError`` here rather than minting a credential every gate rejects as
    ``malformed``.
    """
    if credential_id is None:
        credential_id = f"urn:uuid:{uuid.uuid4()}"
    elif not credential_id:
        raise ValueError("credential_id must be a non-empty string")
    window_start = parse_rfc3339_instant(valid_from)
    window_end = parse_rfc3339_instant(valid_until)
    if window_start is None:
        raise ValueError(f"valid_from {valid_from!r} is not an RFC 3339 instant with offset")
    if window_end is None:
        raise ValueError(f"valid_until {valid_until!r} is not an RFC 3339 instant with offset")
    if window_start > window_end:
        raise ValueError("valid_from is after valid_until")
    issuer_did = issuer_did or did_from_private_key(issuer_sk)
    subject: dict[str, Any] = {
        "id": ledger["subject"],
        "behavioral_merkle_root": ledger.get("behavioral_merkle_root"),
        "scoring_method": ledger.get("scoring_method", SCORING_METHOD_V2),
        "reputation_score": ledger.get("reputation_score"),
        "validity_rate": ledger.get("validity_rate"),
        "receipt_count": ledger.get("receipt_count"),
        "as_of": ledger.get("as_of"),
    }
    # nanda-rep/0.2 facets carry the corroboration rate (the collusion-resistance
    # signal); a 0.1 ledger has none, so the field is omitted there.
    if "corroboration_rate" in ledger:
        subject["corroboration_rate"] = ledger.get("corroboration_rate")
    # Pointer mode: the facet names the published community ledger the verifier must
    # fetch + re-sever, rather than carrying the subject's receipts inline.
    if ledger_uri is not None:
        subject["ledger_uri"] = ledger_uri
    vc: dict[str, Any] = {
        "@context": [CONTEXT_V2, PARC_CONTEXT],
        "id": credential_id,
        "type": list(CREDENTIAL_TYPE),
        "issuer": issuer_did,
        "validFrom": valid_from,
        "validUntil": valid_until,
        "credentialSubject": subject,
    }
    sig = Ed25519PrivateKey.from_private_bytes(issuer_sk).sign(_canonical_bytes_for_signing(vc))
    vc["proof"] = {
        "type": PROOF_TYPE,
        "verificationMethod": issuer_did,
        "proofValue": base64.b64encode(sig).decode("ascii"),
    }
    return vc


def verify_credential_proof(vc: dict[str, Any]) -> bool:
    """True iff the VC's Ed25519 proof verifies under its ``issuer`` did:key over
    the JCS-canonical VC sans-``proof``."""
    proof = vc.get("proof")
    issuer = vc.get("issuer")
    if not isinstance(proof, dict) or not isinstance(issuer, str):
        return False
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str):
        return False
    try:
        pubkey = _pubkey_from_did(issuer)
        pubkey.verify(base64.b64decode(proof_value), _canonical_bytes_for_signing(vc))
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        return False
    return True


__all__ = [
    "build_reputation_credential",
    "did_from_private_key",
    "parse_rfc3339_instant",
    "verify_credential_proof",
]
