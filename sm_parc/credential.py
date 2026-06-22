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
    (caller-supplied; this module takes no wall-clock).
    """
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
        "type": list(CREDENTIAL_TYPE),
        "issuer": issuer_did,
        "validFrom": valid_from,
        "validUntil": valid_until,
        "credentialSubject": subject,
    }
    if credential_id is not None:
        vc["id"] = credential_id
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
    "verify_credential_proof",
]
