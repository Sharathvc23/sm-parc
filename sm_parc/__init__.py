"""PARC — Portable Agent Reputation Credential.

A verifiable, recomputable reputation Verifiable Credential (a W3C VC over a VRP
Receipts Ledger) consumed at chapter admission. The admitting chapter verifies the
issuer signature and recomputes the ledger itself — it never trusts the issuing
chapter's live server.

    from sm_parc import build_reputation_credential, verify_credential_proof
    from sm_parc import AdmissionPolicy, admit

Composes ``sm_arp.vrp`` (behavioral_merkle_root + nanda-rep/0.2 corroborated,
collusion-resistant scoring + ledger verify) from the public ``sm-arp`` package.
"""

from __future__ import annotations

from .admission import (
    AdmissionPolicy,
    AdmissionResult,
    admit,
    admit_over_published_ledger,
    subject_severed_score,
)
from .credential import (
    build_reputation_credential,
    did_from_private_key,
    verify_credential_proof,
)
from .disclosure import InclusionProof, inclusion_proof, verify_inclusion

__version__ = "0.2.0"

__all__ = [
    "AdmissionPolicy",
    "AdmissionResult",
    "InclusionProof",
    "admit",
    "admit_over_published_ledger",
    "build_reputation_credential",
    "did_from_private_key",
    "inclusion_proof",
    "subject_severed_score",
    "verify_credential_proof",
    "verify_inclusion",
]
