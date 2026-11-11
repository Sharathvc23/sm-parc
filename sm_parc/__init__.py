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

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _dist_version

from .admission import (
    WARNING_ANCHOR_CHECK_DISABLED,
    AdmissionPolicy,
    AdmissionResult,
    admit,
    admit_over_published_ledger,
    subject_severed_score,
)
from .credential import (
    build_reputation_credential,
    did_from_private_key,
    parse_rfc3339_instant,
    verify_credential_proof,
)
from .disclosure import InclusionProof, inclusion_proof, verify_inclusion

# Derived from installed distribution metadata, never hand-maintained. A literal
# here is a second copy of pyproject's ``version`` with nothing comparing them —
# the shape that shipped sm-provision 0.1.0 reporting "0.0.1" and sm-authority
# 0.1.0 reporting the same wrong value from the same template. Correct today is
# not the test; it drifts at the next bump.
try:  # pragma: no cover - trivial branch, both sides asserted in tests
    __version__ = _dist_version("sm-parc")
except _PackageNotFoundError:  # running from a source tree, not installed
    __version__ = "0.0.0.dev0"

__all__ = [
    "WARNING_ANCHOR_CHECK_DISABLED",
    "AdmissionPolicy",
    "AdmissionResult",
    "InclusionProof",
    "admit",
    "admit_over_published_ledger",
    "build_reputation_credential",
    "did_from_private_key",
    "inclusion_proof",
    "parse_rfc3339_instant",
    "subject_severed_score",
    "verify_credential_proof",
    "verify_inclusion",
]
