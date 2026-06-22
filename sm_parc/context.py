"""PARC constants — the credential @context, type, and proof identifiers."""

from __future__ import annotations

# W3C Verifiable Credentials 2.0 base context + the PARC term context.
CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
PARC_CONTEXT = "https://stellarminds.ai/contexts/parc/v0.1"

# Credential type. A ReputationCredential is a VC whose credentialSubject is a
# VRP verifiable-receipts facet (behavioral_merkle_root + nanda-rep/0.2 scores).
CREDENTIAL_TYPE = ["VerifiableCredential", "ReputationCredential"]

# Proof suite identifier (Ed25519 over the JCS-canonical VC sans-proof — the same
# canonical signing path as ARP/DAT receipts).
PROOF_TYPE = "Ed25519Signature2020"

__all__ = ["CONTEXT_V2", "CREDENTIAL_TYPE", "PARC_CONTEXT", "PROOF_TYPE"]
