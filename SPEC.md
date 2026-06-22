# PARC — Portable Agent Reputation Credential — Working Draft

**Version (wire):** `parc/0.1`
**Status:** Working Draft. Reviewable, not yet frozen.
**Last updated:** 2026-06-20

> **Source of truth.** When a runtime disagrees with this specification, the
> runtime is wrong by definition. Behaviour changes require a PR to this document
> plus updates to the suite and every reference implementation. Conformance is
> verified mechanically by the test suite.

> **Conformance language.** Normative requirements use RFC 2119 keywords
> (**MUST**, **SHOULD**, **MAY**). All other text is non-normative.

---

## 1. Scope and non-goals

### 1.1 Scope
This profile defines (a) the **ReputationCredential** — a W3C Verifiable Credential
whose `credentialSubject` is a Verifiable Receipts Profile (VRP) facet — and (b) the
**admission gate** that consumes it: how a verifier decides to admit or reject an
agent from a reputation credential it can verify without trusting the issuer's
server.

### 1.2 Non-goals
The receipt format (Agency Receipt Protocol, ARP), the ledger commitment + scoring (VRP / `sm_arp.vrp`,
including the `nanda-rep/0.2` corroboration + collusion-severing maths), the
auditor *runtime* that computes attestations, revocation transport, and selective
disclosure are out of scope. PARC composes the first two and verifies the third.

### 1.3 Audiences
| Audience | Read |
| --- | --- |
| Issuers (chapters, auditors) | §3 Credential |
| Verifiers (admitting chapters) | §4 Admission |

## 2. Relationship to other specifications
- **W3C Verifiable Credentials 2.0** — the credential envelope (`@context`, `type`,
  `issuer`, `validFrom`/`validUntil`, `credentialSubject`, `proof`).
- **VRP / `sm_arp.vrp`** — `behavioral_merkle_root`, the `nanda-rep/0.2` scoring
  method (corroboration-gated + collusion-severed) and its `corroboration_rate`, the
  Receipts Ledger that the credential commits to and the gate recomputes.
- **ARP** — the receipt primitive the ledger is built from. `nanda-rep/0.2` requires
  receipts corroborated by a distinct counterparty (`evidence.witness_signatures`).

Acronyms (ARP, VRP, PARC, DAT, VC, DID, JCS, SCC) are expanded in
[`GLOSSARY.md`](./GLOSSARY.md).

## 3. The ReputationCredential

A `type: ["VerifiableCredential", "ReputationCredential"]` VC. The
`credentialSubject` MUST carry: `id`, `behavioral_merkle_root`, `scoring_method`
(`"nanda-rep/0.2"`), `reputation_score`, `validity_rate`, `corroboration_rate`,
`receipt_count`, `as_of`. The `reputation_score` is the corroborated, collusion-
resistant `nanda-rep/0.2` score: only ARP-valid, counterparty-corroborated, non-
severed receipts contribute; an un-corroborated or wash-traded receipt earns zero
(it still counts toward `validity_rate`). `corroboration_rate` is the share of
ARP-valid receipts that are corroborated and not severed.

`credentialSubject.id` is the **acting agent** — the `issuer_did` of the receipts the
ledger commits to (the identity that signed the actions), NOT the `principal_did` (the
human on whose behalf it acted). Reputation is "how reliably has this agent acted", so
the ledger MUST be built from receipts whose `issuer_did` equals the subject, and
`ledger.subject` MUST equal `credentialSubject.id`. (For a sovereign agent that is its
own principal, `issuer_did == principal_did` and the distinction collapses.)

`issuer` is the originating chapter (self-attested) or a credentialed auditor. The `proof` is `Ed25519Signature2020`: an Ed25519 signature,
base64 in `proof.proofValue`, over the RFC 8785 (JCS) canonical bytes of the VC with
`proof` removed — the same canonical signing path as ARP/DAT. A verifier MUST verify
the proof under the `issuer` did:key.

### 3.1 Inline vs pointer mode

The OPTIONAL `credentialSubject.ledger_uri` field discriminates two admission modes,
and a verifier MUST pair the credential with the matching gate:

- **Inline** (no `ledger_uri`): the subject presents the ledger's own receipts; the
  gate recomputes them and thresholds the per-subject `reputation_score`. Verified by
  `admit`.
- **Pointer** (`ledger_uri` present): the facet's `reputation_score` is the
  **ledger-wide** score of a published *community* ledger, and the gate fetches that
  ledger and DERIVES the subject's collusion-severed score over the full graph. Verified
  by `admit_over_published_ledger`.

A verifier MUST NOT admit a pointer credential through the inline gate: its
`reputation_score` is the community total, so thresholding it would re-admit a severed
ring member. `admit` rejects a credential carrying `ledger_uri` (`wrong_mode`), and
`admit_over_published_ledger` rejects one lacking it (`wrong_mode`).

### 3.2 Selective disclosure

As a ledger grows, a holder need not present every receipt. A holder MAY reveal a
subset of receipts, each accompanied by a **Merkle inclusion proof** against the
credential's signed `behavioral_merkle_root` (`inclusion_proof` / `verify_inclusion`).
The proof uses the SAME leaf and tree construction as the root (leaves =
`SHA-256(JCS(receipt))` sorted by `issued_at` then `receipt_id`; node =
`SHA-256(left || right)`; an odd node is duplicated). A verifier confirms each revealed
receipt is committed **without** the rest of the ledger.

This is a property of the **transactions** layer, NOT the score. The
`reputation_score` is an aggregate over the *whole* committed graph — collusion
severance requires every edge — so it is taken as the issuer's signed value (or
re-derived in pointer mode), never recomputed from a revealed subset. A verifier MUST
NOT treat a disclosed subset as grounds to recompute or adjust the score. The two are
separate disclosures: the signed aggregate proves *how reputable*, the inclusion proofs
prove *which transactions happened*.

### 3.3 Pointer-mode safeguards (v0.1)

Pointer mode (`admit_over_published_ledger`) carries two optional policy controls that a
verifier SHOULD set until the notary layer exists:

- **Required anchors** (`policy.required_anchors`) — a local allowlist of known-honest
  dids. A fetched ledger that involves none of them (as issuer or counterparty) MUST be
  rejected as incomplete (`anchor_absent`). This is a *stopgap* for the curated-ledger
  residual: it defeats a ledger published with no honest anchor at all, but NOT one that
  wires a single real edge to an anchor. See [`THREATMODEL.md`](./THREATMODEL.md).
- **Execution budget** (`policy.max_ledger_receipts`) — collusion severance runs over the
  whole fetched graph, so a verifier MUST be able to bound it. A fetched ledger exceeding
  the cap MUST be rejected (`ledger_too_large`) BEFORE recomputation, keeping the gate a
  deterministic pure function within safe execution limits.

## 4. The admission gate

Given a credential `vc`, the agent's presented Receipts `ledger`, an `is_valid`
receipt predicate, an `AdmissionPolicy`, and (optionally) `now`, a verifier MUST
evaluate, in order, rejecting at the first failure:

1. **signature** — the VC proof MUST verify under `issuer`.
2. **untrusted_issuer** — `issuer` MUST be in `policy.trusted_issuers` (a chapter
   **or** an auditor did — see §4.5).
3. **revoked** — `vc.id` MUST NOT be in `policy.revocation`.
4. **not_yet_valid** — when `now` is given, `now` MUST NOT be before `validFrom`.
5. **stale** — when `now` is given, `now` MUST NOT be after `validUntil`.
6. **scoring_method_unsupported** — `credentialSubject.scoring_method` MUST equal
   `policy.required_scoring_method` (default `"nanda-rep/0.2"`). A credential whose
   facet is the un-corroborated `nanda-rep/0.1` score is rejected here — the gate
   refuses to admit on a score with no collusion resistance (`corroboration_required`).
7. **count_mismatch** — when `policy.require_recomputation` (default true), the
   credential's signed `credentialSubject.receipt_count` MUST equal the number of
   receipts in the presented `ledger` (a presenter MUST NOT withhold receipts to move
   the recomputed scores).
8. **root_mismatch** — the `ledger` MUST be inline-recomputable and
   `behavioral_merkle_root(ledger.receipts)` MUST equal the credential's root.
9. **score_mismatch** — the recomputed `nanda-rep/0.2` `reputation_score`,
   `validity_rate`, and `corroboration_rate` MUST equal the credential's (within
   `policy.score_tolerance`).
10. **below_threshold** — `reputation_score` ≥ `policy.min_reputation_score` and
    `validity_rate` ≥ `policy.min_validity_rate`. A wash-trading ring's severed
    `nanda-rep/0.2` score is ~0, so it fails here even on a self-consistent credential.

A verifier SHOULD keep `require_recomputation` true: recomputation is what lets it
trust the *signature + its own math* rather than the issuer's server, and is what
defeats a signed-but-inflated score. Binding admission to `nanda-rep/0.2` (steps 6
and 9) is what defeats a collusion ring: the same recomputation that catches inflation
also severs self-dealt corroboration.

### 4.5 Bootstrapping `trusted_issuers`

`policy.trusted_issuers` is the set of issuer did:keys an admitting chapter accepts
(chapters and/or auditors). It is bootstrapped from **sm-conformance badges**: a
runtime that passes conformance publishes a signed sm-conformance badge binding its
did:key to a passing result. An admitting chapter SHOULD populate `trusted_issuers`
with the dids of issuers that hold a valid, current sm-conformance badge — verifying
the badge's signature and freshness — optionally narrowed by a manual allowlist or
widened by a federation roster. An auditor is trusted the same way: its did MUST carry
a valid badge for its auditor conformance profile. This keeps the trust root
mechanical (a signed badge anyone can check) rather than a declarative allowlist.

## 5. Conformance
A conformant implementation passes the suite under `tests/`. The suite is the only
mechanical authority; every guarantee here has a happy-path test and every rejection
stage a hostile-path test.

## 6. Versioning
SemVer. A breaking change to the credential shape or the gate ordering bumps major;
additive optional fields bump minor; clarifications bump patch.

## 7. References
- W3C Verifiable Credentials Data Model 2.0.
- RFC 8785 — JSON Canonicalization Scheme (JCS).
- sm-arp (ARP + VRP). sm-conformance (signing infrastructure).

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
