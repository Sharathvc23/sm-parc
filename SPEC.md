# PARC — Portable Agent Reputation Credential — Working Draft

**Version (wire):** `parc/0.1`
**Status:** Working Draft. Reviewable, not yet frozen.
**Last updated:** 2026-11-11 (gate profile 0.3.0)

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

A `type: ["VerifiableCredential", "ReputationCredential"]` VC. The credential MUST
carry an `id` (a non-empty string; issuers SHOULD use `urn:uuid:<uuid4>`) — revocation is
keyed on it, and a verifier MUST reject a credential without one (`missing_id`) rather
than admit something it could never revoke. `validFrom` and `validUntil` MUST both be
present and MUST be RFC 3339 `date-time` strings carrying an offset (`Z` or `±hh:mm`);
an issuer MUST NOT mint an offset-less or missing bound, and a verifier MUST reject one
(`malformed`). The `credentialSubject` MUST carry: `id`, `behavioral_merkle_root`,
`scoring_method` (`"nanda-rep/0.2"`), `reputation_score`, `validity_rate`,
`corroboration_rate`, `receipt_count`, `as_of`. The three rates/scores MUST be finite
JSON numbers (a verifier MUST reject any other type as `malformed`; JCS cannot encode
NaN/Infinity, so such a credential cannot carry a verifying proof either). The `reputation_score` is the corroborated, collusion-
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

### 3.3 Policy safeguards (both modes)

Both gates carry two policy controls. They are optional in the type system so that the
library stays usable in tests and demos; **a production verifier MUST set both**:

- **Required anchors** (`policy.required_anchors`) — a local allowlist of known-honest
  dids. A ledger that VERIFIABLY involves none of them (issued by an anchor, or carrying
  an anchor's verifying co-signature) MUST be rejected (`anchor_absent`). This is the
  sybil defence: dids are free to mint, so a recomputable corroborated score alone proves
  arithmetic, not honesty — **with no anchors, three fresh dids can forge a
  recompute-clean, bar-clearing credential** (self-issued receipts co-signed by throwaway
  counterparties). An empty set disables the check; the gate MUST then report it on every
  result as `warnings: ["anchor_check_disabled"]` (it MUST NOT alter the decision or the
  scores). The anchor rule is still only a *stopgap* for the curated-ledger residual: it
  defeats a ledger with no honest anchor at all, but NOT one that wires a single real
  edge to an anchor. See [`THREATMODEL.md`](./THREATMODEL.md).
- **Execution budget** (`policy.max_ledger_receipts`) — hashing and collusion severance
  run over the whole presented/fetched graph, so a verifier MUST be able to bound it. A
  ledger exceeding the cap MUST be rejected (`ledger_too_large`) BEFORE any per-receipt
  work in BOTH modes (since 0.3.0 the inline gate enforces it too), keeping the gate a
  deterministic pure function within safe execution limits.

## 4. The admission gate

Given a credential `vc`, the did `presenter_did` the verifier has **authenticated** for
the agent presenting it (see §4.6), the agent's presented Receipts `ledger`, an
`is_valid` receipt predicate (normally the ARP verifier), an `AdmissionPolicy`, and the
evaluation instant `now` (defaulting to the verifier's UTC wall clock; injectable for
tests), a verifier MUST evaluate, in order, rejecting at the first failure:

1. **signature** — the VC proof MUST verify under `issuer`.
2. **untrusted_issuer** — `issuer` MUST be in `policy.trusted_issuers` (a chapter
   **or** an auditor did — see §4.5).
3. **missing_id** — `vc.id` MUST be a non-empty string (§3).
4. **revoked** — `vc.id` MUST NOT be in `policy.revocation`.
5. **malformed** — `now`, `validFrom` and `validUntil` MUST each parse as an RFC 3339
   instant with an offset; `credentialSubject` MUST be an object whose `id` is a
   non-empty string; `reputation_score` / `validity_rate` / `corroboration_rate`, when
   present, MUST be finite numbers. The verifier MUST NOT raise on any of these — a
   malformed credential is a rejection, not a crash.
6. **not_yet_valid** — the instant `now` MUST NOT be before the instant `validFrom`.
7. **stale** — the instant `now` MUST NOT be after the instant `validUntil`. Steps 6–7
   compare *instants*, never strings: `2026-07-06T20:00:00-05:00` is after
   `2026-07-07T00:00:00Z` although it sorts before it. They are NOT optional — a
   verifier MUST NOT skip the window when the caller supplies no clock.
8. **presenter_mismatch** — `credentialSubject.id` MUST equal `presenter_did` (§4.6).
9. **scoring_method_unsupported** — `credentialSubject.scoring_method` MUST equal
   `policy.required_scoring_method` (default `"nanda-rep/0.2"`). A credential whose
   facet is the un-corroborated `nanda-rep/0.1` score is rejected here — the gate
   refuses to admit on a score with no collusion resistance (`corroboration_required`).
10. **wrong_mode** — an inline gate MUST refuse a credential carrying `ledger_uri`, and
    vice-versa (§3.1).
11. **ledger_too_large** — when `policy.max_ledger_receipts` is set, the presented (or
    fetched) ledger MUST NOT exceed it; checked BEFORE any per-receipt work (§3.3).
12. **count_mismatch** — when `policy.require_recomputation` (default true), the
    credential's signed `credentialSubject.receipt_count` MUST equal the number of
    receipts in the presented `ledger` (a presenter MUST NOT withhold receipts to move
    the recomputed scores).
13. **ledger_subject_mismatch** (inline mode) — every presented receipt's `issuer_did`
    MUST equal `credentialSubject.id`. An inline ledger is the subject's OWN history;
    without this rule an issuer-signed ledger earned by agent Y, labelled with subject
    X, recomputes perfectly and admits X on Y's reputation. Pointer-mode community
    ledgers are multi-issuer by construction and are bound to the subject by step 16
    instead (only the subject's own receipts are scored).
14. **root_mismatch** — the `ledger` MUST be inline-recomputable and
    `behavioral_merkle_root(ledger.receipts)` MUST equal the credential's root.
15. **anchor_absent** — when `policy.required_anchors` is non-empty, some receipt MUST
    verifiably involve an anchor (§3.3). When it is empty the result MUST carry the
    `anchor_check_disabled` warning.
16. **score_mismatch** — the recomputed `nanda-rep/0.2` `reputation_score`,
    `validity_rate`, and `corroboration_rate` MUST equal the credential's (within
    `policy.score_tolerance`). In pointer mode the ledger-wide score is recomputed and
    the subject's collusion-severed score is then DERIVED over the full graph.
17. **below_threshold** — `reputation_score` ≥ `policy.min_reputation_score` and
    `validity_rate` ≥ `policy.min_validity_rate`. A wash-trading ring's severed
    `nanda-rep/0.2` score is ~0, so it fails here even on a self-consistent credential.

Every result — admitted or rejected — carries `warnings`, a list of the policy
defences left disabled (today: `anchor_check_disabled`). Warnings MUST NOT change the
decision.

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

### 4.6 Presenter binding

A credential and its ledger are public bytes: nothing in them is secret, and nothing in
the envelope says who is holding them. A gate that checks only the issuer's signature
therefore admits *anyone* who obtained a copy. The verifier MUST bind admission to the
agent it is actually talking to: `presenter_did` is the did the verifier has
**authenticated out-of-band** for the connecting agent — e.g. the `did:key` that signed
the admission request, or the mutually-authenticated session identity — and the gate
admits only when `credentialSubject.id == presenter_did`. A verifier MUST NOT derive
`presenter_did` from the credential or the ledger it is verifying; doing so re-opens the
replay hole this step closes. Authenticating the presenter (the channel, the request
signature) is the verifier's responsibility and out of scope here; PARC only guarantees
that whatever identity was authenticated is the one the credential is for.

## 5. Conformance
A conformant implementation passes the suite under `tests/`. The suite is the only
mechanical authority; every guarantee here has a happy-path test and every rejection
stage a hostile-path test.

## 6. Versioning
SemVer. A breaking change to the credential shape or the gate ordering bumps major;
additive optional fields bump minor; clarifications bump patch. While the package is
pre-1.0, breaking changes to the *gate API* (such as 0.3.0's required `presenter_did`)
bump minor and are called out in `CHANGELOG.md` with a migration section in the README.

## 7. References
- W3C Verifiable Credentials Data Model 2.0.
- RFC 8785 — JSON Canonicalization Scheme (JCS).
- sm-arp (ARP + VRP). sm-conformance (signing infrastructure).

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
