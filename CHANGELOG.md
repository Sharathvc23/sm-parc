# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.2] — 2026-07-03

Security release: the anchor rule now actually defends what it claims to.

### Fixed
- **`required_anchors` was silently ignored by the inline `admit()` path.** The
  policy field was accepted but only `admit_over_published_ledger` enforced it,
  so an inline gate configured with anchors got no anchor enforcement at all.
  Inline `admit()` now applies the same rule, and — fail closed — refuses
  (`anchor_absent`) when `required_anchors` is set with
  `require_recomputation=False`, since anchor contact is only checkable from a
  presented ledger.
- **The anchor check counted unverified mentions.** `_involves_anchor` matched
  any receipt that merely *named* an anchor as issuer or counterparty — one
  junk receipt naming an anchor laundered an otherwise anchor-free ledger
  through the pointer-mode gate. An anchor now counts only when its
  involvement VERIFIES: the anchor issued the receipt (and it passes
  `is_valid`), or the anchor's counterparty co-signature verifies
  (`is_corroborated`). Both admission modes share the hardened check.

### Changed
- Behavior change for hostile inputs only: ledgers relying on nominal anchor
  mentions now fail `anchor_absent`. Genuinely co-signed anchor contact is
  unaffected (all pre-0.2.2 tests pass unchanged).

### Notes
- Found while building The Town Notary's `/countersign-parc` gate, which
  shipped the verified-involvement rule service-side first.
- Known twin: the Nanda Town `trust: parc` plugin (projnanda/nandatown PR #63)
  is an idiomatic re-implementation of this design under that simulator's
  constraints (stdlib-only, its own receipt format, tick clocks, sorted-key
  canonicalization). It is not a consumer of this package; where vocabularies
  differ, THIS package is canonical. The twin also carries features this
  package does not yet have (issuer key-rotation windows verified as-of
  `validFrom`; presenter binding) — candidates for 0.3.

## [0.2.1] — 2026-06-22

Initial public release.

### Added
- **Portable reputation credential.** A signed W3C Verifiable Credential over a VRP
  behavioral facet — `behavioral_merkle_root` plus a corroboration-gated,
  collusion-severed `nanda-rep/0.2` score. Issue with `build_reputation_credential`;
  verify the signature with `verify_credential_proof`.
- **Admission gate, two modes.** `admit` — inline, single-subject, fully offline — and
  `admit_over_published_ledger` — pointer mode, where the credential names a published
  ledger and the verifier fetches it, checks it against the signed
  `behavioral_merkle_root`, and recomputes the subject's collusion-severed score over the
  full graph itself. Pointer mode catches an N-party Sybil ring that the single-subject
  inline credential structurally cannot.
- **Pointer-mode policy controls.** `AdmissionPolicy.required_anchors` rejects a fetched
  ledger that involves no known-honest issuer (`anchor_absent`); `max_ledger_receipts`
  bounds the recomputation against an oversized ledger (`ledger_too_large`).
- **Selective disclosure** (`inclusion_proof` + `verify_inclusion`). A holder reveals only
  chosen receipts, each with a Merkle inclusion proof against the credential's signed
  root, without exposing the rest of the ledger. Pure SHA-256 over the same leaf/tree
  construction as the VRP root — no zero-knowledge.
- **Mode safety.** The inline gate refuses a pointer credential and vice-versa
  (`wrong_mode`), so a pointer credential can never be thresholded inline and re-admit a
  severed ring member.
- **Documentation** — `README`, `SPEC` (normative credential + admission profile),
  `WHITEPAPER`, `THREATMODEL` (what the gate does and does not defend), `GOVERNANCE`,
  `GLOSSARY`, and an illustrated `docs/WALKTHROUGH.md`.
- **Examples** — `mint_and_admit`, `two_city_admission`, `three_city_economy` (one PARC
  carried community → marketplace → enterprise), and `published_ledger_admission`
  (pointer-mode ring severance).

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
