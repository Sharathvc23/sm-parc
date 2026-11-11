# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-11-11

Security release from the 2026-11 audit. **Breaking**: `admit` and
`admit_over_published_ledger` take a required `presenter_did` keyword, and the
validity window is enforced against the real clock by default. Migration notes are
in the README ("Upgrading from 0.2.x to 0.3.0").

### Security
- **Expiry was opt-in and string-compared.** `now` defaulted to `None`, which
  skipped both window checks — an expired credential was admitted whenever the
  caller passed no clock — and the comparison was lexical, so a `+05:00` offset
  defeated it. `now` now defaults to `datetime.now(UTC)`; `now`, `validFrom` and
  `validUntil` are parsed as offset-aware RFC 3339 instants (naive, missing or
  unparseable → `malformed`) and compared as instants. `now` stays injectable
  (RFC 3339 string or aware `datetime`) for tests.
- **No presenter binding.** A credential + ledger is public bytes and nothing
  checked who presented it; anyone holding a copy was admitted as its subject.
  Both gates now take `presenter_did` — the did the verifier authenticated for
  the connecting agent — and reject `presenter_mismatch` unless it equals
  `credentialSubject.id`.
- **Another agent's ledger was admitted under the subject.** An issuer-signed
  inline ledger of agent Y's receipts labelled with subject X recomputed
  perfectly (root, count, scores) and admitted X on Y's reputation. The inline
  gate now requires every receipt's `issuer_did == credentialSubject.id`
  (`ledger_subject_mismatch`). Pointer-mode community ledgers are multi-issuer
  by design and bind the subject through the derived per-subject score instead.
- **Revocation was unenforceable for id-less credentials.**
  `build_reputation_credential(credential_id=None)` omitted `id`, and the gate
  keys revocation on `vc.id`. The builder now always emits an `id`
  (`urn:uuid:<uuid4>` when none is supplied; an empty string raises) and the
  gate rejects a credential without one (`missing_id`).
- **`max_ledger_receipts` was pointer-mode only.** The inline gate now enforces
  it too, BEFORE any hashing or recomputation (`ledger_too_large`).
- **Non-numeric facet values raised out of the gate.** `float()` on a string,
  `None`, list or bool score crashed the verifier; they are now a `malformed`
  rejection. NaN/Infinity (which would pass both the tolerance and threshold
  comparisons) are refused as well — JCS cannot encode them, so such a
  credential also fails the proof.

### Added
- **`AdmissionResult.warnings`** — structured list of defences the policy left
  disabled. Today: `anchor_check_disabled` whenever `required_anchors` is empty,
  on every result (admitted or rejected). The default policy is unchanged and
  scores are never altered; README/SPEC/THREATMODEL now say plainly that a
  production policy MUST set anchors (three fresh dids forge a recompute-clean
  credential without them).
- **`parse_rfc3339_instant`** and **`WARNING_ANCHOR_CHECK_DISABLED`** exported.
- **Real-verifier end-to-end suite** (`tests/test_end_to_end_real_verifier.py`):
  real sm-arp receipts issued and signed by the agent, co-signed by real
  counterparties (`sm_arp.vrp.cosign_receipt`), scored by `build_ledger` and
  admitted with `is_valid=lambda r: sm_arp.verify_receipt(r).ok` — trusted issuer
  admitted; untrusted / tampered score / proof removed / expired on the default
  clock / wrong presenter / another agent's ledger / over cap / forged receipt
  signature all rejected. Every other test module stubbed validity with
  `_always` and `"AA=="` signatures, so the production composition had never
  been exercised.
- Hostile-path tests for every new stage (`missing_id`, `malformed`,
  `presenter_mismatch`, `ledger_subject_mismatch`, inline `ledger_too_large`),
  for the offset-defeats-string-comparison case, and for the warning.

### Changed
- **`build_reputation_credential` validates the window**: `valid_from` /
  `valid_until` must be RFC 3339 instants with an offset and `valid_from` must
  not be after `valid_until`, else `ValueError` — rather than minting a
  credential every 0.3.0 gate rejects as `malformed`.
- **sm-arp pin raised to `>=0.4.0,<0.5`.** 0.4.0's canonical bytes exclude
  `evidence.witness_signatures`, so a real ARP receipt stays verifiable after a
  counterparty co-signs it — which is what makes the real-verifier suite
  possible. (The README's install line still said `<0.3`; fixed.)
- Examples (`mint_and_admit`, `two_city_admission`, `published_ledger_admission`,
  `three_city_economy`) pass the authenticated presenter explicitly and print the
  gate's warnings.
- CI installs sm-arp 0.4.0 from its merged commit on GitHub until that version is
  on PyPI; the step is marked for removal once it is.

## [0.2.3] — 2026-07-08

Compatibility release — no behavior change.

### Changed
- **Lifted the `sm-arp<0.3` cap to `<0.4`.** sm-arp 0.3.0 (the DAT bridge) is
  backward compatible — its new `verify_authority_chain` hooks are opt-in and
  the pre-bridge behavior is preserved when they aren't passed. The full
  sm-parc suite passes unchanged against sm-arp 0.3.0. This unblocks
  downstreams that were forced to hold sm-arp at 0.2.3 solely because of this
  cap (they can now unify on 0.3.0).

### Fixed
- **`__version__` no longer drifts from the dist metadata** (#1): it was stuck
  at `"0.2.0"` while the package published 0.2.2.

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
