# PARC Threat Model (`parc/0.1`)

Portable Agent Reputation Credential — what the credential + admission gate actually
defend against, and (just as important) what they **do not**. This document is the
honest counterweight to a demo that can look more complete than it is.

> **One sentence:** PARC's trust boundary depends on which admission mode you run.
> *Inline* mode (self-contained credential) is fully offline but can only catch
> self-dealing — its boundary is **issuer integrity**. *Pointer* mode (the credential
> names a published ledger the gate fetches) lets the gate **re-run the collusion
> severance itself**, so it catches N-party rings — but its boundary moves to **ledger
> completeness**: the gate recomputes faithfully over *what was published*, and cannot
> see what an issuer left out.

## The layered stack — each layer owns one threat class

```
ARP   (sm-arp)      signs the act              — authenticity of a single receipt
VRP   (sm_arp.vrp)  severs collusion            — corroboration + Tarjan SCC severance over the ledger
PARC  (this repo)   ports the score             — a signed, verifiable credential + admission gate
notary / attestation (future)  anchors issuer trust  — who may issue, multi-issuer cross-attestation
```

**ARP** = Agency Receipt Protocol · **VRP** = Verifiable Receipts Profile · **PARC** =
Portable Agent Reputation Credential. All acronyms: [`GLOSSARY.md`](./GLOSSARY.md).

No single layer claims to stop every attack. PARC inherits collusion-resistance from
VRP (by **requiring `nanda-rep/0.2`**, the corroborated + severed score), and it
inherits issuer trust from the layer above (the verifier's `trusted_issuers` set).

## Two admission modes — a tradeoff, not a ladder

PARC's gate has two paths, and **neither dominates the other**:

| | **Inline** (`admit`) | **Pointer** (`admit_over_published_ledger`) |
| --- | --- | --- |
| Credential carries | the subject's OWN receipts | a `ledger_uri` + the root of a published community ledger |
| Offline? | ✅ fully | ⚠️ one fetch, then root-verified / cacheable |
| Privacy | only the subject's history is seen | the verifier fetches the issuer's **entire community ledger** |
| Availability | self-contained | depends on the ledger host |
| Catches self-dealing | ✅ corroboration filter | ✅ |
| Catches an N-party ring | ❌ — a single subject's graph is a star, never an SCC | ✅ — the gate re-runs SCC severance over the full graph |
| Trust residual | the issuer computed `nanda-rep/0.2` honestly | the issuer published a **complete** ledger |

Pointer mode buys ring-resistance by spending offline-ness, privacy, and availability.
The gate **derives** the subject's severed score from the fetched ledger (it does not
trust an attested number) — but it can only sever what is *in* that ledger.

## Coverage

| Threat | Demo | PARC v0.1 mitigation | Honest residual gap |
| --- | --- | --- | --- |
| **Self-dealing / wash receipts** | ✅ shown (both modes) | Gate's **corroboration filter** — a receipt counts only if a *distinct* counterparty co-signed it | Degenerate ring of 1–2 parties |
| **N-party Sybil corroboration ring** | ✅ shown (pointer mode) | **The gate fetches the full community ledger and re-runs Tarjan SCC severance itself** — an isolated dense ring is severed to 0, *derived by the verifier*. Inline mode structurally cannot show this (single-subject graph is a star) | **Ledger completeness, NOT independently checkable.** A *colluding* issuer that publishes the ring without the anchor (ring becomes the largest SCC → never severed), or injects one cross-edge to the anchor, recomputes HIGH and is admitted. The gate catches a *lazy-but-honest* issuer; the colluding one is the notary layer's problem |
| **History laundering (colluding issuer)** | ✅ shown (`laundered-visitor`) | `trusted_issuers` allowlist + the pointer-mode recompute | **Trust-anchored to issuer honesty** — same anchor as the Sybil residual. Shown concretely: the identical ring member is rejected over a complete ledger and admitted over a curated one. An independent receipt source (cross-attestation) is the only real fix |
| **Credential replay by a third party** | ✅ tested | **Presenter binding** (0.3.0): `admit(..., presenter_did=)` is required and the gate admits only when `credentialSubject.id` is the did the verifier *authenticated* for the connecting agent (`presenter_mismatch`). Before 0.3.0 anyone holding a copy of a public credential + ledger was admitted as its subject | Authenticating the presenter (request signature / channel identity) is the verifier's job; PARC binds to whatever did it was given. A verifier that reads `presenter_did` out of the credential has disabled the check |
| **Reputation borrowing (another agent's ledger)** | ✅ tested | **Subject-bound inline ledger** (0.3.0): every presented receipt's `issuer_did` must equal the subject (`ledger_subject_mismatch`). Before 0.3.0 an issuer-signed ledger of agent Y's receipts labelled with subject X recomputed perfectly and admitted X | Pointer-mode community ledgers are multi-issuer by design; there the binding is the *derived* per-subject score (only the subject's own receipts count) — which inherits the ledger-completeness residual above |
| **Stale credential** | ✅ tested | `validFrom`–`validUntil` enforced against the **UTC wall clock by default** (0.3.0) and compared as RFC 3339 *instants*; an offset-less or missing bound is `malformed`. Before 0.3.0 the window was skipped when the caller passed no `now`, and the string comparison was defeated by any offset other than `Z` | The verifier's clock must be right (NTP); `now` is injectable so a verifier that pins it badly re-opens the hole |
| **Threshold gaming** | ❌ not shown | Multi-dimensional policy (score + corroboration_rate + validity_rate + categories) | Demo uses a single-dimension score threshold |
| **Revocation not checked / unrevocable credential** | ⚠️ not visible | Revocation-set input to the gate, keyed on `vc.id`; since 0.3.0 the builder always emits an `id` and the gate refuses a credential without one (`missing_id`) | No revocation endpoint shown in the demo UI; revocation *transport* is out of scope |
| **Sybil forgery with anchors unset** | ✅ tested (warning) | `required_anchors` is the defence; when empty the gate reports `warnings: ["anchor_check_disabled"]` on every result (0.3.0) rather than silently admitting on arithmetic alone | **The default policy is unsafe for production**: with no anchors, three fresh dids forge a recompute-clean credential. The warning is informational by design (scores are never altered); operators MUST set anchors |
| **Verifier exhaustion (oversized ledger)** | ✅ tested | `max_ledger_receipts` → `ledger_too_large` BEFORE any hashing or severance, in **both** modes since 0.3.0 (inline was unbounded before) | The bound is the verifier's to set per its compute budget |
| **Malformed facet** | ✅ tested | A non-numeric score, a naive timestamp or a non-object subject is a `malformed` rejection, never an exception out of the gate (0.3.0) | — |
| **LLM steganographic collusion** | ❌ not shown | None — known open problem | Research-level; flagged for the whitepaper, not claimed here |

## What the demos prove (precisely)

**Inline mode — `examples/two_city_admission.py`.** City B admits/rejects visitors
**offline, from the credential alone**, with **zero access to City A's receipts**:

- `honest-visitor` — corroborated → `nanda-rep/0.2` > 0 → **admitted**.
- `wash-visitor` — **self-dealing** (self-cosigned, fails the corroboration filter) →
  `0.2` = 0 → **rejected**.

All visitors carry an *identical* `nanda-rep/0.1` score; only the corroborated `0.2`
score, which travels inside the PARC, tells them apart at a gate that never saw their
history. Inline mode cannot show an N-party ring — a single subject's corroboration
graph is a star, never a strongly-connected component.

**Pointer mode — `examples/published_ledger_admission.py`.** The credential names a
published community ledger; City B fetches it, checks it against the signed root, and
**re-runs the severance itself**:

- `honest-visitor` (anchor member) → survives severance → **admitted**.
- `ring-visitor` (isolated-ring member) → the gate, seeing the honest anchor the ring
  is isolated from, **severs the ring to 0** → **rejected**. City B *derived* this; it
  did not trust an attested number.
- `laundered-visitor` — the **same** ring member, **same** receipts, but a *colluding*
  issuer publishes the ring **without** the anchor → nothing severs → **admitted
  (wrongly)**.

The load-bearing contrast: `ring-visitor` and `laundered-visitor` are the identical
agent. Only the **completeness of the published ledger** flips the decision — which is
the residual, demonstrated rather than asserted.

## What the demos do NOT prove

- **The gate cannot *fully* detect a *curated* ledger.** Pointer mode re-runs severance,
  but only over what the issuer published. `policy.required_anchors` narrows this — a
  local allowlist of known-honest dids; the gate rejects (`anchor_absent`) any ledger
  that involves none of them. Since 0.2.2 the rule is enforced in **both** admission
  modes (the inline path previously ignored it silently), fails closed when set without
  `require_recomputation`, and counts only **verified** involvement: the anchor issued
  the receipt, or the anchor's co-signature verifies — a junk receipt merely *naming*
  an anchor no longer launders a ledger through the check. That defeats the *trivial*
  laundering (`laundered-visitor`) and the mention-injection bypass, but **not** the
  sophisticated case: an issuer that wires one real corroborated edge to a required
  anchor passes the check and still evades severance. Closing that residual needs an
  **independent** receipt source (cross-attestation / notary — deployed as The Town
  Notary's `/countersign-parc`, which additionally treats its certified register as
  the anchor set), not the published ledger.
- **Denial of service is bounded, not free.** Severance runs over the whole fetched graph;
  `policy.max_ledger_receipts` caps the ledger the gate will process (`ledger_too_large`)
  so a hostile issuer cannot exhaust the verifier with an enormous graph. The bound is the
  verifier's to set per its compute budget.
- **Inline mode does not detect collusion at all** beyond self-dealing — it is
  single-subject by construction.
- **Selective disclosure proves *transactions*, not the *score*.** A Merkle inclusion
  proof shows a revealed receipt is committed under the signed root; it says nothing
  about reputation. The score is an aggregate over the *whole* graph (severance needs
  every edge), so it stays the issuer's signed value — a verifier MUST NOT recompute or
  adjust it from a disclosed subset. Revealing 3 honest receipts does not launder a
  severed score. The two are deliberately separate layers (`SPEC.md` §3.2).
- Freshness, revocation, presenter binding and multi-dimensional policy are specified
  and tested (`tests/test_parc.py`, `tests/test_end_to_end_real_verifier.py` — the latter
  on real sm-arp receipts under the real `verify_receipt`) but not exercised in the demo
  UI, whose fixtures pin `now` inside their June-2026 window.
- **The demos run with `required_anchors` unset** and therefore carry the
  `anchor_check_disabled` warning. That is fine for a fixture with known identities and
  exactly the posture a production verifier MUST NOT ship with.

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
