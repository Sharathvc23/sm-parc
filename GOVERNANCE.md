# Governance

## Scope

| In scope | Out of scope |
| --- | --- |
| the ReputationCredential envelope (W3C VC) + the admission gate | the receipt format (Agency Receipt Protocol, ARP), the ledger commitment + scoring (Verifiable Receipts Profile, VRP — `sm_arp.vrp`), the auditor runtime, revocation transport, selective disclosure |

The primitive owns one thing — making a VRP reputation facet portable + checkable at
admission. Anything outside the table belongs to a companion package or the consumer.

## Versioning

Semantic Versioning 2.0.0. The credential shape and the admission-gate ordering are
frozen within a major; a change requires an RFC-style PR to `SPEC.md` before code.

## Conformance

The test suite under `tests/` is the authoritative behavioural specification. A change
in behaviour without a corresponding test change is a bug. Every guarantee in the
README has a happy-path test; every rejection stage has a hostile-path test.

## Contributions

- PRs must include tests and pass `ruff` + `mypy --strict` + `pytest`.
- No expansion of the credential/gate surface without an accepted RFC.
- No domain-specific or deployment-specific content — this is a generic primitive.
- Sign off with the Developer Certificate of Origin (DCO).

## Attribution

Composes sm-arp (ARP + VRP) and the sm-conformance signing pattern. Acronyms are
expanded in [`GLOSSARY.md`](./GLOSSARY.md).

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
