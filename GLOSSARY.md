# Glossary

Acronyms used across the agent-receipts stack. **These expansions are canonical — use
them verbatim and identically in every repo.** The source of truth for `ARP` / `VRP` /
`DAT` is [sm-arp](https://github.com/Sharathvc23/sm-arp); for `PARC`, this repo.

## Stack terms

| Acronym | Expansion | What it is |
| --- | --- | --- |
| **ARP** | Agency Receipt Protocol | The signed receipt envelope — *what an agent did*. |
| **VRP** | Verifiable Receipts Profile | Composes ARP receipts into a Receipts Ledger + commitment (`behavioral_merkle_root`) + the corroborated `nanda-rep/0.2` scoring (`sm_arp.vrp`). |
| **PARC** | Portable Agent Reputation Credential | A signed W3C Verifiable Credential over a VRP facet, plus the admission gate (this repo). |
| **DAT** | Delegated Authority Token | The companion to ARP — *what an agent was allowed to do* (a sketch in ARP v0.1, normative in v0.2). |

## Standards referenced

| Acronym | Expansion |
| --- | --- |
| **VC** | Verifiable Credential (W3C VC Data Model 2.0) |
| **DID** | Decentralized Identifier (W3C) |
| **JCS** | JSON Canonicalization Scheme (RFC 8785) |
| **SCC** | Strongly Connected Component (graph theory; Tarjan's algorithm) |

---

Built at [labs.stellarminds.ai](https://labs.stellarminds.ai).
