# Trust-Layer Findings (core excerpt)

This file excerpts the campaign register (`parvault-docs`, `architecture/V0_5_TRUST_LAYER_AUDIT_FINDINGS.md`) for the findings in this repository. IDs match the campaign register. `.enforcement.map` cites this file as `ref=` for every `reach`, `claim` and `open` line.

Status values:

| Status | Meaning |
| :--- | :--- |
| Read | Seen in code by a reviewer. |
| Reproduced | A test in this repository asserts the gap against the real binary. |
| Static | No wire carrier exists; an `open` `reach` line records the gap. |
| Fixed | The differential pair passes and the `open` line is deleted (QA sign-off pending until stated). |
| Deferred | Assigned to a later queue item, with an `open` line or a note below. |

## Enforcement gaps

| ID | Sev | Finding | Item | Status |
| :--- | :--- | :--- | :--- | :--- |
| F-01 | Blocker | Gossip `SlashingEvidence` quarantines on one trusted reporter's accusation, with no guard for genesis or self. | 2b | Reproduced |
| F-02 | High | A repair read (Case B) is not bound to the registered grant; `PutShard` registers any self-signed grant, before the put succeeds, overwriting the existing one. | 2b | Reproduced (F-02a, F-02b) |
| F-03 | High | Web-of-trust admission is never consulted on the wire request path. | 2b | Reproduced |
| F-04 | High | `PutShard` takes a caller-supplied `owner_peer_id`; each invented id gets a fresh account with bootstrap grace. | 2b | Reproduced |
| F-05 | High | Public-commons PoW admission has no wire carrier and no production caller. | 2b | Static |
| F-06 | High | The PoR audit loop is not wired: nothing issues challenges or verifies responses. | 2c | Read |
| F-07 | High | Earned tiers are self-credited by the seed answering its own challenges. | 2c | Read |
| F-08 | High | The eviction council is local TOFU state with no membership epoch; quorum can be configured below majority. | 2c | Reported |
| F-09 | Medium | Eviction orders: `issued_at_ms` unchecked, expiry `0` permanent, replay FIFO rolls over. | 2c | Reported |
| F-10 | Medium | The DHT reader does not bind `owner_pubkey` (a squatted `u64::MAX` wins); a raw Kademlia `put` bypasses the monotonic store. | 2b | Reproduced (F-10a, F-10b) |
| F-11 | Medium | `--no-lan-discovery` does not disable mDNS; mDNS peers enter Kademlia with no admission check. | 2b | Static (no multicast between loopback daemons on the test host) |
| F-12 | Medium | Slashing gossip is receive-only; nothing issues `SlashingEvidence`. | 2c | Reported |
| F-15 | Low | `verify_weather_quorum` has no caller, but `docs/SECURITY_AND_CRYPTOGRAPHY.md` claims it. | 2b | Static |
| F-17 | Medium | `GatewayIdentityStatement` verification does not pin the signing authority; expiry `0` is permanent. | 2c | Reported |
| F-18 | Medium | Onion relay jitter is a blocking `std::thread::sleep` on the swarm task. | 2c | Reported |
| F-20 | High | No production path admits a peer (no handshake caller, no invitation issuer, self-generated genesis). | 2b | Read |
| F-21 | Medium | `HandshakeWoT` does not bind the chain leaf to the sender's transport key. | 2b | Reproduced |
| F-22 | Medium | `RegisterWanRendezvous` lets an unadmitted peer store about `512 MiB` and write the admission-IP map. | 2c | Reproduced |
| F-23 | Medium | `RenewBlindedLease` carries no credential. | 2c | Reproduced |
| F-24 | Medium | Blinded-shard vouchers are self-certifying (the receiver trusts the issuer the voucher names). | 2b (admission), 2c (issuer policy) | Reproduced (blinded put, onion final delivery) |
| F-25 | Medium | `SyndicateLiteStripe` accepts a `PersonalDeviceCert` not bound to the sender (any key that holds a valid cert can replay it) and re-uploads under a constant owner; `PutDhtEnvelope` writes self-signed records into uncapped maps. | 2b | Reproduced (cert replay by another key; unadmitted DHT put) |
| F-26 | Low | First-wins grant registration lets an admitted holder of one shard squat a stripe root on other nodes (residual after F-02). | 2c | Read |

## Proof gaps

| ID | Sev | Finding | Item | Status |
| :--- | :--- | :--- | :--- | :--- |
| P-01 | High | No Kani harness touches `src/network/*`. | 2d-β | Reported |
| P-02 | High | Specs hardcode the properties they claim to check. | 2d-β | Reported |
| P-03 | Medium | `ParVaultZeroKeyAdminAndQuorum`: tautological replay guard; Byzantine count fixed by `ASSUME`. | 2d-β | Reported |
| P-04 | Medium | Earned-tier invariants are near-tautologies; no spec models pairing, rendezvous or PoW admission. | 2d-β | Reported |
| P-05 | Low | Subtree slash limit is `3` in the spec cfg and `5` in Rust. | 2d-β | Reported |

## Completeness and artifact lines

| ID | Line | Status |
| :--- | :--- | :--- |
| E-WIRE | Every `MeshWireRequest` variant is covered by a claim. | Open until every variant has a claim (2b covers the admitted classes; the rest follow in 2c). |
| D-ADR | Every accepted ADR is a claim's `adr=` or has a `noenforce` line. | Open (2c). |
| A-DOCKER | `scripts/docker_acceptance_gate.sh` stages binaries through `stage_artifact.sh`. | Open; converted before item 7. |
