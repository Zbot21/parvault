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
| F-01 | Blocker | Gossip `SlashingEvidence` quarantines on one trusted reporter's accusation, with no guard for genesis or self. | 2b | Fixed (QA pending): gossip subscription and handler removed until 2c; `slash_target_decision` guards genesis and own keys (unit-tested; no wire trigger remains, so no claim) |
| F-02 | High | A repair read (Case B) is not bound to the registered grant; `PutShard` registers any self-signed grant, before the put succeeds, overwriting the existing one. | 2b | Fixed (QA pending): `grant_registration_decision` (F-02a), `repair_read_decision` (F-02b); first-wins residual is F-26 |
| F-03 | High | Web-of-trust admission is never consulted on the wire request path. | 2b | Fixed (QA pending): `admission_decision`, claims F-03 and F-03-SEED |
| F-04 | High | `PutShard` takes a caller-supplied `owner_peer_id`; each invented id gets a fresh account with bootstrap grace. | 2b | Fixed (QA pending): `shard_owner_decision`, claim F-04; leave, seed syndication and 40 gateway lanes tested |
| F-05 | High | Public-commons PoW admission has no wire carrier and no production caller. | 2b | Fixed (QA pending): `AdmitPublicTicket`, `public_ticket_decision`, claim F-05 |
| F-06 | High | The PoR audit loop is not wired: nothing issues challenges or verifies responses. | 2c | Read |
| F-07 | High | Earned tiers are self-credited by the seed answering its own challenges. | 2c | Read |
| F-08 | High | The eviction council is local TOFU state with no membership epoch; quorum can be configured below majority. | 2c | Reported |
| F-09 | Medium | Eviction orders: `issued_at_ms` unchecked, expiry `0` permanent, replay FIFO rolls over. | 2c | Reported |
| F-10 | Medium | The DHT reader does not bind `owner_pubkey` (a squatted `u64::MAX` wins); a raw Kademlia `put` bypasses the monotonic store. | 2b | Fixed (QA pending): reader bound to its own identity (`dht_candidate_decision`, claim F-10a; post-quantum manifests are not owner-bound, no reader uses them); Kademlia records filtered (`kad_record_decision`, claim F-10b) |
| F-11 | Medium | `--no-lan-discovery` does not disable mDNS; mDNS peers enter Kademlia with no admission check. | 2b | Fixed (QA pending): `--no-lan-discovery` turns mDNS off without changing the Kademlia mode; mDNS never feeds Kademlia, admission does (`kad_routing_decision`, claim F-11) |
| F-12 | Medium | Slashing gossip is receive-only; nothing issues `SlashingEvidence`. | 2c | Deferred (2c): the topic is no longer subscribed; publishing proof-carrying evidence is 2c |
| F-15 | Low | `verify_weather_quorum` has no caller, but `docs/SECURITY_AND_CRYPTOGRAPHY.md` claims it. | 2b | Fixed (QA pending): function, its attestation type and the doc claim deleted |
| F-17 | Medium | `GatewayIdentityStatement` verification does not pin the signing authority; expiry `0` is permanent. | 2c | Reported |
| F-18 | Medium | Onion relay jitter is a blocking `std::thread::sleep` on the swarm task. | 2c | Reported |
| F-20 | High | No production path admits a peer (no handshake caller, no invitation issuer, self-generated genesis). | 2b | Fixed for option A (QA pending): `parvault wot init` creates a ring (the only way a genesis is created); `wot invite` emits the chain with the genesis public key; `install-chain` verifies and pins it; invitees serve the ring; no silent genesis; conflicting sources refuse to start |
| F-21 | Medium | `HandshakeWoT` does not bind the chain leaf to the sender's transport key. | 2b | Fixed (QA pending): `chain_leaf_decision`, claim F-21 |
| F-22 | Medium | `RegisterWanRendezvous` lets an unadmitted peer store about `512 MiB` and write the admission-IP map. | 2c | Reproduced |
| F-23 | Medium | `RenewBlindedLease` carries no credential. | 2c | Reproduced |
| F-24 | Medium | Blinded-shard vouchers are self-certifying (the receiver trusts the issuer the voucher names). | 2b (admission), 2c (issuer policy) | Admission fixed (QA pending): claims F-24, F-24-ONION; issuer policy open (2c) |
| F-25 | Medium | `SyndicateLiteStripe` accepts a `PersonalDeviceCert` not bound to the sender (any key that holds a valid cert can replay it) and re-uploads under a constant owner; `PutDhtEnvelope` writes self-signed records into uncapped maps. | 2b | Fixed (QA pending): admission (claim F-25-DHT) and cert bound to the sender (`device_cert_decision`, claim F-25); seed re-uploads accounted to the seed (F-04) |
| F-26 | Low | First-wins grant registration lets an admitted holder of one shard squat a stripe root on other nodes (residual after F-02). | 2c | Read |
| F-27 | High | Public-commons ticket admission amplifies: every accepted ticket rewrote the whole registry, a ticket was reusable (no freshness, not bound to the verifier), and a sybil could flush legitimate peers from the FIFO (QA 2b B4). | 2b | Fixed (QA pending): admissions written in batches; re-sent ticket a no-op; ticket fresh within 10 min and bound to the verifier key (the refusal states key and bits, the client re-mints once); 8 new tickets per subnet per minute; when full, expired admissions are pruned and new tickets refused (a live admission is never evicted). Claim F-27, unit tests per rule |
| F-28 | Medium | The handshake was a quarantine oracle: quarantine was checked before signatures and the raw error was returned on the wire (QA candidate 1). | 2b | Fixed (QA pending): chain verified before quarantine; one fixed refusal text ("handshake refused"), code in the local log |
| F-29 | Medium | Inbound Kademlia `PutRecord` had no admission check, a route around F-25-DHT (QA candidate 2). | 2b | Fixed (QA pending): `kad_record_decision` requires an admitted source, claim F-29 |
| F-30 | Medium | An admitted member could sub-invite unlimited keys, `admitted_chains` was unbounded and rewritten in full on every handshake (QA candidate 3). | 2b | Fixed (QA pending): a member sub-invites at most 64 keys; at most 65,536 chains, new leaves refused when full (never evicted); a re-sent chain writes nothing; writes batched (F-27). Unit-tested |
| F-31 | Medium | Onion forwarding is an open relay for unadmitted originators (pre-existing; accepted in the verdict; an amplification vector). A per-source relay budget is planned. | 2c | Read |

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
| B-DISC | `src/network/discovery.rs` has three `std::thread::sleep` calls (LAN beacon and probe loops); review whether any runs on the async runtime. | Open (2c). |
| T-SPECS | Every spec passes the non-vacuity lint and every `INVARIANT` has a QA-authored mutant (P-02, P-04). | Open (2d-β). |
| X-ADR, X-ADR-DOC | Every `ADR-NN` reference in code and docs names an existing ADR file. | Enforced. |

## Claim ids

Claim lines in `.enforcement.map` use the finding id, or the finding id with a suffix when one finding has several pairs.

| ID | Pair |
| :--- | :--- |
| F-02a | F-02, grant registration (after the put, matching root, no owner replacement). |
| F-02b | F-02, repair reads bound to the registered grant. |
| F-03-SEED | F-03 on `parvault-seed`. |
| F-10a | F-10, the DHT reader. |
| F-10b | F-10, inbound Kademlia records. |
| F-24-ONION | F-24 admission at onion final delivery, single-layer branch (forwarding needs no admission). |
| F-24-LAYERED | F-24 admission at onion final delivery, layered branch (`open_final_target_pq`). |
| F-25-DHT | F-25 admission for `PutDhtEnvelope`. |
