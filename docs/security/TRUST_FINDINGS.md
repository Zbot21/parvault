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
| F-02 | High | A repair read (Case B) is not bound to the registered grant; `PutShard` registers any self-signed grant, before the put succeeds, overwriting the existing one. | 2b | Fixed (QA pending): `grant_registration_decision` (F-02a: after the put, matching root), `repair_read_decision` (F-02b) |
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
| F-24 | Medium | Blinded-shard vouchers are self-certifying (the receiver trusts the issuer the voucher names). | 2b (admission), 2c (issuer policy) | Admission fixed (QA pending): claims F-24, F-24-ONION, F-24-LAYERED; issuer policy open (2c, claim F-24-ISSUER) |
| F-25 | Medium | `SyndicateLiteStripe` accepts a `PersonalDeviceCert` not bound to the sender (any key that holds a valid cert can replay it) and re-uploads under a constant owner; `PutDhtEnvelope` writes self-signed records into uncapped maps. | 2b | Fixed (QA pending): admission (claim F-25-DHT) and cert bound to the sender (`device_cert_decision`, claim F-25); seed re-uploads accounted to the seed (F-04) |
| F-26 | High | A repair grant is registered before the put succeeds and for any stripe; first-wins lets an admitted holder of one shard squat a stripe root on other nodes (residual after the F-02 fix). QA 2026-11-12: the first-registered grant also authorises owner reads, so a squat grants ciphertext reads and locks the real owner out on that node; fix moved into 2b. | 2b | Fixed (QA pending): grants keyed by (root, owner); each shard records the owner of the grant it was stored with; reads and repair reads need that owner (`grant_owner_decision`, claim F-26) |
| F-27 | High | A ring-member client presents its admission chain before `PutBlindedShard` and `RelayPqOnionEnvelope`, identifying the originator to the entry relay (breaks ADR-11 layer 3). Introduced by 2b at `256adf1`; found by QA before merge. | 2b | Fixed (QA pending): `OnionOriginator` cannot present a credential; only the relay's last hop is admitted (test `ring_member_originator_stays_anonymous_at_the_relay`) |
| F-28 | High | Bootstrap option A incomplete at `256adf1`: `install-chain` records no genesis public key; a daemon with no genesis silently generates its own, so an invited node refuses every ring member, and any node that ever ran a daemon can issue chains for a private one-node ring. No test or Docker stage runs an invitee as a server. | 2b | Fixed (QA pending): `parvault wot init` is the only way to create a genesis; `wot invite` emits the chain with the ring key; `install-chain` verifies and pins it; no silent genesis; conflicting sources stop the daemon; invitee-as-server test and Docker stage 3b |
| F-29 | Medium | `AdmitPublicTicket` (public/hybrid mode): every accepted ticket rewrites the whole registry (up to about `7 MiB`); a re-sent ticket costs no PoW (`timestamp_ms` unchecked); cheap new keys can flush legitimate peers from the FIFO. | 2b | Fixed (QA pending): batched writes; re-sent ticket a no-op; 10-minute freshness; bound to the verifier key; 8 new tickets per subnet per minute; full registry refuses, never evicts a live admission (claim F-29, unit tests per rule) |
| F-30 | Medium | Handshake is a quarantine oracle: the ack returns the raw `WebOfTrustError` and quarantine is checked before signatures. | 2b | Fixed (QA pending): chain verified before quarantine; one fixed refusal text (2a suite row) |
| F-31 | Medium | Inbound Kademlia `PutRecord` has no admission check (route around the admitted-only DHT put). | 2b | Fixed (QA pending): `kad_record_decision` requires an admitted source (claim F-31) |
| F-32 | Medium | An admitted member can sub-invite unlimited keys (depth `8`); `admitted_chains` is unbounded and rewritten in full on every handshake. | 2b | Fixed (QA pending): at most 64 sub-invites per member and 65,536 chains, refused when full, never evicted; a re-sent chain writes nothing; writes batched (unit tests) |
| F-33 | Medium | Onion forwarding is an open relay for unadmitted originators (amplification). Accepted for 2b; open for 2c. | 2c | Open (`claim-missing` line) |
| F-34 | High | No verifier can check a PoR response: the commitment is `SHA-256(nonce ‖ bytes)`, so the verifier needs the shard bytes; ADR-03's stateless-witness model cannot work as written. | 2c | Reported (2c plan) |
| F-35 | Medium | Voucher nullifiers are a FIFO of `65,536` with no voucher expiry, so a spent voucher is redeemable again after rollover. | 2c | Reported (2c plan) |
| F-36 | High | `authorize_owner_shard_delete` accepts a delete token signed by any key for a shard stored without a grant, so an admitted peer can delete another peer's grant-less shards by id. | 2b | Fixed (QA pending): `shard_delete_decision` (grant owner, or else the key that stored the shard), claim F-36 |
| W-05 | Medium | Regular `.shard` file names start with the first 8 bytes of the stripe Merkle root, then the shard index (`ShardId::file_key`, `storage/block_store.rs:159`), so a storage node can group the shards of each stripe and count stripes. Blinded `.bshard` names exist only on the seed/lite path. | 2e | Registered, not redesigned: documented in the README limits section |
| F-37 | Critical | A node outside any ring used the all-zero key as its genesis (`TICKET_ONLY_GENESIS`), a small-order Ed25519 point, and signatures were checked with non-strict `verify`, so a stranger could forge a one-hop chain and get full ring-member admission on a public-commons node. | 2b | Fixed (QA pending): no ring is an absent genesis (`Option`), every `HandshakeWoT` is refused in that state (`ring_handshake_decision`, `reject.handshake_no_ring`, claim F-37); all Ed25519 checks use `verify_strict`; the public-commons genesis helpers, whose seed is public, are test-only. Reproduced at `56b81e1` (forged chain accepted). |
| B-SEED-SYND | Medium | `parvault-seed` handles `SyndicateLiteStripe` by re-uploading every shard to its mesh peers inside the request, holding the seed's shared-state lock and the swarm task until done (blocking, like F-18). Under load it exceeds a client's default 1.2 s timeout (seen as the `f04_seed_syndication_accounted_to_seed` flake). | 2c | Registered for the architect (2e gate run): defer the re-upload off the swarm task, or keep it and document the timeout |
| F-38 | Medium | `SyndicateLiteStripe` registered the attached repair grant after checking only its signature and stripe root, never its owner, so an owner-certified device could attach a grant self-signed by any key X, and X could then read the stripe's shards as their owner (F-25, F-02a). | 2e | Fixed (QA pending, L-40): the seed refuses the whole request unless the grant owner is the authenticated sender on the full 32-byte key (`syndication_grant_decision`, `reject.syndication_grant_not_sender`, claim and Kani harness F-38); with F-25 the cert names the sender, so the grant owner is bound to the owner root. The lite client sends as the vault identity again; `parvault identity --seed-phrase/--vault-namespace` prints its Vault Device Peer ID for the cert. Reproduced at `d0a99f5` (`repro_syndication_grant_from_foreign_owner`) |
| F-38-ADM | Low | The vault key must be admitted at the seed: a member extends its own chain one hop for it (`admission.rs` `credential_for`), so an invited client at depth d presents d+1 hops, which must stay within `MAX_DELEGATION_DEPTH` (8). | 2e | Registered (L-40); tested at depth 2 (`f38_invited_client_syndicates_as_vault_key`) |
| F-38-SHARED | Low | A phrase-derived vault identity is shared by every device holding the phrase: one cert covers them all, so per-device revocation is lost for lite syndication. | 2e | Registered (L-40) |
| F-38-PREFIX | Low | The cert names a device id, the first 16 hex characters of the key (`keys.rs` `device_peer_id_for_pubkey`), so it binds only a 64-bit prefix (predates F-38). | after v0.5.0 | Registered (L-40): name the full key in the cert after v0.5.0 |
| F-38-NET | Low | The lite path's client is built with all mesh endpoints: it sends `SyndicateLiteStripe` only to the seed, but publishes the snapshot's DHT envelope to every mesh endpoint as the vault identity. | 2e | Registered (L-40 asked to confirm it talks only to the seed: it does not, for the DHT put) |
| F-38-GRANT | Blocker | PutShard (`network/wire_handler.rs`) bound `owner_peer_id` to the sender but never the repair grant's owner, and a re-put of a stored shard overwrote its accounted owner (`record_shard_stored`), grant owner (`register_grant`) and PoR session commit, so an admitted peer holding a shard's bytes could take it over, then read or delete it. | 2e | Fixed (QA pending): `shard_rebind_decision` (first writer wins, L-41), checked before `put_shard` in PutShard (claim F-38-GRANT) and for every bundle shard in SyndicateLiteStripe (claim F-38-GRANT-SEED); `register_grant` never replaces a different owner; delete and a fresh bind clear stale bindings; Kani `proof_shard_rebind_first_writer_wins` |
| F-38-GRANT-SQUAT | Medium | Pre-squat: a peer holding a shard's bytes can first-write it on a node that does not hold it yet; the owner's put is then refused there (placement DoS, existing copies unaffected). Real fix binds the owner to the stripe id. | post-v0.5.0 | Deferred (L-41) |
| F-38-GRANT-HANDOFF | Low | Handoff aborts on any refused put (`storage/block_store.rs` handoff loop, `?`), so one squatted shard on the target stalls a whole handoff. | post-v0.5.0 | Deferred (L-41) |
| F-38-GRANT-VERSION | Low | Grants have no version: the accounted owner can roll its own grant back to an older one, and third parties can never refresh one (`Keep` changes nothing). | post-v0.5.0 | Deferred (L-41) |
| F-38-GRANT-KEY | Low | The binding is keyed on `ShardId::file_key`, which keeps 64 bits of the stripe root and 128 of the shard hash. | post-v0.5.0 | Deferred (L-41) |
| F-38-GRANT-RESYND | Low | A seed refuses a re-syndication with no grant of a stripe it already holds ungranted (no owner to match); the lite client always attaches a grant, so only grant-less callers are affected. | 2e | Read (L-41) |
| F-38-GRANT-UNCHECKED | Low | Not checked: other eviction and takedown paths (`storage/eviction.rs:~2602`) for stale verifier bindings (a fresh `Bind` clears them, so a stale entry never survives a re-store); no TLA+ spec models shard binding. | 2e | Read (L-41) |
| F-38-GRANT-QUOTA | Low | Rule 4 trusts the accounted owner in `quota_state.bin`. `shard_owners` has been in that layout since `v0.1.0` (`81865ce`), and the layout is unchanged through `v0.4.0` and `v0.5.0`, so no released version writes a file without it. Its `#[serde(default)]` (`storage/quota.rs:117`) has no effect under bincode. But a missing, corrupt or undecodable `quota_state.bin` is silently replaced by an empty manager (`storage/quota.rs:153`), leaving stored shards with no accounted owner: the owner's grant-less re-put is then refused (`reject.shard_bound_to_another_owner`), and so is its delete of a grant-less shard (F-36). Re-puts with the owner's grant still bind or keep. | post-v0.5.0 | Read (QA 2e r2) |
| T-REUSEPORT | Low | The mesh TCP listener (`network/transport.rs:47`, `tcp::Config::default()`) gets `SO_REUSEPORT`, so another process running as the same UID can bind the daemon's port too and take a share of its inbound connections (seen as cross-process test flakes, QA 2e r2). libp2p-tcp 0.42 has no switch: the listener always uses `PortUse::Reuse` (`libp2p-tcp` `lib.rs:276`) and `Config::port_reuse` is a deprecated no-op, so a fix needs a custom transport or an upstream change. Same-UID processes are already trusted with the data directory. | post-v0.5.0 | Read (QA 2e r2) |
| T-SHARD-TIMEOUT | Low | Per-shard `PutShard` and `GetCiphertextShard` (`network/client.rs`, about 1 MiB each for a 16 MiB stripe at 16-of-20) use the 1.2 s client default. That is fine on a LAN, but a seed forwarding to WAN peers (`bootstrap.rs` ~1323), a handoff, or a seed-dead restore over a slow uplink needs about 7 Mbit/s or the request times out. Only lite syndication has a longer timeout (`LITE_SYNDICATION_TIMEOUT`, 30 s). | post-v0.5.0 | Read (registered, not fixed, for v0.5.0) |
| T-UDP-DISC-TEST | Low | Test risk only: `tests/zero_config_lan_and_router_soc_tests.rs` (:201/537/693/854) reserves a UDP discovery port and releases it, and the discovery socket sets `SO_REUSEPORT` on purpose (`os_sys.rs:402`), so two concurrent test processes that draw the same port hear each other's beacons, and exact-count discovery asserts can fail. Port 0 cannot be used: the port is the rendezvous every daemon and `discover`/`pair` call in a test must share. | post-v0.5.0 | Read (QA 2e r3) |
| F-38-TLA | Info | `ParVaultLiteClientAndSeedFailover.tla` models no grant or cert binding. | after v0.5.0 | Registered, not blocking (L-40) |

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
| F-02a | F-02, grant registration (after the put, matching root). |
| F-02b | F-02, repair reads bound to the registered grant. |
| F-03-SEED | F-03 on `parvault-seed`. |
| F-10a | F-10, the DHT reader. |
| F-10b | F-10, inbound Kademlia records. |
| F-24-ONION | F-24 admission at onion final delivery, single-layer branch (forwarding needs no admission). |
| F-24-LAYERED | F-24 admission at onion final delivery, layered branch (`open_final_target_pq`). |
| F-25-DHT | F-25 admission for `PutDhtEnvelope`. |
