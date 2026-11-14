# ADR-05: Recursive Ed25519 Web-of-Trust Delegation & Subtree Slashing

- **Status:** Accepted — Extended by [ADR-12](ADR-12-asymmetric-post-quantum-hybrids.md) and [ADR-24](ADR-24-public-commons-pow-swarm-mode.md)
- **Formal model:** `specs/ParVaultProtocol.tla`
- **Subsystem:** `network::wot`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

> **[Historical Evolution Note (`v0.4.0`)]:** Originally designed for closed Ed25519 invitation rings in `v0.1`. Extended in [ADR-12](ADR-12-asymmetric-post-quantum-hybrids.md) with composite post-quantum device/delegation signatures (`Ed25519 + ML-DSA-65`) and in [ADR-24](ADR-24-public-commons-pow-swarm-mode.md) with optional `TrustPoolMode::{PublicCommons, Hybrid}` Hashcash PoW tickets while preserving strict `PrivateRing` isolation by default.

---

## Context

In private neighborhood and co-op rings, uninvited Sybil nodes must be rejected before consuming storage or routing table slots, and an inviter who vouches for malicious or chronically failing nodes must face bounded accountability so Sybil subtrees are pruned automatically.

## Decision

1. **Bounded-Depth Delegation Chains (`DelegationChain`):** Peers in `TrustPoolMode::PrivateRing` authenticate with a signed chain (`Genesis -> ... -> Inviter -> Invitee`, `InvitationHop`) verified against pinned genesis roots and persisted at `wot_state.bin`.
2. **Gossipsub Slashing & Ancestor Propagation (`SlashingEvidence`):** Any cryptographic fault (poisoned shard Merkle proof or confirmed egress withholding) triggers immediate 1-strike leaf quarantine (`slash_immediately`), while `≥ 3` unexcused PoR audit failures quarantine the leaf and increment its parent inviter's fault counter—pruning compromised invitation branches in finite steps (`≤ M`) with anti-replay `(reporter_pubkey, offender_pubkey, nonce)` tracking.
3. **Unauthenticated Framing Immunity:** Unverified wire handshakes never increment failure counters against a claimed `leaf_pubkey`, preventing attackers from framing honest peers with bit-flipped packets.

## `v0.5.0` Enforcement

- **Admission on the wire:** a `PutShard`, `SyndicateLiteStripe`, `PutDhtEnvelope` or `PutBlindedShard` from a sender that is not admitted (genesis, an unquarantined chain, or a public-commons ticket) is refused with `peer not admitted; v0.5.0 requires ring admission`. A sender without an Ed25519 transport key is refused.
- **Handshake binding:** `HandshakeWoT` admits only the key at the chain's leaf, and that key must be the sender's transport key.
- **A ring is one genesis**, created only by `parvault wot init` (`ring_genesis.seed`). The holder self-issues one-hop chains; other nodes join with `parvault wot invite --peer <pubkey>` / `parvault wot install-chain --token <hex>`, which verifies the chain against the ring key and pins it (`ring_genesis.pub`). No node creates a genesis on its own; conflicting sources stop the daemon.
- **Decision 2 is suspended:** nodes do not subscribe to the slashing gossip topic, so `SlashingEvidence` is not applied from gossip until it is proof-carrying (item 2c). The genesis and the node's own key are never slashed.
- Register: `docs/security/TRUST_FINDINGS.md` (F-01, F-03, F-20, F-21).

## Consequences & Verification

- **Consequences:** Sybil branches are isolated within `≤ 3` faults without a central certificate authority, and honest nodes cannot be framed by spoofed handshakes.
- **Verification:** `specs/ParVaultProtocol.tla` (`SybilResistanceInvariant`, `EventuallyBranchPruned`), `tests/formal_verification.rs` (Stateright BFS), and `tests/red_team_hardening_tests.rs`.
