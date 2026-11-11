# ADR-24: Zero-Pairing Public Commons Swarm Mode & Hashcash `PublicCommonsTicket` Sybil Defense

- **Status:** Accepted
- **Subsystem:** `network::wot` / `network::wan_rendezvous`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Closed invitation rings (`PrivateRing`) provide maximum isolation for families and private co-ops, but operators wishing to initialize an opt-in BitTorrent-style open swarm need zero-pairing stranger admission without exposing private rings or succumbing to zero-cost Sybil connection floods.

## Decision

1. **Explicit Trust Pool Modes (`TrustPoolMode`):** Separates default `PrivateRing` (strict invitation chains only) from opt-in `PublicCommons` and `Hybrid` (`--public --tracker <MULTIADDR>`, indexed under `PUBLIC_COMMONS_SWARM_SLOT`).
2. **Self-Signed Hashcash Admission (`PublicCommonsTicket`):** Stranger nodes in `PublicCommons` mode mint a self-signed Ed25519 ticket carrying a leading-zero SHA-256 Hashcash Proof-of-Work (`DEFAULT_PUBLIC_WOT_POW_BITS = 12`) bound to their `PeerId` and timestamp, paired with mandatory `10-of-20` Reed-Solomon redundancy, `/24` subnet caps, and pre-decoding Merkle quarantine.

## Consequences & Verification

- **Consequences:** Supports optional self-hosted public swarms with zero manual pairing codes while keeping default `PrivateRing` deployments 100% isolated from public trackers.
- **Verification:** `network::wan_rendezvous::tests` (`src/network/wan_rendezvous.rs`) and `tests/zero_config_lan_and_router_soc_tests.rs`.
