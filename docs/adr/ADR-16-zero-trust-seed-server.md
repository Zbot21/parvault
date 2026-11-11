# ADR-16: Dedicated Zero-Trust Seed & Redundancy Server (`parvault-seed`)

- **Status:** Accepted — Extended by [ADR-30](ADR-30-filesystem-free-in-memory-seed-mode.md)
- **Subsystem:** `bin/parvault-seed` / `bootstrap`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Homelabbers want a headless 24/7 companion binary for NAS, Raspberry Pi, or VPS hardware that earns `HighUptimeAnchor` standing for their household laptops without holding plaintext files on the server, while network bootstrap operators need a low-cost seed anchor binary whose storage footprint drains toward zero as organic peers join.

## Decision

1. **Strictly Zero-Plaintext Standalone Binary (`parvault-seed`, `ZeroTrustSeedServer`):** Enforces `holds_own_plaintext_files == false` across two operating modes:
   - `HomelabRedundancyVault` (`--mode homelab-vault`): Verifies composite post-quantum `PersonalDeviceCert`s (`PARVAULT-CERT-V1:` tokens) from the owner's personal devices (`0.0×` self-quota tax) while answering mesh PoR challenges 24/7 to earn `16-of-20` `HighUptimeAnchor` standing (`5.0×` reciprocity multiplier).
   - `PublicNetworkBootstrapper` (`--mode public-bootstrap`): Stateless seed/rendezvous anchor that ingests anonymized `.bshard` leases during cold-start and drains to `0 bytes` (`~$95/mo` flat micro-VPS footprint across 20 anchors) once organic `VerifiedNeighbor` peers scale past `20+` nodes.

## Consequences & Verification

- **Consequences:** Decouples always-on PoR uptime duties from battery-powered client laptops while keeping NAS/VPS hosts 100% zero-knowledge.
- **Verification:** `tests/seed_server_integration.rs` and `parvault-seed self-test`.
