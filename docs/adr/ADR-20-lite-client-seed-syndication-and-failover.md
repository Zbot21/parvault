# ADR-20: Lite-Client `1.0×` Seed Syndication, NAS-Death Mesh Failover & Selective Byte-Range Restore

- **Status:** Accepted
- **Subsystem:** `bootstrap` / `sync`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Laptop users on battery or Wi-Fi want `1.0×` single-stream uploads to their home `parvault-seed` NAS without hosting foreign shards or fanning out `20` Reed-Solomon connections directly, yet must still recover selectively if their home NAS is destroyed and their laptop SSD is smaller than the multi-TiB backup.

## Decision

1. **Zero-Knowledge `1.0×` Lite Syndication (`ZeroTrustSeedServer::ingest_and_syndicate_lite_stripe`):** In `ClientOperatingMode::LiteSeedBacked`, the laptop encrypts stripes locally with `AES-256-GCM` (`K_user` never leaves the laptop) and sends a `1.0×` `LiteStripeSyndicationBundle` + `PersonalDeviceCert` to `parvault-seed`, which encodes the `K-of-N` Reed-Solomon shards over ciphertext, caches a 1-hop fast-read copy (`ViaSeedServerFastPath`), and syndicates all $N$ shards to mesh peers.
2. **Automatic NAS-Death Mesh Failover (`restore_selective_with_seed_fallback`):** Because seed and mesh share identical `FileManifest` and `ShardId` layouts, if `parvault-seed` goes offline permanently, the laptop automatically switches to `DirectFromMeshPeersFallback` and reconstructs from any $K$ surviving mesh peers.
3. **Zero-Shard Catalog Browse & Selective / Byte-Range Restore:** `list-snapshot` inspects catalogs with zero shard downloads, `--filter` restores only matching paths/globs, and `restore_file_byte_range` fetches only stripes overlapping `[offset, offset + length)`.

## Consequences & Verification

- **Consequences:** Delivers "Cloud Away From Home" `1.0×` laptop battery/uplink efficiency with automatic decentralized failover when the home NAS dies.
- **Verification:** `specs/ParVaultLiteClientAndSeedFailover.tla` (`0` errors), `tests/sync_daemon_usability_and_cli_regression_tests.rs`, `tests/seed_server_integration.rs`, and Stage 6 of `scripts/docker_acceptance_gate.sh`.
