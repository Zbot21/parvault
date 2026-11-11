# ADR-02: Kademlia DHT Encrypted Manifests & Vault Catalog Indexing

- **Status:** Accepted — Extended by [ADR-12](ADR-12-asymmetric-post-quantum-hybrids.md) and [ADR-18](ADR-18-seed-phrase-house-fire-disaster-recovery.md)
- **Subsystem:** `storage::block_store` / `crypto::aes` / `network::client`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

> **[Historical Evolution Note (`v0.4.0`)]:** Originally keyed directly off classical `MasterKey` subkeys in `v0.1`. Extended in [ADR-09](ADR-09-byzantine-merkle-quarantine-and-egress-slashing.md) with monotonic rollback-resistant signatures (`SignedDhtManifestEnvelope`), in [ADR-12](ADR-12-asymmetric-post-quantum-hybrids.md) with composite post-quantum `Ed25519 + ML-DSA-65` manifest envelopes (`PqSignedDhtManifestEnvelope`), and in [ADR-18](ADR-18-seed-phrase-house-fire-disaster-recovery.md) with `Argon2id` BIP-39 root catalog sealing (`EncryptedVaultCatalogEnvelope`).

---

## Context

If a user's workstation or home NAS suffers catastrophic disk loss, local `.manifest.bin` metadata (mapping `file_merkle_root` to stripe salts, shard hashes, blinded locators, and $(K, M)$ parameters) is destroyed. Without off-host manifest replication, surviving ciphertext shards in the mesh could not be located or reassembled.

## Decision

1. **Client-Side AEAD Manifest Sealing:** Every `FileManifest` is serialized with bounded `bincode` and encrypted client-side via `encrypt_manifest` (`AES-256-GCM` under `manifest_aead_subkey`) prior to network publication.
2. **Deterministic Blinded DHT Routing Keys:** Encrypted manifests and root vault catalogs are published to both `libp2p` Kademlia (`kad::Behaviour`) and peers' disk-persisted `ZeroTrustDhtStore` under deterministic HMAC routing keys:

```text
K_dht_routing = HKDF-SHA256(ikm = K_user, info = "parvault-subkey-dht-routing-v1")
DHT_Key_file  = HMAC-SHA256(K_dht_routing, "parvault-manifest:" || file_merkle_root)
DHT_Key_root  = HMAC-SHA256(K_dht_routing, "parvault-vault-root:" || vault_namespace)
```

3. **Zero-Knowledge DHT Storage:** DHT peers verify outer envelope signatures and monotonic version numbers (`new.monotonic_version > existing.monotonic_version`) without learning file names, directory trees, or shard keys.

## Consequences & Verification

- **Consequences:** Full vault metadata survives total local hardware destruction while leaking zero directory structure to Kademlia routing nodes.
- **Verification:** `tests/phase1_to_4_integration.rs`, `tests/red_team_hardening_tests.rs`, and Stage 9 of `scripts/docker_acceptance_gate.sh`.
