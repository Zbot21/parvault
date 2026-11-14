# ADR-25: 4-Vector HMAC-Blinded Bad-Actor Shard Eviction & Multi-Pass `0x00` Forensic Shredding

- **Status:** Accepted
- **Formal model:** `specs/ParVaultZeroKeyAdminAndQuorum.tla`
- **Subsystem:** `storage::eviction`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Node and seed operators need sovereign administrative tools to purge abusive peers or illegal stripes and block repeat ingress, yet storing plaintext uploader IP addresses or unblinded `PeerId`s in persistent logs would destroy uploader privacy if a disk is stolen or forensically imaged.

## Decision

1. **Zero-Plaintext-IP Keyed-HMAC Index (`PrivacyPreservingEvictionEngine`):** Each node generates an isolated `0600` 32-byte secret key `K_node_evict` (`eviction_hmac.seed`, `ZeroizeOnDrop`). Persistent `eviction_index.bin` stores **zero plaintext IPs and zero plaintext PeerIds**, indexing all 4 eviction vectors (`IpAddress`/`IpSubnet`, `Libp2pPeerId`, `PeerOrIssuerPubkey` `.bshard` cohorts, and `StripeMerkleRoot`/`BlindedLocator`) via domain-separated HMAC tags (with dual-stack `::ffff:a.b.c.d` canonicalization):

```text
tag_ip      = HMAC-SHA256(K_node_evict, "parvault-evict-ip-v1:"     || canonical_ip_bytes)
tag_subnet  = HMAC-SHA256(K_node_evict, "parvault-evict-subnet-v1:" || canonical_cidr_bytes)
tag_peer_id = HMAC-SHA256(K_node_evict, "parvault-evict-peerid-v1:" || peer_id_bytes)
```

   Because `K_node_evict` is independent per node, tags on Node A and Node B are statistically independent (`Pr[H_A(IP) = H_B(IP)] = 2^-256`), defeating cross-node disk correlation.
2. **Multi-Pass `0x00` Forensic Shredding (`shred_and_unlink_file`):** Overwrites 100% of evicted `.shard` and `.bshard` file bytes with `0x00` in `64 KiB` chunks and calls `File::sync_all()` before `fs::remove_file()`.

## Consequences & Verification

- **Consequences:** Delivers immediate ingress firewalling and physical zero-wipe purging while preserving zero-plaintext-IP disk forensics.
- **Verification:** Kani harness `proof_eviction_hmac_dual_stack_normalization_and_domain_isolation` and `storage::eviction::tests` (`src/storage/eviction.rs`).
