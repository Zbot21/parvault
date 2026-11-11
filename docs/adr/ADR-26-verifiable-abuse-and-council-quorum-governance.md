# ADR-26: Cryptographic Reporter Burden-of-Proof (`VerifiableAbuseReport`), Zero-Private-Key `admin_rpc` & `M-of-N` Council Quorum

- **Status:** Accepted
- **Subsystem:** `storage::eviction` / `admin_rpc`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

On opt-in public trackers, unverified takedown notices would let griefers censor honest encrypted backups, storing `tracker_admin.seed` on an internet-facing VPS would expose signing authority if the VPS is rooted, and a single rogue federated tracker operator could unilaterally wipe swarm shards.

## Decision

1. **Cryptographic Reporter Burden-of-Proof (`VerifiableAbuseReport`):** Reporters alleging public distribution of illegal content must supply `(FileManifest, disclosed_master_key_hex, sample_stripe_index, sample_shards)`. The verifier checks leaf hashes against `stripe_merkle_root`, reconstructs the stripe in $GF(2^8)$, verifies the 128-bit `AES-256-GCM` tag under `disclosed_master_key` (framing probability $2^{-128}$), immediately wipes plaintext RAM via `zeroize::Zeroize`, and queues the report in `PendingAdminReview` (zero auto-eviction).
2. **Zero-Private-Key-on-VPS `admin_rpc` & Air-Gapped Signing:** `parvault-seed` never auto-generates `tracker_admin.seed` on VPS disk; remote administration (`src/admin_rpc.rs`) uses forward-secret `X25519 + ChaCha20-Poly1305` + `Ed25519` challenge-response (`±60 s` replay window, `64 KiB` initial alloc cap) where pre-signed `SignedBadActorEvictionOrder` payloads originate from air-gapped operator hardware (`parvault-control`).
3. **Strict Mode Isolation & `M-of-N` Federated Council Quorum (`TrackerOperatorCosignature`):** `PrivateRing` nodes unconditionally reject external tracker admin keys; `PublicCommons` nodes require strict majority co-signing (`2M > N`, e.g. `2-of-3`, `3-of-5`) across distinct `trusted_council_pubkeys`:

```text
ValidSigners(Order) = ({issuer_pubkey} union {cosigner_k}) intersect TrustedCouncilPubkeys
Authorized(Order)   <=> |ValidSigners(Order)| >= M  AND  now_ms <= expires_at_ms
```

## Consequences & Verification

- **Consequences:** Eliminates false-positive framing ($2^{-128}$), VPS admin-key theft, private-ring overreach, and single-operator rogue takedowns.
- **Verification:** `specs/ParVaultZeroKeyAdminAndQuorum.tla` (`2,325` states, `0` errors) and Kani harnesses `proof_eviction_quorum_sub_threshold_and_duplicate_signer_rejected`, `proof_eviction_quorum_authorized_distinct_signers_and_expiry`, `proof_eviction_signing_payload_collision_free_across_all_fields`, `proof_admin_rpc_wire_frame_header_no_panic_or_unbounded_alloc`, and `proof_admin_rpc_replay_window_challenge_and_zero_key_rejection`.
