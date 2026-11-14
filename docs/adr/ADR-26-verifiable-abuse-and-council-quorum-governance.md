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

### Council manifest (v0.5.0, F-08)

- The council is a signed, epoch-versioned `CouncilManifest { scope_root, epoch, members, quorum, issued_at_ms, signatures }` (`storage::council`), not config, env or CLI input. Epoch 1 is signed by the scope root, which follows the node's mode: in private mode the ring genesis (no public tracker authority affects a private ring); in public mode the pinned tracker admin key, and on a public seed its own tracker admin key. Epoch `n + 1` needs a quorum of epoch `n`'s members and the same scope root. `council_manifest_decision` refuses fewer than one or more than 64 members, a quorum that is not a strict majority (`reject.council_quorum_below_majority`), and any break in the chain (`reject.council_epoch_chain`).
- One resolver, `council_from_manifest`, serves the daemon, the seed and the seed admin RPC. With no manifest, a node accepts no council orders. `PARVAULT_EVICTION_AUTHORITIES`, `PARVAULT_TRACKER_EVICTION_QUORUM`, the config keys `eviction_authorities` / `tracker_eviction_quorum` and the seed flags `--council-pubkeys` / `--council-quorum` are removed.
- **Tooling (v0.5.0).** In v0.5.0 only `parvault council init` signs a manifest, and only a private ring's epoch 1 (signed with the ring genesis); a public-mode epoch 1 (signed by the tracker admin key) and every later epoch (signed by a quorum of the previous one) come with `parvault-control` (item 6). `council install` accepts any correctly signed manifest.
- **Re-pinning (public mode).** If a node re-pins to another tracker key, its installed manifest keeps the old root and no longer matches, so the node has no council (fails closed) until the operator deletes `council_manifest.bin` and installs the new tracker's manifest. A lost manifest file lets any old root-signed epoch 1 install again.
- **Local owner (1-of-1).** An order signed by the receiving node's own key applies on that node only. No other node counts that key, so a peer receiving the order refuses it like any order without a manifest quorum.
- **Orders (F-09).** `SignedBadActorEvictionOrder` carries `council_epoch` (signed; domain `parvault-bad-actor-eviction-order-v2:`, golden vectors in `storage::eviction`). `order_admission_decision` admits an order only for the installed epoch (`reject.order_no_council`, `reject.order_council_epoch`), issued within `[now - 7 days, now + 5 min]` (`reject.order_stale`), with an expiry in `(issued, issued + 365 days]` (`reject.order_unbounded_expiry`) that has not passed. The quorum is checked before the replay cache. Seen ids are kept until their order expires; a full cache (16,384) refuses new orders (`reject.order_replay_cache_full`) and never evicts. Replay ids from an index written before v0.5.0 are dropped on load (their `-v1:` orders no longer verify). Orders this crate issues itself (takedowns, emergency evictions, `evict --propagate`) expire after 90 days. The same freshness and expiry rules apply on every path, including a tracker applying its own orders locally (`apply_signed_eviction_order`, which skips only the council-epoch check): no path admits a permanent order. `SignedBadActorEvictionOrder::unsigned` + `with_signature` replace struct literals for external signers.
- **Newer epochs.** An order whose epoch is above the installed one is refused (`reject.order_council_epoch_ahead`) and the node fetches the chain in the background from peers it admitted (a private-mode node with no manifest asks from epoch 0, and epoch 1 must verify against its ring genesis; a public-mode node never auto-installs epoch 1, because its root is a TOFU-pinned tracker key: the operator runs `council install`, QA 2c R1): `GetCouncilManifest { scope_root, from_epoch }` returns the manifests after `from_epoch`, oldest first, the oldest that fit in 64 KiB; the node installs them in order through `council_manifest_decision`, stops at the first refusal, and asks again from its new epoch (at most 16 rounds per peer). Bounds: one fetch per scope at a time, one fetch per peer per minute, at most 8 peers, 5 s per request. Each node keeps its last 256 epochs (`council_history.bin`) to serve peers behind.
- **Scope root by mode** (invariant; architect sign-off for 2c):

  | Node | Scope root | Test |
  | :-- | :-- | :-- |
  | Private-mode daemon | ring genesis | `council::tests::scope_root_follows_the_mode`, `f08_*`, equivalence `broadcast_eviction_order` |
  | Homelab seed | ring genesis | equivalence `broadcast_eviction_order` |
  | Public-mode daemon | the pinned tracker admin key that rooted its installed manifest (while still pinned); with none installed, the first pinned key in `known_peers.json` order (sorted by tracker address), else the legacy `pinned_tracker_admins.json` | `scope_root_follows_the_mode`, `public_scope_root_follows_the_installed_manifest`, `zero_config` test 7 |
  | Public seed | its own tracker admin key | equivalence (a genesis-rooted council is not its council: `[true, true, false]`), `zero_config` test 7 |

  A hybrid node (in a ring and in public mode) uses the public row: public mode wins, so one node has one council. A private ring is never governed by a tracker key.
- **`evict --propagate`** needs the node to be a member of its installed council; otherwise the eviction stays local.
- **Known limit: equivocation.** A quorum of epoch `n` that signs two different epoch `n + 1` manifests forks the council: each node keeps the successor it installs first, and no node can prove the equivocation to another. Registered in `docs/security/TRUST_FINDINGS.md`.

## Consequences & Verification

- **Consequences:** Eliminates false-positive framing ($2^{-128}$), VPS admin-key theft, private-ring overreach, and single-operator rogue takedowns.
- **Verification:** `specs/ParVaultZeroKeyAdminAndQuorum.tla` (`2,325` states, `0` errors) and Kani harnesses `proof_eviction_quorum_sub_threshold_and_duplicate_signer_rejected`, `proof_eviction_quorum_authorized_distinct_signers_and_expiry`, `proof_eviction_signing_payload_collision_free_across_all_fields`, `proof_admin_rpc_wire_frame_header_no_panic_or_unbounded_alloc`, and `proof_admin_rpc_replay_window_challenge_and_zero_key_rejection`.
