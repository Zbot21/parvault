# User & CLI Reference Manual (`parvault` & `parvault-seed`)

This manual provides the complete command-line reference, step-by-step operational workflows, `.parvaultignore` syntax, disaster recovery recipes, and `config.toml` tuning guide for **`parvault`** (Client & Peer Daemon) and **`parvault-seed`** (Dedicated Zero-Trust Seed & Redundancy Server).

> [!TIP]
> Looking for a 60-second plain-English introduction? Start with **[`QUICKSTART.md`](../QUICKSTART.md)**.

---

## Table of Contents
1. [Binary Overview (`parvault` vs. `parvault-seed`)](#1-binary-overview-parvault-vs-parvault-seed)
2. [Complete `parvault` CLI Reference](#2-complete-parvault-cli-reference)
3. [Complete `parvault-seed` CLI Reference](#3-complete-parvault-seed-cli-reference)
4. [Step-by-Step Operational Workflows](#4-step-by-step-operational-workflows)
   - [4.1 Finding Your `device-peer-id` and `owner-pq-pubkey-hex` (`identity`)](#41-finding-your-device-peer-id-and-owner-pq-pubkey-hex-identity)
   - [4.2 Issuing & Sharing a Post-Quantum `PersonalDeviceCert` (`.json` or `PARVAULT-CERT-V1:` Token)](#42-issuing--sharing-a-post-quantum-personaldevicecert-json-or-parvault-cert-v1-token)
   - [4.3 Excluding Files with `.parvaultignore` & Previewing with `diff-folder`](#43-excluding-files-with-parvaultignore--previewing-with-diff-folder)
   - [4.4 Selective Single-File Restoration (`restore-folder --file`)](#44-selective-single-file-restoration-restore-folder---file)
   - [4.5 Zero-Local-State "House Fire" Recovery (`recover-from-seed`)](#45-zero-local-state-house-fire-recovery-recover-from-seed)
5. [Configuration File (`config.toml`), Bandwidth Rate Limits, Free Disk Reserve & Bit-Rot Scrubbing](#5-configuration-file-configtoml-bandwidth-rate-limits-free-disk-reserve--bit-rot-scrubbing)

---

## 1. Binary Overview (`parvault` vs. `parvault-seed`)

| Binary | Target Machine | Holds User MasterKey? | Primary Role |
| :--- | :--- | :---: | :--- |
| **`parvault`** | Laptops, desktops, workstations, or servers whose own folders are being backed up | **Yes** *(sealed in `<data_dir>/master_key.sealed` or passed via `--key-hex` / `--seed-phrase`)* | Encrypts files (`AES-256-GCM` + 512-bit `PqVaultMasterKey`), splits stripes into Reed-Solomon $GF(2^8)$ shards, watches folders incrementally, and restores backups. |
| **`parvault-seed`** | Headless 24/7 NAS, Raspberry Pi, Unraid/TrueNAS, mini-PC, or VPS | **No — Never** (`holds_own_plaintext_files == false`) | Stores anonymized `.bshard` / `.shard` ciphertext, verifies `PersonalDeviceCert`s (`homelab-vault` mode), answers PoR audits to earn `16-of-20` `HighUptimeAnchor` standing, or acts as an auto-draining community seed (`public-bootstrap` mode). |

---

## 2. Complete `parvault` CLI Reference

Global option: `-c, --config <PATH>` loads a custom `config.toml` file before executing any subcommand.

### 2.1 Identity & Personal Device Certificates
| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `parvault identity` | *(none)* | Initializes (if absent) and displays your persistent `Device Peer ID`, `Ed25519 Public Key`, `Owner PQ Public Key Hex` (`Ed25519 + ML-DSA-65`), and `Master Key Fingerprint`. |
| `parvault issue-device-cert` | `--device-peer-id <ID>` *(required)*<br>`--device-label <LABEL>` *(default: `"personal-device"`)*<br>`--cert-out <PATH>` *(optional)* | Signs a post-quantum composite `PersonalDeviceCert` (`Ed25519 + NIST FIPS 204 ML-DSA-65`) authorizing `<device-peer-id>` to store shards on your Personal Device Ring at `0.0x` quota cost. Outputs both JSON and a compact `PARVAULT-CERT-V1:<hex>` token. |
| `parvault verify-device-cert` | `--cert <PATH_OR_JSON_OR_TOKEN>` *(required)*<br>`--owner-pq-pubkey-hex <HEX>` *(optional)* | Cryptographically verifies a `PersonalDeviceCert` from a `.json` file, raw JSON string, or `PARVAULT-CERT-V1:<hex>` token against the expected Owner PQ Public Key. |

### 2.2 Continuous Folder Sync, Diff & Disaster Recovery
| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `parvault diff-folder` | `--folder <PATH>` *(required)*<br>`--snapshot <PATH>` *(optional)*<br>`--key-hex <HEX>` *(optional)* | Performs a read-only dry-run scan of `<folder>` (respecting `.parvaultignore`), compares streaming 64 KiB SHA-256 digests against `<snapshot>`, and prints added, modified, unchanged, deleted, and ignored file counts without writing shards. |
| `parvault watch-folder` | `--folder <PATH>` *(required)*<br>`--snapshot-out <PATH>` *(default: `./folder_snapshot.manifest.bin`)*<br>`--tier <consumer\|mixed\|homelab\|relay>` *(default: `homelab`)*<br>`--interval-secs <SECS>` *(default: `5`)*<br>`--once` *(run 1 pass and exit)*<br>`--dry-run` *(preview changes without writing shards)*<br>`--prune-deleted` *(delete orphaned local shards for removed files)*<br>`--key-hex <HEX>` *(optional)*<br>`--seed-phrase <PHRASE>` *(optional)*<br>`--vault-namespace <NS>` *(default: `"default"`)*<br>`--catalog-out <PATH>` *(optional `.catalog.bin`)* | Incrementally backs up new and modified files in `<folder>` using constant-memory 64 KiB streaming SHA-256 checks and 16 MiB `AES-256-GCM` + Reed-Solomon stripes. When `--seed-phrase` and `--catalog-out` are provided, also seals a post-quantum `EncryptedVaultCatalogEnvelope` for zero-local-state disaster recovery. |
| `parvault restore-folder` | `--snapshot <PATH>` *(required)*<br>`--out-dir <PATH>` *(required)*<br>`--key-hex <HEX>` *(optional)*<br>`--file <REL_PATH>` *(optional selective single-file restore)* | Reconstructs Reed-Solomon shards in $GF(2^8)$, verifies `AES-256-GCM` tags and end-to-end file SHA-256 on a staging file, blocks path/symlink traversal (`resolve_safe_restore_path`), and atomically writes the restored directory tree (or just `--file <REL_PATH>`) into `<out-dir>`. |
| `parvault recover-from-seed` | `--seed-phrase <PHRASE>` *(required)*<br>`--vault-namespace <NS>` *(default: `"default"`)*<br>`--catalog-envelope <PATH>` *(required)*<br>`--out-dir <PATH>` *(required)* | **Zero-Local-State "House Fire" Recovery (`ADR-15`):** Deterministically re-derives `MasterKey`, 512-bit `PqVaultMasterKey`, `NodeIdentity`, and `dht_key` from `(seed_phrase, vault_namespace)` using 10,000 rounds of key stretching, opens the `EncryptedVaultCatalogEnvelope`, and restores the entire directory tree into `<out-dir>`. |

### 2.3 Single-File Vault Operations, Scrubbing, Graceful Leave & Daemon
| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `parvault file store` | `<PATH>` or `--path <PATH>` *(required)*<br>`--tier <consumer\|mixed\|homelab\|relay>` *(default: `consumer`)*<br>`--key-hex <HEX>` *(optional)* | Streams a single file in 16 MiB stripes, encrypts with `AES-256-GCM`, encodes into Reed-Solomon shards, and writes the encrypted manifest. |
| `parvault file restore` | `<MANIFEST_OR_ROOT>` or `--manifest-or-root <ARG>` *(required)*<br>`<OUTPUT>` or `--output <PATH>` *(required)*<br>`--key-hex <HEX>` *(optional)* | Reconstructs and decrypts a single file from its 64-character hex File Merkle Root or `.manifest.bin` path. |
| `parvault scrub` | *(none)* | Scans every local `.shard` and `.bshard` file on disk, recomputes leaf SHA-256 digests, and quarantines any bit-rotted shard files (`BlockStore::scrub_all_shards`). |
| `parvault leave` | `--handoff-to <CSV>` *(optional)*<br>`--keep-local` *(optional)* | Gracefully decommissions the node, performing a `1.0x` direct shard handoff and writing a signed `graceful_departure_receipt.json` that preserves Earned Standing without PoR slashing. |
| `parvault status` | *(none)* | Displays node configuration, active transport (`TCP + Noise XX + Yamux`), storage quota usage, minimum free disk reserve, bandwidth rate limits, SLA erasure pools, and Earned Standing ladder. |
| `parvault daemon start` | `--listen <MULTIADDR>` *(default: `/ip4/0.0.0.0/tcp/4001`)*<br>`--enable-quic` *(optional)* | Starts the asynchronous P2P storage, Kademlia DHT, Gossipsub slashing, and stateless PoR responder daemon. |

### 2.4 Dedicated Empirical Benchmark Binary (`parvault-bench`)
| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `parvault-bench benchmark` *(alias: `10-node`)* | `--nodes <CSV>` `--payload-mib <MIB>` `--por-challenges <N>` `--killed-node-indices <CSV>` | Runs the 10-node live containerized Noise XX + PoR + 4-node kill recovery benchmark. |
| `parvault-bench benchmark100-node` *(alias: `100-node`)* | `--num-nodes 100` `--num-vaults 50` `--vault-size-mb 100` `--churn-percent 30` | Runs the 100-node scale & 30% rolling churn benchmark with proactive `18/20` witness repair. |
| `parvault-bench benchmark-matrix` *(alias: `matrix`)* | `--payload-kb <KB>` *(default: `256`)* | Runs the 8-Profile Network & Hardware Degradation Matrix with Hedged Parallel $K$-of-$N$ recovery. |

---

## 3. Complete `parvault-seed` CLI Reference

| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `parvault-seed start` | `--mode <homelab-vault\|public-bootstrap>` *(default: `public-bootstrap`)*<br>`--listen <MULTIADDR>` *(default: `/ip4/0.0.0.0/tcp/4002`)*<br>`--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--max-gb <GIB>` *(default: `500`)*<br>`--owner-pq-pubkey-hex <HEX>` *(optional, for `homelab-vault`)*<br>`--grace-epochs <EPOCHS>` *(default: `2`)*<br>`--once` *(print status report and exit)* | Starts the standalone Zero-Trust Seed & Redundancy Server over `TCP + Noise XX + Yamux` with periodic background lease sweeping. |
| `parvault-seed identity` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)* | Displays or initializes the seed server's persistent `Device Peer ID` and `Owner PQ Public Key Hex` (`HybridPqPublicKey`). |
| `parvault-seed issue-device-cert` | `--device-peer-id <ID>` *(required)*<br>`--device-label <LABEL>` *(default: `"personal-device"`)*<br>`--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--cert-out <PATH>` *(optional)* | Issues a post-quantum `PersonalDeviceCert` signed by the seed server's persistent owner PQ keypair and prints both JSON and the `PARVAULT-CERT-V1:<hex>` token. |
| `parvault-seed verify-device-cert` | `--cert <PATH_OR_JSON_OR_TOKEN>` *(required)*<br>`--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--owner-pq-pubkey-hex <HEX>` *(optional)* | Verifies a `PersonalDeviceCert` against the seed server's configured `owner-pq-pubkey-hex`. |
| `parvault-seed status` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)* | Prints the live storage allocation, active blinded leases, earned trust level, and JSON telemetry report. |
| `parvault-seed drain-plan` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--organic-peers <N>` *(default: `20`)*<br>`--target-n <N>` *(default: `20`)* | Simulates and previews deterministic `SeedAnchorDrainMigration` steps showing how shards drain off the seed server onto verified organic peers. |
| `parvault-seed sweep-expired` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--current-epoch <EPOCH>` *(required)* | Physically unlinks expired `.bshard` files where `lease_expires_epoch + grace_epochs <= current_epoch`. |
| `parvault-seed scrub` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)* | Runs `BlockStore::scrub_all_shards` on the seed server's data directory to detect and quarantine silent disk bit-rot. |
| `parvault-seed self-test` | *(none)* | Executes an automated end-to-end self-test verifying `HomelabRedundancyVault` (PQ cert verification + 200 PoR heartbeats -> `16-of-20`) and `PublicNetworkBootstrapper` (lease sweep + organic peer auto-drain -> `0` bytes). |

---

## 4. Step-by-Step Operational Workflows

### 4.1 Finding Your `device-peer-id` and `owner-pq-pubkey-hex` (`identity`)

Every `parvault` and `parvault-seed` node automatically generates and persists its cryptographic identity inside `<data_dir>` on first run:
- `node_identity.key`: 32-byte `Ed25519` seed (`NodeIdentity`), from which your deterministic `device-peer-id` (`parvault-peer-<16_hex_chars>`) is derived.
- `owner_pq_keypair.bin`: Post-Quantum hybrid signing keypair (`Ed25519 + NIST FIPS 204 ML-DSA-65`), whose public key is displayed as `Owner PQ Public Key Hex`.

Run `parvault identity` on your laptop:
```bash
parvault identity
```
Example output:
```text
=== ParVault Node & Post-Quantum Identity ===
Data Directory          : .parvault-data
Device Peer ID          : parvault-peer-8f3a9c12e4b07d11
Ed25519 Public Key (hex): 8f3a9c12e4b07d11c3a8...
Owner PQ Public Key Hex : 20000000... (3,976 hex chars; pass to `--owner-pq-pubkey-hex`)
Master Key Fingerprint  : sha256:4b19e8f021a7c6d4
```

### 4.2 Issuing & Sharing a Post-Quantum `PersonalDeviceCert` (`.json` or `PARVAULT-CERT-V1:` Token)

To link your laptop (`parvault`) and your closet NAS (`parvault-seed --mode homelab-vault`) into a **Day-1 Personal Device Ring** with **zero reciprocity quota tax (`0.00x`)**:

1. **On your laptop (`parvault`), get your `Device Peer ID` and `Owner PQ Public Key Hex`:**
   ```bash
   parvault identity
   ```
2. **Issue a certificate for your laptop (saving `.json` AND printing the compact `PARVAULT-CERT-V1:` token):**
   ```bash
   parvault issue-device-cert \
     --device-peer-id "parvault-peer-8f3a9c12e4b07d11" \
     --device-label "ThinkPad-Linux" \
     --cert-out ./laptop.device-cert.json
   ```
   This prints a single-line copy-pasteable token:
   ```text
   Shareable Token : PARVAULT-CERT-V1:0a4f8b...
   ```
3. **On your NAS (`parvault-seed`), verify the certificate using either the `.json` file or the `PARVAULT-CERT-V1:...` token:**
   ```bash
   parvault-seed verify-device-cert \
     --cert "PARVAULT-CERT-V1:0a4f8b..." \
     --owner-pq-pubkey-hex "<OWNER_PQ_PUBKEY_HEX_FROM_STEP_1>"
   ```
4. **Start your NAS `parvault-seed` server locked to your `Owner PQ Public Key Hex`:**
   ```bash
   parvault-seed start \
     --mode homelab-vault \
     --data-dir /mnt/nas/parvault-seed \
     --max-gb 500 \
     --owner-pq-pubkey-hex "<OWNER_PQ_PUBKEY_HEX_FROM_STEP_1>" \
     --listen /ip4/0.0.0.0/tcp/4002
   ```

### 4.3 Excluding Files with `.parvaultignore` & Previewing with `diff-folder`

When syncing a directory tree, `FolderSyncEngine` automatically skips noisy build/cache artifacts by default and honors an optional **`.parvaultignore`** file at the root of the watched folder.

- **Built-In Default Exclusions (always ignored unless negated with `!pattern`):**
  - `.git`, `node_modules`, `target`, `.DS_Store`, `Thumbs.db`
  - `*.tmp`, `*.swp`, `*.parvault_restore_staging`
- **Custom `.parvaultignore` Rules:**
  ```gitignore
  # Ignore local virtualenvs, Docker volumes, and ISO downloads
  .venv/
  dist/
  *.iso
  *.log

  # Negation (!) re-includes a file even if a wildcard matched it
  !important.log
  ```

Before running a sync pass, preview exactly what `parvault` will do using `diff-folder` (or `watch-folder --dry-run`):
```bash
parvault diff-folder \
  --folder ./my-projects \
  --snapshot ./my-projects.manifest.bin
```

To automatically garbage-collect local shards belonging to files you deleted from `<folder>`, pass `--prune-deleted`:
```bash
parvault watch-folder \
  --folder ./my-projects \
  --snapshot-out ./my-projects.manifest.bin \
  --prune-deleted \
  --once
```

### 4.4 Selective Single-File Restoration (`restore-folder --file`)

Accidentally overwrote a single configuration file or spreadsheet inside a 500 GB folder backup? You don't have to restore the entire folder tree—pass `--file <REL_PATH>`:

```bash
parvault restore-folder \
  --snapshot ./my-projects.manifest.bin \
  --out-dir ./recovered-single-file \
  --file "configs/wireguard/wg0.conf"
```

### 4.5 Zero-Local-State "House Fire" Recovery (`recover-from-seed`)

What if a house fire, flood, or theft destroys your laptop **and** your local `.manifest.bin` / `master_key.sealed` files?

1. **During normal backups, pass `--seed-phrase` and `--catalog-out`** so `parvault` derives deterministic keys from your 24-word recovery phrase and seals a post-quantum `EncryptedVaultCatalogEnvelope`:
   ```bash
   parvault watch-folder \
     --folder ./family-vault \
     --snapshot-out ./family-vault.manifest.bin \
     --seed-phrase "abandon ability able about above absent absorb abstract absurd abuse access accident" \
     --vault-namespace "family-vault-2026" \
     --catalog-out ./family-vault.catalog.bin \
     --once
   ```
2. **After a total local hardware loss, install `parvault` on a brand-new machine and run `recover-from-seed`:**
   ```bash
   parvault recover-from-seed \
     --seed-phrase "abandon ability able about above absent absorb abstract absurd abuse access accident" \
     --vault-namespace "family-vault-2026" \
     --catalog-envelope ./family-vault.catalog.bin \
     --out-dir ./restored-family-vault
   ```
   `recover-from-seed` runs 10,000 rounds of domain-separated SHA-256 key stretching + HKDF-SHA256 to reconstruct your exact `MasterKey`, 512-bit `PqVaultMasterKey`, `NodeIdentity`, and `dht_key`, verifies the catalog's zero-knowledge signature, and restores every file bit-for-bit.

4. **Selective Partial Restore (`--filter`) & Zero-Download Catalog Browsing (`list-snapshot`):**
   If your home NAS dies and your laptop only has a 512 GiB SSD, you never have to restore your entire multi-terabyte vault at once. First, browse the snapshot catalog (`list-snapshot` downloads **zero** shards), or pass `--filter` (comma-separated path prefixes, exact paths, or `*`/`?` globs) to `restore-folder` or `recover-from-seed`:
   ```bash
   # Browse all files, byte sizes, and stripe counts in a snapshot without downloading any shards
   parvault list-snapshot --snapshot ./family-vault.manifest.bin

   # Restore ONLY matching paths/globs from a snapshot (or via recover-from-seed --filter)
   parvault restore-folder \
     --snapshot ./family-vault.manifest.bin \
     --out-dir ./restored-subset \
     --filter "docs/urgent/*,*.pdf"
   ```

5. **Laptop Lite-Client Mode (`--lite-seed-dir` & `--device-cert`):**
   Run your laptop in `LiteSeedBacked` mode (`ADR-17`) so your laptop uploads `1.0x` locally-encrypted `AES-256-GCM` stripes to your `parvault-seed` box while your `parvault-seed` box performs the `16-of-20` Reed-Solomon encoding and mesh syndication:
   ```bash
   parvault watch-folder \
     --folder ./laptop-workspace \
     --snapshot-out ./laptop.manifest.bin \
     --lite-seed-dir /mnt/nas/parvault-seed \
     --device-cert ~/.parvault-data/laptop.cert.bin \
     --once
   ```
   Because your laptop and `parvault-seed` share the identical `FolderSnapshotManifest` and `ShardId` protocol, if your `parvault-seed` NAS ever dies, your laptop automatically fails over to reconstructing any $K$-of-$N$ surviving shards directly from the Neighborhood Cloud mesh.

---

## 5. Configuration File (`config.toml`), Bandwidth Rate Limits, Free Disk Reserve & Bit-Rot Scrubbing

You can pass `-c config.toml` to `parvault` to customize paths, quotas, bandwidth ceilings, and minimum free disk reserves:

```toml
# Example config.toml for parvault
data_dir = ".parvault-data"
listen_tcp = "/ip4/0.0.0.0/tcp/4001"
enable_quic = false
listen_quic = "/ip4/0.0.0.0/udp/4001/quic-v1"

# 16 MiB streaming stripe size (caps active gateway RAM < 32 MiB per ADR-01)
stripe_size_bytes = 16777216
default_tier = "Consumer"

# Maximum storage space committed to mesh shards (100 GiB) & initial bootstrap grace (10 GiB)
max_storage_bytes = 107374182400
bootstrap_grace_bytes = 10737418240

# Minimum free disk space reserve (5 GiB default) so mesh shards never fill your root OS disk
min_free_disk_bytes = 5368709120

# Optional token-bucket bandwidth rate limits in Mbps (0 = unlimited)
max_upload_mbps = 50
max_download_mbps = 100

# Proof-of-Retrievability & 70/30 ASN Locality tuning
por_timeout_ms = 300
local_rtt_threshold_ms = 5
intra_asn_ratio = 0.70
```

### Proactive Bit-Rot Scrubbing (`parvault scrub` & `parvault-seed scrub`)
Consumer hard drives and aged SSDs occasionally suffer silent sector corruption ("bit-rot"). Run `parvault scrub` (or `parvault-seed scrub --data-dir /mnt/nas/parvault-seed`) via cron or systemd timer to verify every stored `.shard` and `.bshard` against its expected SHA-256 digest and automatically quarantine corrupted files so witness repair can replace them cleanly.

### Graceful Node Decommissioning (`parvault leave` & `parvault-seed leave`)
While the protocol automatically survives ungraceful node departures via PoR timeouts and $K$-of-$N$ Reed-Solomon lazy repair, running `parvault leave` (or `parvault-seed leave`) before permanently retiring a machine or migrating a drive provides three major advantages:
1. **$16\times$ Bandwidth Savings (`1.0x` Direct Handoff vs. `16.0x` Reed-Solomon Reconstruction):** Directly evacuates intact `.shard` and `.bshard` files instead of forcing 16 remote peers to stream shards across the WAN to reconstruct 1 missing shard.
2. **Zero Redundancy Dip (`20/20` Stays `20/20`):** Avoids leaving stripes at `19/20` while waiting for the lazy-repair threshold (`18/20`).
3. **Preserves Earned Uptime Standing & Reciprocity Credits:** Issues a signed `GracefulDepartureReceipt` (`graceful_departure_receipt.json`) so your node's `HomelabAnchor` / `VerifiedNeighbor` standing is frozen rather than slashed for missed PoR challenges.

```bash
# Simply run `leave` — automatically redistributes hosted shards across the mesh at 1.0x bandwidth
parvault leave
parvault-seed leave --data-dir /mnt/nas/parvault-seed
```
