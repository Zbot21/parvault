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
   - [4.0 Zero-IP Home LAN & Online WAN Onboarding Flow (`v0.3.0`)](#40-zero-ip-home-lan--online-wan-onboarding-flow-v030)
   - [4.1 Finding Your `device-peer-id` and `owner-pq-pubkey-hex` (`identity`)](#41-finding-your-device-peer-id-and-owner-pq-pubkey-hex-identity)
   - [4.2 Issuing & Sharing a Post-Quantum `PersonalDeviceCert` (`.json` or `PARVAULT-CERT-V1:` Token)](#42-issuing--sharing-a-post-quantum-personaldevicecert-json-or-parvault-cert-v1-token)
   - [4.3 Excluding Files with `.parvaultignore` & Previewing with `diff-folder`](#43-excluding-files-with-parvaultignore--previewing-with-diff-folder)
   - [4.4 Selective Single-File Restoration (`restore-folder --file`)](#44-selective-single-file-restoration-restore-folder---file)
   - [4.5 Zero-Local-State "House Fire" Recovery (`recover-from-seed`)](#45-zero-local-state-house-fire-recovery-recover-from-seed)
   - [4.6 Privacy-Preserving Bad-Actor & Content Eviction (`parvault evict`, `ADR-19`)](#46-privacy-preserving-bad-actor--content-eviction-parvault-evict-adr-19)
   - [4.7 Public Tracker Abuse Reporting & Admin Takedown Workflow (`parvault report-abuse`, `parvault-seed admin`, `ADR-19`)](#47-public-tracker-abuse-reporting--admin-takedown-workflow-parvault-report-abuse-parvault-seed-admin-adr-19)
5. [Configuration File (`config.toml`), Bandwidth Rate Limits, Free Disk Reserve & Bit-Rot Scrubbing](#5-configuration-file-configtoml-bandwidth-rate-limits-free-disk-reserve--bit-rot-scrubbing)

---

## 1. Binary Overview (`parvault` vs. `parvault-seed`)

| Binary | Target Machine | Holds User MasterKey? | Primary Role |
| :--- | :--- | :---: | :--- |
| **`parvault`** | Laptops, desktops, workstations, or servers whose own folders are being backed up | **Yes** *(sealed in `<data_dir>/master_key.sealed` via `LocalFileKeystore` with `Argon2id` passphrase / `0600` local key, or passed via `--key-hex` / `--seed-phrase`)* | Encrypts files (`AES-256-GCM` + dual-cipher `PqVaultMasterKey` cascade), splits stripes into Reed-Solomon $GF(2^8)$ shards, watches folders incrementally, and restores backups. |
| **`parvault-seed`** | Headless 24/7 NAS, Raspberry Pi, Unraid/TrueNAS, mini-PC, or VPS | **No — Never** (`holds_own_plaintext_files == false`) | Stores anonymized `.bshard` / `.shard` ciphertext, verifies `PersonalDeviceCert`s (`homelab-vault` mode), answers PoR audits to earn `16-of-20` `HighUptimeAnchor` standing, or acts as an auto-draining community seed (`public-bootstrap` mode). |

---

## 2. Complete `parvault` CLI Reference

Global options (available on all subcommands):
- `-c, --config <PATH>`: Load a custom `config.toml` file.
- `--data-dir <PATH>`: Override local data directory for shards, manifests, and identity keys.
- `--profile <router-soc|homelab-nas|desktop>`: Select hardware optimization profile (sets stripe size to `1 MiB` on `router-soc`, `4 MiB` on `homelab-nas`, `16 MiB` on `desktop`).
- `--peers <CSV>`: Comma-separated list of mesh peer `Multiaddr`s or `host:port` endpoints (overrides `bootstrap_peers` / `PARVAULT_PEERS`).
- `--seed-addr <ADDR>`: Paired `parvault-seed` `Multiaddr` or `host:port` endpoint (overrides `lite_seed_addr` / `PARVAULT_SEED_ADDR`).
- `--lan-discovery-port <PORT>`: UDP port for zero-config signed LAN beacon discovery (default: `4009`).
- `--no-lan-discovery`: Disable automatic UDP LAN beaconing and responder.
- `--public`: Enable open BitTorrent-style Public Commons mode (uses self-signed Hashcash PoW ticket, zero pairing required).
- `--tracker <MULTIADDR>`: Specify public commons bootstrap tracker `Multiaddr`.

### 2.1 Zero-IP Onboarding, Auto-Discovery & Turnkey Appliance Mode (`v0.3.0`)
| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `parvault init` | `--profile <PROFILE>` *(default: `desktop`)*<br>`--watch <DIR>` *(optional)*<br>`--label <NAME>` *(optional)*<br>`--max-storage-gib <GIB>` *(optional)* | Initializes fresh node identity keys (`0600`), generates and prints a 24-word BIP-39 recovery mnemonic, creates `<data_dir>/config.toml`, and creates `<watch>` directory. |
| `parvault discover` | `--timeout-ms <MS>` *(default: `500`)*<br>`--port <PORT>` *(default: `4009`)*<br>`--json` *(optional)* | Scans the local network over UDP port `4009` and multicast `239.255.80.86`, verifies signed `LanBeaconPacket`s, upserts verified multiaddrs in `<data_dir>/known_peers.json`, and prints a human-readable table or structured JSON — **zero IP addresses required!** |
| `parvault pair` | `--port <PORT>` *(default: `4009`)*<br>`--duration-secs <SECS>` *(default: `120`)*<br>`--once` *(optional)*<br>`--wan` *(optional)* | Derives a human-friendly 4-word BIP-39 SAS pairing code (e.g. `shield-copper-alpine-matrix`), broadcasts the commitment via `LanBeaconResponder` (or registers an encrypted WAN rendezvous slot on `--seed-addr`), and stays active for joining peers. |
| `parvault join` | `--code <CODE_OR_TOKEN>` *(required)*<br>`--timeout-ms <MS>` *(default: `1500`)*<br>`--port <PORT>` *(default: `4009`)*<br>`--wan` *(optional)* | Probes the LAN (or looks up WAN rendezvous) for the peer broadcasting the matching 4-word code, verifies signature and SAS commitment, and pins `/p2p/<PeerId>` in `known_peers.json`. |
| `parvault up` | `--profile <router-soc\|homelab-nas\|desktop>` *(default: `desktop`)*<br>`--folder <DIR>` *(optional continuous watch directory)*<br>`--interval-secs <SECS>` *(default: `5`)*<br>`--status-http <ADDR>` *(e.g. `0.0.0.0:4080`)*<br>`--pair` *(optional; outputs 4-word code)*<br>`--public` *(optional; zero-pairing public swarm)*<br>`--tracker <MULTIADDR>` *(optional public tracker)* | **Turnkey Single-Command Appliance Mode:** Starts the P2P storage daemon, signed UDP LAN beacon responder, embedded `RouterNasStatusServer` HTTP dashboard/API, and background incremental folder watcher. |

### 2.2 Identity & Personal Device Certificates
| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `parvault identity` | *(none)* | Initializes (if absent) and displays your persistent `Device Peer ID`, `Ed25519 Public Key`, `Owner PQ Public Key Hex` (`Ed25519 + ML-DSA-65`), and `Master Key Fingerprint`. |
| `parvault issue-device-cert` | `--device-peer-id <ID>` *(required)*<br>`--device-label <LABEL>` *(default: `"personal-device"`)*<br>`--cert-out <PATH>` *(optional)* | Signs a post-quantum composite `PersonalDeviceCert` (`Ed25519 + NIST FIPS 204 ML-DSA-65`) authorizing `<device-peer-id>` to store shards on your Personal Device Ring at `0.0x` quota cost. Outputs both JSON and a compact `PARVAULT-CERT-V1:<hex>` token. |
| `parvault verify-device-cert` | `--cert <PATH_OR_JSON_OR_TOKEN>` *(required)*<br>`--owner-pq-pubkey-hex <HEX>` *(optional)* | Cryptographically verifies a `PersonalDeviceCert` from a `.json` file, raw JSON string, or `PARVAULT-CERT-V1:<hex>` token against the expected Owner PQ Public Key. |
| `parvault wot invite` | `--peer <PUBKEY_HEX>` *(required)* | Prints a chain token admitting that key to this ring (`v0.5.0`). Needs the ring genesis seed (`PARVAULT_GENESIS_SEED_HEX` or `<data_dir>/genesis_root.seed`). |
| `parvault wot install-chain` | `--token <HEX>` *(required)* | Installs a chain token into `<data_dir>/wot_chains/`; the node then presents it before storing on ring peers. |

### 2.3 Continuous Folder Sync, Diff & Disaster Recovery
| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `parvault diff-folder` | `--folder <PATH>` *(required)*<br>`--snapshot <PATH>` *(optional)*<br>`--key-hex <HEX>` *(optional)* | Performs a read-only dry-run scan of `<folder>` (respecting `.parvaultignore`), compares streaming 64 KiB SHA-256 digests against `<snapshot>`, and prints added, modified, unchanged, deleted, and ignored file counts without writing shards. |
| `parvault watch-folder` | `--folder <PATH>` *(required)*<br>`--snapshot-out <PATH>` *(default: `./folder_snapshot.manifest.bin`)*<br>`--tier <consumer\|mixed\|homelab\|relay>` *(default: `homelab`)*<br>`--interval-secs <SECS>` *(default: `5`)*<br>`--once` *(run 1 pass and exit)*<br>`--dry-run` *(preview changes without writing shards)*<br>`--prune-deleted` *(delete orphaned local & remote shards for removed files)*<br>`--key-hex <HEX>` *(optional)*<br>`--seed-phrase <PHRASE>` *(optional)*<br>`--vault-namespace <NS>` *(default: `"default"`)*<br>`--catalog-out <PATH>` *(optional `.catalog.bin`)*<br>`--lite-seed-dir <MULTIADDR_OR_PATH>` *(alias: `--lite-seed-addr`)*<br>`--device-cert <PATH_OR_TOKEN>` *(optional)* | Incrementally backs up new and modified files in `<folder>` using constant-memory 64 KiB streaming SHA-256 checks and 16 MiB `AES-256-GCM` + Reed-Solomon stripes distributed across `--peers` over `libp2p`. When `--seed-phrase` is provided, also seals and publishes a post-quantum `EncryptedVaultCatalogEnvelope` to the Kademlia DHT for zero-local-state disaster recovery. |
| `parvault list-snapshot` | `--snapshot <PATH>` *(required)* | Lists all file paths, byte sizes, stripe counts, and Merkle root prefixes inside `<snapshot>` with zero shard downloads (`ADR-17`). |
| `parvault restore-folder` | `--snapshot <PATH>` *(required)*<br>`--out-dir <PATH>` *(alias: `--target-dir`, required)*<br>`--key-hex <HEX>` *(optional)*<br>`--file <REL_PATH>` *(optional single-file restore)*<br>`--filter <CSV>` *(optional glob/prefix subset restore)* | Reconstructs Reed-Solomon shards in $GF(2^8)$ across `--peers`, verifies `AES-256-GCM` tags and end-to-end file SHA-256 on a staging file, blocks path/symlink traversal (`resolve_safe_restore_path`), and atomically writes the restored directory tree into `<out-dir>`. |
| `parvault recover-from-seed` | `--seed-phrase <PHRASE>` *(required)*<br>`--vault-namespace <NS>` *(default: `"default"`)*<br>`--catalog-envelope <PATH>` *(optional; if omitted, queries Kademlia DHT via `--peers`)*<br>`--out-dir <PATH>` *(default: `./recovered_vault`)*<br>`--filter <CSV>` *(optional glob/prefix subset recovery)* | **Zero-Local-State "House Fire" Recovery (`ADR-15` / `ADR-17`):** Deterministically re-derives `MasterKey`, 512-bit `PqVaultMasterKey`, `NodeIdentity`, and `dht_key` from `(seed_phrase, vault_namespace)` using memory-hard `Argon2id` (`64 MiB`, `t=3`, `p=4`) + `HKDF-SHA256`, fetches and opens the highest-version `EncryptedVaultCatalogEnvelope`, and restores the directory tree into `<out-dir>`. |

### 2.4 Single-File Vault Operations, Scrubbing, Graceful Leave & Daemon
| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `parvault file store` | `<PATH>` or `--path <PATH>` *(required)*<br>`--tier <consumer\|mixed\|homelab\|relay>` *(default: `consumer`)*<br>`--key-hex <HEX>` *(optional)* | Streams a single file in 16 MiB stripes (or 1 MiB on `router-soc`), encrypts with `AES-256-GCM`, encodes into Reed-Solomon shards, distributes shards across `--peers` (auto-discovering LAN peers if `--peers` is omitted), and publishes the encrypted manifest to the DHT. |
| `parvault file restore` | `<MANIFEST_OR_ROOT>` or `--manifest-or-root <ARG>` *(required)*<br>`<OUTPUT>` or `--output <PATH>` *(required)*<br>`--key-hex <HEX>` *(optional)* | Reconstructs and decrypts a single file from its 64-character hex File Merkle Root (fetching the manifest and shards over `--peers` or auto-discovered LAN peers) or `.manifest.bin` path. |
| `parvault scrub` | *(none)* | Scans every local `.shard` and `.bshard` file on disk, recomputes leaf SHA-256 digests, and quarantines any bit-rotted shard files (`BlockStore::scrub_all_shards`). |
| `parvault evict` | `--ip <IP>` *(optional)*<br>`--subnet <CIDR>` *(optional)*<br>`--peer-id <ID>` *(optional)*<br>`--pubkey-hex <HEX>` *(optional)*<br>`--merkle-root <HEX>` *(optional)*<br>`--locator <HEX>` *(optional)*<br>`--reason <TEXT>` *(optional, max 256 B)*<br>`--propagate` *(broadcast signed order to mesh peers)* | **Privacy-Preserving 4-Vector Eviction (`ADR-19`):** Overwrites matching `.shard` / `.bshard` files with `0x00` zero bytes across their entire allocation, calls `sync_all()`, unlinks from disk, and installs persistent in-memory HMAC ingress firewall rules without storing any plaintext IPs on disk. |
| `parvault report-abuse` | `--tracker <MULTIADDR>` *(required)*<br>`--manifest <PATH>` *(required)*<br>`--disclosed-key-hex <HEX>` *(required)*<br>`--allegation <TEXT>` *(required, max 256 B)*<br>`--contact <TEXT>` *(optional)*<br>`--bad-actor-ip <IP>` *(optional)*<br>`--stripe-index <U64>` *(default: `0`)* | **Cryptographic Burden-of-Proof Abuse Reporting (`ADR-19`):** Submits a `VerifiableAbuseReport` to a Public Tracker Operator, proving illegal content distribution via leaked decryption key, sample shards, and AES-256-GCM authenticated plaintext digest for human admin takedown review. |
| `parvault leave` | `--handoff-to <CSV>` *(optional `Multiaddr`s or paths)*<br>`--keep-local` *(optional)* | Gracefully decommissions the node, performing a `1.0x` direct shard handoff over `libp2p` (preserving PoR session keys and `RepairGrant`s) and writing a signed `graceful_departure_receipt.json`. |
| `parvault status` | *(none)* | Displays node configuration, active transport (`TCP + Noise XX + Yamux`), hardware profile, storage quota usage, minimum free disk reserve, bandwidth rate limits, SLA erasure pools, and Earned Standing ladder. |
| `parvault daemon start` | `--listen <MULTIADDR>` *(default: `/ip4/0.0.0.0/tcp/4001`)*<br>`--profile <router-soc\|homelab-nas\|desktop>` *(optional)*<br>`--lan-discovery-port <PORT>` *(default: `4009`)*<br>`--no-lan-discovery` *(optional)*<br>`--status-http <ADDR>` *(optional)*<br>`--enable-quic` *(optional)* | Starts the asynchronous P2P storage, Kademlia DHT, Gossipsub slashing, periodic bit-rot scrubber, UDP LAN beacon responder, and stateless PoR responder daemon. |

---

## 3. Complete `parvault-seed` CLI Reference

Global option: `--peers <CSV>` (`PARVAULT_PEERS`) configures mesh peer `Multiaddr`s for Lite-Client stripe syndication and handoff.

| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `parvault-seed start` | `--mode <homelab-vault\|public-bootstrap>` *(default: `public-bootstrap`)*<br>`--listen <MULTIADDR>` *(default: `/ip4/0.0.0.0/tcp/4002`)*<br>`--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--max-gb <GIB>` *(default: `500`)*<br>`--lan-discovery-port <PORT>` *(default: `4009`)*<br>`--no-lan-discovery` *(optional)*<br>`--owner-pq-pubkey-hex <HEX>` *(optional, for `homelab-vault`)*<br>`--grace-epochs <EPOCHS>` *(default: `2`)*<br>`--admin-rpc-listen <SOCKET_ADDR>` *(optional)*<br>`--admin-rpc-pubkey <HEX>` *(optional, repeatable/CSV)*<br>`--council-pubkeys <CSV>` *(optional)*<br>`--council-quorum <N>` *(default: `1`)*<br>`--once` *(print status report and exit)* | Starts the standalone Zero-Trust Seed & Redundancy Server over `TCP + Noise XX + Yamux`. In `--mode public-bootstrap`, also acts as a Zero-Pairing BitTorrent-Style Public Swarm Tracker (`ADR-18`), indexing active public peers and answering WAN rendezvous lookups. Supports opt-in authenticated admin RPC (`--admin-rpc-listen` + `--admin-rpc-pubkey`) for fleet management via `parvault-control` with forward-secret X25519 + ChaCha20-Poly1305 + Ed25519 framing and zero private keys required on the seed server. |
| `parvault-seed identity` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)* | Displays or initializes the seed server's persistent `Device Peer ID` and `Owner PQ Public Key Hex` (`HybridPqPublicKey`). |
| `parvault-seed issue-device-cert` | `--device-peer-id <ID>` *(required)*<br>`--device-label <LABEL>` *(default: `"personal-device"`)*<br>`--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--cert-out <PATH>` *(optional)* | Issues a post-quantum `PersonalDeviceCert` signed by the seed server's persistent owner PQ keypair and prints both JSON and the `PARVAULT-CERT-V1:<hex>` token. |
| `parvault-seed verify-device-cert` | `--cert <PATH_OR_JSON_OR_TOKEN>` *(required)*<br>`--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--owner-pq-pubkey-hex <HEX>` *(optional)* | Verifies a `PersonalDeviceCert` against the seed server's configured `owner-pq-pubkey-hex`. |
| `parvault-seed status` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--mode <homelab-vault\|public-bootstrap>` *(default: `homelab-vault`)* | Prints the live storage allocation, active blinded leases, earned trust level, and JSON telemetry report. |
| `parvault-seed drain-plan` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--organic-peers <N>` *(default: `20`)*<br>`--target-n <N>` *(default: `20`)* | Simulates and previews deterministic `SeedAnchorDrainMigration` steps showing how shards drain off the seed server onto verified organic peers. |
| `parvault-seed sweep-expired` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--current-epoch <EPOCH>` *(required)* | Physically unlinks expired `.bshard` files where `lease_expires_epoch + grace_epochs <= current_epoch`. |
| `parvault-seed scrub` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)* | Runs `BlockStore::scrub_all_shards` on the seed server's data directory to detect and quarantine silent disk bit-rot. |
| `parvault-seed evict` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--ip <IP>` *(optional)*<br>`--subnet <CIDR>` *(optional)*<br>`--peer-id <ID>` *(optional)*<br>`--pubkey-hex <HEX>` *(optional)*<br>`--merkle-root <HEX>` *(optional)*<br>`--locator <HEX>` *(optional)*<br>`--reason <TEXT>` *(optional)*<br>`--propagate` *(optional)* | **Privacy-Preserving 4-Vector Eviction on Seed Server (`ADR-19`):** Overwrites matching regular or blinded `.bshard` files with `0x00` zero bytes, resolves and purges associated ticket/voucher public key cohorts, installs HMAC ingress firewall rules, and optionally propagates signed eviction orders to mesh peers. |
| `parvault-seed admin` | `show-authority`<br>`list-takedowns [--data-dir <PATH>]`<br>`inspect-takedown --report-id <HEX> [--data-dir <PATH>]`<br>`approve-takedown --report-id <HEX> --note <TEXT> [--data-dir <PATH>] [--export-order <PATH>] [--propagate]`<br>`reject-takedown --report-id <HEX> --reason <TEXT> [--data-dir <PATH>]`<br>`emergency-evict --data-dir <PATH> (--ip <IP> \| --subnet <CIDR> \| --pubkey-hex <HEX> \| --peer-id <ID>) --warrant-ref <TEXT> [--export-order <PATH>] [--propagate]`<br>`cosign-eviction --data-dir <PATH> --order-file <PATH> [--out <PATH>] [--propagate]` | **Public Tracker Admin Governance & Takedown Queue (`ADR-19`):** Manages the persistent takedown queue (`admin_takedown_queue.bin`), inspects cryptographic burden-of-proof outcomes, rejects baseless reports, signs and broadcasts `SignedBadActorEvictionOrder`s using `tracker_admin.seed`, issues unilateral emergency warrant evictions, or co-signs orders to reach federated `M-of-N` Tracker Council quorum. |
| `parvault-seed leave` | `--data-dir <PATH>` *(default: `./.parvault-seed-data`)*<br>`--handoff-to <CSV>` *(optional `Multiaddr`s or paths)*<br>`--keep-local` *(optional)* | Gracefully decommissions the seed server, performing a `1.0x` direct shard handoff over `libp2p` and writing a signed `graceful_departure_receipt.json`. |
| `parvault-seed self-test` | *(none)* | Executes an automated end-to-end self-test verifying `HomelabRedundancyVault` (PQ cert verification + 200 PoR heartbeats -> `16-of-20`) and `PublicNetworkBootstrapper` (lease sweep + organic peer auto-drain -> `0` bytes). |

---

## 4. Step-by-Step Operational Workflows

### 4.0 Zero-IP Home LAN & Online WAN Onboarding Flow (`v0.3.0`)

With `v0.3.0`, you never need to look up or type IP addresses on your home network or across residential ISPs:

#### 1. Quick Initialization (`parvault init`)
Initialize keys, generate a 24-word BIP-39 recovery mnemonic, and create a ready-to-run `config.toml`:
```bash
parvault init --profile router-soc --watch /mnt/usb-nas/shared --label "Router-NAS"
```

#### 2. Turnkey Appliance Mode (`parvault up`)
Start your node as a continuous backup appliance with zero further setup:
```bash
parvault up \
  --profile router-soc \
  --folder /mnt/usb-nas/shared \
  --status-http 0.0.0.0:4080 \
  --pair
```
This prints a **4-word BIP-39 SAS pairing code** (e.g. `shield-copper-alpine-matrix`), launches the P2P daemon, responds to signed LAN discovery beacons on UDP `4009`, and serves the live web dashboard on port `4080`.

#### 3. Zero-IP Auto-Discovery & Pairing on Laptops (`parvault discover` & `join`)
On any other computer on your Wi-Fi/LAN:
```bash
# Auto-discover local nodes without entering any IP address:
parvault discover

# Pair permanently using the 4-word code:
parvault join --code shield-copper-alpine-matrix
```
Both devices are now pinned in `<data_dir>/known_peers.json`. If your router reboots or DHCP assigns a new internal IP, ParVault auto-heals the connection dynamically.

#### 4. Zero-Pairing BitTorrent-Style Public Commons Mode (`--public`)
If you want to back up files without pairing with anyone, connect directly to the Public Commons swarm:
```bash
parvault watch-folder \
  --folder ~/Documents \
  --public \
  --tracker /dns4/tracker.neighborhoodcloud.org/tcp/4002/p2p/12D3KooW... \
  --once
```
Files are encrypted locally with `AES-256-GCM` + Post-Quantum keys, erasure-coded across stranger nodes (`10-of-20` Consumer redundancy), and protected by pre-decoding Merkle quarantine.

---

### 4.1 Finding Your `device-peer-id` and `owner-pq-pubkey-hex` (`identity`)

Every `parvault` and `parvault-seed` node automatically generates and persists its cryptographic identity inside `<data_dir>` on first run:
- `node_identity.seed`: 32-byte `Ed25519` seed (`NodeIdentity`), from which your deterministic `device-peer-id` (`parvault-peer-<16_hex_chars>`) and `libp2p` `PeerId` are derived.
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

1. **During normal backups, pass `--seed-phrase` and `--catalog-out`** so `parvault` derives deterministic keys from your 12-word (128-bit) or 24-word (256-bit) checksummed BIP-39 recovery phrase (validated against the 2,048-word English wordlist, SHA-256 checksum, and Unicode NFKD whitespace normalization) and seals a post-quantum `EncryptedVaultCatalogEnvelope`:
   ```bash
   parvault watch-folder \
     --folder ./family-vault \
     --snapshot-out ./family-vault.manifest.bin \
     --seed-phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
     --vault-namespace "family-vault-2026" \
     --catalog-out ./family-vault.catalog.bin \
     --once
   ```
2. **After a total local hardware loss, install `parvault` on a brand-new machine and run `recover-from-seed`:**
   ```bash
   parvault recover-from-seed \
     --seed-phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
     --vault-namespace "family-vault-2026" \
     --catalog-envelope ./family-vault.catalog.bin \
     --out-dir ./restored-family-vault
   ```
   `recover-from-seed` runs memory-hard `Argon2id` (`m = 64 MiB (65,536 KiB)`, `t = 3`, `p = 4`) + `HKDF-SHA256` to reconstruct your exact `MasterKey` (and its domain-separated HKDF subkey hierarchy), dual-cipher `PqVaultMasterKey`, `NodeIdentity`, and `dht_key`, verifies the catalog's zero-knowledge signature, and restores every file bit-for-bit.

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
   Run your laptop in `LiteSeedBacked` mode (`ADR-17`) so your laptop uploads `1.0x` locally-encrypted `AES-256-GCM` stripes to your `parvault-seed` box over `libp2p` while your `parvault-seed` box performs the `16-of-20` Reed-Solomon encoding and mesh syndication:
   ```bash
   parvault --peers "/ip4/10.42.1.11/tcp/4001,/ip4/10.42.1.12/tcp/4001" watch-folder \
     --folder ./laptop-workspace \
     --snapshot-out ./laptop.manifest.bin \
     --lite-seed-dir /ip4/10.42.1.10/tcp/4002 \
     --device-cert ./laptop.device-cert.json \
     --once
   ```
   Because your laptop and `parvault-seed` share the identical `FolderSnapshotManifest` and `ShardId` protocol, if your `parvault-seed` NAS ever dies, your laptop automatically fails over to reconstructing any $K$-of-$N$ surviving shards directly from the Neighborhood Cloud mesh.

### 4.6 Privacy-Preserving Bad-Actor & Content Eviction (`parvault evict`, `ADR-19`)

If an administrator or homelab node operator identifies abusive network spammers or illegal content, they can execute a privacy-preserving purge without compromising innocent users' privacy:

```bash
# 1. Evict by IP address (overwrites shards with 0x00 and installs in-memory HMAC firewall rule):
parvault evict --ip 203.0.113.42 --reason "Abusive flood traffic"

# 2. Evict an entire abusive /24 or /48 CIDR subnet:
parvault evict --subnet 203.0.113.0/24 --reason "Spam cohort"

# 3. Evict and shred illegal content stripes by Merkle Root and broadcast to mesh peers:
parvault evict --merkle-root c5a349b529494f223af1b81ab5beee0cc812e044679c252e12725de981911dfd \
  --reason "DMCA / Illegal content takedown" \
  --propagate

# 4. On a seed anchor, purge all blinded shards associated with an admitted bad-actor ticket:
parvault-seed evict --data-dir /mnt/nas/parvault-seed \
  --pubkey-hex 8f3a9c12e4b07d11... \
  --reason "Slashed Sybil identity"
```

All evicted shards are overwritten with `0x00` zero bytes across their entire file size and synced to disk before unlinking. **Zero plaintext IP addresses or PeerIds are ever stored on disk** (`eviction_index.bin` stores only keyed HMAC tags).

### 4.7 Public Tracker Abuse Reporting & Admin Takedown Workflow (`parvault report-abuse`, `parvault-seed admin`, `ADR-19`)

In `--public` (\"Public Commons / Public Tracker\") swarms, storage nodes store encrypted ciphertext shards without knowing what data they contain. To prevent griefing and vigilantism:
1. **Anti-Griefing Governance:** Random public peers cannot issue eviction orders. Public storage nodes reject eviction broadcasts from arbitrary peers (`accepted: false`). They accept eviction orders **only** when signed by pinned/configured `eviction_authorities` (specifically the Public Tracker Operator's `tracker_admin.seed` authority, advertised in tracker discovery responses, or local node identity).
2. **Reporter Burden-of-Proof:** Because the network is zero-knowledge, the burden of proof rests entirely on the reporting entity. If illegal content is being publicly shared via ParVault, the distributor had to publish a `(FileManifest, MasterKey)` bundle so recipients could download and view it. The reporter submits this bundle to the Public Tracker Operator.
3. **Cryptographic Proof Pipeline:** The tracker verifies:
   - Sample shard leaf hashes match `stripe.shard_hashes` and `stripe.stripe_merkle_root` in the manifest.
   - Reed-Solomon reconstructs the stripe ciphertext in $GF(2^8)$.
   - `AES-256-GCM` authenticated decryption under the disclosed `MasterKey` passes 128-bit tag verification and computes `verified_plaintext_sha256`.
   - The verified plaintext buffer is immediately zeroized in memory (`zeroize::Zeroize`) so illegal content bytes never touch disk or persist in RAM.
   - **Anti-Framing Guarantee:** Malicious griefers cannot frame innocent users' private vaults because guessing or forging a 256-bit `MasterKey` results in `AES-256-GCM` tag validation failure ($2^{-128}$).
4. **Human-in-the-Loop Queue:** Successful verification places the report into `PendingAdminReview` at `<data_dir>/admin_takedown_queue.bin` (`0600`). Shards are **NEVER auto-evicted** without human review.

#### Submitting a Verifiable Abuse Report (`parvault report-abuse`)
```bash
parvault report-abuse \
  --tracker /ip4/203.0.113.10/tcp/4002/p2p/12D3KooWPublicTracker... \
  --manifest ./leaked_contraband.manifest.bin \
  --disclosed-key-hex 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --allegation "CSAM / DMCA takedown violation" \
  --contact "abuse-response@example.org" \
  --bad-actor-ip 198.51.100.77
```

#### Public Tracker Operator Takedown Administration (`parvault-seed admin`)
```bash
# 1. View the tracker's persistent admin authority public key:
parvault-seed admin show-authority --data-dir /mnt/nas/parvault-seed

# 2. List queued abuse reports awaiting review:
parvault-seed admin list-takedowns --data-dir /mnt/nas/parvault-seed

# 3. Inspect cryptographic burden-of-proof details for a report:
parvault-seed admin inspect-takedown \
  --report-id 7c9f8e12... \
  --data-dir /mnt/nas/parvault-seed

# 4. Reject a baseless or malicious report:
parvault-seed admin reject-takedown \
  --report-id 7c9f8e12... \
  --reason "Baseless allegation / non-violating content" \
  --data-dir /mnt/nas/parvault-seed

# 5. Approve takedown, shred local shards with 0x00, sign eviction order, and broadcast to swarm:
parvault-seed admin approve-takedown \
  --report-id 7c9f8e12... \
  --note "Confirmed illegal contraband; purging mesh-wide" \
  --data-dir /mnt/nas/parvault-seed \
  --propagate

# 6. Lane 2: Unilateral Emergency Law-Enforcement / Warrant Eviction (Public Trackers ONLY):
# If contraband is private (no leaked keys) but law enforcement presents a warrant citing an IP/subnet:
parvault-seed admin emergency-evict \
  --data-dir /mnt/nas/parvault-seed \
  --ip 203.0.113.66 \
  --warrant-ref "US-DOJ-WARRANT-2026-8812" \
  --export-order ./order_203_0_113_66.json \
  --propagate

# 7. Federated Tracker Council Co-Signing (M-of-N Quorum):
# A second independent council operator reviews and co-signs to reach M-of-N majority quorum:
parvault-seed admin cosign-eviction \
  --data-dir /mnt/nas/parvault-seed-operator-2 \
  --order-file ./order_203_0_113_66.json \
  --propagate
```

> [!IMPORTANT]
> **Strict Mode Isolation & M-of-N Quorum Invariants:**
> - In `TrustPoolMode::PrivateRing` (family or homelab rings), nodes **unconditionally ignore and reject** external `tracker_admin_pubkey` eviction orders. Unilateral tracker admin actions can never affect private rings.
> - In `TrustPoolMode::PublicCommons` / `Hybrid` (`--public`), nodes trust their pinned `tracker_admin_pubkey` council for swarm-wide protection while rejecting arbitrary non-admin public peers.
> - If multiple tracker council operators exist ($N \ge 2$), a single rogue tracker operator cannot unilaterally wipe shards without reaching $M$-of-$N$ threshold co-signatures (`default_tracker_quorum_threshold(N) = \lfloor N/2 \rfloor + 1`).

---

## 5. Configuration File (`config.toml`), Bandwidth Rate Limits, Free Disk Reserve & Bit-Rot Scrubbing

You can pass `-c config.toml` to `parvault` to customize paths, quotas, bandwidth ceilings, minimum free disk reserves, and eviction authorities:

```toml
# Example config.toml for parvault
data_dir = ".parvault-data"
listen_tcp = "/ip4/0.0.0.0/tcp/4001"
enable_quic = false
listen_quic = "/ip4/0.0.0.0/udp/4001/quic-v1"

# Hardware Profile (router-soc: 1 MiB, homelab-nas: 4 MiB, desktop: 16 MiB)
hardware_profile = "desktop"
stripe_size_bytes = 16777216
default_tier = "Consumer"

# Zero-IP Home LAN Discovery
lan_discovery_enabled = true
lan_discovery_port = 4009

# Eviction Authorities (trusted Ed25519 pubkeys for SignedBadActorEvictionOrder)
eviction_authorities = [
  "8f3a9c12e4b07d11c3a8...",
]
# Minimum M-of-N threshold quorum required for federated tracker council eviction (default: strict majority)
# tracker_eviction_quorum = 2

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
