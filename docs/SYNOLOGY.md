# ParVault on a Synology NAS (Container Manager, no SSH)

Every `v0.5.x` image is a **dev build** (B-131, L-113): reproducible, and signed with the ParVault dev/test key, not a release key. The DS923+ (AMD Ryzen R1600) is x86_64, so use `parvault-image-amd64-dev.tar`. `parvault-image-arm64-dev.tar` is for ARM NAS models and has not been tested on one.

The image has no OS and no shell: just the five static binaries, user `65532:65532`, data in `/var/lib/parvault`, and a healthcheck through `parvault gateway health`. Everything below is done in the DSM web UI (File Station and Container Manager), so SSH can stay off. The SSH commands are in the [appendix](#appendix-the-same-over-ssh). For any other Docker host, or a NAS used over SSH, see [DOCKER.md](DOCKER.md).

Three compose files ship, one per role:

| File | Use it on | What it does |
|---|---|---|
| [`deploy/synology/compose.yaml`](../deploy/synology/compose.yaml) | the first node | one service: the daemon starts a new ring on an empty volume (`up --init-if-absent`), then runs; issues invites |
| [`deploy/synology/join.compose.yaml`](../deploy/synology/join.compose.yaml) | every other NAS | prints its key (`identity`), installs a token (`install-chain`), runs the daemon |
| [`deploy/docker/compose.yaml`](../deploy/docker/compose.yaml) | a Linux or Docker Desktop host | the same join, with `--peers` and a non-default `--listen` port |

`scripts/test_compose_projects.sh` runs all three on a real Docker host with the real image: first start, rebuild, join, a store and byte-identical restore, the invite described in step 4, and the encrypted ring backup and restore of step 5 in the documented order.

## 1. Verify the download

On a machine with OpenSSH 8.1 or later (Linux, macOS and Windows 10+ have it):

```sh
# in a directory with SHA256SUMS, SHA256SUMS.sig and parvault-image-amd64-dev.tar
curl -fsSLO https://raw.githubusercontent.com/Zbot21/parvault/main/security/dev-allowed-signers
ssh-keygen -Y verify -f dev-allowed-signers -I parvault-dev -n parvault-dev-build \
  -s SHA256SUMS.sig < SHA256SUMS
head -n1 SHA256SUMS            # must be: # parvault <the tag you downloaded> dev
grep ' parvault-image-amd64-dev.tar$' SHA256SUMS | sha256sum -c -
```

The signature must say `Good "parvault-dev-build" signature for parvault-dev` with key `SHA256:w3YrtCVqvG0hUxHHdnrlxuxg/X8LkeuUaZudDswGQ+A`. More detail: [REPRODUCIBLE_BUILDS.md](REPRODUCIBLE_BUILDS.md).

## 2. Import the image

1. In File Station, copy `parvault-image-amd64-dev.tar` **into the `docker` shared folder**. Imported from another share, Container Manager has dropped the tar's tag and tagged the image with a date instead (seen: `20251115`).
2. Container Manager > Image > Add > Import from file, and pick the tar in `docker`.
3. Check the image list. The tag should be `parvault:<version>-dev`. Whatever tag it shows is the one to put in every `image:` line of your project.
4. Check the image ID. Container Manager shows the image's config digest. It is different for every release: each release's notes list it (taken from the build whose image tar is the image line of that release's signed `SHA256SUMS`), and it must match the notes of the release you downloaded.

Docker with the containerd image store (recent Docker Desktop, for example) shows the manifest digest instead; the release notes list that too. Both name the same image.

Earlier releases, for reference only (not the ID of a newer image):

| Release | amd64 config digest | amd64 manifest digest |
|---|---|---|
| `v0.5.3` | `sha256:6404dc144b371cbd39ab67a2a92279a40569bc4dddbe08df84149f0988a496ad` | `e3254abb2889...` |

Every service in the shipped files has `pull_policy: never`. Without it, a mistyped or missing tag makes Container Manager try to pull `parvault` from Docker Hub and fail with "pull access denied". With it, the error says the image is missing.

## 3. Start a ring (the first node)

1. In File Station, make a folder, for example `docker/parvault`, and copy `deploy/synology/compose.yaml` into it.
2. Set every `image:` line in it to the tag from step 2.
3. Container Manager > **Project** > Create. Choose the folder, use the existing `compose.yaml`, and build.

The project has one service, the daemon `parvault`. On the first build the volume is empty, so the daemon creates the ring before it starts (`up --init-if-absent`): its Log tab says `Started a new ring. Genesis public key: <64 hex>`. It turns healthy within about a minute (about 5 s on the test host). On every later start it finds its ring and just runs. Nothing is left behind as an exited container.

`--init-if-absent` never starts a second ring over data it does not know: a volume that holds anything but its own ring (and `lost+found`, `@eaDir`) is refused with `reject.init_volume_not_empty` and left as it is. One data dir serves one process: a second daemon or a `wot` command on the same volume while the daemon runs is refused (`reject.datadir_locked`).

## 4. Add a node

Each new node needs a token from the first node, issued for the new node's key.

**On the new NAS.** Import the image (step 2), then make a project from `deploy/synology/join.compose.yaml` the same way, with every `image:` set. Build it.

- `identity` prints the node's key. Open its **Log** tab and copy the value of `Ed25519 Public Key (hex)`. Use the Log tab: the Container Manager terminal does not let you copy text.
- `install-chain` fails, because the token is still the placeholder (`Error: Invalid character 'P' at position 0`). The build reports that failure and the daemon stays in Created. That is expected at this point.

**On the first node.** Stop the project. In `compose.yaml`, uncomment the `invite-node2` example at the end and put the new node's key in place of `NODE_KEY_64_HEX` (keep the quotes). Build. Open the **Log** tab of `invite-node2` and copy the token: one long hex line that starts with the ring's genesis key. For more nodes, copy the service under another name (`invite-node3`, ...) with each node's key.

**On the new NAS.** Stop the project, replace `PASTE_TOKEN_HERE` in its `compose.yaml` with the token, and build. `install-chain` logs `Joined the ring <genesis key>. Installed chain for <key> (this node's key)`, then the daemon starts and turns healthy. On later starts `install-chain` installs the same token again and exits 0.

Once the node has joined, you can delete its `invite-*` service on the first node. Left in place it prints a token on every start, which is harmless: a token admits only the key it names.

**Why the invite waits for a healthy daemon.** An invite reads the ring's genesis, which the daemon writes on the very first start. Started beside it on a fresh volume, an invite can run first and fail with `this node does not hold a ring genesis`. So the example invite has `depends_on: parvault: condition: service_healthy`: the daemon turns healthy only once the ring exists. The test script covers it.

**A node on another Docker host** (a Linux server, a desktop with Docker): follow [DOCKER.md](DOCKER.md), or use `deploy/docker/compose.yaml` with `docker compose up -d` in the same three steps. Read the key with `docker compose logs identity`. Set `--peers` to the first node's LAN address and port (`<NAS IP>:4001`); LAN discovery does not reach into Docker Desktop or WSL2. Its example `--listen` port is TCP 4011, for a host where 4001 is taken. It uses the image's own healthcheck. Do not add `--health-cmd` or a shell-form `healthcheck:`: the image has no shell, so those always fail.

## 5. What you will see in Container Manager

- **Healthy means in a ring.** The daemon refuses to start on a node that is not in a ring, and the healthcheck asks the running daemon over its gateway socket. Healthy does not say how many peers are connected (B-148). For peers, read the daemon's Log tab: `Kademlia routing table updated peer=...` once a peer is admitted. Before that, `peer not added to the Kademlia routing table code="reject.kad_peer_not_admitted"` is normal: a peer is admitted after its first handshake, which comes with its first request.
- **0 network use.** With `network_mode: host` there is no per-container interface, so Container Manager shows 0 network use for ParVault even while it stores and serves shards (B-148). Host networking is needed: LAN discovery (UDP 4009 broadcast) and the mesh port (TCP 4001) must be on the NAS's own address, not behind a bridge's NAT.
- **No volume in the UI.** Data lives in the named volume `parvault-data`, which starts owned by `65532:65532`. Container Manager does not list named volumes, but it is there and survives rebuilds.
- **Deleting a project can delete its data.** Deleting a project in Container Manager can remove its volume, and with it the node's keys and ring membership. To change a project, stop it, edit `compose.yaml`, and build. Never delete the first node's project: its volume holds the ring genesis, which every invite needs.

**Encrypted ring backup (UI only).** `parvault-data` holds the node's keys and, on the first node, the ring genesis secret, which every invite needs. Without a copy, losing it ends the ring. `parvault ring backup` writes one encrypted file of what makes this node itself: the ring genesis and its pin, the node key, its chains, the council files, the PQ keys, `config.toml`, each vault's catalog version floor and the vault master key. It leaves out the gateway token key (a restore would revive every token ever issued), the TLS key, the per-vault keys (your seed phrase recovers them), and the quota, audit and shard state. The file is Argon2id-protected (64 MiB, 3 passes) with a passphrase of at least 20 characters and XChaCha20-Poly1305; without the passphrase it is useless. Make one once, and again after any change of ring.

*The passphrase (once per NAS).* The backup reads the passphrase from a file owned by the container user with mode `0600`, which File Station cannot make. A one-shot `busybox` project installs it into its own volume, `parvault-secrets`. Pull `busybox` once by digest: in Container Manager > Registry, search `busybox`, download the tag `1.37.0`, then check in Image that its **RepoDigest** is the one pinned below (the multi-arch index digest `sha256:a7dbc319...`), not the image ID.

1. Make a shared folder `parvault-secrets-in` that only your account can read. Put a text file `passphrase.txt` in it holding the passphrase (at least 20 characters; one trailing newline is ignored).
2. Make a project (folder `docker/parvault-passphrase`) from this `compose.yaml` and build it. It prints `installed`. Then delete `passphrase.txt` and keep the passphrase somewhere other than this NAS. Stop the project, but **do not delete it**: deleting it can delete `parvault-secrets`.

```yaml
name: parvault-passphrase
services:
  passphrase:
    image: busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec   # busybox 1.37.0
    pull_policy: never
    network_mode: none
    restart: "no"
    read_only: true
    cap_drop: [ALL]
    cap_add: [CHOWN, DAC_OVERRIDE]   # to read your file and hand the copy to the container user
    security_opt: ["no-new-privileges:true"]
    command: ["sh", "-c", "umask 077 && cp /in/passphrase.txt /secrets/passphrase && chmod 0600 /secrets/passphrase && chown 65532:65532 /secrets/passphrase && echo installed"]
    volumes:
      - parvault-secrets:/secrets
      - /volume1/parvault-secrets-in:/in:ro
volumes:
  parvault-secrets:
    name: parvault-secrets
```

*Backup.*

1. Make a shared folder `parvault-backup` for the backup files. Give only your own account Read/Write and everyone else No access.
2. **Stop the `parvault` project.** The backup takes the data-dir lock, which the running daemon holds (`reject.datadir_locked`).
3. Make a project (folder `docker/parvault-ring-backup`) from this `compose.yaml`, with `image:` set, and build it:

```yaml
name: parvault-ring-backup
services:
  ring-backup:
    image: parvault:0.5.6-dev
    pull_policy: never
    user: "65532:65532"
    network_mode: none
    restart: "no"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    command: ["--data-dir", "/var/lib/parvault", "ring", "backup", "--out", "/backup", "--passphrase-file", "/secrets/passphrase"]
    volumes:
      - parvault-data:/var/lib/parvault
      - parvault-secrets:/secrets:ro
      - /volume1/parvault-backup:/backup
volumes:
  parvault-data:
    external: true
    name: parvault-data
  parvault-secrets:
    external: true
    name: parvault-secrets
```

Its Log tab names the file (`parvault-ring-backup-<node>-<time>.pvbak`), the ring id and the node id; note the ring id. Delete the `parvault-ring-backup` project (its volumes are `external`, so no data goes) and **start the `parvault` project again**. Not yet tested on DSM: whether the container user (65532) may write into a share and read a `0600` file there (H-4). If the backup logs `Permission denied` for `/backup`, report it rather than loosening the share for everyone.

*Restore, on a new NAS or a new volume.* A restore **moves** the node: the old one must be stopped and never started again, because two live nodes with one identity break the ring's one-writer rule. The restore runs before the daemon's very first start, because that start would otherwise create a new ring on the empty volume (`reject.backup_target_not_empty` afterwards).

1. Import the image and install the same passphrase on this NAS (above). Copy the `.pvbak` file into its `parvault-backup` share.
2. In `deploy/synology/compose.yaml`, before the first build, uncomment the `ring-restore` service, the `depends_on` block in `parvault` and `parvault-secrets` under `volumes`. Put the file name in place of `BUNDLE_FILE_NAME` and the ring id in place of `RING_ID_64_HEX`.
3. Build. `ring-restore` logs `Restored node ... of ring ...` and exits 0; then the daemon starts in that ring and turns healthy. A wrong passphrase, a damaged or foreign file, or a used volume is refused with a `reject.backup_*` code and changes nothing.
4. Stop the project, comment the three blocks again, and build.

*Residual risks.* The file and its passphrase leaked together; a compromised running NAS; rolling back to an older backup; restoring and then starting the old node anyway (a clone); the file's header names the ring and node ids in clear; tar exports made with the `v0.5.5` guide are not encrypted, so delete them once you have an encrypted backup. If you also back up the share with Hyper Backup, encrypt that task (Hyper Backup > Backup Settings > Enable client-side encryption).

What every project also does:

- Runs each service as `65532:65532`, with `cap_drop: [ALL]`, `no-new-privileges`, a read-only root, and tmpfs for `/tmp` (and `/run/parvault` for the daemon). The one-shot services have `network_mode: none` and `restart: "no"`.
- The Synology projects turn on the token-gated status page, bound to loopback (`--status-http 127.0.0.1:4080` in `command:`); the image alone has none. To use it from the LAN, change `127.0.0.1` to the NAS's LAN address. With host networking that is the NAS's own interface, so never use `0.0.0.0` or a WAN-facing address.

**Older versions (UI only).** When the daemon backs up a folder (`up --folder`), it keeps older versions of it (by default the last 3, plus one a day for 3 days). To get one back, make a shared folder `parvault-restore`, then in `compose.yaml` uncomment the `restore-version` service, set `VERSION_NUMBER` to a retained version, and build. The service runs once and writes that version's files into `parvault-restore`; the daemon keeps running. Comment the service again afterwards. A version that is no longer retained is refused (`reject.version_not_retained`) and its error lists the retained versions.

## 6. Firewall

If the DSM firewall is on (Control Panel > Security > Firewall), allow from the LAN:

- **TCP 4001**: the mesh port (or the `--listen` port you set).
- **UDP 4009**: LAN discovery.
- TCP 4080 only if you moved the status page off loopback.

On a Docker host with `deploy/docker/compose.yaml`, open its `--listen` port (TCP 4011 in the example).

## 7. Upgrading

1. Verify the new tar (step 1), copy it into the `docker` share, import it, and check its tag and image ID (step 2).
2. Stop the project, change **every** `image:` line in `compose.yaml` to the new tag, and build (Project > Action > Build).

The volume is kept: the daemon finds its ring (`install-chain` on a joined node runs again and exits 0). Do not delete the project to upgrade.

## Appendix: the same over SSH

Optional; [DOCKER.md](DOCKER.md) is the full shell guide. Over SSH on the NAS, the first run can be done with `docker run` on the same volume (it starts owned by `65532:65532`). After that, use `deploy/synology/compose.yaml` on that node, whether it started the ring or joined one: `up --init-if-absent` finds the ring and the daemon starts. Do not use `join.compose.yaml` there: its placeholder token would hold the daemon back.

```sh
IMG=parvault:0.5.6-dev   # the tag you imported
sudo docker load -i parvault-image-amd64-dev.tar
# This NAS starts a new ring (the first node):
sudo docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:mode=1777 -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault wot init
# On the first node, invite a node by its 64-hex key:
sudo docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:mode=1777 -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault wot invite --peer <KEY>
# Or this NAS joins a ring: print its key, get a token from the first node, install it.
sudo docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:mode=1777 -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault identity
sudo docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:mode=1777 -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault wot install-chain --token <TOKEN>
```
