# ParVault on a Synology NAS (Container Manager, no SSH)

Every `v0.5.x` image is a **dev build** (B-131, L-113): reproducible, and signed with the ParVault dev/test key, not a release key. The DS923+ (AMD Ryzen R1600) is x86_64, so use `parvault-image-amd64-dev.tar`. `parvault-image-arm64-dev.tar` is for ARM NAS models and has not been tested on one.

The image has no OS and no shell: just the five static binaries, user `65532:65532`, data in `/var/lib/parvault`, and a healthcheck through `parvault gateway health`. Everything below is done in the DSM web UI (File Station and Container Manager), so SSH can stay off. The SSH commands are in the [appendix](#appendix-the-same-over-ssh). For any other Docker host, or a NAS used over SSH, see [DOCKER.md](DOCKER.md).

Three compose files ship, one per role:

| File | Use it on | What it does |
|---|---|---|
| [`deploy/synology/compose.yaml`](../deploy/synology/compose.yaml) | the first node | starts a new ring (`init`), runs the daemon, issues invites |
| [`deploy/synology/join.compose.yaml`](../deploy/synology/join.compose.yaml) | every other NAS | prints its key (`identity`), installs a token (`install-chain`), runs the daemon |
| [`deploy/docker/compose.yaml`](../deploy/docker/compose.yaml) | a Linux or Docker Desktop host | the same join, with `--peers` and a non-default `--listen` port |

`scripts/test_compose_projects.sh` runs all three on a real Docker host with the real image: first start, rebuild, join, a store and byte-identical restore, and the invite race described in step 4.

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
4. Check the image ID. Container Manager shows the image's config digest, which must match:

| Release | amd64 image ID |
|---|---|
| `v0.5.3` | `sha256:6404dc144b371cbd39ab67a2a92279a40569bc4dddbe08df84149f0988a496ad` |

Docker with the containerd image store (recent Docker Desktop, for example) shows the manifest digest instead: `e3254abb2889...` for `v0.5.3` amd64. Both name the same image.

Every service in the shipped files has `pull_policy: never`. Without it, a mistyped or missing tag makes Container Manager try to pull `parvault` from Docker Hub and fail with "pull access denied". With it, the error says the image is missing.

## 3. Start a ring (the first node)

1. In File Station, make a folder, for example `docker/parvault`, and copy `deploy/synology/compose.yaml` into it.
2. Set every `image:` line in it to the tag from step 2.
3. Container Manager > **Project** > Create. Do not use the Container wizard: it cannot run the one-shot service beside the daemon on one volume. Choose the folder, use the existing `compose.yaml`, and build.

On the first build, `init` creates the ring and exits 0. Its Log tab says `Started a new ring. Genesis public key: <64 hex>`. The daemon, `parvault`, turns healthy within about a minute (about 5 s on the test host).

On every later start, `init` runs again, logs `Error: Invalid key or hex encoding: this node is already in the ring <key>` (versions after 0.5.3 drop the `Invalid key or hex encoding:` prefix) and exits 1. That is harmless: it refuses before writing anything. Container Manager shows it as stopped.

## 4. Add a node

Each new node needs a token from the first node, issued for the new node's key.

**On the new NAS.** Import the image (step 2), then make a project from `deploy/synology/join.compose.yaml` the same way, with every `image:` set. Build it.

- `identity` prints the node's key. Open its **Log** tab and copy the value of `Ed25519 Public Key (hex)`. Use the Log tab: the Container Manager terminal does not let you copy text.
- `install-chain` fails, because the token is still the placeholder (`Error: Invalid character 'P' at position 0`). The build reports that failure and the daemon stays in Created. That is expected at this point.

**On the first node.** Stop the project. In `compose.yaml`, uncomment the `invite-node2` example at the end and put the new node's key in place of `NODE_KEY_64_HEX` (keep the quotes). Build. Open the **Log** tab of `invite-node2` and copy the token: one long hex line that starts with the ring's genesis key. For more nodes, copy the service under another name (`invite-node3`, ...) with each node's key.

**On the new NAS.** Stop the project, replace `PASTE_TOKEN_HERE` in its `compose.yaml` with the token, and build. `install-chain` logs `Joined the ring <genesis key>. Installed chain for <key> (this node's key)`, then the daemon starts and turns healthy. On later starts `install-chain` installs the same token again and exits 0.

Once the node has joined, you can delete its `invite-*` service on the first node. Left in place it prints a token on every start, which is harmless: a token admits only the key it names.

**Why the invite waits for a healthy daemon.** An invite reads the ring's genesis, which `init` writes on the very first start. Started beside `init` on a fresh volume, an invite can run first and fail with `this node does not hold a ring genesis`. So the example invite has `depends_on: parvault: condition: service_healthy`: the daemon only runs, and so only turns healthy, once the ring exists. It does not use `init` with `service_completed_successfully`, because `init` exits 1 on every later start and would block those starts. Both the race and the fix are covered by the test script.

**A node on another Docker host** (a Linux server, a desktop with Docker): follow [DOCKER.md](DOCKER.md), or use `deploy/docker/compose.yaml` with `docker compose up -d` in the same three steps. Read the key with `docker compose logs identity`. Set `--peers` to the first node's LAN address and port (`<NAS IP>:4001`); LAN discovery does not reach into Docker Desktop or WSL2. Its example `--listen` port is TCP 4011, for a host where 4001 is taken. It uses the image's own healthcheck. Do not add `--health-cmd` or a shell-form `healthcheck:`: the image has no shell, so those always fail.

## 5. What you will see in Container Manager

- **Healthy means in a ring.** The daemon refuses to start on a node that is not in a ring, and the healthcheck asks the running daemon over its gateway socket. Healthy does not say how many peers are connected (B-148). For peers, read the daemon's Log tab: `Kademlia routing table updated peer=...` once a peer is admitted. Before that, `peer not added to the Kademlia routing table code="reject.kad_peer_not_admitted"` is normal: a peer is admitted after its first handshake, which comes with its first request.
- **0 network use.** With `network_mode: host` there is no per-container interface, so Container Manager shows 0 network use for ParVault even while it stores and serves shards (B-148). Host networking is needed: LAN discovery (UDP 4009 broadcast) and the mesh port (TCP 4001) must be on the NAS's own address, not behind a bridge's NAT.
- **No volume in the UI.** Data lives in the named volume `parvault-data`, which starts owned by `65532:65532`. Container Manager does not list named volumes, but it is there and survives rebuilds.
- **Deleting a project can delete its data.** Deleting a project in Container Manager can remove its volume, and with it the node's keys and ring membership. To change a project, stop it, edit `compose.yaml`, and build. Never delete the first node's project: its volume holds the ring genesis, which every invite needs.

**Back up the first node's volume (UI only).** `parvault-data` holds the node's keys and, on the first node, the ring genesis secret, which every invite needs. Without a copy, losing it ends the ring. Make one once, and again after any change of ring. The copy is one tar file; a restore is a second project.

Both projects use `busybox`, because the ParVault image has no shell and no `tar`. It is a one-time manual pull, by digest so the project never fetches anything else: in Container Manager > Registry, search `busybox`, download the tag `1.37.0`, then check in Image that it is the one pinned below. Compare the image's **RepoDigest** (the multi-arch index digest `sha256:a7dbc319...`) in the image details, not the image ID: on a classic-store Docker the image ID is the config digest and differs. If you pull a different version, put that image's digest in both `image:` lines. `pull_policy: never` stops Compose from fetching on its own.

*Export*

1. Control Panel > Shared Folder > Create a folder, for example `parvault-backup`. Give only your own account Read/Write and everyone else No access; leave "Hide this shared folder in My Network Places" on. Do not enable a recycle bin or a share to other users.
2. **Stop the `parvault` project** (Project > Action > Stop), so the store database is not being written while it is copied.
3. Make a second project (folder `docker/parvault-export`) from this `compose.yaml`, and build it:

```yaml
name: parvault-export
services:
  export:
    image: busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec   # busybox 1.37.0
    pull_policy: never
    network_mode: none
    restart: "no"
    read_only: true
    cap_drop: [ALL]
    cap_add: [DAC_OVERRIDE]    # to read files owned by 65532
    security_opt: ["no-new-privileges:true"]
    command: ["sh", "-c", "umask 077 && tar -cf /backup/parvault-data.tar -C /data . && echo exported"]
    volumes:
      - parvault-data:/data:ro
      - /volume1/parvault-backup:/backup
volumes:
  parvault-data:
    external: true
    name: parvault-data
```

It prints `exported` and exits 0. Set the share's path in place of `/volume1/parvault-backup` if the share is on another volume. Then stop and delete the `parvault-export` project, which touches no data (its volume is `external`), and **start the `parvault` project again**.

The tar keeps the files' owner (65532) and modes. The tar itself is owned by `root` with mode `0600` (from `umask 077`). The share's own permissions decide who can reach it: on DSM, an administrator can open the share in File Station and download `parvault-data.tar`, and a share permission may not be enough for a non-admin to read a root-owned `0600` file (we have not tested this on DSM). If you need another account to read it, copy it out as an administrator instead of loosening the file's mode.

*Restore (import).* This **replaces the volume's entire contents**: everything in `parvault-data` is deleted first, including anything not in the backup, and then the tar is extracted. Use it to bring back a lost or damaged node, never on a node that is working. The volume must exist (the project declares it `external`): if it is gone, build and start the `parvault` project once to create it, then continue.

1. **Stop the `parvault` project.**
2. Make a project (folder `docker/parvault-import`) from this `compose.yaml`, and build it. It first checks that `/backup/parvault-data.tar` is a readable tar holding the node's identity (`node_identity.seed`), then empties the volume and extracts the tar into it, keeping owners (65532) and modes. If the import prints nothing or an error (no tar, a wrong share path, or a tar that is not a ParVault export), the volume was not touched:

```yaml
name: parvault-import
services:
  import:
    image: busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec   # busybox 1.37.0
    pull_policy: never
    network_mode: none
    restart: "no"
    read_only: true
    cap_drop: [ALL]
    cap_add: [CHOWN, FOWNER, DAC_OVERRIDE]   # to delete the old files, keep owners and modes, and write into the volume
    security_opt: ["no-new-privileges:true"]
    command: ["sh", "-c", "tar -tf /backup/parvault-data.tar >/dev/null && tar -tf /backup/parvault-data.tar | grep -q 'node_identity[.]seed$' && find /data -mindepth 1 -delete && tar -xpf /backup/parvault-data.tar -C /data && echo imported"]
    volumes:
      - parvault-data:/data
      - /volume1/parvault-backup:/backup:ro
volumes:
  parvault-data:
    external: true
    name: parvault-data
```

3. It prints `imported` and exits 0. **Stop and delete the `parvault-import` project** (its volume is `external`, so the data stays).
4. **Start the `parvault` project.** It turns healthy with the same ring; `init` exits 1 (`already in the ring`), as on any later start.

**Keep it private: anyone with that copy can admit nodes to your ring.** Do not put it in a shared folder others can read, a cloud sync folder, or a backup job that uploads it unencrypted. If you also back up the share with Hyper Backup, encrypt that task (Hyper Backup > Backup Settings > Enable client-side encryption). Backing up the Docker volume path directly (`/volume1/@docker/volumes/parvault-data`) in Hyper Backup is not documented by Synology, so this guide does not rely on it.

What every project also does:

- Runs each service as `65532:65532`, with `cap_drop: [ALL]`, `no-new-privileges`, a read-only root, and tmpfs for `/tmp` (and `/run/parvault` for the daemon). The one-shot services have `network_mode: none` and `restart: "no"`.
- The Synology projects turn on the token-gated status page, bound to loopback (`--status-http 127.0.0.1:4080` in `command:`); the image alone has none. To use it from the LAN, change `127.0.0.1` to the NAS's LAN address. With host networking that is the NAS's own interface, so never use `0.0.0.0` or a WAN-facing address.

## 6. Firewall

If the DSM firewall is on (Control Panel > Security > Firewall), allow from the LAN:

- **TCP 4001**: the mesh port (or the `--listen` port you set).
- **UDP 4009**: LAN discovery.
- TCP 4080 only if you moved the status page off loopback.

On a Docker host with `deploy/docker/compose.yaml`, open its `--listen` port (TCP 4011 in the example).

## 7. Upgrading

1. Verify the new tar (step 1), copy it into the `docker` share, import it, and check its tag and image ID (step 2).
2. Stop the project, change **every** `image:` line in `compose.yaml` to the new tag, and build (Project > Action > Build).

The volume is kept. `init` or `install-chain` runs again and exits as on any later start. Do not delete the project to upgrade.

## Appendix: the same over SSH

Optional; [DOCKER.md](DOCKER.md) is the full shell guide. Over SSH on the NAS, the first run can be done with `docker run` on the same volume (it starts owned by `65532:65532`). After that, use `deploy/synology/compose.yaml` on that node, whether it started the ring or joined one: its `init` exits 1 (`already in the ring`) and the daemon starts. Do not use `join.compose.yaml` there: its placeholder token would hold the daemon back.

```sh
IMG=parvault:0.5.3-dev   # the tag you imported
sudo docker load -i parvault-image-amd64-dev.tar
# This NAS starts a new ring (the first node):
sudo docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:mode=1777 -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault wot init
# On the first node, invite a node by its 64-hex key:
sudo docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:mode=1777 -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault wot invite --peer <KEY>
# Or this NAS joins a ring: print its key, get a token from the first node, install it.
sudo docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:mode=1777 -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault identity
sudo docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:mode=1777 -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault wot install-chain --token <TOKEN>
```
