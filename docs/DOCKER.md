# ParVault on a Docker host (shell or SSH)

For any Linux host with Docker, used from a local shell or over SSH: a server, a desktop, a NAS with SSH on. For a Synology NAS with SSH off, use the Container Manager guide, [SYNOLOGY.md](SYNOLOGY.md), instead: same image, UI only.

The image `parvault:<version>-dev` is a **dev build** (B-131, L-113), signed with the ParVault dev/test key. It has no OS and no shell: five static binaries, user `65532:65532`, data in `/var/lib/parvault`, and a built-in healthcheck (`parvault gateway health`, exec form).

`scripts/test_docker_doc.sh` runs the command blocks of this page verbatim on a real Docker host, with its own names and ports; `scripts/test_compose_projects.sh` runs the compose file. During the verbatim `docker load`, the shared tag `parvault:<version>-dev` briefly (about 1 s, under the tests' image lock) points at the test build, then is put back; a running container is unaffected, and only a compose recreate in that window would pick up the test build.

Every block below uses these shell variables. Set them first, in the shell you run the blocks from:

<!-- docker-doc: vars -->
```sh
IMG=parvault:0.5.4-dev        # the tag `docker load` prints
VOL=parvault-data             # this node's data volume
NAME=parvault                 # this node's daemon container
PORT=4001                     # this node's mesh port (TCP); e.g. 4011 if 4001 is taken
PEERS=192.168.1.10:4001       # joining nodes: a ring member's address and port
CHECK=$HOME/pv-check          # a scratch folder for the round trip in step 5
BACKUP=$HOME/pv-backup        # a private folder for the secrets backup in step 7
```

## 1. Verify and load the image

In a directory with `SHA256SUMS`, `SHA256SUMS.sig` and `parvault-image-amd64-dev.tar` (`-arm64-` on ARM), with OpenSSH 8.1 or later:

<!-- docker-doc: verify -->
```sh
curl -fsSLO https://raw.githubusercontent.com/Zbot21/parvault/main/security/dev-allowed-signers
ssh-keygen -Y verify -f dev-allowed-signers -I parvault-dev -n parvault-dev-build -s SHA256SUMS.sig < SHA256SUMS
head -n1 SHA256SUMS
grep ' parvault-image-amd64-dev.tar$' SHA256SUMS | sha256sum -c -
```

The signature must say `Good "parvault-dev-build" signature for parvault-dev` with key `SHA256:w3YrtCVqvG0hUxHHdnrlxuxg/X8LkeuUaZudDswGQ+A`, and the first line of `SHA256SUMS` must name the tag you downloaded. More detail: [REPRODUCIBLE_BUILDS.md](REPRODUCIBLE_BUILDS.md).

<!-- docker-doc: load -->
```sh
docker load -i parvault-image-amd64-dev.tar
docker image inspect -f '{{.Id}}' "$IMG"
```

The image ID depends on Docker's image store. For `v0.5.3` amd64 it is `sha256:6404dc144b371cbd39ab67a2a92279a40569bc4dddbe08df84149f0988a496ad` (the config digest, classic store, as on Synology) or `sha256:e3254abb288999dd08d9aff904570d357016d687d6b61eb1954b839fa4d323eb` (the manifest digest, containerd store, as on recent Docker Desktop). Any other ID is a different image.

## 2. Start a ring (the first node)

A node must be in a ring before its daemon starts. `wot init` creates one, once, on the node's volume; it needs no network. Then start the daemon:

<!-- docker-doc: ring -->
```sh
docker run --rm --network none --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp:mode=1777 -v "$VOL:/var/lib/parvault" "$IMG" --data-dir /var/lib/parvault wot init
docker run -d --name "$NAME" --restart unless-stopped --network host --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /run/parvault:uid=65532,gid=65532,mode=0700 --tmpfs /tmp:mode=1777 -v "$VOL:/var/lib/parvault" "$IMG" --data-dir /var/lib/parvault up --ipc-socket /run/parvault/parvault.sock --listen "/ip4/0.0.0.0/tcp/$PORT"
```

`wot init` prints `Started a new ring. Genesis public key: <64 hex>`. Run again, it refuses with `Error: Invalid key or hex encoding: this node is already in the ring <key>` (versions after 0.5.3 drop the `Invalid key or hex encoding:` prefix) and exit 1, and changes nothing. Wait for the daemon to turn healthy (usually seconds):

<!-- docker-doc: health -->
```sh
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ]; do sleep 3; done; echo "$NAME healthy"
```

Healthy means the daemon is running in a ring and answers on its gateway socket. It does not count peers: for those, `docker logs "$NAME"` shows `Kademlia routing table updated peer=...` once a peer is admitted (after its first handshake; `reject.kad_peer_not_admitted` before that is normal).

## 3. Join a ring (every other node)

On the new node, set the variables (with `PEERS` pointing at a ring member) and print its key:

<!-- docker-doc: identity -->
```sh
docker run --rm --network none --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp:mode=1777 -v "$VOL:/var/lib/parvault" "$IMG" --data-dir /var/lib/parvault identity
```

Copy the value of `Ed25519 Public Key (hex)`. On the ring's first node (the one that ran `wot init`; it holds the genesis key), issue a token for that key:

<!-- docker-doc: invite -->
```sh
KEY=PASTE_KEY_HERE           # the 64-hex key from identity
docker run --rm --network none --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp:mode=1777 -v "$VOL:/var/lib/parvault" "$IMG" --data-dir /var/lib/parvault wot invite --peer "$KEY"
```

It prints one long hex line, the token; it admits only that key. Back on the new node, install it and start the daemon with `--peers`:

<!-- docker-doc: join -->
```sh
TOKEN=PASTE_TOKEN_HERE       # the token from wot invite
docker run --rm --network none --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp:mode=1777 -v "$VOL:/var/lib/parvault" "$IMG" --data-dir /var/lib/parvault wot install-chain --token "$TOKEN"
docker run -d --name "$NAME" --restart unless-stopped --network host --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /run/parvault:uid=65532,gid=65532,mode=0700 --tmpfs /tmp:mode=1777 -v "$VOL:/var/lib/parvault" "$IMG" --data-dir /var/lib/parvault up --ipc-socket /run/parvault/parvault.sock --listen "/ip4/0.0.0.0/tcp/$PORT" --peers "$PEERS"
```

`install-chain` prints `Joined the ring <genesis key>. Installed chain for <key> (this node's key)`. Then wait for healthy as in step 2.

**With `docker compose` instead.** [`deploy/docker/compose.yaml`](../deploy/docker/compose.yaml) does the same join as three services: `identity`, `install-chain` (token placeholder `PASTE_TOKEN_HERE`) and the daemon. Set `image:`, `--listen` and `--peers` in it, then:

1. `docker compose up -d`. `install-chain` fails (no token yet), compose reports it, and the daemon waits. `docker compose logs identity` shows the key.
2. Issue a token for that key on the first node, as above.
3. Put the token in place of `PASTE_TOKEN_HERE` and run `docker compose up -d` again. On later starts `install-chain` installs the same token again and exits 0.

The project and volume are named `parvault` and `parvault-data`; rename both to run a second node on one host. To start a ring with compose, use [`deploy/synology/compose.yaml`](../deploy/synology/compose.yaml): it works on any Docker host (its `init` service exits 1 on later starts, harmlessly).

## 4. Networking and health

- **Host networking** (`--network host`, `network_mode: host`): the mesh port and LAN discovery must be on the host's own address. Behind a bridge's NAT, peers cannot reach the mesh port and discovery broadcasts do not leave the container. `docker stats` then shows no network use for ParVault; that is expected.
- **`--listen`** sets the mesh port. The default is TCP 4001; use another (`PORT=4011`) where 4001 is taken or for a second node on one host.
- **`--peers`** lists ring members (`host:port`, comma-separated) to dial at start. Use it whenever LAN discovery cannot reach them: another subnet, Docker Desktop, WSL2. On a plain Linux host on the ring's LAN, discovery (UDP 4009) finds them without it.
- **Health:** do not pass `--health-cmd` or a shell-form `healthcheck:`. The image has no shell, so those always fail; its built-in exec-form `HEALTHCHECK` already works.
- **Firewall:** allow, from the LAN, TCP on the `--listen` port and UDP 4009. With `ufw`:

<!-- docker-doc: firewall -->
```sh
sudo ufw allow "$PORT/tcp"
sudo ufw allow 4009/udp
```

- **Status page:** off unless asked for. Add `--status-http 127.0.0.1:4080` to `up` for a token-gated page on loopback. Never bind it to `0.0.0.0` or a WAN-facing address.

## 5. Check the ring: store and restore

From a node that has joined (on the first node, set `PEERS` to another member), store a small file with a one-off client on the node's own volume, restore it, and compare:

<!-- docker-doc: roundtrip -->
```sh
mkdir -p "$CHECK" && chmod 0777 "$CHECK" && head -c 65536 /dev/urandom > "$CHECK/sample.bin"
ROOT=$(docker run --rm --network host --user 65532:65532 --read-only --tmpfs /tmp:mode=1777 --cap-drop ALL --security-opt no-new-privileges:true -v "$VOL:/var/lib/parvault" -v "$CHECK:/io" "$IMG" --data-dir /var/lib/parvault file store --path /io/sample.bin --peers "127.0.0.1:$PORT,$PEERS" | sed -n 's/^File Merkle Root : //p'); echo "root $ROOT"
docker run --rm --network host --user 65532:65532 --read-only --tmpfs /tmp:mode=1777 --cap-drop ALL --security-opt no-new-privileges:true -v "$VOL:/var/lib/parvault" -v "$CHECK:/io" "$IMG" --data-dir /var/lib/parvault file restore --manifest-or-root "$ROOT" --output /io/restored.bin --peers "127.0.0.1:$PORT,$PEERS"
cmp "$CHECK/sample.bin" "$CHECK/restored.bin" && echo "byte-identical"
```

The restore ends with `=== ParVault Vault Restore Verified ===`, and both daemons' logs show `Kademlia routing table updated`.

## 6. Upgrading

Verify and load the new tar (step 1), set `IMG` to its tag, then replace the daemon container. The volume, and with it the node's keys and ring, is kept:

<!-- docker-doc: upgrade -->
```sh
docker rm -f "$NAME"
docker run -d --name "$NAME" --restart unless-stopped --network host --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /run/parvault:uid=65532,gid=65532,mode=0700 --tmpfs /tmp:mode=1777 -v "$VOL:/var/lib/parvault" "$IMG" --data-dir /var/lib/parvault up --ipc-socket /run/parvault/parvault.sock --listen "/ip4/0.0.0.0/tcp/$PORT" --peers "$PEERS"
```

(On the first node, leave out `--peers "$PEERS"` if it has none.) With compose: change `image:` and run `docker compose up -d`.

## 7. Removing a node

The volume holds the node's keys, and for the first node the ring's genesis key, which every invite needs. Keep a copy before you delete it (it holds secrets, so keep it private):

<!-- docker-doc: remove -->
```sh
docker stop "$NAME"
mkdir -p -m 0700 "$BACKUP"
docker cp "$NAME:/var/lib/parvault" "$BACKUP/$NAME-backup" && chmod -R go-rwx "$BACKUP/$NAME-backup"
docker rm "$NAME"
docker volume rm "$VOL"
```

With compose, `docker compose down` keeps the volume and `docker compose down -v` deletes it. Files the node stored need its keys to restore: restore them first, or keep the copy.
