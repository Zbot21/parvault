# ParVault on a Synology NAS (dev container)

Every `v0.5.x` image is a **dev build** (B-131, L-113): reproducible, and signed with the ParVault dev/test key, not a release key. The DS923+ (AMD Ryzen R1600) is x86_64, so use `parvault-image-amd64-dev.tar`. `parvault-image-arm64-dev.tar` is for ARM NAS models and has not been tested on one.

The image has no OS: just the five static binaries, user `65532:65532`, data in `/var/lib/parvault`, and a healthcheck through `parvault gateway health`.

## 1. Verify the download

On a machine with OpenSSH 8.1 or later (Linux, macOS and Windows 10+ have it; on the NAS, check `ssh -V` over SSH first):

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

Container Manager > Image > Add > Import from file, and pick `parvault-image-amd64-dev.tar`. Or over SSH: `sudo docker load -i parvault-image-amd64-dev.tar`. Either way the result is `parvault:<version>-dev`.

## 3. Start a ring or join one (first run only)

The daemon refuses to start until the node is in a ring. Over SSH on the NAS, create the data volume and do one of these with the same tag (the volume starts owned by `65532:65532`):

```sh
IMG=parvault:0.5.3-dev   # the tag you imported
# This NAS starts a new ring (the first node):
sudo docker run --rm -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault wot init
# Or it joins an existing ring: print its key, get a token from a member, install it.
sudo docker run --rm -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault identity
#   on a ring member: parvault wot invite --peer <that 64-hex key>
sudo docker run --rm -v parvault-data:/var/lib/parvault "$IMG" --data-dir /var/lib/parvault wot install-chain --token <TOKEN>
```

## 4. Create the project

1. Make a folder for it, for example `/volume1/docker/parvault`, and copy [`deploy/synology/compose.yaml`](../deploy/synology/compose.yaml) into it.
2. Set `image:` in it to the tag you imported.
3. Container Manager > Project > Create, choose that folder, and use the existing `compose.yaml`.

What the project does:

- Runs as `65532:65532`, with `cap_drop: [ALL]`, `no-new-privileges`, a read-only root, and tmpfs for `/run/parvault` and `/tmp`.
- Uses host networking, so LAN discovery (UDP 4009) and the mesh port (TCP 4001) work on the NAS's own address.
- Keeps state in the named volume `parvault-data` (from step 3), which starts owned by `65532:65532`. If you bind a NAS folder instead, `chown -R 65532:65532` it first.
- Turns healthy once the daemon answers on its gateway socket.
- Binds the token-gated status page to loopback. To use it from the LAN, change `127.0.0.1:4080` in `command:` to the NAS's LAN address.

## Upgrading

Verify and import the new tar, change `image:` to the new tag, then rebuild the project (Project > Action > Build). The data volume is kept.
