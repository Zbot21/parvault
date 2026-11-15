#!/usr/bin/env bash
# Dev container image (B-131) from the reproducible binaries, as a `docker load` archive (the
# `docker save` format). The archive is written byte by byte here, not by `docker build`, so the
# same binaries and SOURCE_DATE_EPOCH give the same bytes: release.yml compares it between build
# and rebuild, and SHA256SUMS (signed with the dev key) lists it.
# Image: one layer, no OS, user 65532:65532, data in /var/lib/parvault (owned by 65532), the
# gateway socket in /run/parvault, and a healthcheck through `parvault gateway health`.
# Usage: scripts/make_dev_image.sh --arch <amd64|arm64> --bins <dir> --target <triple> --out <file.tar>
set -euo pipefail
ARCH=""; BINS=""; TARGET=""; OUTF=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) ARCH=$2; shift 2 ;;
    --bins) BINS=$2; shift 2 ;;
    --target) TARGET=$2; shift 2 ;;
    --out) OUTF=$2; shift 2 ;;
    *) echo "make_dev_image.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$ARCH" && -n "$BINS" && -n "$TARGET" && -n "$OUTF" ]] || { echo "usage: make_dev_image.sh --arch A --bins D --target T --out F" >&2; exit 2; }
[[ -n "${SOURCE_DATE_EPOCH:-}" ]] || { echo "make_dev_image.sh: SOURCE_DATE_EPOCH is not set" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n1)
[[ -n "$VERSION" ]] || { echo "make_dev_image.sh: no version in Cargo.toml" >&2; exit 2; }
python3 -I - "$ARCH" "$BINS" "$TARGET" "$OUTF" "$VERSION" "$SOURCE_DATE_EPOCH" <<'PY'
import hashlib, io, json, sys, tarfile, time

arch, bins_dir, target, out, version, epoch = sys.argv[1:7]
epoch = int(epoch)
if arch not in ("amd64", "arm64"):
    sys.exit(f"make_dev_image.sh: unsupported arch {arch}")
BINS = ["parvault", "parvault-seed", "parvault-fuse", "parvault-sync", "parvault-status"]
UID = 65532
SOCK = "/run/parvault/parvault.sock"
DATA = "/var/lib/parvault"


def tar_bytes(entries):
    """entries: (name, kind, mode, uid, data) sorted by name; fixed mtime, no user names."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, kind, mode, uid, data in sorted(entries):
            ti = tarfile.TarInfo(name)
            ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = epoch, mode, uid, uid, "", ""
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            else:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


passwd = b"root:x:0:0:root:/root:/sbin/nologin\nparvault:x:65532:65532:parvault:/var/lib/parvault:/sbin/nologin\n"
group = b"root:x:0:\nparvault:x:65532:\n"
entries = [
    ("etc", "dir", 0o755, 0, None),
    ("etc/passwd", "file", 0o644, 0, passwd),
    ("etc/group", "file", 0o644, 0, group),
    ("run", "dir", 0o755, 0, None),
    ("run/parvault", "dir", 0o700, UID, None),
    ("tmp", "dir", 0o1777, 0, None),
    ("usr", "dir", 0o755, 0, None),
    ("usr/local", "dir", 0o755, 0, None),
    ("usr/local/bin", "dir", 0o755, 0, None),
    ("var", "dir", 0o755, 0, None),
    ("var/lib", "dir", 0o755, 0, None),
    ("var/lib/parvault", "dir", 0o700, UID, None),
]
for b in BINS:
    with open(f"{bins_dir}/{b}-{target}-dev", "rb") as f:
        entries.append((f"usr/local/bin/{b}", "file", 0o755, 0, f.read()))
layer = tar_bytes(entries)
diff_id = hashlib.sha256(layer).hexdigest()

created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
pv = "/usr/local/bin/parvault"
config = {
    "architecture": arch,
    "os": "linux",
    "created": created,
    "config": {
        "User": f"{UID}:{UID}",
        "Env": ["PATH=/usr/local/bin", f"HOME={DATA}"],
        "WorkingDir": DATA,
        "Entrypoint": [pv],
        # The status page binds the container's own interface (B-54 note in Dockerfile.router-soc);
        # with host networking, set --status-http to the NAS's LAN address instead (compose.yaml).
        "Cmd": ["--data-dir", DATA, "up", "--ipc-socket", SOCK, "--status-http", "0.0.0.0:4080"],
        "Volumes": {DATA: {}},
        "ExposedPorts": {"4001/tcp": {}, "4009/udp": {}, "4080/tcp": {}},
        "Healthcheck": {
            "Test": ["CMD", pv, "--data-dir", DATA, "gateway", "health", "--socket", SOCK],
            "Interval": 30_000_000_000,
            "Timeout": 10_000_000_000,
            "StartPeriod": 60_000_000_000,
            "Retries": 3,
        },
        "Labels": {
            "org.opencontainers.image.title": "parvault",
            "org.opencontainers.image.version": f"{version}-dev",
            "org.opencontainers.image.licenses": "AGPL-3.0-only",
            "org.opencontainers.image.source": "https://github.com/Zbot21/parvault",
            "dev.parvault.build-kind": "dev",
        },
    },
    "rootfs": {"type": "layers", "diff_ids": [f"sha256:{diff_id}"]},
    "history": [{"created": created, "created_by": "scripts/make_dev_image.sh (B-131)"}],
}
if arch == "arm64":
    config["variant"] = "v8"
cfg = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
cfg_id = hashlib.sha256(cfg).hexdigest()
tag = f"parvault:{version}-dev"
manifest = json.dumps(
    [{"Config": f"{cfg_id}.json", "RepoTags": [tag], "Layers": [f"{diff_id}/layer.tar"]}],
    separators=(",", ":"),
).encode()
repos = json.dumps({"parvault": {f"{version}-dev": diff_id}}, separators=(",", ":")).encode()
archive = tar_bytes([
    (f"{cfg_id}.json", "file", 0o644, 0, cfg),
    (diff_id, "dir", 0o755, 0, None),
    (f"{diff_id}/layer.tar", "file", 0o644, 0, layer),
    ("manifest.json", "file", 0o644, 0, manifest),
    ("repositories", "file", 0o644, 0, repos),
])
with open(out, "wb") as f:
    f.write(archive)
print(f"make_dev_image.sh: {out}: {tag} ({arch}), image id sha256:{cfg_id}")
PY
