# Reproducible, signed builds

Since `v0.5.3` (L-17), the static musl binaries and the router bundle are reproducible: two builds of the same commit give the same bytes, whatever directory they are built in. `SHA256SUMS` is signed with `ssh-keygen -Y sign`.

## Dev builds and release builds

| | Dev build | Release build |
|---|---|---|
| Which | every `v0.5.x` artifact | none yet; they start with the owner's offline hardware key |
| Key | dev/test key, desktop only, never in CI | owner key (`ed25519-sk`), not created yet |
| Principal, namespace | `parvault-dev`, `parvault-dev-build` | `parvault-release`, `parvault-release-build` |
| Allowed signers | [`security/dev-allowed-signers`](../security/dev-allowed-signers) | [`security/release-allowed-signers`](../security/release-allowed-signers) (empty) |
| Asset names | `<bin>-<target>-dev`, `parvault-router-soc-bundle-dev.tar.gz` | `<bin>-<target>` |
| `SHA256SUMS` first line | `# parvault <tag> dev` | `# parvault <tag> release` |
| `install.sh` | only with `PARVAULT_ALLOW_DEV_BUILD=1` | by default |

The dev key is a test key with no passphrase (L-110). A dev signature says that the Lead's desktop signed these sums; it is not a release promise. The dev key is never listed as a release signer. The two namespaces are separate, so a dev signature does not verify as a release even if the same key were listed in both files.

Dev key fingerprint: `SHA256:w3YrtCVqvG0hUxHHdnrlxuxg/X8LkeuUaZudDswGQ+A`.

## Verify a download

Needs OpenSSH 8.1 or later. OpenWrt ships dropbear, which has no `ssh-keygen`: verify on another machine, then copy the binaries over.

```sh
# in a directory with SHA256SUMS, SHA256SUMS.sig and the assets
curl -fsSLO https://raw.githubusercontent.com/Zbot21/parvault/main/security/dev-allowed-signers
ssh-keygen -Y verify -f dev-allowed-signers -I parvault-dev -n parvault-dev-build \
  -s SHA256SUMS.sig < SHA256SUMS
head -n1 SHA256SUMS                       # must be: # parvault <the tag you meant> dev
grep -v '^#' SHA256SUMS | sha256sum -c --ignore-missing -
```

The first line of `SHA256SUMS` is covered by the signature. It names the tag, so an older signed `SHA256SUMS` cannot be passed off as a newer release. Check that it names the tag you asked for.

Each asset also has a GitHub provenance attestation. It says which workflow run and commit built the file (it does not replace the signature: a compromised CI run still gets valid provenance):

```sh
gh attestation verify parvault-x86_64-unknown-linux-musl-dev --repo Zbot21/parvault
```

## What `install.sh` does

1. Downloads `SHA256SUMS` and `SHA256SUMS.sig`.
2. Verifies the signature with `ssh-keygen -Y verify`, first against the release key (none yet), then against the dev key. A signature that verifies against neither is refused; no setting overrides that.
3. Checks the signed first line: the tag must equal the version it was asked for, and the kind must match the key that signed it.
4. For a dev build, stops unless `PARVAULT_ALLOW_DEV_BUILD=1`, and says plainly that it is installing a dev build.
5. Downloads the binaries and checks each against `SHA256SUMS`.

| Case | Result |
|---|---|
| No `SHA256SUMS.sig` | refused, unless `PARVAULT_ALLOW_UNSIGNED=1` |
| Signature by another key, or sums changed after signing | refused |
| Dev key signature in the release namespace | refused |
| Signed sums of another tag | refused |
| No `ssh-keygen -Y` on the machine | warns, prints the verify command and the fingerprint, and continues with SHA-256 only (L-81); `PARVAULT_REQUIRE_SIGNATURE=1` refuses instead |

`scripts/test_install.sh` tests each case with throwaway keys. `website/install.sh` is a copy that `pages.yml` makes from `scripts/install.sh`; it is not checked in.

## How a dev build is made

- `rust-toolchain.toml` pins rustc (`1.100.0`) and both musl targets. Every workflow reads it.
- Every `cargo` call passes `--locked`. Every action is pinned by commit SHA.
- Builds run inside [`deploy/Dockerfile.build`](../deploy/Dockerfile.build): a Rust base image pinned by digest, and apt packages from a fixed `snapshot.debian.org` date.
- [`scripts/build_release.sh`](../scripts/build_release.sh) sets all build flags in one place: `--remap-path-prefix` for the checkout, `CARGO_HOME` and the target dir; the same maps as `-ffile-prefix-map` for C (ring); one C compiler and linker per target; `SOURCE_DATE_EPOCH` from the commit. The `soc` profile strips symbols; there is no second strip.
- [`scripts/make_bundle.sh`](../scripts/make_bundle.sh) writes the bundle with sorted names, a fixed mtime, owner `0:0`, fixed modes and `gzip -n`.
- On a tag, `release.yml` builds each target twice on separate runners, at different paths and `CARGO_HOME`s, and fails unless every asset matches. It then writes `SHA256SUMS`, attests provenance and creates a **draft** pre-release with no signature.
- On a PR that touches the build inputs, `repro-check.yml` builds `parvault` and the bundle twice in different directories and compares.

Reproduce a build yourself (needs Docker):

```sh
docker build -f deploy/Dockerfile.build -t parvault-build .
bash scripts/repro_proof.sh --target x86_64-unknown-linux-musl --work /tmp/pv-repro \
  --image parvault-build --bundle
```

It prints the sha256 of every output; compare them with the release's `SHA256SUMS`.

## Signing a dev build (Lead, desktop)

The dev private key (`~/.ssh/parvault_dev_signing_ed25519`) stays on the desktop. It never goes into CI, GitHub secrets or the build box.

1. Wait for `release.yml` to finish: build, rebuild and compare match, and a draft pre-release exists.
2. Download its `SHA256SUMS` and assets into a directory, or use the outputs of your own `repro_proof.sh` run and check that they match the draft's `SHA256SUMS`.
3. `bash scripts/sign_dev_build.sh <dir>`. It refuses unless the first line says `dev`, every present asset matches, and the key is the one in `security/dev-allowed-signers`. It writes `SHA256SUMS.sig` and verifies it.
4. `gh release upload <tag> <dir>/SHA256SUMS.sig`, then publish the draft (still a pre-release). `verify-dev-signature.yml` checks the signature and every asset again.

Release signing (owner key, `parvault-release-build`) is not implemented. It starts at `v0.6.0`.
