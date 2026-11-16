# Using ParVault from Windows

Windows has no ParVault program. The vault's writer node, a NAS or Linux machine that runs `parvault` with the vault key and backs the folders up (`watch-folder`), also serves the vault as a read-only network drive over HTTPS (WebDAV), and Windows maps it with its built-in WebDAV client (the `WebClient` service). New backups come from that node's `watch-folder`, for example on a NAS shared folder you copy files into from Windows. Serving WebDAV from a second, read-only node of the same vault is planned for `v0.5.7`.

What works from Windows in `v0.5.6`:

- browse the vault's backed-up folders as drive `Z:`;
- open a file, or copy it out (restore);
- older versions: on the NAS only (`restore-folder --version`, the run-once `restore-version` compose service); a versions view on the drive is planned for `v0.5.7`.

The drive is read-only: Explorer cannot write, rename or delete there.

## 1. On the NAS: start the edge and read the fingerprint

Start the daemon with a WebDAV bind that is not loopback, for example `--vfs-webdav-listen 0.0.0.0:8443`. At the first such start it makes a self-signed certificate and serves HTTPS only; the file `edge_tls.pem` in the data dir holds the certificate and its key (mode `0600`, never re-issued on its own). The start log prints its fingerprint:

```text
[parvault] Edge TLS certificate SHA-256 AB:CD:... (webdav.crt file 1f2e...; pin sha256//...)
```

On Synology this line is in Container Manager, the container's Log tab. On Linux:

<!-- doc-cmd: skip reason="needs a running NAS daemon with a non-loopback WebDAV bind" -->
```bash
parvault tls show
parvault tls export --out /volume1/parvault-share/webdav.crt
```

`tls show` prints the certificate SHA-256, the SHA-256 of the exported file (`webdav.crt SHA-256`), the curl pin, the names and addresses it covers, and its expiry (825 days after it was made).

The certificate covers each address the daemon bound, or every address of the host for a `0.0.0.0` bind (host networking). In a bridge-mode container the daemon cannot see the host's address: add `--tls-san <nas-ip>` (and `--tls-san <name>` for a name) before the first start. If the NAS's address changes later (DHCP), give it a fixed lease, or run `parvault tls rotate` and register the new certificate on every client.

## 2. On Windows: register the certificate (once)

Copy `webdav.crt` from the share, then in an administrator PowerShell:

```text
certutil -hashfile webdav.crt SHA256
certutil -addstore -f Root webdav.crt
net stop webclient
net start webclient
```

The `certutil -hashfile` output must equal the `webdav.crt SHA-256` line of `tls show`. If it does not, do not register the file: it is not your NAS's certificate. `-addstore Root` without `-user` adds it to the Local Machine store, which the `WebClient` service reads.

## 3. Get a read-only token

On the NAS (or in the run-once `token` compose service):

<!-- doc-cmd: skip reason="needs the NAS data dir" -->
```bash
parvault token mint --ttl-secs 2592000 --out /volume1/parvault-share/webdav.token
```

The command prints only the file's path; the file (`0600`) holds the token. Tokens for WebDAV stay under 255 characters, which Windows accepts as a password; `token mint` warns if one is longer (drop caveats you do not need). Every token is read-only by default.

## 4. Map the drive

```text
net use Z: \\192.168.1.75@SSL@8443\DavWWWRoot /user:token <token>
```

Use the NAS's address and the WebDAV port. The user name is ignored; the token is the password. Over HTTPS the old `BasicAuthLevel` registry step is not needed.

## 5. Browse and restore

Open `Z:\` in Explorer. Copy a file out to restore it. Notes:

- Explorer reports the drive as read-only; copying into it fails.
- `WebClient` refuses files over about 50 MB by default (`FileSizeLimitInBytes`, `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters`, in bytes; the maximum is 4294967295). Raise it and restart `WebClient` to open larger files.
- `WebClient` keeps one connection for a burst of requests (the edge keeps an authenticated connection for up to 100 requests or 15 s idle), so browsing does not pay a TLS handshake per file.

## Troubleshooting

| Symptom | Cause and fix |
| :-- | :-- |
| `net use` asks for a certificate, or reports error 0x80070043 or 67 | The certificate is not in the Local Machine Root store, or the address you used is not in its names (`tls show`). Register it again, or use an address it covers. |
| It worked, then stopped after a NAS restart | The NAS's address changed: fixed lease, or `tls rotate` and register again. |
| `net use` refuses the password | The token is too long: mint one with fewer caveats. If Windows still refuses, report it (an app password is the planned fallback). |
| A large file fails to open | `FileSizeLimitInBytes` (above). |
| You must use plain HTTP | `--insecure-plain-http` serves plain HTTP on a LAN bind; the token then crosses the network in clear, and Windows needs `BasicAuthLevel` set to 2. Not recommended. |

## Owner test record (E2)

The manual run of steps 2 to 5 on Windows 10 and Windows 11, including a file over 50 MB, is recorded here when done.

| Windows | Date | `net use` with the token | IP name match | TLS version | Read-only shown | File over 50 MB | Result |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| 10 | | | | | | | not run yet |
| 11 | | | | | | | not run yet |
