# Parallel Verification Runner (`scripts/verify.sh`)

`scripts/verify.sh` runs every TLA+ cfg and every Kani harness in parallel, with TLC state on
`/dev/shm` so a run writes little to the SSD. It reproduces CI's `tla-model-check` and
`kani-bounded-model-check` jobs. It does not run the TLC guard-removal mutants: those are
patches in `.enforcement.map` (`tla-mutant` lines), and the enforcement runner applies them
and passes a mutant only when TLC reports the named invariant violated.

```sh
make verify-tlc                      # every specs/<Spec>.cfg and specs/<Spec>.<Variant>.cfg
make verify-tlc SPEC=ParVaultProtocol
make verify-kani                     # every Kani harness, KANI_JOBS CBMC threads
make verify-kani HARNESS=proof_webdav_auth_decision,proof_fuse_header_parser_no_panic
make verify-all                      # both; all failures are listed at the end
make verify-test TEST_ARGS='--lib' VERIFY_MOLD=1
make test-verify-runner              # the runner's own test (fake java/cargo, about 40 s)
```

On the dev box, run them only under `pvjob`, as the last command of the job:

```sh
pvjob run --bg --cap tla   --who <me> --wt <wt> --timeout 30m -- make verify-tlc
pvjob run --bg --cap cargo --who <me> --wt <wt> --timeout 20m -- make verify-kani
```

## Discovery

- **TLC:** every `specs/<Spec>.tla` must have `specs/<Spec>.cfg`; every
  `specs/<Spec>.<Variant>.cfg` runs after it (the `RootOffDisk` cfg today). These are CI's rules.
  All discovered cfgs are positive: a cfg passes when TLC exits 0 with no `Error:` line.
- **Kani:** every `#[kani::proof]` and `#[kani::proof_for_contract(..)]` fn in the library
  sources, named as `--harness <name> --exact` needs it (`kani_proofs::proof_x`,
  `crypto::aes::kani_proofs::proof_y`).
- `scripts/test_verify.sh` checks discovery against CI's cfg loop, `docs/metrics.txt`
  (`tla_specs`, `kani_harnesses`), every `harness=` in `.enforcement.map`, and, with
  `VERIFY_KANI_LIST=1`, `cargo kani list --format json` (needs cargo-kani; run it under pvjob).

## Settings

| Variable | Default | Effect |
| :--- | :--- | :--- |
| `TLC_HEAP_PCT` | `70`; `30` under pvjob (Makefile) | `-Xms` = `-Xmx` = this % of physical RAM |
| `TLC_WORKERS` | `auto` | TLC `-workers` |
| `TLC_SHM_MIN_MB` | `2048` | a cfg fails without starting if `/dev/shm` has less free |
| `TLA2TOOLS_JAR` | `/opt/tla/tla2tools.jar`, then `~/.cache/tla/tla2tools.jar` | TLC jar |
| `KANI_JOBS` | `nproc --all / 2`; `16` under pvjob | CBMC threads (jobs mode) or workers (shard mode) |
| `KANI_MODE` | `jobs` | `jobs`: one `cargo kani -j N`; `shard`: N workers of `cargo kani --harness <h> --exact` |
| `KANI_SHARD_TARGETS` | `1` | shard mode: one `CARGO_TARGET_DIR` per worker |
| `SPEC`, `HARNESS` | all | filters; `HARNESS` takes a comma-separated list |
| `FAIL_FAST` | `0` | `1`: stop at the first failure (`--fail-fast` in jobs mode) |
| `VERIFY_MOLD` | `0` | `1`: the `test` step links with mold in `$CARGO_TARGET_DIR-mold` |
| `VERIFY_LOG_DIR` | `$CARGO_TARGET_DIR/verify-logs/<stamp>` | per-cfg and per-harness logs, `kani/times.tsv` |

Each TLC run gets `-XX:+UseParallelGC`, `-workers`, `-cleanup`, `-noGenerateSpecTE`, and a
`-metadir` and `java.io.tmpdir` in `/dev/shm/tlc-<cfg>-<pid>`. A trap removes these dirs on
EXIT, INT and TERM and kills TLC's process group, so `/dev/shm` does not leak. pvjob starts
jobs with SIGINT ignored, which a bash script cannot trap; the runner then re-execs itself
once with SIGINT reset, so `timeout -s INT` stops it at once there too.

Under pvjob other jobs share the box, so the Makefile pins a 30 % heap (about 36 GiB on a
121 GiB box; the largest cfg needs far less). A `tla` job (32 units) can run beside one
`cargo` job (16 units).

## Kani: measured on the dev box (16 cores / 32 threads, Kani 0.68.0, 2026-11-15)

The box ran other pvjob jobs during these runs (load average 8 to 21), so times are upper bounds.

| Run | Wall time |
| :--- | :--- |
| `cargo kani`, serial, cold target dir | 424 s |
| `make verify-kani` (jobs mode, `KANI_JOBS=16`), crate recompiled after an edit | 136 s |
| one `cargo kani --harness <h> --exact`, cold / warm deps | 18 s / 10 s |
| two at once, one shared target dir | 9.9 s, one waits on cargo's build-directory lock |
| two at once, per-worker target dirs, cold / warm | 21.6 s / 9.1 s |

- The slowest harnesses set the floor: `proof_macaroon_peer_uid_and_compact_roundtrip` 115 s,
  `proof_eviction_quorum_sub_threshold_and_duplicate_signer_rejected` 100 s, the next 55 s.
  More than about 8 threads mainly shortens the tail of fast harnesses (not measured).
- Every `cargo kani --harness <h>` with a new harness set recompiles the crate (about 9 s),
  because the filter is a compiler argument. Workers on one target dir queue on cargo's
  build-directory lock; per-worker dirs avoid that but cost about 1.1 GB of SSD writes each
  when cold. So shard mode pays one compile per harness and is not the default.
- `cargo kani -j N` compiles once and runs CBMC on N threads, with no lock and no output
  collision (Kani writes one goto binary per harness under `target/kani`). Jobs mode is the
  default. Kani prints results per thread (with no thread prefix at `-j 1`); the runner
  timestamps each line and maps it to the harness that thread started, for the per-harness
  log, wall time and `times.tsv`. `HARNESS=` passes `--harness <name> --exact` per name.
- Full run: peak summed RSS of the run's process tree 10.3 GiB; 0.38 GB written to disk
  (`write_bytes` of the process tree; tmpfs writes do not count). A cold `target/kani` is
  about 1.4 GB. Moving `target/kani` to `/dev/shm` would save about 0.4 GB per edit-and-rerun,
  which does not justify losing the cache at every reboot, so it stays on disk. TLC state and
  `java.io.tmpdir` are already on `/dev/shm`; logs are a few MB.
- Temperatures (box busy with other jobs): Tctl 91.2 °C before, 95.9 °C peak, 77.1 °C after;
  NVMe Composite 45.9 °C before and at peak, 42.9 °C after. NVMe "Sensor 2" read 76.8 °C in
  every sample, idle or loaded, so it does not track load.
- In pvjob, `make verify-kani` at `KANI_JOBS=16` needs 16 CPU units: run it with
  `--cap cargo` (`w.cargo=16`). `--cap kani` (`w.kani=4`) fits `KANI_JOBS=4` only.

## mold

`VERIFY_MOLD=1` adds `-C link-arg=-fuse-ld=mold` to `RUSTFLAGS` for the runner's `test` step
only, in its own target dir, so other caches keep their fingerprints. If mold is not
installed, the step links with the default linker and says so. Kani runs with `RUSTFLAGS` and
`CARGO_ENCODED_RUSTFLAGS` unset, so mold never reaches `cargo kani`; release, repro and Docker
builds do not use this runner. `scripts/test_verify.sh` checks both.

On the box (mold 2.40.4), `VERIFY_MOLD=1 make verify-test TEST_ARGS='--lib --no-run'` built
the lib tests from cold in 40 s, and the binary's `.comment` names `mold 2.40.4`. A warm
`make verify-kani` run after that build recompiled nothing.
