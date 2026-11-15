# Vendored Scripts

| File | Origin | Commit | SHA-256 |
| :--- | :--- | :--- | :--- |
| `scripts/sync_doc_metrics.sh` | The project's internal skills repository, `quota-aware-verified-swarm` skill, `scripts/sync_doc_metrics.sh` | `cd36260` | `d028aad1a78ca51b105f81e660e1be47c4069207f52d8d3d21c2bbcf65e12ea1` |
| `scripts/stage_artifact.sh` | The project's internal skills repository, `quota-aware-verified-swarm` skill, `scripts/stage_artifact.sh` | `1b3b43c` | `4ade8a75dc60add2d8702ddf5afb2276f6b38aed388179e0894c80478535f7d2` |

Each copy is byte-identical to its origin. Do not edit it here. To update one, copy the new upstream version over it and record the new commit and SHA-256 in this table. CI runs `sync_doc_metrics.sh` as `bash scripts/sync_doc_metrics.sh --check --generate .`. `scripts/docker_acceptance_gate.sh` stages its binaries through `scripts/stage_artifact.sh` (enforcement line `A-DOCKER`).
