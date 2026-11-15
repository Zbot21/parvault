# Vendored Scripts

| File | Origin | Commit | SHA-256 |
| :--- | :--- | :--- | :--- |
| `scripts/sync_doc_metrics.sh` | The project's internal skills repository, `quota-aware-verified-swarm` skill, `scripts/sync_doc_metrics.sh` | `cd36260` | `d028aad1a78ca51b105f81e660e1be47c4069207f52d8d3d21c2bbcf65e12ea1` |
| `scripts/stage_artifact.sh` | The project's internal skills repository, `quota-aware-verified-swarm` skill, `scripts/stage_artifact.sh` | `360b586` | `8fd678a3c56dd0845d65745a06fbc7b31900890c4c267387fcf0de91731d977b` |

Each copy is byte-identical to its origin. Do not edit it here. To update one, copy the new upstream version over it and record the new commit and SHA-256 in this table. CI runs `sync_doc_metrics.sh` as `bash scripts/sync_doc_metrics.sh --check --generate .`. `scripts/docker_acceptance_gate.sh` stages its binaries through `scripts/stage_artifact.sh` (enforcement line `A-DOCKER`).
