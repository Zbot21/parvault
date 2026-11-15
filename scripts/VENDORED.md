# Vendored Scripts

| File | Origin | Commit | SHA-256 |
| :--- | :--- | :--- | :--- |
| `scripts/sync_doc_metrics.sh` | The project's internal skills repository, `quota-aware-verified-swarm` skill, `scripts/sync_doc_metrics.sh` | `6c1d5ad` | `f1ed845a87efb77a98a7280bcabf8242c106558da39ece033bfe1ab834ccf05b` |
| `scripts/stage_artifact.sh` | The project's internal skills repository, `quota-aware-verified-swarm` skill, `scripts/stage_artifact.sh` | `3ea6da6` | `36f7c20059335342eb021aa86bae5a1c1e674cf17c2777f170de72b47a79e950` |

Each copy is byte-identical to its origin. Do not edit it here. To update one, copy the new upstream version over it and record the new commit and SHA-256 in this table. CI runs `sync_doc_metrics.sh` as `bash scripts/sync_doc_metrics.sh --check --generate .`. `scripts/docker_acceptance_gate.sh` stages its binaries through `scripts/stage_artifact.sh` (enforcement line `A-DOCKER`).
