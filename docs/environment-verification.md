# Environment Verification

- Check date: 2026-10-15 10:43 (Asia/Shanghai)
- Operating system: Windows 11 家庭版 中文版, 10.0.26200 (build 26200)
- Original project directory: `D:\传智杯`
- Integrated acceptance checkout: `D:\传智杯\.backups\task12-readiness`
- Host CPU: Intel Core i7-14650HX, 16 cores / 24 logical processors
- Host physical memory: 16,873,545,728 bytes (15.71 GiB usable physical memory)
- D: free space when checked: 262,716,530,688 bytes (244.67 GiB)
- Machine-readable evidence: `step4-environment.json` in the Task 12 artifact directory linked from `acceptance/task12-readiness.md`.

## Tool versions

| Tool | Actual version | Required version | Result |
|---|---:|---:|---|
| Git | 2.55.0.windows.2 | 2.55.0 | Pass |
| Node.js | 24.15.0 | 24.15.0 | Pass |
| npm | 11.12.1 | 11.12.1 | Pass |
| Corepack | 0.34.6 | 0.34.6 | Pass |
| pnpm | 11.19.0 | 11.19.0 | Pass |
| System Python | 3.13.6 | Keep unchanged | Pass |
| Project Python | 3.12.14 | 3.12.14 | Pass |
| uv | 0.12.16 | 0.12.16 | Pass |
| Docker Engine | 29.7.2 | 29.7.2 | Pass |
| Docker Compose | 5.5.0 | 5.5.0 | Pass |
| WSL | 2.7.3.0 (kernel 6.6.114.1-1) | 2.7.3.0 | Pass |

## Docker verification

- Docker server reachable: Yes
- vm.max_map_count: 1048576
- Docker CPUs: 24
- Docker memory: 7.609GiB
- Docker memory exact: 8,170,549,248 bytes
- PostgreSQL: 17.11 (`pgvector/pgvector:0.8.6-pg17-bookworm`)
- OpenSearch: 3.8.0 (`opensearchproject/opensearch:3.8.0`)
- Dedicated acceptance Compose project: `evidencesoc-task12-acceptance`, configuration `infra/acceptance.compose.yaml`.
- Acceptance ports: `127.0.0.1:5433` / `127.0.0.1:9202`; original development ports: `127.0.0.1:5432` / `127.0.0.1:9201`.
- All four containers reported healthy. A single-node OpenSearch cluster is yellow because replicas have no second node; primary shards are available.
- Separate acceptance volumes retained identical PostgreSQL/OpenSearch marker content and SHA256 after the explicit restart on 2026-10-14, and remained present after the host restarted on 2026-10-15. See the persistence evidence in the acceptance record.

## Notes

- System Python 3.13.6 remains unchanged.
- Project Python 3.12.14 is managed by uv.
- Docker ports must only bind to 127.0.0.1 during development.
- Acceptance credentials are supplied through a local ignored environment file and never included in Git or reports.
