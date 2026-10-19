# Task13 implementation ledger

Approved scope: [design](../specs/2026-10-18-task13-design.md). User requested execution on 2026-10-18. Work on `codex/task13`; preserve pre-existing main-plan/spec edits and Task12 frozen data. No frontend expansion.

User authorization: total model spend <= CNY100; development <= CNY15, both inclusive of retries, failures and unknown charges. User performs human review/approval, Asia/Shanghai 19:00–00:00. This is availability, not blanket action approval. Formal response plans still require individual product approval.

## Global constraints

- Eight groups B0 B1 B2 B3 A1 A2 A3 A4, 22 AIT and 66 DEDALE cases, replicate1/seed42:704 planned rows. No paid final call before all freeze/admission/isolation gates.
- Explicit attack/benign/unknown diagnosis in original graph. Diagnostic snapshot sealed before response, and never changed by simulation.
- A1 disables two evidence tools with nontransferable reservation; A2 disables every RAG entry; A3 semantic-only disables exact and keyword paths. Logical tools <=3/round, <=6/case (A1 <=2/first round and <=5/case). Physical model/tool attempts <=3/logical call.
- Immutable attempts/output hashes; only authorized infra/transport reruns. Unknown/failed/missing remain in denominators; missing usage remains null and charges reservation conservatively.
- Scoring/gold/review never enter worker. Exact accepted data roots, independent case scope, bound worker PID/container/nonce probe. Critical isolation tests may not skip.
- Formal output cannot be claimed from fixtures. Human support judgments cannot be replaced by LLM judgments. Fifteen real-result charts PNG/SVG+CSV+captions+hashes required for final completion.

## P0: protocol and contracts (root, first)

Create `evals/contracts.py`, `evals/run_manifest.schema.json`, `docs/evaluations/protocol.md`, `evals/tests/test_contracts.py`. Use Pydantic strict-extra neutral WorkerRunSpec and controller-only path-bearing specs. Define policies, attempts, result and usage types. Test rejection of answer-bearing fields, invalid verdicts, unsupported reruns and incomplete formal freeze. Generate JSON schema from the contract and check it matches. Approved budget and reviewer recorded, model price/version snapshot source recorded.

## P1: execution (runner agent)

Create `evals/runners/{cli,manifest,execute,score}.py`, `evals/run_formal.ps1`. Build explicit matrix from accepted selection, preserve all rows in resume and score. Store attempts append-only with config/input/output binding; require persisted rerun authorization, never select best score. Validate admission, freeze hashes and source commit before final dispatch. Tests cover planned counts, missing/unknown retention, crash recovery, tamper detection and forbidden reruns. CLI `--help`, fixture plan/execute/score must work without credentials.

## P2: metrics (metrics agent)

Create classification/evidence/attack_chain metrics and `evals/tests/test_metrics.py`. Use manual expected counts for mixed attack/benign/unknown/failed; fixed six-class macro with zero-support F1=0; P@5 pads empty positions; trusted registry citation matching; repeated stage instances and partial orders; no unsupported gold inferred. Separate DEDALE binary applicability, AIT available labels, human semantic review and null resources.

## P3a: original backend graph (backend agent)

Create shared backend diagnosis/capability/verification types. Inject optional policy through original graph/services/collector/retriever with legacy API compatibility. Persist and seal diagnosis in graph checkpoint and run summaries. Typed before/after observations determine three simulation outcomes; approvals/completed actions alone never prove success. Add failing behavioral tests first, then run affected backend tests. One owner edits backend common modules.

## P3b: real adapters and model ledger (root)

Create `evals/adapters/{evidencesoc,diagnosis,model_client,verification_observations}.py`. B0/B1 each make one analysis call; B1 fixed seed-derived knowledge retrieval; B2 one bounded investigator; B3/A use original graph. Mechanical seed from raw agent events with canonical evidence IDs, no answer titles. Explicit JSON schema prompt/nonthinking/temperature0 and per-call max output, three total attempts including schema errors; no SDK retry. SQLite atomic campaign reservation includes in-flight max costs, unknown usage charged at reserved upper bound. Store raw response metadata, requested/response model, request ID, fingerprints, timestamps and schema status; version drift halts dispatch.

## P4: isolation and development (runner agent + root integration)

Create worker export/mount/probe bootstrap using pinned source and full Linux dependencies, no repository root/.git/docs/gold/other cases/.env mount. Worker making model requests runs bound identity/read-denial probe. Validate cross-case tools/indexes. Fixture tests first, then genuine developer samples only after offline gates and price/credential checks. Measure actual tokens/latency/resources at concurrency1 before expanding; dev costs <=15. Never replace live isolation evidence with Task12 model-free evidence.

## P5: freeze, figures, report (all integration)

Create config/freeze templates which fail closed until measured values, artifact hashes, tested commit and real isolation evidence exist. Pin plotting dependency in backend lock. Metrics agent creates 15 figure exporters and tests; root visually inspects every output and reconciles CSV/JSON/hash. Final input must be immutable independently scored results plus human review; unavailable data clearly marked. Report and machine acceptance record distinguish implemented/tested/development/formal/human review states. Formal actual execution needs explicit allow-final-test and every gate; retain incomplete status if any prerequisite is unavailable.

## Verification commands

Use `services/backend/.venv/Scripts/python.exe -m pytest evals/tests -q`, then affected agents/tools/rag suites and Task12 integration/security checks with real services and zero critical skips. `uv` commands set `UV_CACHE_DIR=D:\传智杯\.uv-cache` to stay inside workspace. Run `python -m evals.runners.cli --help`, fixture end-to-end and plot replay. Capture command/count/skip evidence. Whole-change independent review follows integration; fix important issues and rerun covering tests before completion.

## Progress

- Context/design audited; branch created. Existing user doc changes retained.
- Budget/reviewer authorization recorded above.
- P0–P3 implementation exists; P4 integration and real development acceptance are in progress. Runner, metrics, human-review and verification counterexamples have targeted passing checks; aggregate verification and source commit remain required.
- Linux Python3.12.14 import smoke passed with network disabled and no model key; working-tree import evidence is not G4.
- Public knowledge snapshot prepared:997 registered chunks plus pinned offline model. AIT development control selection derives2 attack+2 normal cases from accepted development input.
- Independent review identified and drove fixes for full-report review binding, mixed error rerun categories, MCP child import paths and incomplete usage aggregation. Do not infer a complete experiment from these engineering fixes.
- At preparation checkpoint, formal/paid generation calls remain0. Formal freeze, real worker isolation, actual human approvals/review,704 rows and15 final figures remain required.
