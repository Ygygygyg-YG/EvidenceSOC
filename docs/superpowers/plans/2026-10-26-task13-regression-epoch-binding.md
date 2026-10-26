# Task13 Regression Epoch Binding Implementation Plan

> **For agentic workers:** Execute inline using TDD, following the approved source epoch architecture. No live registration, commit, service, credential use or network dispatch is authorized.

**Goal:** Bind the fixed 176 regression slots to an explicitly registered latest source epoch on the original unchanged budget.

**Architecture:** Preserve the v2 request class and default bundle serialization. Introduce a separate strict regression-only v3 subclass and bundle branch; read-only runtime validation checks registered epoch, original history and host budget path, actual exported bytes, controller entrypoints and runtime identity before reusing the existing guarded remediation runner.

**Tech Stack:** Existing Python/Pydantic, sqlite3, pytest, httpx.MockTransport.

## Global Constraints

- Code changes only in the new tree; real budgets and original 36 requests receive no writes.
- Preserve fixed 176 slot IDs, pair order, B2/B3 policy, model, seed, configuration and input hashes. Development and f8 cannot use the new schema.
- Preserve global 100/15, supplement 30, purpose 6/16/6 and held 2. No reset or allowance is introduced.
- Registration remains host-only and external consent remains separately required. Latest epoch lookup grants no outbound authority.
- Root owns `scripts/task13_worker_runtime.py`; this implementation supplies its shared preflight interface.

### Task 1: Reproduce missing epoch dispatch and preserve v2

**Files:** Create `evals/tests/test_epoch_remediation.py`; leave `evals/adapters/remediation_contracts.py` unchanged.

- [x] Add a test requiring an explicit v3 request and showing its budget binding contains `epoch_id` while default v2 rejects epoch fields.
- [x] Run the focused test with the approved Python, new-tree backend/source PYTHONPATH, unique temporary directory, no bytecode/cache, SSLKEYLOGFILE removed; confirm the missing v3 module is the failure.
- [x] Record original request source hash and validate archived original 36 raw requests without rewriting them.

### Task 2: Separate regression schema and read-only preflight

**Files:** Create `evals/adapters/epoch_remediation.py`; minimally modify `evals/adapters/remediation_worker.py`.

**Interface:** `validate_epoch_runtime(request, agent_dir, source, budget_path, runtime_binding, source_commit, worker=False) -> dict` returns the registered latest manifest. `run_epoch_remediation(request, agent_dir)` performs PID1/nonce/formal checks and reads `TASK13_RUNTIME_BINDING` plus `TASK13_EPOCH_HOST_BUDGET_PATH` before calling the existing real runner.

- [x] Add temporary synthetic ledger/export tests for latest registered epoch, wrong source/config/manifest/runtime/image/dependencies/knowledge/controller hash, missing entrypoints, copied budget and identity mismatch; assert rejection precedes runner/model/service boundary.
- [x] Implement regression-only v3 subclass with required `epoch_id` and `epoch_manifest_sha256`; add only epoch ID to the inherited monetary binding.
- [x] Implement SELECT-only preflight with original identity, latest epoch, exported file verification and complete registered entrypoint equality. Host compares all actual controller files; worker requires its full subset and compares every registered entry present in the minimal export, without mounting host-only controller code.
- [x] Add guarded v3 parsing to existing validation/runner; preserve all prior security checks and v2 behavior.

### Task 3: Explicit v3 bundle and execution invariants

**Files:** Modify `evals/remediation.py`; extend `evals/tests/test_epoch_remediation.py`.

**Interface:** `prepare_bundle(..., epoch_binding=None)` accepts only `{'epoch_id': str, 'epoch_manifest_sha256': sha256}` for regression. Explicit bundles use `task13-remediation-bundle-v3`; matching gates use `task13-v3-execution-gate-v1` and include both epoch fields.

- [x] Add failing tests for optional v3 projection, all 176 original slots/order, default byte equivalence, invalid development use, mixed schemas, epoch/gate/config/input drift and execution no-replay/mutation stop.
- [x] Implement minimal schema-dependent projection/validation/dispatch, retaining the existing external admitter, writer lock, unknown stop and immutable campaign binding. V3 also carries the registered order digest, without changing v2 payloads.
- [x] Run focused plus existing remediation/source epoch/budget/model tests. Core: 165 passed; source epoch security/accounting subset: 46 passed, 8 excluded after observing Windows hardlink publication denial in unrelated temporary journal setup. Inspect diff and report command results and limits to the external audit Markdown. Leave code uncommitted for root review.
