# Frozen regression host implementation plan

> **For agentic workers:** Execute the already accepted E2 source-epoch design using the existing fixed-matrix library. The parent owns the final commit and candidate.

**Goal:** Make the later, separately authorized 176-row regression executable from the same frozen source as E, without introducing a new paid runner after E timing.

**Architecture:** Add `scripts/task13_regression.py`, an existing-input-only pinned host. It verifies external final-freeze, actual E timing, fresh RAG/model evidence, Task12 admissions, original budget/epoch/runtime and a separate actual regression consent before delegating to `evals.remediation.execute_bundle`. A synthetic manifest alone can accept explicitly free worker/runtime dependencies. Missing future artifacts yield PENDING without database/provider access.

**Tech stack:** Python 3.12, existing Pydantic contracts and append-only execution library, pytest and Ruff.

## Constraints

- Own only this plan, the new host, its new tests, and the implementation audit.
- Preserve the shared E core config; timing, final freeze and consent stay outside it.
- Keep the original 22 AIT / 66 DEDALE adjacent B2/B3 registration and original account.
- Do not register an epoch, create consent, call a provider, renew a plan, replay an unknown request, or change any existing source file.
- Pin the actual new host entrypoint in both the registered epoch and source file manifest.

## Steps

- [x] Write `evals/tests/test_regression_host.py` covering absent-module RED; absent future inputs fail before runtime; synthetic-only dependency injection; actual pinned 176 order and input checks; consent/final-freeze/timing/config/deadline/source drift; real evidence requirements; unknown dispatch stops and never replays.
- [x] Run the new tests using the main backend Python, `-B`, new worktree PYTHONPATH, removed SSLKEYLOGFILE and a unique workspace `--basetemp`; preserve RED output.
- [x] Implement `RegressionHost(manifest_path, manifest_sha256, free_dependencies=None)`, read-only `readiness`/`status`, explicit `execute(row_limit=None)`, and CLI. Reuse immutable pin helpers and `prepare_bundle`/`execute_bundle`; never accept a real caller-supplied worker or admission callback.
- [x] Verify external artifact pins, synthetic provenance, E timing reconstruction and `observed_six_branch_max`, current source/runtime/epoch/budget and actual scope decision before every dispatch. Preserve any mismatched received model result and halt further dispatch.
- [ ] Run focused tests and Ruff. Fix only owned files. Have the assigned independent reviewer inspect the stable result.
- [x] Write the exact schemas, RED/GREEN evidence, limitations and source hashes to the implementation audit; report them to the parent for final candidate assembly and commit.

Root final25tests passed; lint/format all52changed/new Python files pass. Initial independent findings were fixed, but the reviewer hit its usage limit before final closure. Root then fixed the host/minimal-worker-export boundary with a failing-then-passing test. Final stable independent review remains required; do not mark the combined review step complete.
