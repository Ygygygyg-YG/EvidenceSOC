# Task13 E planning contracts implementation plan

> Scope approved by root: implement only new Task B modules and temporary tests. No core bridge, graph, timing, runtime, budget, source epoch, real registration or model changes. No commit.

1. RED: write synthetic contract/registration tests for original insufficient selection, one source and three deterministic independent planning/trial identities, full original output/request/manifest lineage, fixed response-only limits and immutable model binding. Run with main backend venv and a unique temporary pytest root.
2. GREEN: implement `evals/adapters/e_planning_contracts.py` and `evals/e_planning.py`; re-run contract tests. The source field is `analysis_output_sha256`, matching the bridge review fix.
3. RED: write journal tests for externally pinned host authority, worker registration denial, exactly three registered slots, read-only existing open, one-time concurrent claims, mismatch/replay rejection and immutable tables. Legacy ImportDispatchJournal is untouched.
4. GREEN: implement new `evals/adapters/e_planning_journal.py`; run both new test files with temporary synthetic SQLite only.
5. Verify new files with ruff check/format, run focused tests plus the existing legacy import journal test, then write the implementation evidence to the new BASE audit report. Source package verification and all live worker integration remain separate work.

All test commands remove SSLKEYLOGFILE and set UTF-8/no-bytecode in the child environment. No fake authority is written outside synthetic temporary fixtures.
