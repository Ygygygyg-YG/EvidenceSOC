# Actual original 36 analysis source selection

**Goal:** Produce an offline first-three receipt from all 36 actual terminal attempts, preserving the immutable selected slot 9 lineage.

**Architecture:** A new host reader validates the original master bundle, all terminal records, every captured comparison byte binding, raw HTTP and worker output, and original source AST equivalence. Failed attempts are rejected before requiring model artifacts. Completed attempts use the existing controlled strict semantic replay; benign and unknown become legal rejected sources only after reaching its actionable-attack gate. Actionable sources require a real typed portable replay. New terminal indexes are explicitly distinct from immutable original manifests.

**Constraints:** No original files modified; no supplier calls, budget construction, database access, registration, epoch, service gates, or copied Python execution. Existing production files/tests remain untouched while the independent full suite runs.

- [x] Add narrow tests for all-36 order and terminal integrity, zero-payload failures, legal non-attack replay, and citation/source drift refusal; observe the missing-module failure.
- [x] Add `evals/e_source_selection.py` with the terminal reader and exact inventory export; keep immutable original manifest hashes only for verified selected lineage.
- [x] Run the narrow tests with the existing virtualenv, no bytecode/cache, and a unique temporary directory.
- [x] Export a new actual receipt and 36 indexes; verify all 25 legal completed outputs and all 11 failed attempts, all captured bytes unchanged, exact 9-key selected lineage, and EPlanning consumption.
- [x] Record the receipt byte and canonical hashes, code/test evidence, limitations, and zero-side-effect scope in the requested audit report.
