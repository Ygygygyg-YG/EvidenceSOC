# Task13 Source Epochs Implementation Plan

> **For agentic workers:** Execute this isolated plan using executing-plans and test-driven-development. No commit or live registration is authorized by this plan.

**Goal:** Allow a host to append explicitly authorized source epochs to the existing supplement budget without resetting any historical accounting or silently registering an epoch in a worker.

**Architecture:** Keep the legacy constructor and its frozen campaign bytes. A separate host registration module owns append-only epoch and reservation mapping tables; the optional epoch constructor only verifies pre-existing registration. Every reservation validates its epoch and inserts its mapping inside the original BEGIN IMMEDIATE transaction; all monetary sums remain campaign/global sums.

**Tech Stack:** Existing Python, sqlite3, pytest, httpx.MockTransport, Ruff.

## Global Constraints

- Only `D:/传智杯/.backups/task13-stage-e` may receive code changes. Frozen remediation tree and real budget databases receive no writes.
- Tests use pytest `tmp_path` databases; paid transport calls remain zero.
- Preserve 100 total / 15 development / 30 supplement, purpose 6/16/6 and held 2, all historical reservations, IDs and frozen_config bytes.
- `epoch_id=None` keeps the legacy binding and physical key unchanged. Explicit epoch construction cannot create a DB, campaign, schema or registration.
- Registration requires an independently pinned manifest and externally supplied authority record, frozen historical budget identity, and quiescent controller roots and ledger. No consent file or approval is generated.
- Worker/runtime/contracts/bridge/timing files are outside this change.

## Files

- Create `evals/adapters/source_epochs.py`: strict manifest/authority validation, host-only registration, append-only chain and read-only verification.
- Create `scripts/task13_register_source_epoch.py`: explicit host CLI that reads existing manifest/authority JSON only.
- Modify `evals/adapters/budget_v2.py`: optional epoch binding, transactional mapping and cross-epoch semantic duplicate checks.
- Create `evals/tests/test_source_epochs.py`: synthetic historical ledger and adversarial temporary database tests.

### Task 1: Host registration and immutable chain

- [x] Write a synthetic existing ledger fixture and a failing registration/read-only lookup test.
- [x] Run the focused test and confirm missing source epoch capability is the failure.
- [x] Implement strict manifest validation and independent hash-pinned authority input. The manifest also binds the original absolute host budget_path, refusing copied ledgers and filesystem links. Registration verifies fixed historical identity and old campaign/caps in one transaction, acquires existing controller writer locks, rejects active/unknown receipts and any unsettled reservations, and appends epoch 0 only when source/config match the old campaign.
- [x] Add rejection tests for wrong identity/manifest, nonmonotonic numbering, incorrect predecessor, active/inflight state and mutation. Every new behavior starts with a failing test before implementation.

### Task 2: Bound budget integration

- [x] Write failing tests showing explicit construction cannot register/create or change frozen campaign bytes, while an explicitly registered epoch can reserve and settle.
- [x] Add only the optional epoch branch. It uses existing tables via read-only verification; reservation and settlement recheck the epoch and immutable mapping within the original transaction.
- [x] Add failing tests for request ID reuse and semantic replay across source/config/epochs, including role binding. Preserve legacy-to-legacy behavior.
- [x] Verify existing 34 budget tests unchanged, physical key byte equivalence, old reservation/request/frozen_config rows unchanged and no historical mapping backfill.

### Task 3: Accounting, races and model boundary

- [x] Add failing temporary DB tests for aggregate purpose/global/development caps across epochs, unknown/inflight upper bounds, concurrency, wrong-epoch settlement and MockTransport-only model calls.
- [x] Implement the minimum correction exposed by each test; do not add epoch filters to monetary sums.
- [x] Run `evals/tests/test_source_epochs.py`, `test_budget_v2.py`, `test_model_client.py` with the approved Python, new-tree PYTHONPATH, UTF8 and no bytecode.
- [x] Run Ruff on the three implementation files and new tests, inspect the diff, and record real command results/counts/limitations in the external audit report. Leave all changes uncommitted for root review.
