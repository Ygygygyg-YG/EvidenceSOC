# Task13 additional-analysis terminal recovery

The user approved the concrete 6b5e75b recovery scope through
call_bd73558eddbc4419913d86244d0645ec. Actual registration was attempted once and
failed before opening the original budget for mutation. Source/model tables
remain at 5/2 rows; the attempted source 5/model 2 are not registered. Keep the
failed registration receipts and all original analysis artifacts.

## Root cause and design

`_lock_controller_roots` assumes every `started.json` uses the legacy bundle
protocol. The actual failed additional-analysis launcher uses a distinct typed
start record, has no bundle hash, and writes `stop.json` and `launch-receipt.json`
instead of a completed-only `attempt.json`. A finished failed run is consequently
misclassified as active. Manufacturing a legacy bundle field, removing the root,
or dropping the one-shot marker would destroy evidence and is rejected.

Dispatch validation by the actual start schema. Preserve legacy validation and
all writer locks. For additional completed attempts, validate matching typed
bindings and result bytes without granting analysis qualification. For the
failed-before-provider case, require the actual terminal receipt, stop record,
matching bindings, timestamp ordering, pinned original artifact inventory,
failed result, and zero model calls/payloads. Missing, mismatched, altered,
unknown, active or paid-but-unreconciled attempts remain blocked. No networking
or provider call is added to registration. Independently recheck the old exact
resources and ledger before any later actual registration.

The operator check also found an inherited selection-policy path: the launcher
expects the candidate-local path while the proposal reused the predecessor
path. Copy the identical frozen policy bytes into the successor candidate and
update both references, without changing the policy or choosing another case.

Ruling: continue these necessary free fixes under the user's ongoing repair
authorization; no extra design approval. The earlier exact-source sending
approval is retained but cannot silently be relabelled to changed source bytes.
Finish and review the concrete successor before requesting that adoption delta.

## Execution and verification

1. Reproduce the actual additional failed terminal shape with temporary accounts;
   record RED before the production fix and test malformed/active variants.
2. Implement the narrow protocol validation; run source/model/additional-analysis
   integration tests, lint and format checks. Independent review must be C0/I0.
3. Run the fixed locking admission against actual original roots with no budget
   mutation; preserve and compare all existing file bytes and original SQL rows.
   Check exact old container/database/index absence separately.
4. Commit the source correction. Retain the previous cold-start 65 tests and
   native lookup evidence with their original hashes; do not relabel those runs.
5. Prepare the successor source 5/model 2 from the still-latest registered source
   4/model 1. Copy and pin the same policy. Keep the same case, model fingerprint,
   1 analysis + 3 plans / 12 physical requests, 6 CNY total, 19:00–00:00 with user
   presence, original deadline, individual plan approvals and stop conditions.
6. Verify candidate paths and operator interfaces before requesting adoption.
   No actual provider dispatch, E slot registration, plan approval or timing is
   credited by this engineering work.

## Verified result

Production commit: `facd10e2f378fbebbcc8acfe0746e63a15a947dc`.
Related regression: 268 passed, 2 Windows symlink-privilege skips. Actual native
Linux symlink/hardlink/directory-symlink checks passed separately. Three RED
rounds cover the original protocol mismatch, unknown-protocol fallback, and
incomplete finalization/mixed protocols. Independent review: C0/I0. Actual
32-root admission passed; all 64 locks released, all 12 original output files
and all three original SQLite logical states unchanged. The old 6b5 candidate
was not registered and made no provider request.

The new candidate copies identical selection-policy bytes locally. Its frozen
scope packet is `3ee457d67c7f261e3db9d57c55d9c832cfd820935e349c554646efb98e8ee900`
under `development/cold-terminal-candidate-20261030-facd10e2`. It explicitly
replaces the unused 6b5 scope without increasing its maximum 12 requests. New
exact-source adoption was actually approved via
`call_1ba004a856204c05afaed80aea532af5` and source5/model2 were registered once in
the original account. The original rows/schema remain intact. Actual local
launch bindings, source/dependency/knowledge hashes and registered identity
checks passed; midday dispatch and E derivation without a real analysis package
were refused. Resume instructions are saved in the candidate's
`activation/resume-boundary.json`. Original sending bounds persist. Actual
analysis, individual plan approvals and three timing trials remain pending the
19:00–00:00 window with the user present. No new provider request or fee.
