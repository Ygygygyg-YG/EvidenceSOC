# Task13 manual audit recovery implementation plan

> **For agentic workers:** Use subagent-driven-development and verification-before-completion. Implement and review the tasks below without requesting another design approval. Actual adoption and case-data outbound remain separate, final concrete approvals.

**Goal:** Preserve the stopped pool and C10 evidence while making exactly five remaining planning attempts available through a separately approved recovery protocol.

**Architecture:** A new parent registration/receipt v2 wraps two unchanged native three-slot registrations. A separate native authority v2 grants the first child three requests and the second child two, and rejects its third request in the native journal. A pinned manual quarantine records the predecessor's original unknown stop; it never changes that stop or grants timing credit.

**Tech stack:** Existing Python/Pydantic, SQLite append-only ledgers, native timing controller, isolated Docker runtime and the existing backend virtual environment.

**Resumed candidate status (2026-11-01):** Implementation for Tasks 1–5 is present. The root-owned stable baseline was 946 passed / 6 legacy-fixture failures / 10 skips; those fixture corrections remain under their full targeted rerun. Three integration findings and two COW-harness findings have been fixed and independently re-reviewed with zero remaining Critical/Important findings in those scopes. Fresh core verification is 217 passed. This is a development candidate for free validation, not final acceptance, metadata adoption, outbound authority or new timing credit. The original unknown prefix, one eligible C10 observation and remaining five logical/fifteen physical requests remain unchanged. Actual original-path quarantine, complete opt-in COW/native rehearsal, final whole-branch acceptance and the concrete user-approved scope still gate real recovery.

## Global constraints

- Development permission is the actual reply to `call_7ea4eaaa5a3a4ce6b4d9f8f87d719644`, archived under the predecessor's activation directory. It authorizes free implementation and independent review, not adoption or case-data outbound.
- Preserve predecessor registration, journal bytes and head `68a42b853ae3ba98b9fc0605e0cf7e635f63ece6212d78d9883cda31fad7f4d9`. Do not clear STOP, label the old attempt as TTL-settled, or invoke its resume.
- Historical planning consumed: 8 logical / 24 physical. Remaining: 5 / 15. Maximum: 13 / 39; with the original analysis, 40 physical. Do not add attempts or reset spending.
- Development cumulative cap is CNY 6. Deadline is 2026-11-02 23:59:59 Asia/Shanghai. Original global halt and two legacy unknown reservations remain unchanged.
- Preserve business logic, provider/model configuration and received identity, plan TTL 1800 seconds, first-dispatch remaining time strictly greater than 1500 seconds, per-branch 180 seconds and total 1200 seconds. Do not renew plans or combine results across expiry.
- C10 source9/model6 observation 384.562 seconds is the only candidate import. Revalidate its full raw evidence and execution equivalence; incompatibility stops this recovery, without an automatic whole-group rerun.
- Original worker inventory remains all 117 paths. Authorization/recovery changes require precise before/after file and AST review; no whole-file exclusions. Native e_timing.py and e_planning.py remain byte-identical.
- New source/model identities use the actual latest predecessors. Do not relabel old requests or results with new identities.
- Preserve old v1 schemas, serialization, hashes and strict six-slot validation.
- Keep one pending actual plan approval at a time. Real plan handoff remains exclusive to the root, with five-second polling and immediate high-resolution capture.

## Task 1: Native limited authorization

Files: `evals/adapters/e_planning_journal.py`, the authority parser call in `scripts/task13_e_trial.py`, and `evals/tests/test_e_planning_limited_authority.py`.

- [x] Reproduce v1 rejection of a limited grant before implementing v2.
- [x] Keep `EPlanningAuthority` v1 unchanged; add `ManualRecoveryGrant`, `LimitedEPlanningAuthority` and `parse_authority(value)`.
- [x] Retain three registered request hashes. Require disjoint ordered authorized/denied lists covering exactly those hashes; bind the two grant children to exactly 3+2 authorized requests.
- [x] Refuse denied requests in native validation and transactional claim. Refuse a journal containing a denied claim, even if its other fields were rehashed.
- [x] Run limited authorization plus legacy journal/worker/controller tests. Actual result: 201 passed; preserve failed sandbox hardlink runs as well.

The grant binds fixed counts and limits, recovery-plan/quarantine hashes, predecessor registration/raw journal/head hashes, actual future scope/decision hashes and both new child registrations. It does not reference the final parent hash.

## Task 2: Independent execution equivalence

Files: `evals/recovery_equivalence.py`, `evals/tests/test_recovery_equivalence.py`.

Public interfaces:

```python
describe_ast_nodes(path)
review_policy_fingerprint(policy)
validate_recovery_equivalence(original_execution, candidate_execution, policy_pin)
```

- [x] Validate the original independently pinned worker receipt and all 117 original/candidate files.
- [x] Require native timing/planning/verification and host-trial paths, with exact reviewed changes for permitted control nodes.
- [x] Close every permitted AST hole with before/after node hashes and complete before/after raw-file hashes; compare the remaining AST structure exactly.
- [x] Reject unregistered transformation fingerprints, omitted files, link/reparse paths, business drift, type drift and forged whole-class exclusions.
- [x] Keep the production reviewed-policy registry empty until the final actual transformation has been independently reviewed.
- [x] Mark the result as source-and-declared-conditions only, with no authorization or timing credit. Actual native evidence and received model identity remain mandatory outer checks.

Register the reviewed transformation fingerprint rather than the complete policy-file hash: the fingerprint covers the worker/native maps and exact changes, but excludes future commit/identity/binding/review fields. The final scope separately pins the complete raw policy and final controller freeze, avoiding a self-referential commit hash.

## Task 3: Quarantine and adoption locks

Files: `evals/timing_pool_recovery.py`, authorization-only changes to `source_epochs.py` and `model_identities.py`, and dedicated tests.

Public interfaces:

```python
manual_recovery_quiescence(spec)  # context manager yielding RecoveryLease
audit_old_pool_locked(inputs, *, lease)
validate_quarantine_evidence(evidence, *, expected_scope)
```

- [ ] Bind the exact predecessor manifest/head and verify all plan/read/decision evidence, actual approval, settled physical requests, both native genesis journals, zero dispatched branches and fresh owned-worker absence.
- [ ] Hold all predecessor pool/host fences and locks. Reject every unrelated pending or unknown prefix.
- [ ] Keep the native registry locks and SQL transaction. An optional `locked_audit` callback only adds verification immediately before insertion; it cannot skip the original checks.
- [ ] Authenticate the callback's live native-lock capability, rather than trusting a caller-supplied list.
- [ ] Bind the stable baseline audit to the independent recovery-plan pin. The later scope pins this audit; do not put a future scope hash into the baseline and create a hash cycle.
- [ ] Verify rollback on audit rejection, stale/forged leases, missing locks, active workers, changed approval, unsettled cost and changed raw evidence.

## Task 4: Parent policy, controller and consumers

Files: `evals/timing_pool.py`, `timing_pool_controller.py`, `timing_pool_evidence.py`, `scripts/task13_timing_pool.py`, host-trial control integration and consumer schema routing.

- [ ] Add strict `pool_policy(pool_or_schema)` dispatch: v1 = future6/history7/21; v2 = future5/history8/24.
- [ ] Require explicit v2 journal genesis with the complete grant and quarantine binding. Default v1 initialization must continue to reject five slots.
- [ ] Make v2 attempt order exactly the five authorized requests; list and inspect the denied sixth structural slot separately.
- [ ] Reject any denied-slot claim, planning/decision/trial artifact or native branch activity, including activity outside the five-attempt inventory.
- [ ] Preserve earliest-three selection, all failures, max(wall, monotonic), strict cross-child first-dispatch guards, TTL recovery rules and unknown hard stops.
- [ ] Route formal176/F8 receipt consumers by exact schema; never synthesize a native three-observation receipt.
- [ ] Normalize only the explicitly future source/model/authority and scope/decision grant hashes in proposals; recompute dependent request/grant hashes and retain all historical pins.

## Task 5: Pending compiler and explicit adoption

File: `scripts/task13_manual_recovery.py`, with isolated compiler/adoption tests.

```python
prepare(spec)
compile_adoption(preparation, preparation_pin, request_pin, chat_pin)
adopt(spec, *, resume=False)
```

- [ ] Read current source10/model7, original analysis, raw ledger, predecessor quarantine and actual C10 evidence. Fix new IDs and the five future attempts before scope submission.
- [ ] Build inert proposals and a concrete scope question. Prepared questions are not user decisions; do not create authority, native registrations or an execution journal during preparation.
- [ ] Require the exact actual question reply and a separately pinned independent scope review before any metadata adoption.
- [ ] Validate only durable metadata prefixes (0,0), (1,0), (1,1), with no changes to old tables/rows except exact source/model appends. Resume uses the identical original authority and materials.
- [ ] Register source/model, then two limited native child authorities, native timing genesis and the new parent genesis. Never execute a plan from an adoption operation.
- [ ] Retire the old five requests through latest-source identity and the preserved old STOP, with no double-run interval.

## Task 6: Free final verification and handoff

- [ ] Verify migration tampering, duplicate adoption, every durable-prefix crash boundary, five-slot exhaustion, concurrent claims, unknown cost/execution, legacy v1 strictness, actual-plan TTL boundaries and source identity drift.
- [ ] Run the complete affected free suite once on stable bytes; retain failures and skips, and rerun only cases with a justified change or unresolved issue.
- [ ] Run a COW native NoGO rehearsal with no provider key or planning credit, preserving the actual original databases and old evidence byte-for-byte.
- [ ] Complete independent whole-change review and register the exact reviewed transformation. Revalidate real C10 evidence without issuing analysis or planning requests.
- [ ] Freeze the final code, dependencies, image, model, knowledge, configuration and evidence. Prepare the concrete five-attempt recovery scope, with actual final hashes and exact remaining budget.
- [ ] Stop for that concrete scope approval. Each later real plan remains separately approved. Formal176/F8 still requires its joint concrete scope after timing acceptance.
