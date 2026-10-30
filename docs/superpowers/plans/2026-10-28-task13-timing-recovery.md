# Task13 Timing Recovery Implementation Plan

> For agentic workers: use subagent-driven-development for bounded implementation and independent review.

**Goal:** Repair the identified errors and make a real evidence-supported, actually user-approved plan usable in real E timing without an unresolved interruption. Verify the actual complete six-branch lifecycle and pursue the three authorized trials; a successful free test, new candidate, null response, approval, or mere branch start alone does not complete the updated goal.

**Architecture:** Preserve the stopped ef46d66 candidate and repair successor code in this isolated worktree. Derive physical call identity from trusted request inputs through the actual wrapper contract; retain independent raw-response, reservation, and cross-slot checks. Separately verify an eligible observable source and a startup path that fits the existing 1800-second TTL before preparing the concrete recovery scope.

**Tech Stack:** Existing Python 3.12, pytest, SQLite account, PostgreSQL/OpenSearch, fixed Linux worker image and Task13 host.

## Global Constraints

- Latest user goal explicitly authorizes completing the necessary engineering and preparation. Existing exact sending approval does not permit replay after null/failure/unknown; prepare a concrete recovery packet before any further model send.
- Frozen source ef46d664aa4727a21e03cd71e218df50de77e3e8, its archived bytes, existing epochs, slots, halt records and provider evidence remain unchanged.
- Original account remains authoritative: 52 supplement development physical requests, 0.36919368 CNY spent, 6 CNY development cap, supplement unknown/inflight both zero. Preserve historical original formal unknowns and original 3350-row prefix.
- No external model calls during engineering. Tests use temporary isolated accounts and synthetic transport only; never load provider keys or modify the real account.
- No forced actions, fabricated evidence, fallback timing credit, hidden labels, model-output shopping, TTL extension, or backdated approvals.
- Keep Beijing 19:00–00:00, TTL 1800 seconds, strict remaining >1500 seconds before first branch, branch timeout180 seconds and total1200 seconds unless a separately reviewed recovery requires a concrete user-approved scope change.
- Each real plan requires actual user approval; general scope approval is not plan approval.

## Task 1: Repair physical identity verification

Files: evals/adapters/model_identity_runtime.py; evals/tests/test_model_identity_runtime.py; related existing identity/worker tests only as needed.

- [x] Reproduce the real RespondOnlyModel -> StableCallModel -> TrackedModel wrapper chain against temporary registered identity/account and fake HTTP response. It must currently fail with `physical ledger belongs to another planning slot` for its own valid response.
- [x] Derive the expected inner hint deterministically from trusted request.slot_id, role respond and logical ordinal1 (`v2-` + canonical_hash([slot_id, 'respond', 1])); do not trust a ledger-supplied hint to decide expected identity.
- [x] Keep exact reservation mapping, raw model/fingerprint and physical-attempt validation. Reject another slot, forged stable hint, wrong role and mismatched raw identity. Cover both null and nonempty parsed outputs and retries through the real wrappers where necessary.
- [x] Run targeted identity/model-client/budget/E no-plan tests; record failing and passing evidence, lint/format, independent review. Do not rewrite original unknown/halt as success.

Evidence: commit c75683abf06c009d9759e411d5c9f2f154dca17a; independent review `.tmp/task13-timing-recovery-task1-review.md` reports no Critical/Important findings. The fixed verifier also accepted the actual retained provider response in a read-only check, with the original account/start/terminal/halt hashes unchanged: `data/task13/supplements/task13-repair-202610-v2/audit/identity-plan1-fixed-verifier-readonly-20261028.json`. Its actual plan remains null; this is not timing credit or authority to retry the stopped slot.

## Task 2: Establish eligible source and startup feasibility

- [x] Read the actual supplement plan and existing source-selection rejection evidence. Identify a permitted observable source with sufficient action evidence, or document the exact source/analysis work required. Do not substitute synthetic evidence for real timing.
- [x] Measure free repeated startup costs and identify why multiple review invocations may exceed the 300-second bootstrap allowance. Select the least invasive evidence-preserving solution after measurement, then test before adopting.
- [x] Retain verified original PostgreSQL multi-host routing receipt for host/worker connectivity; use original service credentials, no model key, and exact approved service targets only.
- [x] Add strict v4 epoch-aware one-analysis development admission while preserving v2/v3 contracts. Commit f4c11936edac423fb1e5b0a371d7da615162c94c; 232 focused tests pass; independent review `.tmp/task13-timing-recovery-epoch-development-review.md` reports no Critical/Important findings.
- [x] Finish independent additional-analysis package replay and bind it through source selection, planning, approval and timing; retain all legacy-source guards.
- [x] Verify the integrated free flow and actual service/startup budget before freezing a successor or requesting its sending scope. Final production source 7239ffd15daa3c8f19178494c80a79ac3783256e passed 156 timing/controller tests, 7 real-service checks, R1/R2 and native Linux verification. Full real approval-to-first-branch TTL remains an actual execution measurement, not claimed from component tests.

Source preparation: existing development case `ait-635abb2308567d0b7afb6602`, 19 original events, frozen under `audit/timing-recovery-development-case-20261028`. Selection uses observable event content and is disclosed as devised after raw development inspection. The user approved its one-analysis/three-plan scope via call_e9f8e2891f9e4487b3663232770ecf57/0. Source epoch4 and same expected model identity successor1 have now been registered while preserving old rows. The one authorized analysis launch began at 2026-10-28 13:06 UTC and stopped at 13:07:23 UTC: actual lookup_attack_technique returned DEPENDENCY_TIMEOUT before any model request. The unchanged account and exact resource cleanup were independently verified. No analysis/package/planning/timing credit was produced; the original stopped attempt will not be replayed.

Startup preparation: repeated complete original dependency/knowledge hashes took 8.134–8.476 seconds after warming; fixed-image imports took 20.068–20.760 seconds. Prewarming keeps normal full checks intact. These measurements and the verified PostgreSQL multi-host route do not yet establish integrated approval-to-first-branch TTL compliance.

## Task 3: Freeze successor and obtain necessary actual decisions

- [x] Export the reviewed successor commit, verify required gates and actual service environment, and prepare one concrete recovery packet binding source, model, case, budget, request count and unchanged timing window.
- [x] Reuse valid existing user authorization where its scope remains sufficient; obtain only the new sending/source scope actually needed after the recorded stop. Actual approved scope packet SHA bc31ed2c7e2ba88b739bb53be02e4237f3c3e1f8d6c19a5f58941bfa22b08d7b; answer “确认按新确认单发送，继续三次计时”. No repeated scope confirmation is needed for its deterministic analysis/E metadata. Each actual plan still needs its separate decision. Previous stop evidence remains intact.
- [ ] Generate one real plan, inspect its actual approval packet, and obtain the user's exact-plan decision. Null/failure/unknown/drift stops the sending sequence and triggers evidence-based recovery.

## Task 4: Verify actual timing start

- [ ] Record the actual approval in the product and execute the frozen timing entrypoint with service-only credentials.
- [ ] Inspect authoritative timing journal/worker evidence proving a real first branch has started from that exact approved plan within its validity period. Continue authorized six-branch lifecycle; preserve any terminal failure.
- [ ] Mark the active goal complete only after the repaired real plan/approval/timing lifecycle completes without an unresolved interruption and all required completion evidence is inspected, not merely predicted by tests or receipts.

## Task 5: Repair proven native MCP cold initialization timeout

Observed evidence: the actual worker service/isolation probes passed, but its first hybrid knowledge lookup exceeded the audited tool's 9-second work allowance (10 seconds including audit). A free offline measurement in the identical image/source/dependencies/knowledge mounts and 2 CPU/2 GB limits measured first embed 12.0718 seconds, including verified model file reads 2.0269, fastembed import 6.3709 and total model loading 12.0384. The second same-process embed took 0.0110 seconds and produced an identical vector. The original query, model, top5, tool deadline and retrieval semantics must remain unchanged.

Coverage gap: the seven service tests cover imported-analysis planning, with initial retrieval disabled. R1/R2 do exercise fresh real MCP/embedding on Windows, but not the actual constrained Linux worker and this frozen query. The earlier Linux gate checks contracts/package replay and native links, not initial MCP retrieval.

Minimal design: expose offline provider preparation without a fake query; attach it to the same AttackLookupWork/provider used for later calls. Keep build_server/discovery lazy by default. Only the actual MCP process startup, after context validation and when capability permits knowledge lookup and retrieval is enabled, prepares that provider before serving requests. A preparation failure must stop startup; tool runtime/audit limits remain unchanged. Warming an unrelated parent/probe process does not satisfy this requirement.

- [x] Retain the actual stopped attempt and independently establish zero provider calls, unchanged fees and exact cleanup.
- [x] Measure the identical offline model's first-load versus same-process subsequent query cost.
- [x] Implement explicit preparation, same-provider reuse, startup policy and error propagation; 65 focused tests passed on 2026-10-30. Prior unit RED output is unavailable and not newly asserted. Actual stopped worker evidence remains the direct failure evidence.
- [x] Run the native real-MCP query gate with fixed query/top5, actual dependencies and temporary service resources. Exact old-code control passed at7.7527s on the warmed host; do not relabel it as failing RED. Fixed snapshot passed at0.3052s after18.0783s initialization, with identical five returned blocks and content/order. No provider or original account access; all four test containers/databases confirmed absent. Frozen source115 files unchanged.
- [x] Independently review the change (C0/I0), commit6b5e75bc678add0b18a82e6b0136baa758e05b80, and prepare the concrete successor/recovery materials. The failed original attempt remains terminal; zero provider calls do not imply replay authorization.

Prepared on2026-10-30: `BASE/development/cold-recovery-candidate-20261030-6b5e75bc/scope-packet.json`, raw SHA38f0ef00a6730a12ae2645cc25f7c0e3336f5b1c83f8122853309e8bbbc68fe0. Source5/model2 are proposals only. Pending: actual changed-source recovery decision, registration, a qualified analysis, three real plans and their individual approvals/timings. Original19–00 window/deadline/budget remain in force. Free verification evidence: `BASE/development/cold-recovery-engineering-20261030/verification.json`.
