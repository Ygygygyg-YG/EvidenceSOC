# Task13 backend implementation record

2026-10-18. This record covers the P3 backend integration. It is not a formal experiment result or a Task13 completion declaration. No model request was made by this backend work package.

## Contracts and original graph

The canonical answer-free contract lives in `services/backend/src/evidencesoc/agents/diagnosis.py`: `Diagnosis`, `FactClaim`, and `StageInstance`. Mapped attack types are unique members of the frozen six-class taxonomy. `attack + out_of_taxonomy` remains an attack. Existing `AttackClassification` and public API response models retain their existing shapes. `AnalysisOutput.diagnosis` is optional for old product callers; the evaluation adapter must require it for actual evaluation analysis responses.

`InvestigationWorkflow(..., capabilities=None, initial_state=None)` uses the existing six-role LangGraph. Trusted initial input may contain only `alerts`, `evidence`, `knowledge`, and an opaque `verification_namespace`. Existing `WorkflowServices` implementations and in-memory checkpointers remain usable. Explicit benign ends without response planning; explicit attack routes to reconstruction even with no mapped types; unknown retains the original single collection fallback. The legacy classification route is used only when no explicit diagnosis exists.

Analysis/reconstruction status is distinct from product status. An exhausted model/schema retry records diagnosis failure even when the product rule fallback provides an inspectable output. Canonical origin entities require actual cited observations, and technique mappings require retrieved knowledge. Reconstruction updates canonical stage instances from the actual reconstructed steps.

The graph seals a deep-copied `diagnostic_snapshot` with SHA-256 after the last legal analysis/reconstruction and before response/approval/simulation. Benign and terminal unknown also receive snapshots. Later response evidence cannot alter the sealed diagnostic input. Checkpoints retain internal fields; `AgentRunTable.output_summary` persists diagnosis/snapshot/status without a new table or public endpoint.

## Capability integration

`InvestigationCapabilities(allowed_tools, rag_mode, verification_enabled, first_round_reserved_calls, total_reserved_calls)` is immutable and opt-in. Defaults preserve existing product capabilities. `capability_scope(policy)` carries trusted restrictions through asynchronous calls and threads. The policy is injected into the workflow, node handlers, collector, and `PostgresWorkflowServices`.

The collector advertises only enabled tools, rejects disabled choices before dispatch, and skips the initial alert query when disabled. A1 reserves a nontransferable first-round slot and one total slot, so actual logical calls remain at most two in round one and five overall. Reservations are reported independently of real charged calls. `Ledger` enforces effective limits inside its existing incident transaction lock; its new reservation keywords default to zero. Each physical tool attempt still passes through the existing limit of three.

`HybridRetriever(..., mode=None)`, `HybridAttackKnowledgeRepository(..., mode=None)`, and `retrieve_knowledge(..., mode=None)` support `hybrid`, `semantic_only`, and `disabled`. Trusted context restrictions cannot be expanded by a caller argument. Semantic-only skips both the technique-ID exact shortcut and keyword channel; direct PostgreSQL exact/keyword entrypoints also reject that context. Disabled public retrieval rejects before opening its database or embedding model. MCP child capability transport and the legacy attack-work guard are integrated outside this backend-owned file set.

`DeepSeekStructuredModel` includes diagnosis in role context. The evaluation model wrapper must perform exactly one physical request per `structured(...)` invocation: `NodeHandlers` and `BoundedCollector` own the total three-attempt transport/schema retry budget; SDK retries must remain zero.

## Simulation observations

`EffectObservation` is a strict typed contract in `agents/verification.py`. It contains only opaque namespace, action ID, target, observation time, evidence IDs, the relevant observed control flags, and optional explicit error code. It rejects condition/truth labels. `evaluate_simulated_effect(action_type, before, after)` is deterministic and introduces no validation LLM.

Frozen transitions are unblocked→blocked, connected→isolated, and enabled→disabled for the three existing simulated actions. Matching target, approval, and completed simulated execution are necessary but insufficient. Missing, unchanged, unordered, mismatched, or uncited observations yield `insufficient_evidence`; an explicit cited post-action error yields `failure`. Success remains simulated evidence and cannot establish real traffic blocking.

`PostgresWorkflowServices(..., verification_observer=None)` optionally accepts an asynchronous observer `(state, run_id, normal_verify_result) -> dict`. Its return may contain only `effect_observations` and registered `evidence`. The observations map is `{check_id: {before: EffectObservation, after: EffectObservation}}`. The validate node checks the current opaque namespace, approved action/target, and real before/after citations before computing the outcome. PostgreSQL observers must register returned evidence in the isolated database before persistence. Worker-specific services may implement the same interface directly.

Validation evidence has its own state registry, and both validation IDs and validation run IDs include the opaque namespace. Paired conditions still require independent workers/checkpointers/database copies, as specified; namespace suffixes alone are not proof of worker isolation. Disabled verification performs no verifier call and explicitly returns `unverified` with no success result. Static production log requery now correctly ends in manual review with insufficient evidence.

## Verification evidence

Tests were written and observed failing before the corresponding new behavior: explicit verdict routing, mapped taxonomy rejection, semantic-only exact bypass, repository bypass, A1 effective/atomic budgets, pre-response snapshots, three observed effect outcomes, missing observation namespaces, canonical origin provenance, and model retry failure status.

The real PostgreSQL/OpenSearch/MCP acceptance suite completed with **2 passed, 0 skipped**. It exercised the original six roles, human approval interfaces, fresh-process checkpoint resume, and all three simulated actions. It used fixture diagnosis and did not call a model. Static evidence remained insufficient rather than being misreported as effect success.

For local Windows tests, unset inherited `SSLKEYLOGFILE` in the test process and choose `--basetemp` under workspace `.pytest_cache`; the inherited external TLS key-log path and default sandbox temp directory otherwise cause unrelated permission failures. Use the existing backend interpreter directly when the default uv cache is inaccessible:

```powershell
Remove-Item Env:SSLKEYLOGFILE -ErrorAction SilentlyContinue
& services/backend/.venv/Scripts/python.exe -m pytest services/backend/tests/agents/test_nodes.py services/backend/tests/agents/test_graph.py services/backend/tests/agents/test_model.py services/backend/tests/agents/test_collection_planner.py services/backend/tests/agents/test_collect_policy.py services/backend/tests/agents/test_services.py services/backend/tests/agents/test_task13_contracts.py services/backend/tests/rag/test_retrieval.py services/backend/tests/tools/test_ledger.py --basetemp .pytest_cache/task13-backend-verification -q
& services/backend/.venv/Scripts/python.exe -m pytest services/backend/tests/agents/test_acceptance.py --basetemp .pytest_cache/task13-backend-live-verification -q
```

Formal worker isolation, model metadata/usage/cost, the 704-item matrix, actual approvals/reviews, independent paired validation coverage, frozen implementation SHA, and final figures are separate Task13 gates. Backend tests cannot substitute for those gates.

## Resume audit, 2026-10-19

The interrupted answer-free observer adapter is now implemented in
`evals/adapters/verification_observations.py`. `clone_approved_state` verifies the
exact approved plan and sealed diagnostic hash, deep-copies the state, and adds a
random opaque 128-bit namespace. `ControlledObservationAdapter` accepts only
measured timestamps, control flags and explicit error codes. It registers an
independent before/after evidence pair per approved action through a mandatory
asynchronous callback before returning observations. Evidence identifiers include
the namespace in their digest, so paired workers cannot alias each other's
records. Registration must write to each worker's actual isolated evidence store;
the adapter itself does not establish container or database isolation.

The original validate node now accepts registered baseline observations returned
in that same verification batch without changing the sealed diagnostic registry.
It cites the returned after evidence and still enforces the approved target,
action, plan version, completed simulation, namespace and ordered transition.
Malformed observation maps yield `insufficient_evidence`. Effect flags are strict
booleans: strings and numbers cannot be coerced into a successful transition.
Existing static-target checks remain insufficient evidence.

`PostgresWorkflowServices(model_timeout=...)` passes the frozen per-call timeout
to `BoundedCollector`; its product default remains 60 seconds. The evaluation
caller must supply the model configuration's frozen timeout (120 seconds in the
current default evaluation configuration). `NodeHandlers._structured` and every
collector planning decision now create `_model_call_id` once before their retry
loop and pass the same ID on all three physical attempts. The evaluation model
wrapper must use this ID, including when schema parsing succeeds but the caller
rejects citations or a missing explicit Diagnosis. Each separate logical decision
gets a new ID. Missing Diagnosis is rejected inside the analysis retry loop and
exhaustion records `diagnosis_execution_status=failed`.

New red/green regressions reproduced frozen-timeout loss, permissive boolean
coercion, absent logical-call IDs, and malformed observation-map exceptions.
The A1 concurrent-reservation test also verifies exactly two successful first
round reservations and three second round reservations under eight competing
threads, with five charged calls overall.

Fresh sandbox verification after these fixes: **351 passed, 3 skipped** for all
agents/tools/RAG tests plus observation contracts, excluding
`tests/agents/test_acceptance.py` and `tests/tools/test_mcp_client.py`. Ruff check
passed for the backend-owned source, affected tests and observation adapter. This
run used the existing `.venv` interpreter, unset `SSLKEYLOGFILE`, and the local
`.tmp/pytest_inherited.py` launcher, which preserves inherited Windows ACLs only
when pytest creates a directory under workspace `.tmp` with mode 0700.

The broader sandbox run reached **350 passed, 3 skipped, 4 failed** before the
last malformed-observation and concurrency additions. All four failures arose
from Windows named-pipe `CreateFile` permission errors while starting real MCP
children (the two live acceptance tests and two MCP client tests). The requested
fixture-only elevated rerun was not executed: automatic approval review failed
because its selected model was at capacity. That review failure was not a safety
rejection, and no approval check was bypassed. The earlier 2026-10-18 live result
above remains historical; this resume audit does not claim a fresh live pass.
No paid model request, Task12 data change or commit was made by this work package.

## F8 retained workflow and approval audit, 2026-10-19

The controller preserves the complete 88-case, three-condition plan: 264 pairs
and 528 enabled/disabled branches. Missing sources, diagnosis failures, benign or
unknown diagnoses, expired plans, rejected decisions, unpersisted approvals and
invalid worker receipts remain explicit rows. No shortened executable subset
replaces those planned denominators. Controller condition names stay outside the
strict answer-free worker input.

`resource_fields` forwards only `database_name` and `index_name` from the full
retained `case-resource.json` reference. `SourceResources` requires both names to
share one case namespace. Workers copy that actual PostgreSQL database and
OpenSearch index to a fresh, matching branch namespace. The copied product
approval/plan rows and full original checkpoint must match the approved input.
Before and after observation evidence is registered only in that branch's copy.
The disabled branch performs no verification calls and reports `unverified`.

Review packets bind the complete original checkpoint hash, sealed diagnostic
hash and response-plan hash. A changed checkpoint is rejected before approval
or renewal; earlier code emitted the full state hash but checked only the other
two hashes. The regression was observed failing for both operations before the
full hash check was added. Imported JSON approvals alone cannot pass the
PostgreSQL row verifier.

`open_retained_workflow(reference, model=None)` opens the retained database/index
and original PostgreSQL checkpointer with explicit `NodeHandlers`. Packet reads
and explicit decisions use no model. `renew_expired_plan` accepts only that
factory's exact `TrackedModel` bound to the node handlers and workflow services.
Its account must be the existing `TASK13_BUDGET_DB` with unchanged 100 CNY total
and 15 CNY development limits. Renewal also requires phase `verification`, PID 1,
a worker nonce and the retained reference's source commit matching
`TASK13_SOURCE_COMMIT`. Fixture and untracked workflows cannot renew plans.

`SourceReviewRequest` and `run_source_review` expose `read_packet`, `decision`
and `renew_plan`. The inspected runtime entrypoint is
`scripts.task13_worker_runtime.run_source_review_container`. It binds the actual
agent file hash and source commit, uses the existing isolation handshake, and
passes a model credential only for renewal. A decision requires the original
review packet, explicit `approved`/`rejected` input, a nonempty reason and reviewer
`user`. A packet read neither supplies nor records a decision. Expired decisions
are refused without inserting an approval row.

Renewal invokes the original `InvestigationWorkflow.renew_plan`: the product
rehydrates its evidence and regenerates its response plan through `respond`.
It does not rerun reconstruction. The renewal model has one logical decision and
at most three physical attempts, charged through the same campaign account.
Missing valid model output or a new response model error leaves the review worker
failed. Renewal produces a fresh pending packet and never approves it. The
result exports model/tool ledgers, checkpoint hashes and the source reference
without credentials; the controller must preserve that immutable result.

### Callable operation sequence

Use the actual B3 `case-resource.json`, neutral case record, frozen runtime
options and corresponding agent directory. No database names or approval
decisions should be invented. This helper writes an immutable controller copy of
each real worker result:

```python
import uuid
from pathlib import Path

from evals.adapters.verification_worker import SourceReviewRequest
from evals.runners.manifest import write_immutable_json
from evals.verification import resource_fields
from scripts.task13_worker_runtime import run_source_review_container


async def review_operation(
    operation, *, case, reference, agent_dir, runtime_options, audit_dir,
    model_config, packet=None, decision=None, reason=None,
):
    assert reference["source_commit"] == runtime_options["source_commit"]
    supplied = {}
    if packet is not None:
        supplied["packet"] = packet
    if decision is not None:
        supplied.update(decision=decision, reason=reason)
    request = SourceReviewRequest(
        request_id=uuid.uuid4().hex, namespace=uuid.uuid4().hex,
        case_id=case["case_id"], dataset=case["dataset"],
        agent_sha256=case["agent_sha256"],
        source_commit=reference["source_commit"],
        source_resources=resource_fields(reference),
        incident_id=reference["incident_id"], operation=operation,
        model=model_config, **supplied,
    )
    options = {**runtime_options, "phase": "verification"}
    value = await run_source_review_container(request, Path(agent_dir), options)
    write_immutable_json(Path(audit_dir) / (request.request_id + ".json"), value)
    if value["status"] != "completed":
        raise RuntimeError(value["error_type"])
    return value
```

1. Call `review_operation("read_packet", ...)` and show its `approval_packet`
   to the actual user. The packet contains the real plan and its hashes.
2. If it reports `renewal_required`, call `review_operation("renew_plan", ...,
   packet=packet)` only for the user's renewal request. This is a real budgeted
   model operation. Show the returned fresh pending packet to the user.
3. After the user gives a decision and reason, call
   `review_operation("decision", ..., packet=current_packet,
   decision=user_decision, reason=user_reason)`. Never substitute an agent's
   inference for that input. Preserve the result and its persistent receipt.
4. For an approved result, assign `sources[case["case_id"]] = value["source"]`.
   Call `run_verification_plan(complete_plan, sources, worker=worker,
   approval_verifier=verify_source_approval, output_dir=...)`, where `worker`
   delegates to `run_verification_container(request,
   agent_directories[request.case_id], runtime_options)`. The complete plan is
   built from all 22 AIT and 66 DEDALE case rows. Missing or ineligible sources
   still produce all their planned rows.

The original retained database/index must remain available through review and
paired execution. Every worker deletes only its own fresh copies. A plan that
expires before or during copying remains unexecuted until another original
renewal and explicit user decision.

### Synthetic live evidence and limits

The opt-in `evals/tests/test_verification_live.py` uses synthetic raw logs, an
expired synthetic plan, an HTTP-mocked real `TrackedModel` with a separate
synthetic account, and a clearly labeled fixture decision through the original
persistent workflow. It exercises packet reads, refusal of an expired decision,
original renewal, fresh review, PostgreSQL approval rows, real checkpoint resume,
real MCP queries, all six independent PostgreSQL/OpenSearch branch copies and
their cleanup. Observed outcomes are `success/unverified`, `failure/unverified`
and `insufficient_evidence/unverified`; enabled/disabled tool calls are 1/0.
The source stores survive while all six branch stores are removed.

This test substitutes the PID1 guard and nonce, so it cannot establish container
isolation. Its mocked provider usage/accounting and fixture decision are never
formal model usage, experiment approvals or human review metrics. It makes no
paid request and does not touch the real campaign account or Task12 data.

Run the complete verification contract suite plus live synthetic replay with:

```powershell
$env:TASK13_LIVE_SYNTHETIC_VERIFICATION='1'
& services/backend/.venv/Scripts/python.exe .tmp/pytest_inherited.py `
  evals/tests/test_verification_plan.py evals/tests/test_verification_observations.py `
  evals/tests/test_verification_live.py evals/tests/test_worker_isolation.py `
  -p no:cacheprovider --basetemp D:\传智杯\.tmp\verification-fresh-unique -q
```

Formal F8 results still require actual retained B3 sources, actual user decisions,
fresh original renewals when necessary, and inspected container receipts from
the frozen source/runtime. Passing synthetic tests cannot replace those gates.

Fresh combined verification after the guarded worker and live synthetic renewal
were implemented: **51 passed in 26.01s** across verification contracts,
observations, the opt-in live test and runtime isolation tests. Ruff check and
format checks passed for all six owned Python source/test files. No commit was
made by this work package.
