"""Task13 real baselines and original six-role graph adapter."""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from copy import deepcopy
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from evidencesoc.agents.capabilities import InvestigationCapabilities, capability_scope
from evidencesoc.agents.checkpoint import open_checkpointer
from evidencesoc.agents.graph import InvestigationWorkflow
from evidencesoc.agents.nodes import NodeHandlers, validate_output_citations
from evidencesoc.agents.services import PostgresWorkflowServices
from evidencesoc.tools.ledger import Ledger

from evals.adapters.diagnosis import Diagnosis, validate_diagnosis
from evals.adapters.environment import case_environment
from evals.adapters.isolation_probe import run_service_probe
from evals.adapters.model_client import BudgetAccount, BudgetLimit, TrackedModel
from evals.adapters.seed import load_seed
from evals.adapters.worker_errors import exception_category
from evals.contracts import AdapterResult, WorkerRunSpec, canonical_hash


def capabilities(spec):
    policy = spec.capabilities
    return InvestigationCapabilities(
        allowed_tools=frozenset(policy.allowed_tools),
        rag_mode=policy.rag_mode,
        verification_enabled=policy.verification_enabled,
        first_round_reserved_calls=policy.first_round_reserved_calls,
        total_reserved_calls=policy.total_reserved_calls,
    )


async def one_diagnosis(model, state, registry):
    errors = []
    state = {**state, "_model_call_id": uuid.uuid4().hex}
    for _ in range(3):
        try:
            value = await model.structured("analyze", Diagnosis, state)
            validate_output_citations(value, state)
            return validate_diagnosis(value, registry).model_dump(mode="json"), errors
        except BudgetLimit:
            raise
        except Exception as error:  # noqa: BLE001 - sanitize provider errors at boundary
            errors.append(
                {
                    "stage": "diagnosis",
                    "type": type(error).__name__,
                    "category": exception_category(error),
                }
            )
    return None, errors


async def run_with_services(
    spec, seed, services, settings, model, checkpointer, incident_id
):
    """Dependency injection supports contract tests without paying or loading gold."""
    policy = capabilities(spec)
    state = {
        "incident_id": incident_id,
        "trace_id": "TRACE-"
        + canonical_hash([spec.run_id, spec.case_id, spec.group])[:26],
        "alerts": seed["alerts"],
        "evidence": seed["evidence"],
        "knowledge": [],
        "fallback_count": 0,
        "collection_round": 0,
        "collection_budget_used": 0,
        "events": [],
    }
    registry = dict(seed["registry"])
    with capability_scope(policy):
        if spec.group in {"B0", "B1"}:
            if spec.group == "B1":
                from evidencesoc.rag.retriever import retrieve_knowledge

                query = " ".join(item["summary"] for item in seed["evidence"][:3])[:300]
                state["knowledge"] = await asyncio.to_thread(
                    retrieve_knowledge, query, spec.seed.knowledge_top_k, mode="hybrid"
                )
            diagnosis, errors = await one_diagnosis(model, state, registry)
            return {
                "diagnostic_snapshot": {
                    "diagnosis": diagnosis,
                    "sealed_after": "analyze",
                    "sealed_at": datetime.now(UTC).isoformat(),
                }
                if diagnosis
                else None,
                "diagnosis_status": "succeeded" if diagnosis else "failed",
                "execution_status": "completed" if diagnosis else "failed",
                "product_status": "diagnosed" if diagnosis else "failed",
                "errors": errors,
                "evidence_registry": registry,
                "tool_ledger": [],
            }
        services.planner_model = model
        if spec.group == "B2":
            errors = []
            diagnosis = None
            for round_no in range(2):
                state["fallback_count"] = round_no
                run_id = await services.start_run(state, "collect")
                delta = await services.collect(state, run_id)
                await services.finish_run(run_id, delta)
                evidence = {
                    item["evidence_id"]: item
                    for item in [*state["evidence"], *delta.get("evidence", [])]
                }
                knowledge = {
                    item["knowledge_chunk_id"]: item
                    for item in [*state["knowledge"], *delta.get("knowledge", [])]
                }
                state.update(
                    delta,
                    evidence=list(evidence.values()),
                    knowledge=list(knowledge.values()),
                )
                registry.update(
                    {
                        key: {
                            **value,
                            "case_id": spec.case_id,
                            "provenance": "scoped_tool",
                        }
                        for key, value in evidence.items()
                    }
                )
                diagnosis, problems = await one_diagnosis(model, state, registry)
                errors.extend(problems)
                if diagnosis is None or diagnosis["verdict"] != "unknown":
                    break
            snapshot = (
                {
                    "diagnosis": diagnosis,
                    "sealed_after": "analyze",
                    "sealed_at": datetime.now(UTC).isoformat(),
                }
                if diagnosis
                else None
            )
            return {
                "diagnostic_snapshot": snapshot,
                "diagnosis_status": "succeeded" if diagnosis else "failed",
                "execution_status": "completed" if diagnosis else "failed",
                "product_status": "diagnosed" if diagnosis else "failed",
                "errors": errors,
                "evidence_registry": registry,
            }
        workflow = InvestigationWorkflow(
            services=services,
            settings=settings,
            checkpointer=checkpointer,
            model=model,
            nodes=NodeHandlers(
                services,
                settings,
                model,
                capabilities=policy,
                model_timeout=spec.model.timeout_seconds,
            ),
            capabilities=policy,
            initial_state={key: seed[key] for key in ("alerts", "evidence")},
        )
        try:
            state = await workflow.run_investigation(incident_id)
        except Exception as error:  # noqa: BLE001 - recover sealed diagnosis after a later failure
            state = await workflow.get_state(incident_id)
            state = {
                **state,
                "status": "failed",
                "errors": [
                    *state.get("errors", []),
                    {
                        "stage": "workflow",
                        "type": type(error).__name__,
                        "category": exception_category(error),
                    },
                ],
            }
        snapshot = state.get("diagnostic_snapshot")
        registry.update(
            {
                item["evidence_id"]: {
                    **item,
                    "case_id": spec.case_id,
                    "provenance": "scoped_tool",
                }
                for item in state.get("evidence", [])
            }
        )
        status = (
            "succeeded"
            if state.get("diagnosis_execution_status") == "completed" and snapshot
            else "failed"
        )
        if status == "succeeded":
            validate_diagnosis(snapshot["diagnosis"], registry)
        # State is an immutable local replay artifact; scoring never reads it into worker.
        output = Path(os.environ.get("TASK13_OUTPUT_DIR", ".tmp"))
        output.mkdir(parents=True, exist_ok=True)
        checkpoint = output / "investigation-state.json"
        with checkpoint.open("x", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=False, sort_keys=True, default=str)
        return {
            "diagnostic_snapshot": snapshot,
            "diagnosis_status": status,
            "execution_status": "failed"
            if status == "failed" or state.get("status") == "failed"
            else "completed",
            "product_status": state.get("status"),
            "degradation": [{"kind": "bounded_rule_fallback"}]
            if state.get("fallback_used")
            else [],
            "errors": state.get("errors", []),
            "evidence_registry": registry,
            "verification": state.get("validation_result"),
            "artifact_hashes": {"investigation_state": canonical_hash(state)},
        }


def _complete_usage(ledger: list[dict]) -> bool:
    """Only complete nonnegative integer token counts may enter resource totals."""
    return bool(ledger) and all(
        isinstance(item.get("usage"), dict)
        and all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in (
                item["usage"].get("prompt_tokens"),
                item["usage"].get("completion_tokens"),
            )
        )
        for item in ledger
    )


async def run_case(spec: WorkerRunSpec, agent_dir: Path) -> AdapterResult:
    if not os.environ.get("TASK13_WORKER_NONCE") or os.getpid() != 1:
        raise PermissionError(
            "real model adapter requires inspected container worker PID1"
        )
    start = time.monotonic()
    model = None
    service_probe = None
    result = {}
    tool_ledger_complete = True
    try:
        seed = load_seed(spec, agent_dir)
        phase = os.environ["TASK13_PHASE"]
        account = BudgetAccount(Path(os.environ["TASK13_BUDGET_DB"]))
        model = TrackedModel(
            spec.model,
            api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
            account=account,
            phase=phase,
            max_calls=spec.budget.max_model_calls * spec.budget.max_model_attempts,
            max_logical_calls=spec.budget.max_model_calls,
        )
        with case_environment(spec, seed) as environment:
            settings, sessions, incident_id = environment

            class SeededWorkflowServices(PostgresWorkflowServices):
                async def load_incident(self, identity):
                    loaded = await super().load_incident(identity)
                    loaded["alerts"] = deepcopy(seed["alerts"])
                    return loaded

            services = SeededWorkflowServices(
                settings,
                session_factory=sessions,
                capabilities=capabilities(spec),
                model_timeout=spec.model.timeout_seconds,
            )
            try:
                tool_ledger_complete = False
                if phase == "development" and spec.group == "B3":
                    before_probe = canonical_hash(model.ledger)
                    service_probe = await run_service_probe(spec, environment, seed)
                    after_probe = canonical_hash(model.ledger)
                    service_probe.update(
                        model_ledger_before_sha256=before_probe,
                        model_ledger_after_sha256=after_probe,
                    )
                    if (
                        before_probe != after_probe
                        or service_probe.get("status") != "passed"
                    ):
                        raise ValueError("independent service isolation probe failed")
                async with open_checkpointer(settings.database_url) as checkpointer:
                    result = await run_with_services(
                        spec, seed, services, settings, model, checkpointer, incident_id
                    )
            finally:
                try:
                    ledger = Ledger(sessions)
                    calls = []
                    for round_no in (1, 2):
                        calls.extend(ledger.calls(incident_id, round_no))
                    result["tool_ledger"] = [
                        asdict(call)
                        for call in {call.call_id: call for call in calls}.values()
                    ]
                    tool_ledger_complete = True
                except Exception as error:  # noqa: BLE001 - retain unknown tool usage explicitly
                    result.setdefault("errors", []).append(
                        {
                            "stage": "tool_ledger_export",
                            "type": type(error).__name__,
                            "category": exception_category(error),
                        }
                    )
                finally:
                    await services.aclose()
            if (
                spec.group == "B3"
                and result.get("diagnosis_status") == "succeeded"
                and result.get("product_status") == "awaiting_approval"
            ):
                path = (
                    Path(os.environ["TASK13_OUTPUT_DIR"]) / "investigation-state.json"
                )
                state = json.loads(path.read_text(encoding="utf-8"))
                reference = {
                    **environment.reference(),
                    "plan_sha256": canonical_hash(state["response_plan"]),
                    "snapshot_sha256": state["diagnostic_snapshot_sha256"],
                    "input_sha256": seed["input_sha256"],
                }
                with (path.parent / "case-resource.json").open(
                    "x", encoding="utf-8"
                ) as stream:
                    json.dump(reference, stream, ensure_ascii=False, sort_keys=True)
                environment.retain()
                result["verification"] = {
                    "status": "awaiting_human_approval",
                    "case_reference": reference,
                }
    except Exception as error:  # noqa: BLE001 - sanitized immutable worker failure result
        result.update(
            execution_status="failed",
            diagnosis_status=result.get("diagnosis_status", "failed"),
            errors=[
                *result.get("errors", []),
                {
                    "stage": "worker",
                    "type": type(error).__name__,
                    "category": exception_category(error),
                },
            ],
        )
    finally:
        import resource  # real worker is Linux; control-side imports stay portable

        ledger = model.ledger if model else []
        result["model_ledger"] = ledger
        if service_probe is not None:
            result.setdefault("isolation_evidence", {})["service_probe"] = service_probe
        usage_complete = _complete_usage(ledger)
        cost_complete = bool(ledger) and all(
            item.get("cost_cny") is not None for item in ledger
        )
        total_latency = round((time.monotonic() - start) * 1000)
        probe_latency = service_probe["latency_ms"] if service_probe is not None else 0
        result["resources"] = {
            "latency_ms": max(0, total_latency - probe_latency),
            "worker_total_latency_ms": total_latency,
            "isolation_probe_latency_ms": probe_latency,
            "input_tokens": sum(item["usage"]["prompt_tokens"] for item in ledger)
            if usage_complete
            else None,
            "output_tokens": sum(item["usage"]["completion_tokens"] for item in ledger)
            if usage_complete
            else None,
            "cost": sum(item["cost_cny"] for item in ledger) if cost_complete else None,
            "model_logical_calls": len({item["logical_call_id"] for item in ledger}),
            "model_physical_attempts": len(ledger),
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "tool_ledger_complete": tool_ledger_complete,
            "missing_reason": None
            if usage_complete and cost_complete
            else "usage_or_cost_unavailable",
        }
    return AdapterResult.model_validate(result)
