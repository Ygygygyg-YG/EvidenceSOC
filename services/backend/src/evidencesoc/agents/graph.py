from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from psycopg import Connection

from evidencesoc.agents.capabilities import capability_scope
from evidencesoc.agents.checkpoint import open_checkpointer, psycopg_url
from evidencesoc.agents.fallback import matching_target
from evidencesoc.agents.models import SimulatedAction
from evidencesoc.agents.nodes import NodeHandlers
from evidencesoc.agents.state import InvestigationState
from evidencesoc.config import Settings, get_settings
from evidencesoc.domain.models import (
    ApprovalDecision,
    ApprovalRecord,
    EvidenceItem,
    ResponsePlan,
)
from evidencesoc.domain.response_action import SimulationExecution
from evidencesoc.evidence.citations import FactualClaim, validate_citations
from evidencesoc.ids import new_ulid

ROLE_NAMES = ("triage", "collect", "analyze", "reconstruct", "respond", "validate")
TERMINAL_STATES = {"completed", "failed", "manual_review", "rejected"}


class CitationViolation(ValueError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _event(state, node, event, *, output=None):
    result = {
        "event_id": len(state.get("events", [])) + 1,
        "event_uuid": new_ulid(),
        "node": node,
        "event": event,
        "incident_id": state["incident_id"],
        "trace_id": state["trace_id"],
        "occurred_at": _now(),
    }
    if output is not None:
        result["output"] = output
    return result


def _validate_output(state, delta):
    combined = {**state, **delta}
    evidence_ids = {item["evidence_id"] for item in combined.get("evidence", [])}
    knowledge_ids = {
        item["knowledge_chunk_id"] for item in combined.get("knowledge", [])
    }
    objects = [
        (key, delta[key])
        for key in ("origin", "classification", "response_plan", "validation_result")
        if delta.get(key) is not None
    ]
    objects.extend(
        (f"step-{index}", step)
        for index, step in enumerate(delta.get("attack_steps", []))
    )
    claims = []
    for name, value in objects:
        if not value.get("evidence_ids"):
            raise CitationViolation("missing evidence citation")
        claims.append(
            FactualClaim(
                claim_id=name,
                text=name,
                evidence_ids=value["evidence_ids"],
                knowledge_chunk_ids=value.get("knowledge_chunk_ids", []),
            )
        )
    claims.extend(
        FactualClaim.model_validate(claim) for claim in delta.get("claims", [])
    )
    diagnosis = delta.get("diagnosis")
    if diagnosis is not None:
        from evidencesoc.agents.diagnosis import Diagnosis

        parsed = Diagnosis.model_validate(diagnosis)
        claims.extend(
            FactualClaim.model_validate(claim.model_dump()) for claim in parsed.claims
        )
        if parsed.evidence_ids:
            claims.append(
                FactualClaim(
                    claim_id="diagnosis",
                    text="Diagnosis",
                    evidence_ids=parsed.evidence_ids,
                )
            )
        for stage in parsed.stage_instances:
            claims.append(
                FactualClaim(
                    claim_id=stage.instance_id,
                    text=stage.phase,
                    evidence_ids=stage.evidence_ids,
                )
            )
    if any(
        claim.status == "unsupported"
        for claim in validate_citations(claims, evidence_ids, knowledge_ids)
    ):
        raise CitationViolation("unsupported citation")
    if delta.get("response_plan"):
        plan = ResponsePlan.model_validate(delta["response_plan"])
        if plan.incident_id != state["incident_id"]:
            raise ValueError("response plan belongs to another investigation")
        action_ids = [action.action_id for action in plan.actions]
        if len(set(action_ids)) != len(action_ids):
            raise CitationViolation("response action identifiers must be unique")
        for action in plan.actions:
            simulated_action = SimulatedAction.model_validate(action)
            if not simulated_action.traceable or not set(
                simulated_action.evidence_ids or []
            ) <= set(plan.evidence_ids):
                raise CitationViolation("response action has no supported citation")
            cited = [
                item
                for item in combined.get("evidence", [])
                if item["evidence_id"] in (simulated_action.evidence_ids or [])
            ]
            if not any(matching_target(item, simulated_action) for item in cited):
                raise CitationViolation("response target has no cited observation")


def _plan_hash(plan):
    return hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _seal_diagnosis(state, role):
    if state.get("diagnostic_snapshot") is not None or state.get("diagnosis") is None:
        return {}
    snapshot = {
        key: deepcopy(state.get(key))
        for key in (
            "diagnosis",
            "origin",
            "classification",
            "attack_steps",
            "claims",
            "evidence",
            "knowledge",
        )
    }
    snapshot.update({"sealed_after": role, "sealed_at": _now()})
    provenance = state.get("analysis_import_provenance")
    if (
        role == "analysis_import"
        and isinstance(provenance, dict)
        and "planning_admission" in provenance
    ):
        snapshot["analysis_import_provenance"] = deepcopy(provenance)
    return {
        "diagnostic_snapshot": snapshot,
        "diagnostic_snapshot_sha256": _plan_hash(snapshot),
    }


def _persisted_plan_version(plan: dict[str, Any]) -> str:
    """Match the canonical version of the persisted ResponsePlanTable row."""
    document = ResponsePlan.model_validate(plan).model_dump(mode="python")
    for key in ("created_at", "expires_at"):
        value = document[key]
        if value is not None:
            document[key] = value.astimezone(UTC).isoformat()
    return hashlib.sha256(
        json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _analysis_route(state):
    if state.get("status") in {"failed", "manual_review"}:
        return "review" if state["status"] == "manual_review" else END
    diagnosis = state.get("diagnosis")
    if diagnosis is not None:
        verdict = diagnosis["verdict"]
        if verdict == "benign":
            return END
        if verdict == "attack":
            return "reconstruct"
        return "retry" if state.get("fallback_count", 0) == 0 else "review"
    classification = state.get("classification") or {}
    if (
        not classification.get("primary_type")
        or classification["primary_type"] == "unknown"
    ):
        return "retry" if state.get("fallback_count", 0) == 0 else "review"
    return "reconstruct"


def _role_route(next_node):
    def route(state):
        if state.get("status") in TERMINAL_STATES:
            return END
        return next_node

    return route


def build_graph(
    nodes,
    services,
    checkpointer,
    *,
    capabilities=None,
    imported_analysis=None,
    planning_admission=None,
):
    builder = StateGraph(InvestigationState)

    def wrap(role):
        async def execute(state):
            run_id = await services.start_run(state, role)
            started = _event(state, role, "node.started")
            writer = get_stream_writer()
            writer(started)
            try:
                with capability_scope(capabilities):
                    if role == "analysis_import":
                        from evidencesoc.agents.models import AnalysisOutput
                        from evidencesoc.agents.nodes import validate_output_citations

                        imported_analysis.revalidate()
                        values = imported_analysis.product_values()
                        if planning_admission is not None:
                            values["analysis_import_provenance"] = (
                                planning_admission.provenance_for(
                                    imported_analysis, state["incident_id"]
                                )
                            )
                        incident = await services.load_incident(state["incident_id"])
                        if not incident or incident.get("status") != "received":
                            raise ValueError("import requires a new persisted incident")
                        verified = await services.hydrate_evidence(
                            state["incident_id"], values["evidence"]
                        )
                        # Hydration checks ownership and the full stored raw hash.
                        # Artifact replay independently verifies the bounded seed.
                        # Compare persisted identity/query/summary, allowing the
                        # service's richer raw projection without expanding the
                        # original evidence subsequently consumed by respond.
                        hydrated_items = {
                            item["evidence_id"]: EvidenceItem.model_validate(item)
                            for item in verified
                        }
                        seed_items = {
                            item["evidence_id"]: EvidenceItem.model_validate(item)
                            for item in values["evidence"]
                        }
                        if (
                            not verified
                            or len(verified) != len(hydrated_items)
                            or len(values["evidence"]) != len(seed_items)
                            or hydrated_items != seed_items
                        ):
                            raise ValueError(
                                "import evidence failed product integrity verification"
                            )
                        output = AnalysisOutput.model_validate(
                            {
                                key: values[key]
                                for key in ("origin", "classification", "diagnosis")
                            }
                        )
                        validate_output_citations(output, values)
                        delta = {
                            **values,
                            "status": "received",
                            "diagnosis_execution_status": "completed",
                        }
                    else:
                        delta = await getattr(nodes, role)({**state, "_run_id": run_id})
                _validate_output(state, delta)
                if (
                    role == "respond"
                    and state.get("analysis_import_provenance")
                    and delta.get("response_plan")
                ):
                    plan = ResponsePlan.model_validate(delta["response_plan"])
                    if (
                        plan.expires_at is None
                        or (plan.expires_at - plan.created_at).total_seconds() != 1800
                    ):
                        raise ValueError(
                            "imported response plan must expire exactly 1800 seconds after creation"
                        )
                combined = {**state, **delta}
                if role == "analysis_import":
                    delta.update(_seal_diagnosis(combined, role))
                if (
                    role in {"analyze", "reconstruct"}
                    and combined.get("diagnosis") is not None
                ):
                    delta.setdefault("diagnosis_execution_status", "completed")
                    verdict = combined["diagnosis"]["verdict"]
                    if delta["diagnosis_execution_status"] == "failed":
                        delta.update(_seal_diagnosis(state, "last_legal_analysis"))
                    elif (
                        role == "reconstruct"
                        or verdict == "benign"
                        or (verdict == "unknown" and combined.get("fallback_count", 0))
                    ):
                        delta.update(_seal_diagnosis(combined, role))
                await services.finish_run(run_id, delta, "completed")
                failed = False
            except Exception as error:  # noqa: BLE001 -- convert dependency failures without leaking exception text
                code = (
                    "UNSUPPORTED_CITATION"
                    if isinstance(error, CitationViolation)
                    else "NODE_FAILED"
                )
                delta = {
                    "status": "manual_review"
                    if isinstance(error, CitationViolation)
                    else "failed",
                    "stop_reason": code.lower(),
                    "errors": [*state.get("errors", []), {"node": role, "code": code}],
                }
                if role in {"analyze", "reconstruct"}:
                    delta["diagnosis_execution_status"] = "failed"
                    delta.update(_seal_diagnosis(state, "last_legal_analysis"))
                await services.finish_run(run_id, delta, "failed")
                failed = True
            if role == "validate" and delta.get("validation_result"):
                delta["status"] = {
                    "success": "completed",
                    "failure": "failed",
                    "insufficient_evidence": "manual_review",
                }[delta["validation_result"]["outcome"]]
            event_state = {**state, "events": [*state.get("events", []), started]}
            event_type = "node.failed" if failed else "node.completed"
            finished = _event(event_state, role, event_type, output=delta)
            merged = {**state, **delta, "events": [*event_state["events"], finished]}
            await services.save_result(merged)
            writer(finished)
            return {**delta, "events": [started, finished]}

        return execute

    for role in ROLE_NAMES:
        builder.add_node(role, wrap(role))
    if imported_analysis is not None:
        builder.add_node("analysis_import", wrap("analysis_import"))

    async def retry(state):
        return {"fallback_count": 1, "status": "collecting"}

    async def review(state):
        delta = {
            "status": "manual_review",
            "stop_reason": state.get("stop_reason") or "insufficient_evidence",
        }
        delta.update(_seal_diagnosis(state, "analyze"))
        await services.save_result({**state, **delta})
        return delta

    async def approval(state):
        plan = ResponsePlan.model_validate(state["response_plan"])
        digest = _plan_hash(state["response_plan"])
        resume = interrupt(
            {
                "incident_id": state["incident_id"],
                "response_plan": plan.model_dump(mode="json"),
                "plan_sha256": digest,
                "requires_approval": True,
            }
        )
        renewal = resume.get("renewal") if isinstance(resume, dict) else None
        if renewal is not None:
            if (
                not isinstance(renewal, dict)
                or renewal.get("response_plan_id") != plan.response_plan_id
                or renewal.get("plan_sha256") != digest
                or not isinstance(renewal.get("requested_by"), str)
                or not renewal["requested_by"].strip()
            ):
                raise ValueError("renewal does not match pending response plan")
            verified = await services.hydrate_evidence(
                state["incident_id"], state.get("evidence", [])
            )
            if not verified or len(verified) != len(state.get("evidence", [])):
                raise ValueError("renewal evidence failed integrity verification")
            generation = state.get("plan_generation", 0) + 1
            renewal_event = _event(
                state,
                "approval",
                "approval.renewed",
                output={
                    "response_plan_id": plan.response_plan_id,
                    "requested_by": renewal["requested_by"],
                    "generation": generation,
                },
            )
            delta = {
                "status": "reconstructing",
                "evidence": verified,
                "response_plan": None,
                "approval": None,
                "validation_result": None,
                "simulation": [],
                "simulation_execution": None,
                "approved_plan_version": "",
                "approved_plan_sha256": "",
                "plan_generation": generation,
                "renewed_from_plan_id": plan.response_plan_id,
                "stop_reason": None,
                "events": [renewal_event],
            }
            await services.save_result(
                {**state, **delta, "events": [*state.get("events", []), renewal_event]}
            )
            return delta
        record = ApprovalRecord.model_validate(resume["approval"])
        if (
            record.response_plan_id != plan.response_plan_id
            or resume.get("plan_sha256") != digest
        ):
            raise ValueError("approval does not match pending response plan")
        approved_version = resume.get("plan_version") or _persisted_plan_version(
            state["response_plan"]
        )
        pending_execution = (
            SimulationExecution(
                simulation_id="SIM-"
                + hashlib.sha256(
                    f"{plan.response_plan_id}|{approved_version}".encode()
                ).hexdigest()[:24],
                response_plan_id=plan.response_plan_id,
                plan_version=approved_version,
                status="pending",
                started_at=None,
                finished_at=None,
                action_results=[],
                error=None,
            ).model_dump(mode="json")
            if record.decision == "approved"
            else None
        )
        delta = {
            "approval": record.model_dump(mode="json"),
            "status": "simulating" if record.decision == "approved" else "rejected",
            "approved_plan_sha256": digest,
            "approved_plan_version": approved_version,
            "simulation_execution": pending_execution,
            "stop_reason": record.reason if record.decision == "rejected" else None,
            "events": [
                _event(
                    state,
                    "approval",
                    "approval.decided",
                    output=record.model_dump(mode="json"),
                )
            ],
        }
        await services.save_result(
            {**state, **delta, "events": [*state.get("events", []), *delta["events"]]}
        )
        return delta

    async def simulate(state):
        plan = ResponsePlan.model_validate(state["response_plan"])
        record = ApprovalRecord.model_validate(state["approval"])
        if (
            record.decision != "approved"
            or record.response_plan_id != plan.response_plan_id
        ):
            raise ValueError(
                "simulation requires approval of the current response plan"
            )
        if state.get("approved_plan_sha256") != _plan_hash(state["response_plan"]):
            raise ValueError("response plan changed after approval")
        actions = [SimulatedAction.model_validate(action) for action in plan.actions]
        execution = state.get("simulation_execution")
        if (
            not isinstance(execution, dict)
            or execution.get("response_plan_id") != plan.response_plan_id
        ):
            raise ValueError("simulation execution does not match approved plan")
        if execution.get("plan_version") != state.get("approved_plan_version"):
            raise ValueError("simulation execution does not match approved version")
        started_at = datetime.now(UTC)
        running = SimulationExecution.model_validate(
            {**execution, "status": "running", "started_at": started_at.isoformat()}
        ).model_dump(mode="json")
        await services.save_result({**state, "simulation_execution": running})
        simulation = []
        action_results = []
        for index, action in enumerate(actions):
            action_started = datetime.now(UTC)
            simulation.append(
                {
                    **action.model_dump(mode="json"),
                    "execution_id": f"{plan.response_plan_id}:{index}",
                    "simulated": True,
                    "status": "simulated",
                    "outcome": "success",
                }
            )
            action_results.append(
                {
                    "action_id": action.action_id,
                    "outcome": "success",
                    "description": action.preview,
                    "started_at": action_started.isoformat(),
                    "finished_at": datetime.now(UTC).isoformat(),
                }
            )
        completed = SimulationExecution.model_validate(
            {
                **running,
                "status": "completed",
                "finished_at": datetime.now(UTC).isoformat(),
                "action_results": action_results,
            }
        ).model_dump(mode="json")
        delta = {
            "simulation": simulation,
            "simulation_execution": completed,
            "status": "validating",
            "events": [
                _event(
                    state,
                    "simulate",
                    "simulation.completed",
                    output={"simulation": simulation},
                )
            ],
        }
        await services.save_result(
            {**state, **delta, "events": [*state.get("events", []), *delta["events"]]}
        )
        return delta

    builder.add_node("retry", retry)
    builder.add_node("review", review)
    builder.add_node("approval", approval)
    builder.add_node("simulate", simulate)
    builder.add_edge(
        START, "analysis_import" if imported_analysis is not None else "triage"
    )
    if imported_analysis is not None:
        builder.add_conditional_edges("analysis_import", _role_route("respond"))
    builder.add_conditional_edges("triage", _role_route("collect"))
    builder.add_conditional_edges("collect", _role_route("analyze"))
    builder.add_conditional_edges("analyze", _analysis_route)
    builder.add_edge("retry", "collect")
    builder.add_edge("review", END)
    builder.add_conditional_edges("reconstruct", _role_route("respond"))
    builder.add_conditional_edges("respond", _role_route("approval"))
    builder.add_conditional_edges(
        "approval",
        lambda state: (
            "simulate"
            if state["status"] == "simulating"
            else "respond"
            if state["status"] == "reconstructing"
            else END
        ),
    )
    builder.add_edge("simulate", "validate")
    builder.add_edge("validate", END)
    return builder.compile(checkpointer=checkpointer, name="six-role-investigation")


class InvestigationWorkflow:
    def __init__(
        self,
        *,
        services,
        settings: Settings,
        checkpointer,
        nodes=None,
        model=None,
        database_url=None,
        capabilities=None,
        initial_state=None,
        _imported_analysis=None,
        _import_admission=None,
        _planning_admission=None,
    ):
        self.services = services
        self.settings = settings
        self.checkpointer = checkpointer
        self.database_url = database_url
        self.capabilities = capabilities
        self._imported_analysis = _imported_analysis
        self._import_admission = _import_admission
        self._planning_admission = _planning_admission
        self.initial_state = deepcopy(initial_state or {})
        if set(self.initial_state) - {
            "alerts",
            "evidence",
            "knowledge",
            "verification_namespace",
        }:
            raise ValueError(
                "initial state may contain only trusted seed inputs and verification namespace"
            )
        self.graph = build_graph(
            nodes or NodeHandlers(services, settings, model, capabilities=capabilities),
            services,
            checkpointer,
            capabilities=capabilities,
            imported_analysis=_imported_analysis,
            planning_admission=_planning_admission,
        )
        if not hasattr(checkpointer, "_investigation_locks"):
            checkpointer._investigation_locks = {}
        self._locks = checkpointer._investigation_locks

    @classmethod
    def for_analysis_import(
        cls, *, imported_analysis, admission=None, planning_admission=None, **kwargs
    ):
        from evidencesoc.agents.analysis_import import (
            ImportDispatchJournal,
            ImportedAnalysis,
            PlanningAdmission,
        )

        if type(imported_analysis) is not ImportedAnalysis or not (
            (type(admission) is ImportDispatchJournal and planning_admission is None)
            or (admission is None and type(planning_admission) is PlanningAdmission)
        ):
            raise TypeError(
                "analysis import requires a verified source and durable dispatch journal"
            )
        if kwargs.get("initial_state") or kwargs.get("nodes") is not None:
            raise ValueError(
                "analysis import cannot override seed state or product nodes"
            )
        imported_analysis.revalidate()
        return cls(
            _imported_analysis=imported_analysis,
            _import_admission=admission,
            _planning_admission=planning_admission,
            **kwargs,
        )

    async def import_analysis(self, incident_id, imported_analysis):
        from evidencesoc.agents.analysis_import import ImportedAnalysis

        if (
            type(imported_analysis) is not ImportedAnalysis
            or self._imported_analysis is not imported_analysis
            or (self._import_admission is None and self._planning_admission is None)
        ):
            raise PermissionError(
                "analysis import requires the explicitly bound workflow constructor"
            )
        config = self._config(incident_id)
        async with self._exclusive(incident_id):
            imported_analysis.revalidate()
            provenance = (
                self._planning_admission.provenance_for(imported_analysis, incident_id)
                if self._planning_admission is not None
                else imported_analysis.provenance
            )
            snapshot = await self.graph.aget_state(config)
            if snapshot.values:
                if (
                    snapshot.next == ("approval",)
                    and snapshot.values.get("status") == "awaiting_approval"
                    and snapshot.values.get("analysis_import_provenance") == provenance
                ):
                    seal = snapshot.values.get("diagnostic_snapshot")
                    if (
                        not isinstance(seal, dict)
                        or snapshot.values.get("diagnostic_snapshot_sha256")
                        != _plan_hash(seal)
                        or seal.get("sealed_after") != "analysis_import"
                        or (
                            self._planning_admission is not None
                            and seal.get("analysis_import_provenance") != provenance
                        )
                        or any(
                            seal.get(key) != value
                            for key, value in imported_analysis.product_values().items()
                            if key
                            in {
                                "diagnosis",
                                "origin",
                                "classification",
                                "attack_steps",
                                "claims",
                                "evidence",
                                "knowledge",
                            }
                        )
                    ):
                        raise PermissionError(
                            "imported diagnosis seal changed while awaiting approval"
                        )
                    return dict(snapshot.values)
                raise PermissionError(
                    "incident already has a checkpoint; automatic import replay refused"
                )
            if self._planning_admission is None:
                self._import_admission.claim(
                    imported_analysis.source_identity, incident_id
                )
            initial = {
                "incident_id": incident_id,
                "trace_id": f"TRACE-{new_ulid()}",
                "status": "received",
                "events": [],
                "errors": [],
                "attack_steps": [],
                "response_plan": None,
                "approval": None,
                "simulation": [],
                "simulation_execution": None,
                "fallback_count": 0,
                "fallback_used": False,
                "diagnostic_snapshot": None,
                "diagnostic_snapshot_sha256": None,
            }
            await self.graph.ainvoke(initial, config)
            return await self.get_state(incident_id)

    def _config(self, incident_id):
        if (
            not isinstance(incident_id, str)
            or not incident_id.strip()
            or len(incident_id) > 64
        ):
            raise ValueError("invalid incident ID")
        return {"configurable": {"thread_id": incident_id}, "recursion_limit": 32}

    @asynccontextmanager
    async def _exclusive(self, incident_id):
        lock = self._locks.setdefault(incident_id, asyncio.Lock())
        async with lock:
            if self.database_url is None:
                yield
                return
            connection = await asyncio.to_thread(
                Connection.connect, psycopg_url(self.database_url), autocommit=True
            )
            key = int.from_bytes(
                hashlib.sha256(f"evidencesoc:{incident_id}".encode()).digest()[:8],
                "big",
                signed=True,
            )
            try:
                cursor = await asyncio.to_thread(
                    connection.execute, "SELECT pg_try_advisory_lock(%s)", (key,)
                )
                acquired = (await asyncio.to_thread(cursor.fetchone))[0]
                if not acquired:
                    raise ValueError("investigation is already running")
                yield
            finally:
                await asyncio.to_thread(connection.close)

    async def get_state(self, incident_id: str) -> dict[str, Any]:
        snapshot = await self.graph.aget_state(self._config(incident_id))
        return dict(snapshot.values)

    async def run_investigation(self, incident_id: str) -> dict[str, Any]:
        async for _ in self.stream_events(incident_id):
            pass
        return await self.get_state(incident_id)

    async def stream_events(
        self, incident_id: str, *, after_event_id: int = 0, trace_id: str | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        if self._imported_analysis is not None:
            raise PermissionError(
                "use the explicit analysis import method on an import workflow"
            )
        config = self._config(incident_id)
        if after_event_id < 0:
            raise ValueError("event cursor must not be negative")
        async with self._exclusive(incident_id):
            snapshot = await self.graph.aget_state(config)
            initial: dict[str, Any] | None
            cursor = after_event_id
            for event in snapshot.values.get("events", []):
                if event["event_id"] > cursor:
                    cursor = event["event_id"]
                    yield event
            if snapshot.values:
                if snapshot.values.get(
                    "status"
                ) in TERMINAL_STATES or snapshot.next == ("approval",):
                    await self.services.save_result(snapshot.values)
                    return
                initial = None
            else:
                initial = {
                    "incident_id": incident_id,
                    "trace_id": trace_id or f"TRACE-{new_ulid()}",
                    "status": "received",
                    "alerts": [],
                    "evidence": [],
                    "knowledge": [],
                    "origin": None,
                    "classification": None,
                    "diagnosis": None,
                    "diagnostic_snapshot": None,
                    "diagnostic_snapshot_sha256": None,
                    "diagnosis_execution_status": "missing",
                    "attack_steps": [],
                    "response_plan": None,
                    "approval": None,
                    "validation_result": None,
                    "simulation": [],
                    "simulation_execution": None,
                    "fallback_count": 0,
                    "fallback_used": False,
                    "collection_round": 0,
                    "collection_budget_used": 0,
                    "collection_round_used": 0,
                    "collection_ledger_ids": [],
                    "collection_tool_attempts": 0,
                    "collection_model_attempts": 0,
                    "collection_observations": [],
                    "collection_stop_reason": None,
                    "verification_call_count": 0,
                    "verification_attempts": 0,
                    "verification_duration_ms": 0,
                    "errors": [],
                    "events": [],
                    "stop_reason": None,
                    **deepcopy(self.initial_state),
                }
            async for mode, chunk in self.graph.astream(
                initial, config, stream_mode=["custom", "updates"]
            ):
                events = (
                    [chunk]
                    if mode == "custom"
                    else [
                        event
                        for delta in chunk.values()
                        if isinstance(delta, dict)
                        for event in delta.get("events", [])
                    ]
                )
                for event in events:
                    if event["event_id"] > cursor:
                        cursor = event["event_id"]
                        yield event
            state = await self.get_state(incident_id)
            await self.services.save_result(state)

    async def approve(
        self,
        incident_id: str,
        *,
        response_plan_id: str,
        decision: str,
        reason: str,
        decided_by: str,
    ) -> dict[str, Any]:
        async for _ in self.stream_approval(
            incident_id,
            response_plan_id=response_plan_id,
            decision=decision,
            reason=reason,
            decided_by=decided_by,
        ):
            pass
        return await self.get_state(incident_id)

    async def renew_plan(
        self, incident_id: str, *, response_plan_id: str, requested_by: str
    ) -> dict[str, Any]:
        async for _ in self.stream_renewal(
            incident_id, response_plan_id=response_plan_id, requested_by=requested_by
        ):
            pass
        return await self.get_state(incident_id)

    async def stream_renewal(
        self, incident_id: str, *, response_plan_id: str, requested_by: str
    ) -> AsyncIterator[dict[str, Any]]:
        if not requested_by.strip():
            raise ValueError("reviewer identity is required")
        config = self._config(incident_id)
        async with self._exclusive(incident_id):
            snapshot = await self.graph.aget_state(config)
            if (
                not snapshot.values
                or snapshot.next != ("approval",)
                or snapshot.values.get("status") != "awaiting_approval"
                or not isinstance(snapshot.values.get("response_plan"), dict)
                or snapshot.values["response_plan"].get("response_plan_id")
                != response_plan_id
            ):
                raise ValueError("investigation has no matching pending plan")
            command: Command[str] = Command(
                resume={
                    "renewal": {
                        "response_plan_id": response_plan_id,
                        "plan_sha256": _plan_hash(snapshot.values["response_plan"]),
                        "requested_by": requested_by,
                    }
                }
            )
            async for mode, chunk in self.graph.astream(
                command, config, stream_mode=["custom", "updates"]
            ):
                events = (
                    [chunk]
                    if mode == "custom"
                    else [
                        event
                        for delta in chunk.values()
                        if isinstance(delta, dict)
                        for event in delta.get("events", [])
                    ]
                )
                for event in events:
                    yield event
            state = await self.get_state(incident_id)
            await self.services.save_result(state)

    async def stream_approval(
        self,
        incident_id: str,
        *,
        response_plan_id: str,
        decision: str,
        reason: str,
        decided_by: str,
        plan_version: str | None = None,
        after_event_id: int = 0,
    ) -> AsyncIterator[dict[str, Any]]:
        config = self._config(incident_id)
        if after_event_id < 0:
            raise ValueError("event cursor must not be negative")
        if not decided_by.strip():
            raise ValueError("reviewer identity is required")
        record = ApprovalRecord(
            approval_id=f"AP-{new_ulid()}",
            response_plan_id=response_plan_id,
            decision=ApprovalDecision(decision),
            reason=reason,
            decided_by=decided_by,
            decided_at=datetime.now(UTC),
        )
        async with self._exclusive(incident_id):
            snapshot = await self.graph.aget_state(config)
            if (
                not snapshot.values
                or snapshot.next != ("approval",)
                or snapshot.values["status"] != "awaiting_approval"
            ):
                raise ValueError("investigation has no pending approval")
            plan = snapshot.values["response_plan"]
            if response_plan_id != plan["response_plan_id"]:
                raise ValueError("approval belongs to a different response plan")
            cursor = after_event_id
            for event in snapshot.values.get("events", []):
                if event["event_id"] > cursor:
                    cursor = event["event_id"]
                    yield event
            command: Command = Command(
                resume={
                    "approval": record.model_dump(mode="json"),
                    "plan_sha256": _plan_hash(plan),
                    "plan_version": plan_version,
                }
            )
            async for mode, chunk in self.graph.astream(
                command, config, stream_mode=["custom", "updates"]
            ):
                events = (
                    [chunk]
                    if mode == "custom"
                    else [
                        event
                        for delta in chunk.values()
                        if isinstance(delta, dict)
                        for event in delta.get("events", [])
                    ]
                )
                for event in events:
                    if event["event_id"] > cursor:
                        cursor = event["event_id"]
                        yield event
            state = await self.get_state(incident_id)
            await self.services.save_result(state)


@asynccontextmanager
async def open_workflow(settings: Settings | None = None):
    from evidencesoc.agents.model import DeepSeekStructuredModel
    from evidencesoc.agents.services import PostgresWorkflowServices

    settings = settings or get_settings()
    services = PostgresWorkflowServices(settings)
    try:
        async with open_checkpointer(settings.database_url) as saver:
            model = (
                DeepSeekStructuredModel(settings)
                if settings.llm_mode == "deepseek"
                else None
            )
            services.planner_model = model
            yield InvestigationWorkflow(
                services=services,
                settings=settings,
                checkpointer=saver,
                model=model,
                database_url=settings.database_url,
            )
    finally:
        services.close()


async def run_investigation(incident_id: str) -> dict[str, Any]:
    async with open_workflow() as workflow:
        return await workflow.run_investigation(incident_id)
