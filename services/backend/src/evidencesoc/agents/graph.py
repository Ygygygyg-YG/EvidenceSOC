from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from psycopg import Connection

from evidencesoc.agents.checkpoint import open_checkpointer, psycopg_url
from evidencesoc.agents.fallback import matching_target
from evidencesoc.agents.models import SimulatedAction
from evidencesoc.agents.nodes import NodeHandlers
from evidencesoc.agents.state import InvestigationState
from evidencesoc.config import Settings, get_settings
from evidencesoc.domain.models import ApprovalDecision, ApprovalRecord, ResponsePlan
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
    if any(
        claim.status == "unsupported"
        for claim in validate_citations(claims, evidence_ids, knowledge_ids)
    ):
        raise CitationViolation("unsupported citation")
    if delta.get("response_plan"):
        plan = ResponsePlan.model_validate(delta["response_plan"])
        if plan.incident_id != state["incident_id"]:
            raise ValueError("response plan belongs to another investigation")
        for action in plan.actions:
            simulated_action = SimulatedAction.model_validate(action)
            cited = [
                item
                for item in combined.get("evidence", [])
                if item["evidence_id"] in plan.evidence_ids
            ]
            if not any(matching_target(item, simulated_action) for item in cited):
                raise CitationViolation("response target has no cited observation")


def _plan_hash(plan):
    return hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _analysis_route(state):
    if state.get("status") in {"failed", "manual_review"}:
        return "review" if state["status"] == "manual_review" else END
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


def build_graph(nodes, services, checkpointer):
    builder = StateGraph(InvestigationState)

    def wrap(role):
        async def execute(state):
            run_id = await services.start_run(state, role)
            started = _event(state, role, "node.started")
            writer = get_stream_writer()
            writer(started)
            try:
                delta = await getattr(nodes, role)({**state, "_run_id": run_id})
                _validate_output(state, delta)
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

    async def retry(state):
        return {"fallback_count": 1, "status": "collecting"}

    async def review(state):
        delta = {
            "status": "manual_review",
            "stop_reason": state.get("stop_reason") or "insufficient_evidence",
        }
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
        record = ApprovalRecord.model_validate(resume["approval"])
        if (
            record.response_plan_id != plan.response_plan_id
            or resume.get("plan_sha256") != digest
        ):
            raise ValueError("approval does not match pending response plan")
        delta = {
            "approval": record.model_dump(mode="json"),
            "status": "simulating" if record.decision == "approved" else "rejected",
            "approved_plan_sha256": digest,
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
        simulation = [
            {
                **action.model_dump(mode="json"),
                "execution_id": f"{plan.response_plan_id}:{index}",
                "simulated": True,
                "status": "simulated",
                "outcome": "success",
            }
            for index, action in enumerate(actions)
        ]
        delta = {
            "simulation": simulation,
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
    builder.add_edge(START, "triage")
    builder.add_conditional_edges("triage", _role_route("collect"))
    builder.add_conditional_edges("collect", _role_route("analyze"))
    builder.add_conditional_edges("analyze", _analysis_route)
    builder.add_edge("retry", "collect")
    builder.add_edge("review", END)
    builder.add_conditional_edges("reconstruct", _role_route("respond"))
    builder.add_conditional_edges("respond", _role_route("approval"))
    builder.add_conditional_edges(
        "approval", lambda state: "simulate" if state["status"] == "simulating" else END
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
    ):
        self.services = services
        self.settings = settings
        self.checkpointer = checkpointer
        self.database_url = database_url
        self.graph = build_graph(
            nodes or NodeHandlers(services, settings, model), services, checkpointer
        )
        if not hasattr(checkpointer, "_investigation_locks"):
            checkpointer._investigation_locks = {}
        self._locks = checkpointer._investigation_locks

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
                    "attack_steps": [],
                    "response_plan": None,
                    "approval": None,
                    "validation_result": None,
                    "simulation": [],
                    "fallback_count": 0,
                    "fallback_used": False,
                    "errors": [],
                    "events": [],
                    "stop_reason": None,
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

    async def stream_approval(
        self,
        incident_id: str,
        *,
        response_plan_id: str,
        decision: str,
        reason: str,
        decided_by: str,
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
