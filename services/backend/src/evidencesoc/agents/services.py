"""Production workflow boundaries: persisted runs and incident-bound MCP tools."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from datetime import UTC, datetime
from hashlib import sha256
from time import monotonic
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from evidencesoc.agents.capabilities import (
    InvestigationCapabilities,
    capability_scope,
    current_capabilities,
)
from evidencesoc.agents.collection import BoundedCollector
from evidencesoc.agents.diagnosis import Diagnosis
from evidencesoc.agents.fallback import matching_target
from evidencesoc.agents.models import SimulatedAction
from evidencesoc.config import BACKEND_ROOT, Settings
from evidencesoc.domain.models import (
    Alert,
    ApprovalRecord,
    EvidenceItem,
    IncidentStatus,
    ResponsePlan,
    ValidationResult,
)
from evidencesoc.ids import new_ulid
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.mcp_server.client import open_stdio_session
from evidencesoc.mcp_server.context import RunContext
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.json_encoding import restore_json
from evidencesoc.persistence.tables import (
    AgentRunTable,
    AlertTable,
    ApprovalTable,
    AttackStepTable,
    EvidenceItemTable,
    IncidentTable,
    ResponsePlanTable,
    SecurityEventTable,
    ValidationResultTable,
)
from evidencesoc.tools.attack import validate_attack_results
from evidencesoc.tools.incident_scope import load_incident_scope
from evidencesoc.tools.incident_scope import observations as _observations
from evidencesoc.tools.ledger import AttemptLimitExceeded, Ledger
from evidencesoc.tools.policy import ALLOWED_TOOLS, validate_event_search


def _utc(value: datetime | str) -> datetime:
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    return (
        parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    )


class PostgresWorkflowServices:
    def __init__(
        self,
        settings: Settings,
        *,
        session_factory: Callable[[], Session] | None = None,
        capabilities: InvestigationCapabilities | None = None,
        verification_observer: Any | None = None,
        model_timeout: float = 60.0,
    ) -> None:
        if model_timeout <= 0:
            raise ValueError("model_timeout must be positive")
        self.settings = settings
        self._engine = None
        if session_factory is None:
            self._engine = create_database_engine(
                settings.database_url, bounded_tool_connections=True
            )
            session_factory = create_session_factory(self._engine)
        self._sessions = session_factory
        self.planner_model: Any | None = None
        self.capabilities = capabilities
        self.verification_observer = verification_observer
        self.model_timeout = model_timeout

    async def aclose(self) -> None:
        await asyncio.to_thread(self.close)

    def close(self) -> None:
        if self._engine is not None:
            self._engine.dispose()

    async def load_incident(self, incident_id: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._load_incident, incident_id)

    def _load_incident(self, incident_id: str) -> dict[str, Any]:
        with self._sessions() as session:
            row = session.execute(
                select(IncidentTable, AlertTable)
                .join(AlertTable, AlertTable.alert_id == IncidentTable.alert_id)
                .where(IncidentTable.incident_id == incident_id)
            ).one_or_none()
            if row is None:
                raise LookupError("incident or its alert does not exist")
            incident, alert = row
            value = Alert(
                alert_id=alert.alert_id,
                title=alert.title,
                severity=alert.severity,
                created_at=_utc(alert.created_at),
                event_ids=alert.event_ids,
            )
            return {
                "alerts": [value.model_dump(mode="json")],
                "status": incident.status,
            }

    async def start_run(self, state: Mapping[str, Any], role: str) -> str:
        return await asyncio.to_thread(self._start_run, dict(state), role)

    def _start_run(self, state: dict[str, Any], role: str) -> str:
        if state.get("trace_id"):
            identity_parts = [
                state["incident_id"],
                state["trace_id"],
                role,
                state.get("fallback_count", 0),
            ]
            if state.get("plan_generation", 0):
                identity_parts.append(state["plan_generation"])
            if role == "validate" and state.get("verification_namespace"):
                identity_parts.append(state["verification_namespace"])
            identity = json.dumps(identity_parts)
            run_id = "AR-" + sha256(identity.encode()).hexdigest()[:32]
        else:
            run_id = "AR-" + new_ulid()
        with self._sessions() as session, session.begin():
            if session.get(IncidentTable, state["incident_id"]) is None:
                raise LookupError("incident does not exist")
            existing = session.get(AgentRunTable, run_id)
            if existing is not None:
                if (
                    existing.incident_id != state["incident_id"]
                    or existing.agent_name != role
                ):
                    raise PermissionError(
                        "agent run belongs to another investigation role"
                    )
                existing.status = "running"
                existing.finished_at = None
                return run_id
            session.add(
                AgentRunTable(
                    run_id=run_id,
                    incident_id=state["incident_id"],
                    agent_name=role,
                    status="running",
                    started_at=datetime.now(UTC),
                    evidence_ids=[],
                )
            )
        return run_id

    async def finish_run(
        self,
        run_id: str,
        delta: Mapping[str, Any],
        status: str = "completed",
    ) -> None:
        await asyncio.to_thread(self._finish_run, run_id, dict(delta), status)

    def _finish_run(self, run_id: str, delta: dict[str, Any], status: str) -> None:
        if status not in {"completed", "failed"}:
            raise ValueError("finished run status must be completed or failed")
        with self._sessions() as session, session.begin():
            row = session.get(AgentRunTable, run_id)
            if row is None:
                raise LookupError("agent run does not exist")
            references = [item["evidence_id"] for item in delta.get("evidence", [])]
            for key in (
                "origin",
                "classification",
                "response_plan",
                "validation_result",
            ):
                if isinstance(delta.get(key), dict):
                    references.extend(delta[key].get("evidence_ids", []))
            for step in delta.get("attack_steps", []):
                references.extend(step.get("evidence_ids", []))
            if delta.get("diagnosis") is not None:
                diagnosis = Diagnosis.model_validate(delta["diagnosis"])
                references.extend(diagnosis.evidence_ids)
                for claim in diagnosis.claims:
                    references.extend(claim.evidence_ids)
                for stage in diagnosis.stage_instances:
                    references.extend(stage.evidence_ids)
                if diagnosis.origin:
                    references.extend(diagnosis.origin.evidence_ids)
            evidence_ids = list(dict.fromkeys(references))
            self._check_evidence_scope(session, row.incident_id, evidence_ids)
            row.evidence_ids = evidence_ids
            row.status = status
            row.finished_at = datetime.now(UTC)
            if row.agent_name == "collect":
                row.output_summary = {
                    key: deepcopy(delta[key])
                    for key in (
                        "collection_round",
                        "collection_budget_used",
                        "collection_round_used",
                        "collection_ledger_ids",
                        "collection_tool_attempts",
                        "collection_model_attempts",
                        "collection_observations",
                        "collection_stop_reason",
                        "collection_refusal_codes",
                        "fallback_used",
                    )
                    if key in delta
                }
            elif row.agent_name == "validate":
                row.output_summary = {
                    key: deepcopy(delta[key])
                    for key in (
                        "verification_call_count",
                        "verification_attempts",
                        "verification_duration_ms",
                    )
                    if key in delta
                }
            internal = {
                key: deepcopy(delta[key])
                for key in (
                    "diagnosis",
                    "diagnostic_snapshot",
                    "diagnostic_snapshot_sha256",
                    "diagnosis_execution_status",
                    "verification_status",
                    "collection_reserved_calls",
                    "response_reason",
                    "no_plan_reason",
                    "no_plan_reason_missing",
                    "response_attempts",
                    "plan_source",
                )
                if key in delta
            }
            if internal:
                row.output_summary = {**(row.output_summary or {}), **internal}

    def _scope(self, incident_id: str) -> dict[str, Any]:
        return load_incident_scope(self._sessions, incident_id)

    @staticmethod
    async def _check_tools(session: Any) -> None:
        discovered = await session.list_tools()
        names = [tool.name for tool in discovered.tools]
        if len(names) != 3 or set(names) != ALLOWED_TOOLS:
            raise PermissionError("MCP server must expose exactly three approved tools")

    @staticmethod
    async def _call(
        session: Any,
        name: str,
        arguments: dict[str, Any],
        *,
        capabilities: InvestigationCapabilities | None = None,
    ) -> list[dict[str, Any]]:
        if name not in ALLOWED_TOOLS:
            raise PermissionError("MCP tool is not allowed")
        policy = capabilities if capabilities is not None else current_capabilities()
        if policy is not None:
            policy.require_tool(name)
        result = await session.call_tool(name, arguments)
        if result.isError:
            payload = result.structuredContent or {}
            code = payload.get("error", {}).get("code", "MCP_TOOL_ERROR")
            raise RuntimeError(f"MCP tool failed: {code}")
        structured = result.structuredContent
        values = structured.get("result") if isinstance(structured, dict) else None
        if not isinstance(values, list) or any(
            not isinstance(item, dict) for item in values
        ):
            raise ValueError("MCP tool returned invalid structured results")
        return values

    async def _verification_call(
        self,
        ledger: Ledger,
        session: Any,
        incident_id: str,
        run_id: str,
        arguments: dict[str, Any],
    ) -> list[dict[str, Any]]:
        row = await asyncio.to_thread(
            ledger.reserve,
            incident_id,
            run_id,
            1,
            "search_security_events",
            arguments,
            "Requery approved simulation target after approval.",
            "verification",
        )
        if row.status == "completed":
            if row.result is None:
                raise ValueError("completed verification call has no recorded result")
            return row.result["values"]
        if row.status == "failed":
            raise RuntimeError(f"verification tool failed: {row.error_code}")
        while True:
            try:
                attempt = await asyncio.to_thread(ledger.begin_attempt, row.call_id)
            except AttemptLimitExceeded as exc:
                await asyncio.to_thread(ledger.fail, row.call_id, "ATTEMPTS_EXHAUSTED")
                raise RuntimeError(
                    "verification tool failed: ATTEMPTS_EXHAUSTED"
                ) from exc
            try:
                values = await asyncio.wait_for(
                    self._call(
                        session,
                        "search_security_events",
                        arguments,
                        capabilities=self.capabilities,
                    ),
                    timeout=10.0,
                )
            except TimeoutError:
                code = "DEPENDENCY_TIMEOUT"
            except Exception as exc:  # noqa: BLE001 - persist a bounded public error code.
                message = str(exc)
                code = (
                    message.rsplit(": ", 1)[-1]
                    if message.startswith("MCP tool failed: ")
                    else "DEPENDENCY_UNAVAILABLE"
                )
                if code not in {
                    "DEPENDENCY_TIMEOUT",
                    "DEPENDENCY_UNAVAILABLE",
                    "NOT_FOUND",
                    "POLICY_DENIED",
                    "MCP_TOOL_ERROR",
                }:
                    code = "DEPENDENCY_UNAVAILABLE"
            else:
                await asyncio.to_thread(
                    ledger.complete, row.call_id, {"values": values}
                )
                return values
            if code in {"NOT_FOUND", "POLICY_DENIED"} or attempt.attempts >= 3:
                await asyncio.to_thread(ledger.fail, row.call_id, code)
                raise RuntimeError(f"verification tool failed: {code}")

    async def hydrate_evidence(
        self,
        incident_id: str,
        values: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._hydrate_evidence, incident_id, values)

    def _hydrate_evidence(
        self,
        incident_id: str,
        values: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        received = {
            item.evidence_id: item
            for item in (EvidenceItem.model_validate(value) for value in values)
        }
        if not received:
            return []
        with self._sessions() as session:
            rows = session.execute(
                select(EvidenceItemTable, SecurityEventTable)
                .join(
                    SecurityEventTable,
                    SecurityEventTable.event_id == EvidenceItemTable.event_id,
                )
                .where(
                    EvidenceItemTable.incident_id == incident_id,
                    EvidenceItemTable.evidence_id.in_(received),
                )
            ).all()
            if {row[0].evidence_id for row in rows} != set(received):
                raise PermissionError("evidence is not owned by this incident")
            result = []
            for evidence, event in rows:
                incoming = received[evidence.evidence_id]
                if (
                    incoming.event_id != evidence.event_id
                    or incoming.source != evidence.source
                    or incoming.content_sha256 != evidence.content_sha256
                    or _utc(incoming.observed_at) != _utc(evidence.observed_at)
                    or event.source != evidence.source
                    or event.content_sha256 != evidence.content_sha256
                    or calculate_content_sha256(event.raw) != event.content_sha256
                ):
                    raise ValueError(
                        "evidence or its source failed integrity verification"
                    )
                stored = EvidenceItem(
                    evidence_id=evidence.evidence_id,
                    event_id=evidence.event_id,
                    source=evidence.source,
                    observed_at=_utc(evidence.observed_at),
                    query=restore_json(evidence.query),
                    summary=evidence.summary,
                    content_sha256=evidence.content_sha256,
                ).model_dump(mode="json")
                stored["raw"] = _observations(event.raw)
                result.append(stored)
        return sorted(
            result, key=lambda item: (item["observed_at"], item["evidence_id"])
        )

    async def collect(self, state: Mapping[str, Any], run_id: str) -> dict[str, Any]:
        with capability_scope(self.capabilities):
            return await self._collect(state, run_id)

    async def _collect(self, state: Mapping[str, Any], run_id: str) -> dict[str, Any]:
        incident_id = state["incident_id"]
        scope = await asyncio.to_thread(self._scope, incident_id)
        context = RunContext(
            run_id, incident_id, state.get("trace_id") or "TRACE-" + new_ulid()
        )
        model = self.planner_model
        if self.settings.llm_mode != "fixture" and model is None:
            try:
                from evidencesoc.agents.model import DeepSeekStructuredModel

                model = DeepSeekStructuredModel(self.settings)
            except Exception:  # noqa: BLE001 - model unavailability triggers bounded rules.
                model = None
        async with open_stdio_session(
            context,
            settings=self.settings,
            backend_dir=BACKEND_ROOT,
            managed_attempts=True,
        ) as session:
            await self._check_tools(session)
            collector = BoundedCollector(
                ledger=Ledger(self._sessions),
                invoke=lambda name, arguments: self._call(
                    session, name, arguments, capabilities=self.capabilities
                ),
                scope={
                    key: scope[key]
                    for key in ("alert_id", "time_from", "time_to", "filters", "limit")
                },
                state=state,
                run_id=run_id,
                model=model,
                llm_mode=self.settings.llm_mode,
                capabilities=self.capabilities,
                model_timeout=self.model_timeout,
            )
            collected = await collector.run()
        values = collected.pop("evidence_values")
        knowledge = collected["knowledge"]
        validate_attack_results(knowledge, limit=10)
        evidence = await self.hydrate_evidence(incident_id, values)
        return {**collected, "evidence": evidence}

    async def verify(self, state: Mapping[str, Any], run_id: str) -> dict[str, Any]:
        if self.capabilities is not None and not self.capabilities.verification_enabled:
            raise PermissionError("verification disabled by investigation capabilities")
        started = monotonic()
        incident_id = state["incident_id"]
        scope = await asyncio.to_thread(self._scope, incident_id)
        if not scope["filters"]:
            return {
                "evidence": [],
                "executed_checks": [],
                "verification_call_count": 0,
                "verification_attempts": 0,
                "verification_duration_ms": round((monotonic() - started) * 1000),
            }
        context = RunContext(
            run_id, incident_id, state.get("trace_id") or "TRACE-" + new_ulid()
        )
        plan = ResponsePlan.model_validate(state["response_plan"])
        if plan.incident_id != incident_id:
            raise PermissionError("verification plan belongs to a different incident")
        queries: dict[str, dict[str, Any]] = {}
        requested_checks: list[tuple[str, str]] = []
        used_check_ids: set[str] = set()
        lower, upper = _utc(scope["time_from"]), _utc(scope["time_to"])
        for index, raw_action in enumerate(plan.actions, start=1):
            action = SimulatedAction.model_validate(raw_action)
            query = action.verification_query
            source = next(
                (
                    item
                    for item in scope["source_scopes"]
                    if item["filters"]
                    and matching_target({"raw": item["raw"]}, action)
                    and all(
                        item["filters"][key] == value
                        for key, value in query["filters"].items()
                        if key in item["filters"]
                    )
                ),
                None,
            )
            if source is None:
                raise PermissionError(
                    "verification target is not observed in the alert source events"
                )
            filters = dict(source["filters"])
            for key, value in query["filters"].items():
                if key == "dataset_id" and key not in scope["filters"]:
                    raise PermissionError(
                        "verification dataset is not anchored to the incident"
                    )
                if key in filters and filters[key] != value:
                    raise PermissionError(
                        "verification conflicts with the incident source filters"
                    )
                filters[key] = value
            start, end = (
                _utc(query.get("time_from", scope["time_from"])),
                _utc(query.get("time_to", scope["time_to"])),
            )
            if start < lower or end > upper:
                raise PermissionError(
                    "verification cannot expand the incident time window"
                )
            limit = query.get("limit", scope["limit"])
            if limit > scope["limit"]:
                raise ValueError("verification limit cannot exceed 100")
            validate_event_search(start, end, filters, limit)
            arguments = {
                "time_from": start.isoformat(),
                "time_to": end.isoformat(),
                "filters": filters,
                "limit": limit,
            }
            query_key = json.dumps(arguments, sort_keys=True)
            queries[query_key] = arguments
            configured_check = next(
                (
                    check
                    for check in plan.validation_checks
                    if check.check_id not in used_check_ids
                    and check.target == action.target
                    and check.query == query
                ),
                None,
            )
            check_id = (
                configured_check.check_id
                if configured_check is not None
                else f"VC-legacy-{index}"
            )
            used_check_ids.add(check_id)
            requested_checks.append((check_id, query_key))
        values: list[dict[str, Any]] = []
        query_values: dict[str, list[dict[str, Any]]] = {}
        ledger = Ledger(self._sessions)
        async with open_stdio_session(
            context,
            settings=self.settings,
            backend_dir=BACKEND_ROOT,
            managed_attempts=True,
        ) as session:
            await self._check_tools(session)
            for key, arguments in queries.items():
                query_values[key] = await self._verification_call(
                    ledger, session, incident_id, run_id, arguments
                )
                values.extend(query_values[key])
        evidence = await self.hydrate_evidence(incident_id, values)
        rows = await asyncio.to_thread(ledger.calls, incident_id, 1, "verification")
        own = [row for row in rows if row.run_id == run_id]
        result = {
            "evidence": evidence,
            "executed_checks": [
                {
                    "check_id": check_id,
                    "condition": queries[key],
                    "evidence_ids": list(
                        dict.fromkeys(item["evidence_id"] for item in query_values[key])
                    ),
                }
                for check_id, key in requested_checks
            ],
            "verification_call_count": len(own),
            "verification_attempts": sum(row.attempts for row in own),
            "verification_duration_ms": round((monotonic() - started) * 1000),
        }
        if self.verification_observer is not None:
            observed = await self.verification_observer(
                dict(state), run_id, deepcopy(result)
            )
            if not isinstance(observed, dict) or set(observed) - {
                "effect_observations",
                "evidence",
            }:
                raise ValueError(
                    "verification observer must return only observations and evidence"
                )
            result.update(observed)
        return result

    @staticmethod
    def _check_evidence_scope(
        session: Session, incident_id: str, evidence_ids: Sequence[str]
    ) -> None:
        if not evidence_ids:
            return
        owned = set(
            session.scalars(
                select(EvidenceItemTable.evidence_id).where(
                    EvidenceItemTable.incident_id == incident_id,
                    EvidenceItemTable.evidence_id.in_(evidence_ids),
                )
            )
        )
        if not set(evidence_ids) <= owned:
            raise PermissionError("result cites evidence outside this incident")

    async def save_result(self, state: Mapping[str, Any]) -> None:
        await asyncio.to_thread(self._save_result, dict(state))

    def _save_result(self, state: dict[str, Any]) -> None:
        incident_id = state["incident_id"]
        status = IncidentStatus(state["status"]).value
        plan = (
            ResponsePlan.model_validate(state["response_plan"])
            if state.get("response_plan")
            else None
        )
        approval = (
            ApprovalRecord.model_validate(state["approval"])
            if state.get("approval")
            else None
        )
        validation = (
            ValidationResult.model_validate(state["validation_result"])
            if state.get("validation_result")
            else None
        )
        if plan is not None and plan.incident_id != incident_id:
            raise PermissionError("response plan belongs to a different incident")
        for result in (approval, validation):
            if result is not None and (
                plan is None or result.response_plan_id != plan.response_plan_id
            ):
                raise PermissionError("result belongs to a different response plan")
        with self._sessions() as session, session.begin():
            incident = session.get(IncidentTable, incident_id)
            if incident is None:
                raise LookupError("incident does not exist")
            incident.status = status
            if plan is not None:
                self._check_evidence_scope(session, incident_id, plan.evidence_ids)
                existing = session.get(ResponsePlanTable, plan.response_plan_id)
                if existing is not None and existing.incident_id != incident_id:
                    raise PermissionError(
                        "response plan identifier is already owned by another incident"
                    )
                session.merge(ResponsePlanTable(**plan.model_dump()))
                session.flush()
            if approval is not None:
                existing_approval = session.get(ApprovalTable, approval.approval_id)
                if (
                    existing_approval is not None
                    and existing_approval.response_plan_id != approval.response_plan_id
                ):
                    raise PermissionError("approval identifier belongs to another plan")
                session.merge(ApprovalTable(**approval.model_dump()))
            if validation is not None:
                self._check_evidence_scope(
                    session, incident_id, validation.evidence_ids
                )
                existing_validation = session.get(
                    ValidationResultTable, validation.validation_id
                )
                if (
                    existing_validation is not None
                    and existing_validation.response_plan_id
                    != validation.response_plan_id
                ):
                    raise PermissionError(
                        "validation identifier belongs to another plan"
                    )
                values = validation.model_dump()
                values["checks"] = [
                    check.model_dump(mode="json") for check in validation.checks
                ]
                session.merge(ValidationResultTable(**values))
            for step in state.get("attack_steps", []):
                values = dict(step)
                self._check_evidence_scope(session, incident_id, values["evidence_ids"])
                existing_step = session.get(AttackStepTable, values["attack_step_id"])
                if (
                    existing_step is not None
                    and existing_step.incident_id != incident_id
                ):
                    raise PermissionError(
                        "attack step identifier belongs to another incident"
                    )
                if values.get("occurred_at") is not None:
                    values["occurred_at"] = _utc(values["occurred_at"])
                values["incident_id"] = incident_id
                session.merge(AttackStepTable(**values))
