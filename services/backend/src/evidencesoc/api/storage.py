"""Transactional, restart-safe API repository over the workflow database."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from sqlalchemy import func, inspect, select, text
from sqlalchemy.orm import Session

from evidencesoc.api.tables import (
    ApiAlertPayloadTable,
    ApiIdempotencyKeyTable,
    ApiInvestigationEventTable,
    ApiInvestigationTable,
)
from evidencesoc.domain.models import IncidentStatus
from evidencesoc.ids import new_ulid
from evidencesoc.persistence.json_encoding import restore_json, safe_json
from evidencesoc.persistence.tables import (
    AgentRunTable,
    AlertTable,
    ApprovalTable,
    AttackStepTable,
    EvaluationRunTable,
    EvidenceItemTable,
    IncidentTable,
    ResponsePlanTable,
    SecurityEventTable,
    ValidationResultTable,
)

TERMINAL_STATUSES = frozenset({"completed", "failed", "manual_review", "rejected"})


class StorageConflict(ValueError):
    """A durable identity or transition already has a conflicting value."""


def _json(value: Any) -> Any:
    if isinstance(value, datetime):
        return (
            value.replace(tzinfo=UTC).isoformat()
            if value.tzinfo is None
            else value.astimezone(UTC).isoformat()
        )
    if isinstance(value, dict):
        return {key: _json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json(item) for item in value]
    return value


def _row(row: Any) -> dict[str, Any]:
    return {
        column.key: _json(getattr(row, column.key))
        for column in inspect(row).mapper.column_attrs
    }


def _metadata(row: ApiInvestigationTable) -> dict[str, Any]:
    result = _row(row)
    result["state"] = restore_json(row.state)
    result["last_event_id"] = row.last_sequence
    return result


def _event(row: ApiInvestigationEventTable) -> dict[str, Any]:
    return {"id": row.sequence, "event": row.event, "data": restore_json(row.data)}


class ApiStore:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._sessions = session_factory

    @staticmethod
    def _write_lock(session: Session, *identities: str) -> None:
        dialect = session.get_bind().dialect.name
        if dialect == "sqlite":
            # SQLite has no SELECT FOR UPDATE; reserve its write transaction early.
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        elif dialect == "postgresql":
            for identity in sorted(set(identities)):
                number = int.from_bytes(
                    sha256(identity.encode()).digest()[:8], "big", signed=True
                )
                session.execute(
                    text("SELECT pg_advisory_xact_lock(:identity)"),
                    {"identity": number},
                )

    @staticmethod
    def _investigation(
        session: Session, identity: str, *, lock: bool = False
    ) -> ApiInvestigationTable:
        query = select(ApiInvestigationTable).where(
            ApiInvestigationTable.investigation_id == identity
        )
        row = session.scalar(query.with_for_update() if lock else query)
        if row is None:
            raise LookupError("investigation does not exist")
        return row

    def ingest_alert(
        self, payload: dict[str, Any], key: str | None
    ) -> tuple[dict[str, Any], bool]:
        normalized = _json(
            {name: value for name, value in payload.items() if value is not None}
        )
        if "created_at" in normalized:
            normalized["created_at"] = _json(
                datetime.fromisoformat(normalized["created_at"])
            )
        payload_hash = sha256(
            json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode()
        ).hexdigest()
        supplied_id = normalized.get("alert_id")
        locks = (["idempotency:" + key] if key is not None else []) + (
            ["alert:" + supplied_id] if supplied_id else []
        )
        with self._sessions() as session, session.begin():
            self._write_lock(session, *locks)
            if key is not None:
                replay = session.get(ApiIdempotencyKeyTable, key)
                if replay is not None:
                    if replay.payload_sha256 != payload_hash:
                        raise StorageConflict(
                            "Idempotency-Key is already bound to another payload"
                        )
                    alert = session.get(AlertTable, replay.alert_id)
                    if alert is None:
                        raise LookupError("idempotent alert no longer exists")
                    return _row(alert), False
            existing = session.get(AlertTable, supplied_id) if supplied_id else None
            if existing is not None:
                receipt = session.get(ApiAlertPayloadTable, supplied_id)
                if receipt is not None:
                    matches = receipt.payload_sha256 == payload_hash
                else:
                    persisted = _row(existing)
                    matches = all(
                        persisted.get(name) == value
                        for name, value in normalized.items()
                    )
                if not matches:
                    raise StorageConflict(
                        "alert_id is already bound to another payload"
                    )
                if key is not None:
                    session.add(
                        ApiIdempotencyKeyTable(
                            key=key,
                            alert_id=existing.alert_id,
                            payload_sha256=payload_hash,
                        )
                    )
                return _row(existing), False
            event_ids = normalized["event_ids"]
            existing_events = set(
                session.scalars(
                    select(SecurityEventTable.event_id).where(
                        SecurityEventTable.event_id.in_(event_ids)
                    )
                )
            )
            if not set(event_ids) <= existing_events:
                raise LookupError("one or more source events do not exist")
            alert_id = supplied_id or "AL-" + new_ulid()
            alert = AlertTable(
                alert_id=alert_id,
                title=normalized["title"],
                severity=normalized["severity"],
                created_at=datetime.fromisoformat(normalized["created_at"])
                if "created_at" in normalized
                else datetime.now(UTC),
                event_ids=event_ids,
            )
            session.add(alert)
            session.flush()
            session.add(
                ApiAlertPayloadTable(alert_id=alert_id, payload_sha256=payload_hash)
            )
            if key is not None:
                session.add(
                    ApiIdempotencyKeyTable(
                        key=key, alert_id=alert_id, payload_sha256=payload_hash
                    )
                )
            return _row(alert), True

    def list_alerts(
        self, page: int, page_size: int, severity: str | None, status: str | None
    ) -> dict[str, Any]:
        if page < 1 or page_size < 1:
            raise ValueError("page and page_size must be positive")
        with self._sessions() as session:
            latest_status = (
                select(
                    func.coalesce(ApiInvestigationTable.status, IncidentTable.status)
                )
                .select_from(IncidentTable)
                .outerjoin(
                    ApiInvestigationTable,
                    ApiInvestigationTable.incident_id == IncidentTable.incident_id,
                )
                .where(IncidentTable.alert_id == AlertTable.alert_id)
                .order_by(
                    IncidentTable.created_at.desc(), IncidentTable.incident_id.desc()
                )
                .limit(1)
                .scalar_subquery()
            )
            alert_status = func.coalesce(latest_status, "received")
            query = select(AlertTable, alert_status.label("status"))
            if severity is not None:
                query = query.where(AlertTable.severity == severity)
            if status is not None:
                query = query.where(alert_status == status)
            total = (
                session.scalar(select(func.count()).select_from(query.subquery())) or 0
            )
            rows = session.execute(
                query.order_by(AlertTable.created_at.desc(), AlertTable.alert_id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            ).all()
            items = [
                {**_row(alert), "status": current_status}
                for alert, current_status in rows
            ]
            return {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
            }

    def create_investigation(
        self, *, alert_id: str | None, incident_id: str | None
    ) -> tuple[dict[str, Any], bool]:
        if alert_id is None and incident_id is None:
            raise ValueError("alert_id or incident_id is required")
        with self._sessions() as session, session.begin():
            self._write_lock(session)
            if incident_id is not None:
                incident = session.scalar(
                    select(IncidentTable)
                    .where(IncidentTable.incident_id == incident_id)
                    .with_for_update()
                )
                if incident is None:
                    raise LookupError("incident does not exist")
                if alert_id is not None and incident.alert_id != alert_id:
                    raise StorageConflict("incident belongs to a different alert")
            else:
                alert = session.scalar(
                    select(AlertTable)
                    .where(AlertTable.alert_id == alert_id)
                    .with_for_update()
                )
                if alert is None:
                    raise LookupError("alert does not exist")
                incident = session.scalar(
                    select(IncidentTable)
                    .where(IncidentTable.alert_id == alert_id)
                    .order_by(IncidentTable.created_at, IncidentTable.incident_id)
                    .limit(1)
                    .with_for_update()
                )
                if incident is None:
                    incident = IncidentTable(
                        incident_id="IN-" + new_ulid(),
                        alert_id=alert.alert_id,
                        status="received",
                        created_at=datetime.now(UTC),
                    )
                    session.add(incident)
                    session.flush()
            existing = session.scalar(
                select(ApiInvestigationTable).where(
                    ApiInvestigationTable.incident_id == incident.incident_id
                )
            )
            if existing is not None:
                return _metadata(existing), False
            row = ApiInvestigationTable(
                investigation_id="IV-" + new_ulid(),
                incident_id=incident.incident_id,
                trace_id="TRACE-" + new_ulid(),
                created_at=datetime.now(UTC),
                status=incident.status,
                state={},
                last_sequence=0,
            )
            session.add(row)
            session.flush()
            return _metadata(row), True

    def get_investigation(self, identity: str) -> dict[str, Any]:
        with self._sessions() as session:
            return _metadata(self._investigation(session, identity))

    def get_incident(self, identity: str) -> dict[str, Any]:
        with self._sessions() as session:
            incident = session.get(IncidentTable, identity)
            if incident is None:
                raise LookupError("incident does not exist")
            metadata = session.scalar(
                select(ApiInvestigationTable).where(
                    ApiInvestigationTable.incident_id == identity
                )
            )
            state = restore_json(metadata.state) if metadata is not None else {}
            result = _row(incident)
            if metadata is not None:
                result["status"] = metadata.status
            result.update(
                {
                    "investigation_id": metadata.investigation_id if metadata else None,
                    "trace_id": metadata.trace_id if metadata else None,
                    "origin": state.get("origin"),
                    "classification": state.get("classification"),
                    "simulation": state.get("simulation", []),
                    "fallback_used": state.get("fallback_used", False),
                    "errors": state.get("errors", []),
                    "stop_reason": state.get("stop_reason"),
                    "knowledge": state.get("knowledge", []),
                }
            )
            alert = session.get(AlertTable, incident.alert_id)
            result["alerts"] = [_row(alert)] if alert is not None else []
            for name, model, ordering in (
                (
                    "evidence",
                    EvidenceItemTable,
                    (EvidenceItemTable.observed_at, EvidenceItemTable.evidence_id),
                ),
                ("attack_steps", AttackStepTable, (AttackStepTable.sequence,)),
                (
                    "runs",
                    AgentRunTable,
                    (AgentRunTable.started_at, AgentRunTable.run_id),
                ),
            ):
                result[name] = [
                    _row(row)
                    for row in session.scalars(
                        select(model)
                        .where(model.incident_id == identity)
                        .order_by(*ordering)
                    )
                ]
            for evidence in result["evidence"]:
                evidence["query"] = restore_json(evidence["query"])
            plan = session.scalar(
                select(ResponsePlanTable)
                .where(ResponsePlanTable.incident_id == identity)
                .order_by(
                    ResponsePlanTable.created_at.desc(),
                    ResponsePlanTable.response_plan_id.desc(),
                )
                .limit(1)
            )
            result["response_plan"] = _row(plan) if plan is not None else None
            result["approval"] = None
            result["validation_result"] = None
            if plan is not None:
                approval = session.scalar(
                    select(ApprovalTable)
                    .where(ApprovalTable.response_plan_id == plan.response_plan_id)
                    .order_by(
                        ApprovalTable.decided_at.desc(),
                        ApprovalTable.approval_id.desc(),
                    )
                    .limit(1)
                )
                validation = session.scalar(
                    select(ValidationResultTable)
                    .where(
                        ValidationResultTable.response_plan_id == plan.response_plan_id
                    )
                    .order_by(
                        ValidationResultTable.checked_at.desc(),
                        ValidationResultTable.validation_id.desc(),
                    )
                    .limit(1)
                )
                result["approval"] = _row(approval) if approval is not None else None
                result["validation_result"] = (
                    _row(validation) if validation is not None else None
                )
            return result

    def get_plan(self, identity: str) -> dict[str, Any]:
        with self._sessions() as session:
            plan = session.get(ResponsePlanTable, identity)
            if plan is None:
                raise LookupError("response plan does not exist")
            investigation = session.scalar(
                select(ApiInvestigationTable).where(
                    ApiInvestigationTable.incident_id == plan.incident_id
                )
            )
            return {
                **_row(plan),
                "investigation_id": investigation.investigation_id
                if investigation
                else None,
            }

    def append_event(
        self, identity: str, event: str, data: dict[str, Any], dedup_key: str
    ) -> dict[str, Any]:
        normalized = safe_json(_json(data))
        with self._sessions() as session, session.begin():
            self._write_lock(session)
            investigation = self._investigation(session, identity, lock=True)
            existing = session.scalar(
                select(ApiInvestigationEventTable).where(
                    ApiInvestigationEventTable.investigation_id == identity,
                    ApiInvestigationEventTable.dedup_key == dedup_key,
                )
            )
            if existing is not None:
                if existing.event != event or existing.data != normalized:
                    raise StorageConflict(
                        "event deduplication key is already bound to another payload"
                    )
                return _event(existing)
            investigation.last_sequence += 1
            row = ApiInvestigationEventTable(
                investigation_id=identity,
                sequence=investigation.last_sequence,
                event=event,
                data=normalized,
                dedup_key=dedup_key,
                created_at=datetime.now(UTC),
            )
            session.add(row)
            session.flush()
            return _event(row)

    def list_events(self, identity: str, after: int) -> list[dict[str, Any]]:
        with self._sessions() as session:
            self._investigation(session, identity)
            return [
                _event(row)
                for row in session.scalars(
                    select(ApiInvestigationEventTable)
                    .where(
                        ApiInvestigationEventTable.investigation_id == identity,
                        ApiInvestigationEventTable.sequence > after,
                    )
                    .order_by(ApiInvestigationEventTable.sequence)
                )
            ]

    def save_state(self, identity: str, state: dict[str, Any]) -> None:
        with self._sessions() as session, session.begin():
            self._write_lock(session)
            row = self._investigation(session, identity, lock=True)
            if row.status in TERMINAL_STATUSES:
                return
            self._save_locked(session, row, state)

    @staticmethod
    def _save_locked(
        session: Session, row: ApiInvestigationTable, state: dict[str, Any]
    ) -> None:
        normalized = _json(state)
        status = IncidentStatus(normalized.get("status", row.status)).value
        pending = restore_json(row.state).get("pending_decision")
        approval = normalized.get("approval")
        consumed = (
            isinstance(pending, dict)
            and bool(pending.get("response_plan_id"))
            and isinstance(approval, dict)
            and approval.get("response_plan_id") == pending["response_plan_id"]
        )
        if status in TERMINAL_STATUSES or consumed:
            normalized.pop("pending_decision", None)
        elif pending is not None:
            normalized["pending_decision"] = pending
        row.state = safe_json(normalized)
        row.status = status
        incident = session.get(IncidentTable, row.incident_id)
        if incident is None:
            raise LookupError("incident does not exist")
        incident.status = status

    def finalize(
        self, identity: str, state: dict[str, Any], event: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        """Commit the terminal event and both status records in one transaction."""
        with self._sessions() as session, session.begin():
            self._write_lock(session)
            row = self._investigation(session, identity, lock=True)
            existing = session.scalar(
                select(ApiInvestigationEventTable).where(
                    ApiInvestigationEventTable.investigation_id == identity,
                    ApiInvestigationEventTable.dedup_key == "terminal",
                )
            )
            if existing is not None:
                canonical = _event(existing)
                status = IncidentStatus(canonical["data"]["status"]).value
                if status not in TERMINAL_STATUSES:
                    raise StorageConflict(
                        "existing terminal event has a nonterminal status"
                    )
                repaired_state = {**restore_json(row.state), "status": status}
                self._save_locked(session, row, repaired_state)
                session.flush()
                return canonical
            normalized = _json(state)
            status = IncidentStatus(
                normalized.get("status", data.get("status", row.status))
            ).value
            if status not in TERMINAL_STATUSES:
                raise ValueError("finalize requires a terminal investigation status")
            event_data = _json(data)
            if event_data.get("status", status) != status:
                raise ValueError("terminal event and state statuses must match")
            event_data["status"] = status
            normalized["status"] = status
            row.last_sequence += 1
            terminal = ApiInvestigationEventTable(
                investigation_id=identity,
                sequence=row.last_sequence,
                event=event,
                data=safe_json(event_data),
                dedup_key="terminal",
                created_at=datetime.now(UTC),
            )
            session.add(terminal)
            self._save_locked(session, row, normalized)
            session.flush()
            return _event(terminal)

    def record_decision(self, plan_id: str, decision: dict[str, Any]) -> dict[str, Any]:
        with self._sessions() as session, session.begin():
            self._write_lock(session)
            plan = session.get(ResponsePlanTable, plan_id)
            if plan is None:
                raise LookupError("response plan does not exist")
            row = session.scalar(
                select(ApiInvestigationTable)
                .where(ApiInvestigationTable.incident_id == plan.incident_id)
                .with_for_update()
            )
            if row is None:
                raise LookupError("plan investigation does not exist")
            state = restore_json(row.state)
            current_plan = state.get("response_plan")
            if (
                isinstance(current_plan, dict)
                and current_plan.get("response_plan_id") != plan_id
            ):
                raise StorageConflict(
                    "response plan is not the current investigation plan"
                )
            persisted_approval = session.scalar(
                select(ApprovalTable.approval_id)
                .where(ApprovalTable.response_plan_id == plan_id)
                .limit(1)
            )
            if (
                row.status != "awaiting_approval"
                or state.get("pending_decision") is not None
                or state.get("approval")
                or persisted_approval is not None
            ):
                raise StorageConflict(
                    "response plan is not awaiting a new approval decision"
                )
            state = {**state, "pending_decision": _json(decision)}
            row.state = safe_json(state)
            return _metadata(row)

    def list_recoverable(self) -> list[dict[str, Any]]:
        with self._sessions() as session:
            return [
                _metadata(row)
                for row in session.scalars(
                    select(ApiInvestigationTable)
                    .where(ApiInvestigationTable.status.not_in(TERMINAL_STATUSES))
                    .order_by(
                        ApiInvestigationTable.created_at,
                        ApiInvestigationTable.investigation_id,
                    )
                )
            ]

    def evaluation(self, identity: str) -> dict[str, Any]:
        with self._sessions() as session:
            row = session.get(EvaluationRunTable, identity)
            if row is None:
                raise LookupError("evaluation run does not exist")
            return _row(row)

    def ready(self) -> None:
        with self._sessions() as session:
            if session.get_bind().dialect.name == "postgresql":
                session.execute(text("SET LOCAL statement_timeout = '1000ms'"))
            session.execute(text("SELECT 1"))
