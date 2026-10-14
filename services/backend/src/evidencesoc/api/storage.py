"""Transactional, restart-safe API repository over the workflow database."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, inspect, or_, select, text
from sqlalchemy.orm import Session, aliased

from evidencesoc.api.tables import (
    ApiAlertPayloadTable,
    ApiDecisionReceiptTable,
    ApiIdempotencyKeyTable,
    ApiInvestigationEventTable,
    ApiInvestigationTable,
)
from evidencesoc.domain.models import (
    IncidentStatus,
    PlanRollbackStep,
    PlanValidationCheck,
)
from evidencesoc.domain.response_action import SimulatedAction
from evidencesoc.ids import new_ulid
from evidencesoc.ingestion.normalize import calculate_content_sha256
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


class PlanExpired(ValueError):
    """The persisted response plan can no longer receive a decision."""


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


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _row(row: Any) -> dict[str, Any]:
    return {
        column.key: _json(getattr(row, column.key))
        for column in inspect(row).mapper.column_attrs
    }


def _step_entity(
    evidence_ids: list[str],
    verified_raw: dict[str, dict[str, Any]],
    keys: tuple[str, ...],
) -> str | None:
    """Expose observed values only when this step's citations agree."""
    values = {
        value.strip()
        for evidence_id in evidence_ids
        for key in keys
        if isinstance(value := verified_raw.get(evidence_id, {}).get(key), str)
        and value.strip()
    }
    return next(iter(values)) if len(values) == 1 else None


def _plan_version(plan: ResponsePlanTable) -> str:
    canonical = json.dumps(
        _row(plan), sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return sha256(canonical.encode()).hexdigest()


def _plan_expired(plan: ResponsePlanTable, *, now: datetime | None = None) -> bool:
    return plan.expires_at is not None and _as_utc(plan.expires_at) <= (
        now or datetime.now(UTC)
    )


def _valid_simulated_actions(actions: Any) -> bool:
    if not isinstance(actions, list) or not actions:
        return False
    try:
        for action in actions:
            SimulatedAction.model_validate(action)
    except (ValidationError, TypeError, ValueError):
        return False
    return True


def _valid_review_details(plan: ResponsePlanTable) -> bool:
    """Recheck persisted review data before offering or accepting approval."""
    if (
        plan.execution_mode != "simulation"
        or plan.risk_level not in {"low", "medium", "high", "critical"}
        or not isinstance(plan.risk_reason, str)
        or not plan.risk_reason.strip()
        or not isinstance(plan.business_impact, str)
        or not plan.business_impact.strip()
        or plan.expires_at is None
        or _plan_expired(plan)
        or _as_utc(plan.expires_at) <= _as_utc(plan.created_at)
        or _as_utc(plan.expires_at) > _as_utc(plan.created_at) + timedelta(minutes=30)
        or not isinstance(plan.rollback_steps, list)
        or not plan.rollback_steps
        or not isinstance(plan.validation_checks, list)
        or not plan.validation_checks
        or not _valid_simulated_actions(plan.actions)
    ):
        return False
    try:
        rollbacks = [
            PlanRollbackStep.model_validate(item) for item in plan.rollback_steps
        ]
        checks = [
            PlanValidationCheck.model_validate(item) for item in plan.validation_checks
        ]
    except (ValidationError, TypeError, ValueError):
        return False
    targets = {action["target"] for action in plan.actions}
    if (
        not isinstance(plan.evidence_ids, list)
        or not plan.evidence_ids
        or any(not isinstance(item, str) or not item for item in plan.evidence_ids)
        or not isinstance(plan.affected_assets, list)
        or any(
            not isinstance(item, str) or not item.strip()
            for item in plan.affected_assets
        )
        or set(plan.affected_assets) != targets
        or {step.target for step in rollbacks} != targets
        or {check.target for check in checks} != targets
    ):
        return False
    citations = set(plan.evidence_ids)
    actions = [SimulatedAction.model_validate(item) for item in plan.actions]
    action_ids = [action.action_id for action in actions]
    if any(not action.traceable for action in actions) or len(set(action_ids)) != len(
        action_ids
    ):
        return False
    rollback_refs = {step.step_id: step for step in rollbacks}
    if any(
        not set(action.evidence_ids or []) <= citations
        or action.rollback_ref not in rollback_refs
        or rollback_refs[action.rollback_ref].target != action.target
        for action in actions
    ):
        return False
    review_steps: list[PlanRollbackStep | PlanValidationCheck] = [*rollbacks, *checks]
    for step in review_steps:
        if (
            not step.description.strip()
            or not step.expected_result.strip()
            or not step.target.strip()
            or not step.evidence_ids
            or not set(step.evidence_ids) <= citations
        ):
            return False
    return all(
        any(
            check.target == action["target"]
            and check.query == action["verification_query"]
            for action in plan.actions
        )
        for check in checks
    )


def _metadata(row: ApiInvestigationTable) -> dict[str, Any]:
    result = _row(row)
    result["state"] = _public_state(row)
    result["last_event_id"] = row.last_sequence
    return result


_SNAPSHOT_META_KEY = "_api_snapshot"


def _public_state(row: ApiInvestigationTable) -> dict[str, Any]:
    state = restore_json(row.state)
    return {key: value for key, value in state.items() if key != _SNAPSHOT_META_KEY}


def _snapshot_revision(row: ApiInvestigationTable) -> int:
    meta = restore_json(row.state).get(_SNAPSHOT_META_KEY, {})
    revision = meta.get("revision") if isinstance(meta, dict) else None
    return max(
        row.last_sequence,
        revision if isinstance(revision, int) and not isinstance(revision, bool) else 0,
    )


def _snapshot_updated_at(row: ApiInvestigationTable) -> str:
    meta = restore_json(row.state).get(_SNAPSHOT_META_KEY, {})
    updated_at = meta.get("updated_at") if isinstance(meta, dict) else None
    return updated_at if isinstance(updated_at, str) else _json(row.created_at)


def _advance_snapshot(
    row: ApiInvestigationTable, state: dict[str, Any] | None = None
) -> None:
    # The cursor counts persisted events; this separate durable revision also
    # advances for state-only writes, without introducing gaps in the SSE sequence.
    public = _public_state(row) if state is None else dict(state)
    public.pop(_SNAPSHOT_META_KEY, None)
    public[_SNAPSHOT_META_KEY] = {
        "revision": _snapshot_revision(row) + 1,
        "updated_at": _json(datetime.now(UTC)),
    }
    row.state = safe_json(public)


def _event(row: ApiInvestigationEventTable) -> dict[str, Any]:
    return {"id": row.sequence, "event": row.event, "data": restore_json(row.data)}


def _state_plan_id(state: dict[str, Any]) -> str | None:
    plan = state.get("response_plan")
    return plan.get("response_plan_id") if isinstance(plan, dict) else None


def _pending_plan_decision(
    state: dict[str, Any], plan_id: str, is_current: bool
) -> str | None:
    pending = state.get("pending_decision")
    if (
        is_current
        and isinstance(pending, dict)
        and pending.get("response_plan_id") in (None, plan_id)
        and pending.get("decision") in ("approved", "rejected")
    ):
        return pending["decision"]
    return None


def _cited_evidence_verified(
    session: Session, plan: ResponsePlanTable, *, lock: bool = False
) -> bool:
    cited_ids = plan.evidence_ids
    if (
        not isinstance(cited_ids, list)
        or not cited_ids
        or any(not isinstance(identity, str) or not identity for identity in cited_ids)
    ):
        return False
    identities = sorted(set(cited_ids))
    evidence_query = (
        select(EvidenceItemTable)
        .where(
            EvidenceItemTable.incident_id == plan.incident_id,
            EvidenceItemTable.evidence_id.in_(identities),
        )
        .order_by(EvidenceItemTable.evidence_id)
    )
    evidence = list(
        session.scalars(evidence_query.with_for_update() if lock else evidence_query)
    )
    if len(evidence) != len(identities):
        return False
    event_query = (
        select(SecurityEventTable)
        .where(SecurityEventTable.event_id.in_({item.event_id for item in evidence}))
        .order_by(SecurityEventTable.event_id)
    )
    events = {
        item.event_id: item
        for item in session.scalars(
            event_query.with_for_update() if lock else event_query
        )
    }
    for item in evidence:
        event = events.get(item.event_id)
        if event is None or not isinstance(event.raw, dict):
            return False
        try:
            calculated = calculate_content_sha256(event.raw)
        except ValueError:
            return False
        if calculated != event.content_sha256 or calculated != item.content_sha256:
            return False
    return True


def _response_plan_item(
    plan: ResponsePlanTable,
    incident: IncidentTable,
    alert: AlertTable,
    investigation: ApiInvestigationTable | None,
    approval_decision: str | None,
    latest_plan_id: str | None,
) -> dict[str, Any]:
    state = restore_json(investigation.state) if investigation is not None else {}
    current_state_plan_id = _state_plan_id(state)
    is_current = plan.response_plan_id == (current_state_plan_id or latest_plan_id)
    pending_decision = _pending_plan_decision(state, plan.response_plan_id, is_current)
    return {
        **_row(plan),
        "plan_version": _plan_version(plan),
        "is_expired": _plan_expired(plan),
        "investigation_id": investigation.investigation_id if investigation else None,
        "alert_id": alert.alert_id,
        "alert_title": alert.title,
        "severity": alert.severity,
        "incident_status": investigation.status if investigation else incident.status,
        "decision_state": approval_decision
        or ("submitting" if pending_decision else "pending"),
        "is_current": is_current,
    }


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
        self,
        page: int,
        page_size: int,
        severity: str | None,
        status: str | None,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        query_text: str | None = None,
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
            if time_from is not None:
                query = query.where(AlertTable.created_at >= time_from)
            if time_to is not None:
                query = query.where(AlertTable.created_at < time_to)
            if query_text is not None:
                escaped = (
                    query_text.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                pattern = f"%{escaped}%"
                query = query.where(
                    or_(
                        AlertTable.title.ilike(pattern, escape="\\"),
                        AlertTable.alert_id.ilike(pattern, escape="\\"),
                    )
                )
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

    def get_alert(self, identity: str) -> dict[str, Any]:
        with self._sessions() as session:
            alert = session.get(AlertTable, identity)
            if alert is None:
                raise LookupError("alert does not exist")
            linked = session.execute(
                select(IncidentTable, ApiInvestigationTable)
                .outerjoin(
                    ApiInvestigationTable,
                    ApiInvestigationTable.incident_id == IncidentTable.incident_id,
                )
                .where(IncidentTable.alert_id == identity)
                .order_by(
                    IncidentTable.created_at.desc(), IncidentTable.incident_id.desc()
                )
                .limit(1)
            ).first()
            incident, investigation = linked if linked is not None else (None, None)
            summaries = {
                event_id: {
                    "event_id": event_id,
                    "source": source,
                    "observed_at": _json(observed_at),
                    "severity": severity,
                    "event_type": event_type,
                }
                for event_id, source, observed_at, severity, event_type in session.execute(
                    select(
                        SecurityEventTable.event_id,
                        SecurityEventTable.source,
                        SecurityEventTable.observed_at,
                        SecurityEventTable.severity,
                        SecurityEventTable.event_type,
                    ).where(SecurityEventTable.event_id.in_(alert.event_ids))
                )
            }
            return {
                **_row(alert),
                "status": (
                    investigation.status
                    if investigation is not None
                    else incident.status
                    if incident is not None
                    else "received"
                ),
                "incident_id": incident.incident_id if incident is not None else None,
                "investigation_id": (
                    investigation.investigation_id
                    if investigation is not None
                    else None
                ),
                "events": [
                    summaries[event_id]
                    for event_id in alert.event_ids
                    if event_id in summaries
                ],
            }

    def create_investigation(
        self,
        *,
        alert_id: str | None,
        incident_id: str | None,
        mode: str | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        if alert_id is None and incident_id is None:
            raise ValueError("alert_id or incident_id is required")
        receipt_key = (
            f"investigation:{idempotency_key}" if idempotency_key is not None else None
        )
        request_hash = sha256(
            json.dumps(
                {"alert_id": alert_id, "incident_id": incident_id, "mode": mode},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        with self._sessions() as session, session.begin():
            self._write_lock(
                session, *([f"idempotency:{receipt_key}"] if receipt_key else [])
            )
            receipt = (
                session.get(ApiIdempotencyKeyTable, receipt_key)
                if receipt_key is not None
                else None
            )
            if receipt is not None and receipt.payload_sha256 != request_hash:
                raise StorageConflict(
                    "Idempotency-Key is already bound to another payload"
                )
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
                if receipt_key is not None and receipt is None:
                    session.add(
                        ApiIdempotencyKeyTable(
                            key=receipt_key,
                            alert_id=incident.alert_id,
                            payload_sha256=request_hash,
                        )
                    )
                return _metadata(existing), False
            if receipt is not None:
                raise StorageConflict("Idempotent investigation no longer exists")
            row = ApiInvestigationTable(
                investigation_id="IV-" + new_ulid(),
                incident_id=incident.incident_id,
                trace_id="TRACE-" + new_ulid(),
                created_at=datetime.now(UTC),
                status=incident.status,
                state={
                    _SNAPSHOT_META_KEY: {
                        "revision": 0,
                        "updated_at": _json(datetime.now(UTC)),
                    }
                },
                last_sequence=0,
            )
            session.add(row)
            session.flush()
            if receipt_key is not None:
                session.add(
                    ApiIdempotencyKeyTable(
                        key=receipt_key,
                        alert_id=incident.alert_id,
                        payload_sha256=request_hash,
                    )
                )
            return _metadata(row), True

    def get_investigation(self, identity: str) -> dict[str, Any]:
        with self._sessions() as session:
            return _metadata(self._investigation(session, identity))

    def prepare_plan_renewal(
        self,
        plan_id: str,
        expected_version: str,
        requested_by: str,
        idempotency_key: str,
    ) -> tuple[dict[str, Any], bool]:
        """Reserve one regeneration of an expired plan on the existing case."""
        if not 1 <= len(idempotency_key) <= 255 or not idempotency_key.strip():
            raise ValueError("invalid Idempotency-Key")
        if not requested_by.strip():
            raise ValueError("reviewer identity is required")
        receipt_key = "plan-renewal:" + sha256(idempotency_key.encode()).hexdigest()
        payload_hash = sha256(
            json.dumps(
                {
                    "plan_id": plan_id,
                    "plan_version": expected_version,
                    "requested_by": requested_by,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        with self._sessions() as session, session.begin():
            self._write_lock(
                session, "renewal-key:" + receipt_key, "renewal-plan:" + plan_id
            )
            plan = session.scalar(
                select(ResponsePlanTable)
                .where(ResponsePlanTable.response_plan_id == plan_id)
                .with_for_update()
            )
            if plan is None:
                raise LookupError("response plan does not exist")
            row = session.scalar(
                select(ApiInvestigationTable)
                .where(ApiInvestigationTable.incident_id == plan.incident_id)
                .with_for_update()
            )
            if row is None:
                raise LookupError("plan investigation does not exist")
            receipt = session.get(ApiIdempotencyKeyTable, receipt_key)
            if receipt is not None:
                if receipt.payload_sha256 != payload_hash:
                    raise StorageConflict(
                        "Idempotency-Key is already bound to another plan renewal"
                    )
                return _metadata(row), False
            if _plan_version(plan) != expected_version:
                raise StorageConflict("response plan version is stale")
            if not _plan_expired(plan):
                raise StorageConflict("response plan has not expired")
            state = restore_json(row.state)
            if (
                row.status != "awaiting_approval"
                or _state_plan_id(state) != plan_id
                or state.get("pending_decision") is not None
                or state.get("pending_renewal") is not None
                or state.get("approval") is not None
                or session.scalar(
                    select(ApprovalTable.approval_id)
                    .where(ApprovalTable.response_plan_id == plan_id)
                    .limit(1)
                )
                is not None
            ):
                raise StorageConflict(
                    "response plan cannot be renewed in its current state"
                )
            if not _cited_evidence_verified(session, plan, lock=True):
                raise StorageConflict(
                    "response plan cited evidence integrity is unavailable"
                )
            command = {
                "response_plan_id": plan_id,
                "plan_version": expected_version,
                "requested_by": requested_by,
            }
            _advance_snapshot(row, {**state, "pending_renewal": command})
            row.status = "reconstructing"
            incident = session.get(IncidentTable, row.incident_id)
            if incident is None:
                raise LookupError("incident does not exist")
            incident.status = "reconstructing"
            session.add(
                ApiIdempotencyKeyTable(
                    key=receipt_key,
                    alert_id=incident.alert_id,
                    payload_sha256=payload_hash,
                )
            )
            return _metadata(row), True

    def get_investigation_snapshot(self, identity: str) -> dict[str, Any]:
        """Read the case, its records, revision, and event cursor from one DB view."""
        with self._sessions() as session, session.begin():
            if session.get_bind().dialect.name == "postgresql":
                session.execute(
                    text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                )
            investigation = self._investigation(session, identity)
            incident = session.get(IncidentTable, investigation.incident_id)
            if incident is None:
                raise LookupError("incident does not exist")
            alert = session.get(AlertTable, incident.alert_id)
            if alert is None:
                raise LookupError("alert does not exist")
            state = _public_state(investigation)
            revision = str(_snapshot_revision(investigation))
            updated_at = _snapshot_updated_at(investigation)

            evidence = [
                {**_row(row), "query": restore_json(row.query)}
                for row in session.scalars(
                    select(EvidenceItemTable)
                    .where(EvidenceItemTable.incident_id == incident.incident_id)
                    .order_by(
                        EvidenceItemTable.observed_at, EvidenceItemTable.evidence_id
                    )
                )
            ]
            steps = [
                _row(row)
                for row in session.scalars(
                    select(AttackStepTable)
                    .where(AttackStepTable.incident_id == incident.incident_id)
                    .order_by(AttackStepTable.sequence, AttackStepTable.attack_step_id)
                )
            ]
            runs = [
                _row(row)
                for row in session.scalars(
                    select(AgentRunTable)
                    .where(AgentRunTable.incident_id == incident.incident_id)
                    .order_by(AgentRunTable.started_at, AgentRunTable.run_id)
                )
            ]
            plan = session.scalar(
                select(ResponsePlanTable)
                .where(ResponsePlanTable.incident_id == incident.incident_id)
                .order_by(
                    ResponsePlanTable.created_at.desc(),
                    ResponsePlanTable.response_plan_id.desc(),
                )
                .limit(1)
            )
            approval = None
            validation = None
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

            # A graph edge is an asserted relationship, not a visual ordering.
            # Current storage only records steps, so no edges can be asserted here.
            evidence_ids = {item["evidence_id"] for item in evidence}
            events_by_id = {
                row.event_id: row
                for row in session.scalars(
                    select(SecurityEventTable).where(
                        SecurityEventTable.event_id.in_(
                            {item["event_id"] for item in evidence}
                        )
                    )
                )
            }
            verified_raw = {}
            for item in evidence:
                event_row = events_by_id.get(item["event_id"])
                if event_row is None or event_row.source != item["source"]:
                    continue
                raw = restore_json(event_row.raw)
                if not isinstance(raw, dict):
                    continue
                try:
                    digest = calculate_content_sha256(raw)
                except (TypeError, ValueError):
                    continue
                if digest == event_row.content_sha256 == item["content_sha256"]:
                    verified_raw[item["evidence_id"]] = raw
            graph_nodes = [
                {
                    "step_id": step["attack_step_id"],
                    "sequence": step["sequence"],
                    "phase": step["phase"],
                    "description": step["description"],
                    "host": _step_entity(
                        step["evidence_ids"],
                        verified_raw,
                        ("host", "hostname", "destination_host"),
                    ),
                    "service": _step_entity(
                        step["evidence_ids"], verified_raw, ("service",)
                    ),
                    "observed_at": step["occurred_at"],
                    "technique_ids": [step["technique_id"]]
                    if step["technique_id"]
                    else [],
                    "confidence": None,
                    "evidence_ids": step["evidence_ids"],
                    "support_status": "supported"
                    if step["evidence_ids"]
                    and set(step["evidence_ids"]) <= evidence_ids
                    else "insufficient",
                }
                for step in steps
            ]
            role_keys = {
                "triage": "triage",
                "collect": "evidence_collection",
                "analyze": "threat_analysis",
                "reconstruct": "attack_reconstruction",
                "respond": "response_decision",
                "validate": "validation",
            }
            agent_runs = [
                {
                    **run,
                    "role_key": role_keys.get(run["agent_name"]),
                    # The run table has no attempt or output summary columns.
                    "attempt": None,
                    "output_summary": None,
                    "error": None,
                }
                for run in runs
            ]
            knowledge_refs = []
            for item in state.get("knowledge", []):
                if not isinstance(item, dict):
                    continue
                source = item.get("source_uri")
                if not isinstance(source, str) or not source.startswith(
                    ("https://attack.mitre.org/techniques/", "internal://knowledge/")
                ):
                    continue
                identifier = item.get("knowledge_chunk_id")
                if not isinstance(identifier, str) or not identifier:
                    continue
                knowledge_refs.append(
                    {
                        "knowledge_chunk_id": identifier,
                        "technique_id": item.get("technique_id") or None,
                        "title": item.get("title") or None,
                        "version": item.get("version") or None,
                        "source_uri": source,
                        "retrieved_at": item.get("retrieved_at"),
                    }
                )

            can_decide = bool(
                plan is not None
                and plan.requires_approval
                and _valid_simulated_actions(plan.actions)
                and not _plan_expired(plan)
                and investigation.status == "awaiting_approval"
                and _state_plan_id(state) in (None, plan.response_plan_id)
                and state.get("pending_decision") is None
                and not state.get("approval")
                and approval is None
            )
            errors = state.get("errors", [])
            last_error = errors[-1] if isinstance(errors, list) and errors else None
            code = last_error.get("code") if isinstance(last_error, dict) else None
            failure = (
                {
                    "code": code,
                    "message": "Investigation failed; review the recorded error code.",
                    "trace_id": investigation.trace_id,
                }
                if investigation.status == "failed" and isinstance(code, str)
                else None
            )
            fallback_count = state.get("fallback_count", 0)
            if not isinstance(fallback_count, int) or isinstance(fallback_count, bool):
                fallback_count = 0
            incident_view = {**_row(incident), "status": investigation.status}
            return {
                **incident_view,
                "investigation_id": investigation.investigation_id,
                "trace_id": investigation.trace_id,
                "alerts": [_row(alert)],
                "evidence": evidence,
                "knowledge": knowledge_refs,
                "attack_steps": steps,
                "runs": runs,
                "origin": state.get("origin"),
                "classification": state.get("classification"),
                "response_plan": _row(plan) if plan is not None else None,
                "approval": _row(approval) if approval is not None else None,
                "validation_result": _row(validation)
                if validation is not None
                else None,
                "simulation": state.get("simulation", []),
                "simulation_execution": state.get("simulation_execution"),
                "fallback_used": bool(state.get("fallback_used", False)),
                "errors": errors,
                "stop_reason": state.get("stop_reason"),
                "revision": revision,
                "stream_cursor": str(investigation.last_sequence),
                "updated_at": updated_at,
                "available_actions": (
                    ["approve", "reject"]
                    if can_decide
                    and plan is not None
                    and _valid_review_details(plan)
                    and _cited_evidence_verified(session, plan)
                    else ["reject"]
                    if can_decide
                    else []
                ),
                "incident": incident_view,
                "alert": _row(alert),
                "agent_runs": agent_runs,
                "knowledge_refs": knowledge_refs,
                "attack_graph": {
                    "revision": revision,
                    "generated_at": _json(datetime.now(UTC)),
                    "nodes": graph_nodes,
                    "edges": [],
                },
                "evidence_summary": {"total": len(evidence), "items": evidence[:20]},
                "validation": _row(validation) if validation is not None else None,
                "review": {
                    "required": investigation.status == "manual_review",
                    "reason": state.get("stop_reason")
                    if investigation.status == "manual_review"
                    else None,
                    "fallback_count": max(fallback_count, 0),
                },
                "error": failure,
            }

    def list_incidents(
        self,
        page: int,
        page_size: int,
        status: str | None,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        risk: str | None = None,
    ) -> dict[str, Any]:
        if page < 1 or page_size < 1:
            raise ValueError("page and page_size must be positive")
        with self._sessions() as session:
            current_status = func.coalesce(
                ApiInvestigationTable.status, IncidentTable.status
            )
            evidence_count = (
                select(func.count(EvidenceItemTable.evidence_id))
                .where(EvidenceItemTable.incident_id == IncidentTable.incident_id)
                .correlate(IncidentTable)
                .scalar_subquery()
            )
            latest_plan = (
                select(ResponsePlanTable.response_plan_id)
                .where(ResponsePlanTable.incident_id == IncidentTable.incident_id)
                .order_by(
                    ResponsePlanTable.created_at.desc(),
                    ResponsePlanTable.response_plan_id.desc(),
                )
                .limit(1)
                .correlate(IncidentTable)
                .scalar_subquery()
            )
            validation_outcome = (
                select(ValidationResultTable.outcome)
                .where(ValidationResultTable.response_plan_id == latest_plan)
                .order_by(
                    ValidationResultTable.checked_at.desc(),
                    ValidationResultTable.validation_id.desc(),
                )
                .limit(1)
                .correlate(IncidentTable)
                .scalar_subquery()
            )
            query = (
                select(
                    IncidentTable,
                    AlertTable.title.label("alert_title"),
                    AlertTable.severity,
                    ApiInvestigationTable.investigation_id,
                    current_status.label("current_status"),
                    evidence_count.label("evidence_count"),
                    validation_outcome.label("validation_outcome"),
                )
                .join(AlertTable, AlertTable.alert_id == IncidentTable.alert_id)
                .outerjoin(
                    ApiInvestigationTable,
                    ApiInvestigationTable.incident_id == IncidentTable.incident_id,
                )
            )
            if status is not None:
                query = query.where(current_status == status)
            if time_from is not None:
                query = query.where(IncidentTable.created_at >= time_from)
            if time_to is not None:
                query = query.where(IncidentTable.created_at < time_to)
            if risk == "high":
                query = query.where(AlertTable.severity.in_(("high", "critical")))
            total = (
                session.scalar(select(func.count()).select_from(query.subquery())) or 0
            )
            rows = session.execute(
                query.order_by(
                    IncidentTable.created_at.desc(), IncidentTable.incident_id.desc()
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
            ).all()
            return {
                "items": [
                    {
                        **_row(incident),
                        "investigation_id": investigation_id,
                        "alert_title": alert_title,
                        "severity": severity,
                        "status": observed_status,
                        "evidence_count": count,
                        "validation_outcome": outcome,
                    }
                    for (
                        incident,
                        alert_title,
                        severity,
                        investigation_id,
                        observed_status,
                        count,
                        outcome,
                    ) in rows
                ],
                "total": total,
                "page": page,
                "page_size": page_size,
            }

    @staticmethod
    def _source_health(session: Session, checked_at: datetime) -> dict[str, Any]:
        source_rows = session.execute(
            select(
                SecurityEventTable.source,
                func.max(SecurityEventTable.ingested_at).label("last_ingested_at"),
            )
            .group_by(SecurityEventTable.source)
            .order_by(
                func.max(SecurityEventTable.ingested_at).desc(),
                SecurityEventTable.source,
            )
            .limit(20)
        ).all()
        return {
            "checked_at": _json(checked_at),
            "postgresql_status": (
                "ok" if session.get_bind().dialect.name == "postgresql" else None
            ),
            "opensearch_status": None,
            "is_stale": False,
            "sources": [
                {
                    "source": source,
                    "last_ingested_at": _json(last_ingested_at),
                    "ingestion_lag_seconds": max(
                        0,
                        int((checked_at - _as_utc(last_ingested_at)).total_seconds()),
                    ),
                    "status": None,
                    "is_stale": None,
                }
                for source, last_ingested_at in source_rows
            ],
        }

    def source_health(self, *, now: datetime | None = None) -> dict[str, Any]:
        checked_at = _as_utc(now) if now is not None else datetime.now(UTC)
        with self._sessions() as session:
            return self._source_health(session, checked_at)

    def dashboard_summary(
        self, window: str, *, now: datetime | None = None
    ) -> dict[str, Any]:
        windows = {
            "1h": (timedelta(hours=1), 12),
            "24h": (timedelta(days=1), 24),
            "7d": (timedelta(days=7), 7),
        }
        if window not in windows:
            raise ValueError("invalid dashboard window")
        duration, bucket_count = windows[window]
        end = _as_utc(now) if now is not None else datetime.now(UTC)
        start = end - duration
        bucket_width = duration / bucket_count
        buckets = [
            {
                "bucket_start": _json(start + bucket_width * index),
                "bucket_end": _json(start + bucket_width * (index + 1)),
                "total": 0,
                "high_risk": 0,
            }
            for index in range(bucket_count)
        ]

        with self._sessions() as session, session.begin():
            alerts = session.scalars(
                select(AlertTable).where(
                    AlertTable.created_at >= start, AlertTable.created_at < end
                )
            ).all()
            for alert in alerts:
                index = int((_as_utc(alert.created_at) - start) // bucket_width)
                bucket = buckets[min(max(index, 0), bucket_count - 1)]
                bucket["total"] += 1
                if alert.severity in {"high", "critical"}:
                    bucket["high_risk"] += 1

            high_risk_incidents = (
                session.scalar(
                    select(func.count(IncidentTable.incident_id))
                    .join(AlertTable, AlertTable.alert_id == IncidentTable.alert_id)
                    .where(
                        IncidentTable.created_at >= start,
                        IncidentTable.created_at < end,
                        AlertTable.severity.in_(("high", "critical")),
                    )
                )
                or 0
            )
            running_investigations = (
                session.scalar(
                    select(func.count(ApiInvestigationTable.investigation_id)).where(
                        ApiInvestigationTable.status.in_(
                            (
                                "triaged",
                                "collecting",
                                "analyzing",
                                "reconstructing",
                                "simulating",
                                "validating",
                            )
                        )
                    )
                )
                or 0
            )

            current_status = func.coalesce(
                ApiInvestigationTable.status, IncidentTable.status
            )
            status_rows = session.execute(
                select(current_status, func.count(IncidentTable.incident_id))
                .select_from(IncidentTable)
                .outerjoin(
                    ApiInvestigationTable,
                    ApiInvestigationTable.incident_id == IncidentTable.incident_id,
                )
                .where(
                    IncidentTable.created_at >= start,
                    IncidentTable.created_at < end,
                )
                .group_by(current_status)
                .order_by(current_status)
            ).all()

            latest_alert_status = (
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
            recent_alerts = [
                {**_row(alert), "status": status or "received"}
                for alert, status in session.execute(
                    select(AlertTable, latest_alert_status)
                    .where(AlertTable.created_at >= start, AlertTable.created_at < end)
                    .order_by(AlertTable.created_at.desc(), AlertTable.alert_id.desc())
                    .limit(8)
                )
            ]
            recent_activity = [
                {
                    "event": event.event,
                    "occurred_at": _json(event.created_at),
                    "incident_id": investigation.incident_id,
                    "investigation_id": investigation.investigation_id,
                }
                for event, investigation in session.execute(
                    select(ApiInvestigationEventTable, ApiInvestigationTable)
                    .join(
                        ApiInvestigationTable,
                        ApiInvestigationTable.investigation_id
                        == ApiInvestigationEventTable.investigation_id,
                    )
                    .where(
                        ApiInvestigationEventTable.created_at >= start,
                        ApiInvestigationEventTable.created_at < end,
                    )
                    .order_by(
                        ApiInvestigationEventTable.created_at.desc(),
                        ApiInvestigationEventTable.investigation_id.desc(),
                        ApiInvestigationEventTable.sequence.desc(),
                    )
                    .limit(8)
                )
            ]

            other_plan = aliased(ResponsePlanTable)
            latest_plan_id = (
                select(other_plan.response_plan_id)
                .where(other_plan.incident_id == ResponsePlanTable.incident_id)
                .order_by(
                    other_plan.created_at.desc(), other_plan.response_plan_id.desc()
                )
                .limit(1)
                .correlate(ResponsePlanTable)
                .scalar_subquery()
            )
            approval_decision = (
                select(ApprovalTable.decision)
                .where(
                    ApprovalTable.response_plan_id == ResponsePlanTable.response_plan_id
                )
                .order_by(
                    ApprovalTable.decided_at.desc(), ApprovalTable.approval_id.desc()
                )
                .limit(1)
                .correlate(ResponsePlanTable)
                .scalar_subquery()
            )
            pending_plans = 0
            for plan, incident, alert, investigation, latest in session.execute(
                select(
                    ResponsePlanTable,
                    IncidentTable,
                    AlertTable,
                    ApiInvestigationTable,
                    latest_plan_id,
                )
                .join(
                    IncidentTable,
                    IncidentTable.incident_id == ResponsePlanTable.incident_id,
                )
                .join(AlertTable, AlertTable.alert_id == IncidentTable.alert_id)
                .outerjoin(
                    ApiInvestigationTable,
                    ApiInvestigationTable.incident_id == IncidentTable.incident_id,
                )
                .where(approval_decision.is_(None))
            ):
                item = _response_plan_item(
                    plan, incident, alert, investigation, None, latest
                )
                if (
                    item["is_current"]
                    and item["incident_status"] == "awaiting_approval"
                    and item["decision_state"] == "pending"
                    and plan.requires_approval
                ):
                    pending_plans += 1

            source_health = self._source_health(session, end)

        return {
            "window": window,
            "time_from": _json(start),
            "time_to": _json(end),
            "generated_at": _json(end),
            "metrics": {
                "alerts_in_window": len(alerts),
                "high_risk_incidents": high_risk_incidents,
                "running_investigations": running_investigations,
                "pending_response_plans": pending_plans,
            },
            "alert_trend": buckets,
            "incident_status_distribution": [
                {"status": status, "count": count} for status, count in status_rows
            ],
            "recent_alerts": recent_alerts,
            "recent_activity": recent_activity,
            "source_health": source_health,
        }

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
                    "simulation_execution": state.get("simulation_execution"),
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

    def list_incident_evidence(
        self, incident_id: str, page: int, page_size: int
    ) -> dict[str, Any]:
        with self._sessions() as session, session.begin():
            if session.get(IncidentTable, incident_id) is None:
                raise LookupError("incident does not exist")
            total = session.scalar(
                select(func.count(EvidenceItemTable.evidence_id)).where(
                    EvidenceItemTable.incident_id == incident_id
                )
            )
            evidence = session.scalars(
                select(EvidenceItemTable)
                .where(EvidenceItemTable.incident_id == incident_id)
                .order_by(EvidenceItemTable.observed_at, EvidenceItemTable.evidence_id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
            return {
                "items": [
                    {**_row(item), "query": restore_json(item.query)}
                    for item in evidence
                ],
                "total": total,
                "page": page,
                "page_size": page_size,
            }

    def get_evidence_detail(self, incident_id: str, evidence_id: str) -> dict[str, Any]:
        with self._sessions() as session, session.begin():
            evidence = session.scalar(
                select(EvidenceItemTable).where(
                    EvidenceItemTable.incident_id == incident_id,
                    EvidenceItemTable.evidence_id == evidence_id,
                )
            )
            if evidence is None:
                raise LookupError("evidence does not belong to incident")
            event = session.get(SecurityEventTable, evidence.event_id)
            if event is None:
                raise LookupError("evidence source event does not exist")
            try:
                calculated_sha = calculate_content_sha256(event.raw)
            except ValueError:
                calculated_sha = None
            status = (
                "unavailable"
                if calculated_sha is None
                else "verified"
                if calculated_sha == event.content_sha256 == evidence.content_sha256
                else "mismatch"
            )
            return {
                "evidence": {**_row(evidence), "query": restore_json(evidence.query)},
                "raw_event": {
                    "event_id": event.event_id,
                    "source": event.source,
                    "observed_at": _json(event.observed_at),
                    "severity": event.severity,
                    "event_type": event.event_type,
                    "raw": event.raw,
                    "content_sha256": event.content_sha256,
                },
                "raw_access": "full",
                "integrity": {
                    "algorithm": "sha256",
                    "canonicalization": "evidencesoc-json-v1",
                    "scope": "postgresql",
                    "status": status,
                    "checked_at": _json(datetime.now(UTC)),
                    "calculated_sha256": calculated_sha,
                    "stored_event_sha256": event.content_sha256,
                    "stored_evidence_sha256": evidence.content_sha256,
                },
            }

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

    def list_response_plans(
        self, page: int, page_size: int, decision_state: str | None
    ) -> dict[str, Any]:
        if page < 1 or page_size < 1:
            raise ValueError("page and page_size must be positive")
        if decision_state not in (None, "pending", "approved", "rejected"):
            raise ValueError("invalid decision state")
        with self._sessions() as session, session.begin():
            other_plan = aliased(ResponsePlanTable)
            latest_plan_id = (
                select(other_plan.response_plan_id)
                .where(other_plan.incident_id == ResponsePlanTable.incident_id)
                .order_by(
                    other_plan.created_at.desc(), other_plan.response_plan_id.desc()
                )
                .limit(1)
                .correlate(ResponsePlanTable)
                .scalar_subquery()
            )
            approval_decision = (
                select(ApprovalTable.decision)
                .where(
                    ApprovalTable.response_plan_id == ResponsePlanTable.response_plan_id
                )
                .order_by(
                    ApprovalTable.decided_at.desc(), ApprovalTable.approval_id.desc()
                )
                .limit(1)
                .correlate(ResponsePlanTable)
                .scalar_subquery()
            )
            query = (
                select(
                    ResponsePlanTable,
                    IncidentTable,
                    AlertTable,
                    ApiInvestigationTable,
                    approval_decision.label("approval_decision"),
                    latest_plan_id.label("latest_plan_id"),
                )
                .join(
                    IncidentTable,
                    IncidentTable.incident_id == ResponsePlanTable.incident_id,
                )
                .join(AlertTable, AlertTable.alert_id == IncidentTable.alert_id)
                .outerjoin(
                    ApiInvestigationTable,
                    ApiInvestigationTable.incident_id == IncidentTable.incident_id,
                )
            )
            if decision_state == "pending":
                query = query.where(approval_decision.is_(None))
            elif decision_state is not None:
                query = query.where(approval_decision == decision_state)
            total = (
                session.scalar(select(func.count()).select_from(query.subquery())) or 0
            )
            rows = session.execute(
                query.order_by(
                    ResponsePlanTable.created_at.desc(),
                    ResponsePlanTable.response_plan_id.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
            ).all()
            return {
                "items": [
                    _response_plan_item(
                        plan, incident, alert, investigation, approval, latest
                    )
                    for plan, incident, alert, investigation, approval, latest in rows
                ],
                "total": total,
                "page": page,
                "page_size": page_size,
            }

    def get_response_plan_detail(self, identity: str) -> dict[str, Any]:
        with self._sessions() as session, session.begin():
            plan = session.get(ResponsePlanTable, identity)
            if plan is None:
                raise LookupError("response plan does not exist")
            incident = session.get(IncidentTable, plan.incident_id)
            if incident is None:
                raise LookupError("plan incident does not exist")
            alert = session.get(AlertTable, incident.alert_id)
            if alert is None:
                raise LookupError("plan alert does not exist")
            investigation = session.scalar(
                select(ApiInvestigationTable).where(
                    ApiInvestigationTable.incident_id == incident.incident_id
                )
            )
            latest_plan_id = session.scalar(
                select(ResponsePlanTable.response_plan_id)
                .where(ResponsePlanTable.incident_id == incident.incident_id)
                .order_by(
                    ResponsePlanTable.created_at.desc(),
                    ResponsePlanTable.response_plan_id.desc(),
                )
                .limit(1)
            )
            approval = session.scalar(
                select(ApprovalTable)
                .where(ApprovalTable.response_plan_id == identity)
                .order_by(
                    ApprovalTable.decided_at.desc(), ApprovalTable.approval_id.desc()
                )
                .limit(1)
            )
            validation = session.scalar(
                select(ValidationResultTable)
                .where(ValidationResultTable.response_plan_id == identity)
                .order_by(
                    ValidationResultTable.checked_at.desc(),
                    ValidationResultTable.validation_id.desc(),
                )
                .limit(1)
            )
            item = _response_plan_item(
                plan,
                incident,
                alert,
                investigation,
                approval.decision if approval else None,
                latest_plan_id,
            )
            state = restore_json(investigation.state) if investigation else {}
            pending_decision = (
                _pending_plan_decision(state, identity, item["is_current"])
                if approval is None
                else None
            )
            safe_simulation = (
                state.get("simulation", []) if _state_plan_id(state) == identity else []
            )
            can_decide = (
                item["is_current"]
                and item["incident_status"] == "awaiting_approval"
                and approval is None
                and state.get("pending_decision") is None
                and not state.get("approval")
                and plan.requires_approval
                and not _plan_expired(plan)
                and _valid_simulated_actions(plan.actions)
            )
            return {
                **item,
                "approval": _row(approval) if approval else None,
                "validation_result": _row(validation) if validation else None,
                "simulation": [
                    execution
                    for execution in safe_simulation
                    if isinstance(execution, dict)
                    and isinstance(execution.get("execution_id"), str)
                    and execution["execution_id"].startswith(identity + ":")
                ]
                if isinstance(safe_simulation, list)
                else [],
                "simulation_execution": (
                    state.get("simulation_execution")
                    if isinstance(state.get("simulation_execution"), dict)
                    and state["simulation_execution"].get("response_plan_id")
                    == identity
                    and state["simulation_execution"].get("plan_version")
                    == _plan_version(plan)
                    else None
                ),
                "pending_decision": pending_decision,
                "available_actions": (
                    ["approve", "reject"]
                    if can_decide
                    and _valid_review_details(plan)
                    and _cited_evidence_verified(session, plan)
                    else ["reject"]
                    if can_decide
                    else []
                ),
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
            _advance_snapshot(investigation)
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
        previous = restore_json(row.state)
        pending = previous.get("pending_decision")
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
        renewal = previous.get("pending_renewal")
        if isinstance(renewal, dict) and status not in TERMINAL_STATUSES:
            fresh_plan_id = _state_plan_id(normalized)
            if not fresh_plan_id or fresh_plan_id == renewal.get("response_plan_id"):
                normalized["pending_renewal"] = renewal
                status = "reconstructing"
                normalized["status"] = status
            else:
                normalized.pop("pending_renewal", None)
        else:
            normalized.pop("pending_renewal", None)
        _advance_snapshot(row, normalized)
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

    def _record_decision_locked(
        self,
        session: Session,
        plan_id: str,
        decision: dict[str, Any],
        *,
        expected_version: str | None = None,
    ) -> dict[str, Any]:
        plan = session.scalar(
            select(ResponsePlanTable)
            .where(ResponsePlanTable.response_plan_id == plan_id)
            .with_for_update()
        )
        if plan is None:
            raise LookupError("response plan does not exist")
        if expected_version is not None and _plan_version(plan) != expected_version:
            raise StorageConflict("response plan version is stale")
        if _plan_expired(plan):
            raise PlanExpired("response plan has expired")
        latest_plan_id = session.scalar(
            select(ResponsePlanTable.response_plan_id)
            .where(ResponsePlanTable.incident_id == plan.incident_id)
            .order_by(
                ResponsePlanTable.created_at.desc(),
                ResponsePlanTable.response_plan_id.desc(),
            )
            .limit(1)
        )
        row = session.scalar(
            select(ApiInvestigationTable)
            .where(ApiInvestigationTable.incident_id == plan.incident_id)
            .with_for_update()
        )
        if row is None:
            raise LookupError("plan investigation does not exist")
        state = restore_json(row.state)
        current_plan = state.get("response_plan")
        current_plan_id = (
            current_plan.get("response_plan_id")
            if isinstance(current_plan, dict)
            else None
        )
        if (current_plan_id or latest_plan_id) != plan_id:
            raise StorageConflict("response plan is not the current investigation plan")
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
        if decision["decision"] == "approved" and not _valid_simulated_actions(
            plan.actions
        ):
            raise StorageConflict("response plan actions are invalid")
        if decision["decision"] == "approved" and not _valid_review_details(plan):
            raise StorageConflict("response plan review details are incomplete")
        if decision["decision"] == "approved" and not _cited_evidence_verified(
            session, plan, lock=True
        ):
            raise StorageConflict(
                "response plan cited evidence integrity is unavailable"
            )
        state = {**state, "pending_decision": _json(decision)}
        _advance_snapshot(row, state)
        return _metadata(row)

    def record_decision(self, plan_id: str, decision: dict[str, Any]) -> dict[str, Any]:
        with self._sessions() as session, session.begin():
            self._write_lock(session)
            return self._record_decision_locked(session, plan_id, decision)

    def record_decision_idempotent(
        self, plan_id: str, decision: dict[str, Any], key: str
    ) -> dict[str, Any]:
        if not 1 <= len(key) <= 255 or not key.strip():
            raise ValueError("invalid Idempotency-Key")
        command = {
            "response_plan_id": plan_id,
            "decision": decision["decision"],
            "reason": decision["reason"],
            "decided_by": decision["decided_by"],
            "plan_version": decision["plan_version"],
        }
        payload_hash = sha256(
            json.dumps(
                command, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest()
        with self._sessions() as session, session.begin():
            self._write_lock(session, "decision-key:" + key)
            receipt = session.get(ApiDecisionReceiptTable, key)
            if receipt is not None:
                if receipt.payload_sha256 != payload_hash:
                    raise StorageConflict(
                        "Idempotency-Key is already bound to another decision"
                    )
                return {
                    "response": restore_json(receipt.accepted_response),
                    "replayed": True,
                }
            metadata = self._record_decision_locked(
                session, plan_id, command, expected_version=command["plan_version"]
            )
            accepted = {
                "response_plan_id": plan_id,
                "investigation_id": metadata["investigation_id"],
                "incident_id": metadata["incident_id"],
                "trace_id": metadata["trace_id"],
                "decision": command["decision"],
                "status": "accepted",
            }
            session.add(
                ApiDecisionReceiptTable(
                    key=key,
                    plan_id=plan_id,
                    payload_sha256=payload_hash,
                    accepted_response=accepted,
                )
            )
            return {"metadata": metadata, "response": accepted, "replayed": False}

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
