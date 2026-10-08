from __future__ import annotations

import importlib
import os
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any

import pytest
from evidencesoc.api.tables import ApiInvestigationEventTable, ApiInvestigationTable
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.persistence.tables import (
    AgentRunTable,
    AlertTable,
    ApprovalTable,
    AttackStepTable,
    Base,
    EvaluationRunTable,
    EvidenceItemTable,
    IncidentTable,
    ResponsePlanTable,
    SecurityEventTable,
    ValidationResultTable,
)
from sqlalchemy import (
    JSON,
    CheckConstraint,
    MetaData,
    create_engine,
    event,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

NOW = datetime(2026, 9, 26, tzinfo=UTC)
PAYLOAD = {"title": "SQL injection", "severity": "high", "event_ids": ["SE-1"]}


def storage_module() -> Any:
    try:
        return importlib.import_module("evidencesoc.api.storage")
    except ModuleNotFoundError as exc:
        if exc.name not in {"evidencesoc.api", "evidencesoc.api.storage"}:
            raise
        pytest.fail("ApiStore is not implemented")


@pytest.fixture
def database(tmp_path: Any) -> Any:
    module = storage_module()
    tables = importlib.import_module("evidencesoc.api.tables")
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'api.db'}")
    metadata = MetaData()
    models = (
        AlertTable,
        IncidentTable,
        SecurityEventTable,
        EvidenceItemTable,
        AttackStepTable,
        AgentRunTable,
        ResponsePlanTable,
        ApprovalTable,
        ValidationResultTable,
        EvaluationRunTable,
    )
    for original in [
        *(model.__table__ for model in models),
        *tables.ApiBase.metadata.tables.values(),
    ]:
        table = original.to_metadata(metadata)
        for column in table.columns:
            if isinstance(column.type, JSONB):
                column.type = JSON()
        for constraint in list(table.constraints):
            if isinstance(constraint, CheckConstraint):
                table.constraints.remove(constraint)
    metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions.begin() as session:
        session.add(
            SecurityEventTable(
                event_id="SE-1",
                source="nginx",
                external_id="1",
                deduplication_key="id:1",
                observed_at=NOW,
                ingested_at=NOW,
                severity="high",
                event_type="web.request",
                raw={"message": "SELECT"},
                content_sha256="a" * 64,
                index_status="indexed",
            )
        )
    yield module.ApiStore(sessions), sessions
    engine.dispose()


def add_verified_evidence(
    sessions: Any, incident_id: str, evidence_id: str = "EV-1"
) -> None:
    with sessions.begin() as session:
        event = session.get(SecurityEventTable, "SE-1")
        digest = calculate_content_sha256(event.raw)
        event.content_sha256 = digest
        session.add(
            EvidenceItemTable(
                evidence_id=evidence_id,
                incident_id=incident_id,
                event_id=event.event_id,
                source=event.source,
                observed_at=event.observed_at,
                query={"event_id": event.event_id},
                summary="Verified cited event",
                content_sha256=digest,
            )
        )


def simulated_action(
    evidence_ids: list[str] | None = None, *, traceable: bool = True
) -> dict[str, Any]:
    action = {
        "action": "block_ip_simulated",
        "target": "203.0.113.42",
        "risk": "Source IP may be shared",
        "impact": "Simulation only",
        "preview": "Simulate blocking the observed source",
        "rollback": "Remove the simulated block",
        "verification_query": {"filters": {"source_ip": "203.0.113.42"}},
    }
    if traceable:
        action.update(
            {
                "action_id": "ACT-1",
                "type": "block_ip_simulated",
                "parameters": {"source_ip": "203.0.113.42"},
                "expected_effect": "Record a simulated block only",
                "rollback_ref": "RB-1",
                "evidence_ids": evidence_ids or ["EV-1"],
            }
        )
    return action


def complete_review_fields(
    created_at: datetime, evidence_ids: list[str] | None = None
) -> dict[str, Any]:
    citations = evidence_ids or ["EV-1"]
    target = simulated_action()["target"]
    return {
        "risk_level": "medium",
        "risk_reason": "The source IP may be shared",
        "affected_assets": [target],
        "business_impact": "Simulation only; no real traffic changes",
        "expires_at": created_at + timedelta(minutes=20),
        "rollback_steps": [
            {
                "step_id": "RB-1",
                "description": "Remove simulated block",
                "target": target,
                "expected_result": "The simulated rule is absent",
                "evidence_ids": citations,
            }
        ],
        "validation_checks": [
            {
                "check_id": "VC-1",
                "description": "Verify the same source IP",
                "target": target,
                "expected_result": "Events remain observable",
                "query": simulated_action()["verification_query"],
                "evidence_ids": citations,
            }
        ],
    }


def test_legacy_response_plan_is_readable_and_rejectable_but_not_approvable(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-legacy-review"}, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    add_verified_evidence(sessions, investigation["incident_id"])
    with sessions.begin() as session:
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-legacy-review",
                incident_id=investigation["incident_id"],
                summary="Legacy simulation plan",
                actions=[simulated_action(traceable=False)],
                created_at=NOW,
                requires_approval=True,
                evidence_ids=["EV-1"],
            )
        )
    store.save_state(
        investigation["investigation_id"],
        {
            "status": "awaiting_approval",
            "response_plan": {"response_plan_id": "RP-legacy-review"},
        },
    )

    detail = store.get_response_plan_detail("RP-legacy-review")
    assert detail["actions"] == [simulated_action(traceable=False)]
    assert detail["risk_level"] is None
    assert detail["rollback_steps"] == []
    assert detail["validation_checks"] == []
    assert detail["available_actions"] == ["reject"]
    assert store.get_investigation_snapshot(investigation["investigation_id"])[
        "available_actions"
    ] == ["reject"]
    with pytest.raises(storage_module().StorageConflict, match="review details"):
        store.record_decision(
            "RP-legacy-review",
            {"decision": "approved", "reason": "Looks safe", "decided_by": "analyst"},
        )
    assert (
        store.get_investigation(investigation["investigation_id"])["state"].get(
            "pending_decision"
        )
        is None
    )
    accepted = store.record_decision(
        "RP-legacy-review",
        {"decision": "rejected", "reason": "Legacy plan", "decided_by": "analyst"},
    )
    assert accepted["state"]["pending_decision"]["decision"] == "rejected"


@pytest.mark.parametrize(
    ("field", "incomplete_value"),
    [
        ("risk_level", None),
        ("risk_reason", "  "),
        ("affected_assets", []),
        ("affected_assets", [{"target": "203.0.113.42"}]),
        ("business_impact", "  "),
        ("expires_at", None),
        ("rollback_steps", []),
        ("validation_checks", []),
    ],
)
def test_approval_requires_each_persisted_review_field(
    database: Any, field: str, incomplete_value: Any
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-review-field"}, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    add_verified_evidence(sessions, investigation["incident_id"])
    created_at = datetime.now(UTC)
    with sessions.begin() as session:
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-review-field",
                incident_id=investigation["incident_id"],
                summary="Complete plan before corruption",
                actions=[simulated_action()],
                created_at=created_at,
                requires_approval=True,
                evidence_ids=["EV-1"],
                **complete_review_fields(created_at),
            )
        )
    store.save_state(
        investigation["investigation_id"],
        {
            "status": "awaiting_approval",
            "response_plan": {"response_plan_id": "RP-review-field"},
        },
    )
    assert store.get_response_plan_detail("RP-review-field")["available_actions"] == [
        "approve",
        "reject",
    ]
    with sessions.begin() as session:
        setattr(
            session.get(ResponsePlanTable, "RP-review-field"), field, incomplete_value
        )
    assert store.get_response_plan_detail("RP-review-field")["available_actions"] == [
        "reject"
    ]
    assert store.get_investigation_snapshot(investigation["investigation_id"])[
        "available_actions"
    ] == ["reject"]
    with pytest.raises(storage_module().StorageConflict, match="review details"):
        store.record_decision(
            "RP-review-field",
            {"decision": "approved", "reason": "Looks safe", "decided_by": "analyst"},
        )


def test_approval_rejects_incomplete_persisted_response_action(database: Any) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-invalid-action"}, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    add_verified_evidence(sessions, investigation["incident_id"])
    with sessions.begin() as session:
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-invalid-action",
                incident_id=investigation["incident_id"],
                summary="Malformed stored action",
                actions=[{"action": "block_ip_simulated"}],
                created_at=NOW,
                requires_approval=True,
                evidence_ids=["EV-1"],
            )
        )
    store.save_state(
        investigation["investigation_id"],
        {
            "status": "awaiting_approval",
            "response_plan": {"response_plan_id": "RP-invalid-action"},
        },
    )

    assert (
        store.get_response_plan_detail("RP-invalid-action")["available_actions"] == []
    )
    assert (
        store.get_investigation_snapshot(investigation["investigation_id"])[
            "available_actions"
        ]
        == []
    )
    with pytest.raises(storage_module().StorageConflict, match="action"):
        store.record_decision(
            "RP-invalid-action",
            {"decision": "approved", "reason": "Looks safe", "decided_by": "analyst"},
        )


@pytest.mark.parametrize("missing_field", ["action_id", "evidence_ids", "rollback_ref"])
def test_approval_requires_traceable_action_fields(
    database: Any, missing_field: str
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-action-trace"}, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    add_verified_evidence(sessions, investigation["incident_id"])
    created_at = datetime.now(UTC)
    action = simulated_action()
    action.pop(missing_field)
    with sessions.begin() as session:
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-action-trace",
                incident_id=investigation["incident_id"],
                summary="Action citation missing",
                actions=[action],
                created_at=created_at,
                requires_approval=True,
                evidence_ids=["EV-1"],
                **complete_review_fields(created_at),
            )
        )
    store.save_state(
        investigation["investigation_id"],
        {
            "status": "awaiting_approval",
            "response_plan": {"response_plan_id": "RP-action-trace"},
        },
    )
    assert store.get_response_plan_detail("RP-action-trace")["available_actions"] == [
        "reject"
    ]
    with pytest.raises(storage_module().StorageConflict, match="review details"):
        store.record_decision(
            "RP-action-trace",
            {"decision": "approved", "reason": "Looks safe", "decided_by": "analyst"},
        )


def test_idempotency_replays_after_store_restart_and_rejects_changed_payload(
    database: Any,
) -> None:
    store, sessions = database
    alert, created = store.ingest_alert(PAYLOAD, "retry-1")
    assert created is True
    replay, created = (
        storage_module().ApiStore(sessions).ingest_alert(dict(PAYLOAD), "retry-1")
    )
    assert created is False
    assert replay == alert
    with pytest.raises(storage_module().StorageConflict):
        store.ingest_alert({**PAYLOAD, "title": "Different"}, "retry-1")
    with sessions() as session:
        assert len(session.scalars(select(AlertTable)).all()) == 1


def test_supplied_alert_id_replays_and_conflicts_without_idempotency_key(
    database: Any,
) -> None:
    store, _ = database
    payload = {**PAYLOAD, "alert_id": "AL-client", "created_at": NOW.isoformat()}
    alert, created = store.ingest_alert(payload, None)
    assert alert["alert_id"] == "AL-client"
    assert created is True
    assert store.ingest_alert(payload, None) == (alert, False)
    with pytest.raises(storage_module().StorageConflict):
        store.ingest_alert({**payload, "event_ids": ["SE-other"]}, None)


def test_missing_source_event_rolls_back_alert_and_idempotency_record(
    database: Any,
) -> None:
    store, _ = database
    with pytest.raises(LookupError):
        store.ingest_alert(
            {**PAYLOAD, "event_ids": ["SE-1", "SE-missing"]}, "recoverable"
        )
    assert store.list_alerts(1, 10, None, None)["total"] == 0
    assert store.ingest_alert(PAYLOAD, "recoverable")[1] is True


def test_alert_detail_keeps_alert_event_order_without_exposing_raw(
    database: Any,
) -> None:
    store, sessions = database
    with sessions.begin() as session:
        session.add(
            SecurityEventTable(
                event_id="SE-2",
                source="firewall",
                external_id="2",
                deduplication_key="id:2",
                observed_at=NOW,
                ingested_at=NOW,
                severity="medium",
                event_type="network.connection",
                raw={"secret": "must-not-leak"},
                content_sha256="b" * 64,
                index_status="indexed",
            )
        )
    alert, _ = store.ingest_alert({**PAYLOAD, "event_ids": ["SE-2", "SE-1"]}, None)
    detail = store.get_alert(alert["alert_id"])
    assert [event["event_id"] for event in detail["events"]] == ["SE-2", "SE-1"]
    assert detail["events"][0]["source"] == "firewall"
    assert detail["status"] == "received"
    assert detail["incident_id"] is None
    assert detail["investigation_id"] is None
    assert "must-not-leak" not in str(detail)
    with pytest.raises(LookupError):
        store.get_alert("AL-does-not-exist")


def test_alert_detail_uses_same_latest_incident_as_list(database: Any) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    original, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    latest_created = datetime.fromisoformat(
        store.get_incident(original["incident_id"])["created_at"]
    ) + timedelta(seconds=1)
    with sessions.begin() as session:
        session.add(
            IncidentTable(
                incident_id="IN-latest",
                alert_id=alert["alert_id"],
                status="failed",
                created_at=latest_created,
            )
        )
        session.add(
            ApiInvestigationTable(
                investigation_id="IV-latest",
                incident_id="IN-latest",
                trace_id="TRACE-latest",
                created_at=latest_created,
                status="failed",
                state={},
                last_sequence=0,
            )
        )
    detail = store.get_alert(alert["alert_id"])
    listed = store.list_alerts(1, 10, None, None)["items"][0]
    assert detail["status"] == listed["status"] == "failed"
    assert detail["incident_id"] == "IN-latest"
    assert detail["investigation_id"] == "IV-latest"
    assert store.create_investigation(alert_id=alert["alert_id"], incident_id=None) == (
        original,
        False,
    )


def test_investigation_is_reused_by_alert_and_incident_after_restart(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, created = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    assert created is True
    assert investigation["investigation_id"].startswith("IV-")
    assert investigation["trace_id"].startswith("TRACE-")
    assert investigation["status"] == "received"
    restored = storage_module().ApiStore(sessions)
    assert restored.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    ) == (investigation, False)
    assert restored.create_investigation(
        alert_id=None, incident_id=investigation["incident_id"]
    ) == (investigation, False)
    assert (
        restored.get_investigation(investigation["investigation_id"]) == investigation
    )


def test_investigation_start_key_replays_after_restart_and_rejects_new_payload(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    request = {
        "alert_id": alert["alert_id"],
        "incident_id": None,
        "mode": "rules",
        "idempotency_key": "start-case-1",
    }
    first, created = store.create_investigation(**request)
    assert created is True
    restored = storage_module().ApiStore(sessions)
    assert restored.create_investigation(**request) == (first, False)
    with pytest.raises(storage_module().StorageConflict):
        restored.create_investigation(**{**request, "mode": "model"})
    assert restored.create_investigation(
        alert_id=alert["alert_id"],
        incident_id=None,
        mode="rules",
        idempotency_key="start-case-2",
    ) == (first, False)


def test_investigation_snapshot_revision_advances_for_state_and_events(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = investigation["investigation_id"]

    initial = store.get_investigation_snapshot(identity)
    assert initial["revision"] == "0"
    assert initial["stream_cursor"] == "0"
    assert initial["incident"]["incident_id"] == investigation["incident_id"]
    assert initial["alert"]["alert_id"] == alert["alert_id"]
    assert initial["available_actions"] == []

    event = store.append_event(identity, "investigation.started", {}, "started")
    after_event = store.get_investigation_snapshot(identity)
    assert event["id"] == 1
    assert int(after_event["revision"]) > int(initial["revision"])
    assert after_event["stream_cursor"] == "1"
    assert store.list_events(identity, int(after_event["stream_cursor"])) == []

    state = {"status": "analyzing", "fallback_count": 1}
    store.save_state(identity, state)
    restored = storage_module().ApiStore(sessions)
    after_state = restored.get_investigation_snapshot(identity)
    assert int(after_state["revision"]) > int(after_event["revision"])
    assert after_state["stream_cursor"] == "1"
    assert after_state["status"] == "analyzing"
    assert restored.get_investigation(identity)["state"] == state
    assert after_state["updated_at"] >= after_event["updated_at"]


def test_investigation_snapshot_uses_persisted_current_incident_records(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = investigation["investigation_id"]
    evidence_id = "EV-" + "0" * 26
    with sessions.begin() as session:
        session.add(
            EvidenceItemTable(
                evidence_id=evidence_id,
                incident_id=investigation["incident_id"],
                event_id="SE-1",
                source="nginx",
                observed_at=NOW,
                query={"event_id": "SE-1"},
                summary="Verified request",
                content_sha256="a" * 64,
            )
        )
        session.add(
            AgentRunTable(
                run_id="AR-snapshot",
                incident_id=investigation["incident_id"],
                agent_name="collect",
                status="completed",
                started_at=NOW,
                finished_at=NOW,
                evidence_ids=[evidence_id],
            )
        )
        session.add(
            AttackStepTable(
                attack_step_id="AS-snapshot",
                incident_id=investigation["incident_id"],
                sequence=1,
                phase="initial-access",
                technique_id="T1190",
                description="Observed request",
                occurred_at=NOW,
                evidence_ids=[evidence_id],
            )
        )
    store.save_state(
        identity,
        {
            "status": "reconstructing",
            "knowledge": [
                {
                    "knowledge_chunk_id": "KC-trusted",
                    "technique_id": "T1190",
                    "title": "Exploit Public-Facing Application",
                    "version": "enterprise-attack-18",
                    "source_uri": "https://attack.mitre.org/techniques/T1190/",
                    "summary": "Do not expose the full retrieval body",
                },
                {
                    "knowledge_chunk_id": "KC-untrusted",
                    "source_uri": "https://attacker.invalid/secret",
                },
            ],
        },
    )

    snapshot = store.get_investigation_snapshot(identity)
    assert snapshot["evidence_summary"]["total"] == 1
    assert snapshot["evidence"][0]["evidence_id"] == evidence_id
    assert snapshot["agent_runs"][0]["role_key"] == "evidence_collection"
    assert snapshot["attack_graph"]["nodes"][0]["step_id"] == "AS-snapshot"
    assert snapshot["attack_graph"]["edges"] == []
    assert [item["knowledge_chunk_id"] for item in snapshot["knowledge_refs"]] == [
        "KC-trusted"
    ]
    assert "Do not expose the full retrieval body" not in str(snapshot)
    assert "attacker.invalid" not in str(snapshot)
    assert "SELECT" not in str(snapshot)

    with pytest.raises(LookupError):
        store.get_investigation_snapshot("IV-missing-private")


def test_investigation_snapshot_gates_decisions_and_sees_atomic_terminal_event(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = investigation["investigation_id"]
    created_at = datetime.now(UTC)
    with sessions.begin() as session:
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-snapshot",
                incident_id=investigation["incident_id"],
                summary="Simulate only",
                actions=[simulated_action()],
                created_at=created_at,
                requires_approval=True,
                evidence_ids=["EV-1"],
                **complete_review_fields(created_at),
            )
        )
    add_verified_evidence(sessions, investigation["incident_id"])
    store.save_state(
        identity,
        {
            "status": "awaiting_approval",
            "response_plan": {"response_plan_id": "RP-snapshot"},
        },
    )
    pending = store.get_investigation_snapshot(identity)
    assert pending["available_actions"] == ["approve", "reject"]
    assert pending["stream_cursor"] == "0"

    store.record_decision(
        "RP-snapshot",
        {"decision": "approved", "reason": "Reviewed", "decided_by": "analyst"},
    )
    submitting = store.get_investigation_snapshot(identity)
    assert submitting["available_actions"] == []
    assert submitting["stream_cursor"] == pending["stream_cursor"]
    assert int(submitting["revision"]) > int(pending["revision"])

    terminal = store.finalize(
        identity,
        {"status": "completed", "response_plan": {"response_plan_id": "RP-snapshot"}},
        "investigation.completed",
        {"status": "completed"},
    )
    final = store.get_investigation_snapshot(identity)
    assert final["status"] == final["incident"]["status"] == "completed"
    assert final["stream_cursor"] == str(terminal["id"])
    assert int(final["revision"]) > int(submitting["revision"])
    assert store.list_events(identity, int(final["stream_cursor"])) == []


def test_investigation_rejects_missing_or_mismatched_targets(database: Any) -> None:
    store, _ = database
    with pytest.raises(ValueError):
        store.create_investigation(alert_id=None, incident_id=None)
    with pytest.raises(LookupError):
        store.create_investigation(alert_id="AL-missing", incident_id=None)
    with pytest.raises(LookupError):
        store.create_investigation(alert_id=None, incident_id="IN-missing")
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    other, _ = store.ingest_alert(PAYLOAD, None)
    with pytest.raises(storage_module().StorageConflict):
        store.create_investigation(
            alert_id=other["alert_id"], incident_id=investigation["incident_id"]
        )


def test_events_are_durable_sequential_deduplicated_and_replayed_from_cursor(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = investigation["investigation_id"]
    first = store.append_event(identity, "status", {"status": "collecting"}, "node:1")
    assert first == {"id": 1, "event": "status", "data": {"status": "collecting"}}
    assert (
        store.append_event(identity, "status", {"status": "collecting"}, "node:1")
        == first
    )
    with pytest.raises(storage_module().StorageConflict):
        store.append_event(identity, "status", {"status": "failed"}, "node:1")
    second = store.append_event(identity, "evidence", {"evidence_id": "EV-1"}, "node:2")
    assert second["id"] == 2
    restored = storage_module().ApiStore(sessions)
    assert restored.list_events(identity, 0) == [first, second]
    assert restored.list_events(identity, 1) == [second]
    assert restored.list_events(identity, 2) == []
    assert restored.get_investigation(identity)["last_sequence"] == 2


def test_state_and_recovery_survive_restart_and_update_incident_status(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = investigation["investigation_id"]
    state = {
        "status": "awaiting_approval",
        "origin": {"source_scope": "external"},
        "classification": {"attack_types": ["sql_injection"]},
    }
    store.save_state(identity, state)
    restored = storage_module().ApiStore(sessions)
    assert restored.get_investigation(identity)["state"] == state
    assert restored.list_recoverable()[0]["investigation_id"] == identity
    assert (
        restored.get_incident(investigation["incident_id"])["origin"] == state["origin"]
    )
    assert (
        restored.get_incident(investigation["incident_id"])["status"]
        == "awaiting_approval"
    )
    for status in ("completed", "failed", "manual_review", "rejected"):
        store.save_state(identity, {"status": status})
        assert restored.list_recoverable() == []


def test_alert_list_filters_paginates_and_includes_investigation_status(
    database: Any,
) -> None:
    store, _ = database
    first, _ = store.ingest_alert(
        {**PAYLOAD, "alert_id": "AL-first", "created_at": NOW.isoformat()}, None
    )
    store.ingest_alert({**PAYLOAD, "alert_id": "AL-other", "severity": "low"}, None)
    investigation, _ = store.create_investigation(
        alert_id=first["alert_id"], incident_id=None
    )
    store.save_state(investigation["investigation_id"], {"status": "completed"})
    listed = store.list_alerts(1, 1, "high", "completed")
    assert listed["total"] == 1
    assert listed["items"][0]["alert_id"] == "AL-first"
    assert listed["items"][0]["status"] == "completed"
    assert listed["page"] == 1
    assert listed["page_size"] == 1
    assert store.list_alerts(2, 1, "high", "completed")["items"] == []


def test_alert_list_time_and_literal_text_filters_before_pagination(
    database: Any,
) -> None:
    store, _ = database
    start = NOW - timedelta(hours=1)
    end = NOW + timedelta(hours=1)
    for alert_id, title, created_at in (
        ("AL-before", "Needle before", start - timedelta(seconds=1)),
        ("AL-start", "Needle% at start", start),
        ("AL-middle", "Needle in window", NOW),
        ("AL-end", "Needle after", end),
    ):
        store.ingest_alert(
            {
                **PAYLOAD,
                "alert_id": alert_id,
                "title": title,
                "created_at": created_at.isoformat(),
            },
            None,
        )

    first_page = store.list_alerts(1, 1, "high", "received", start, end, "needle")
    assert first_page["total"] == 2
    assert [item["alert_id"] for item in first_page["items"]] == ["AL-middle"]
    second_page = store.list_alerts(2, 1, "high", "received", start, end, "needle")
    assert [item["alert_id"] for item in second_page["items"]] == ["AL-start"]
    literal = store.list_alerts(1, 10, None, None, start, end, "%")
    assert [item["alert_id"] for item in literal["items"]] == ["AL-start"]
    identifier = store.list_alerts(1, 10, None, None, start, end, "al-middle")
    assert [item["alert_id"] for item in identifier["items"]] == ["AL-middle"]


def test_incident_list_pages_filters_and_aggregates_only_persisted_rows(
    database: Any,
) -> None:
    store, sessions = database
    for alert_id, severity in (
        ("AL-inc-1", "high"),
        ("AL-inc-2", "low"),
        ("AL-inc-3", "medium"),
    ):
        store.ingest_alert(
            {**PAYLOAD, "alert_id": alert_id, "severity": severity}, None
        )
    with sessions.begin() as session:
        session.add_all(
            [
                IncidentTable(
                    incident_id="IN-1",
                    alert_id="AL-inc-1",
                    status="received",
                    created_at=NOW,
                ),
                IncidentTable(
                    incident_id="IN-2",
                    alert_id="AL-inc-2",
                    status="failed",
                    created_at=NOW + timedelta(hours=1),
                ),
                IncidentTable(
                    incident_id="IN-3",
                    alert_id="AL-inc-3",
                    status="received",
                    created_at=NOW + timedelta(hours=1),
                ),
                ApiInvestigationTable(
                    investigation_id="IV-1",
                    incident_id="IN-1",
                    trace_id="TRACE-1",
                    created_at=NOW,
                    status="awaiting_approval",
                    state={},
                    last_sequence=0,
                ),
                ApiInvestigationTable(
                    investigation_id="IV-3",
                    incident_id="IN-3",
                    trace_id="TRACE-3",
                    created_at=NOW + timedelta(hours=1),
                    status="completed",
                    state={},
                    last_sequence=0,
                ),
                EvidenceItemTable(
                    evidence_id="EV-list-1",
                    incident_id="IN-3",
                    event_id="SE-1",
                    source="nginx",
                    observed_at=NOW,
                    query={},
                    summary="Observed 1",
                    content_sha256="a" * 64,
                ),
                EvidenceItemTable(
                    evidence_id="EV-list-2",
                    incident_id="IN-3",
                    event_id="SE-1",
                    source="nginx",
                    observed_at=NOW,
                    query={},
                    summary="Observed 2",
                    content_sha256="a" * 64,
                ),
                ResponsePlanTable(
                    response_plan_id="RP-list",
                    incident_id="IN-3",
                    summary="Simulation",
                    actions=[simulated_action()],
                    created_at=NOW,
                    requires_approval=True,
                    evidence_ids=["EV-list-1"],
                ),
                ValidationResultTable(
                    validation_id="VR-list",
                    response_plan_id="RP-list",
                    outcome="success",
                    summary="Verified",
                    checked_at=NOW,
                    evidence_ids=["EV-list-1"],
                ),
            ]
        )
    first = store.list_incidents(1, 1, None)
    assert (first["total"], first["page"], first["page_size"]) == (3, 1, 1)
    assert first["items"] == [
        {
            "incident_id": "IN-3",
            "investigation_id": "IV-3",
            "alert_id": "AL-inc-3",
            "alert_title": "SQL injection",
            "severity": "medium",
            "status": "completed",
            "created_at": (NOW + timedelta(hours=1)).isoformat(),
            "evidence_count": 2,
            "validation_outcome": "success",
        }
    ]
    second = store.list_incidents(2, 1, None)
    assert second["items"][0]["incident_id"] == "IN-2"
    assert second["items"][0]["investigation_id"] is None
    assert second["items"][0]["status"] == "failed"
    assert second["items"][0]["evidence_count"] == 0
    assert second["items"][0]["validation_outcome"] is None
    filtered_overflow = store.list_incidents(3, 1, "awaiting_approval")
    assert filtered_overflow["total"] == 1
    assert filtered_overflow["items"] == []
    triage = store.list_incidents(1, 20, "awaiting_approval")
    assert triage["total"] == 1
    assert triage["items"][0]["incident_id"] == "IN-1"
    assert triage["items"][0]["status"] == "awaiting_approval"
    assert store.list_incidents(4, 1, None)["items"] == []
    assert store.list_incidents(1, 20, "rejected") == {
        "items": [],
        "total": 0,
        "page": 1,
        "page_size": 20,
    }


def test_incident_list_time_window_and_high_risk_match_dashboard_scope(
    database: Any,
) -> None:
    store, sessions = database
    start = NOW - timedelta(hours=1)
    end = NOW + timedelta(hours=1)
    for identity, severity, created_at in (
        ("before", "high", start - timedelta(seconds=1)),
        ("start", "high", start),
        ("middle", "critical", NOW),
        ("low", "low", NOW),
        ("end", "high", end),
    ):
        store.ingest_alert(
            {**PAYLOAD, "alert_id": f"AL-window-{identity}", "severity": severity}, None
        )
        with sessions.begin() as session:
            session.add(
                IncidentTable(
                    incident_id=f"IN-window-{identity}",
                    alert_id=f"AL-window-{identity}",
                    status="received",
                    created_at=created_at,
                )
            )

    high = store.list_incidents(1, 20, None, start, end, "high")
    assert high["total"] == 2
    assert {item["incident_id"] for item in high["items"]} == {
        "IN-window-start",
        "IN-window-middle",
    }
    assert store.list_incidents(1, 20, "received", start, end)["total"] == 3
    assert store.list_incidents(2, 1, None, start, end, "high")["total"] == 2


def test_incident_and_plan_aggregate_only_persisted_records(database: Any) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    incident_id = investigation["incident_id"]
    with sessions.begin() as session:
        session.add(
            EvidenceItemTable(
                evidence_id="EV-1",
                incident_id=incident_id,
                event_id="SE-1",
                source="nginx",
                observed_at=NOW,
                query={},
                summary="Observed",
                content_sha256="a" * 64,
            )
        )
        session.add(
            AttackStepTable(
                attack_step_id="AS-1",
                incident_id=incident_id,
                sequence=1,
                phase="initial",
                technique_id="T1190",
                description="Exploit",
                occurred_at=NOW,
                evidence_ids=["EV-1"],
            )
        )
        session.add(
            AgentRunTable(
                run_id="AR-1",
                incident_id=incident_id,
                agent_name="analyze",
                status="completed",
                started_at=NOW,
                finished_at=NOW,
                evidence_ids=["EV-1"],
            )
        )
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-1",
                incident_id=incident_id,
                summary="Simulate",
                actions=[simulated_action()],
                created_at=NOW,
                requires_approval=True,
                evidence_ids=["EV-1"],
            )
        )
        session.flush()
        session.add(
            ApprovalTable(
                approval_id="AP-1",
                response_plan_id="RP-1",
                decision="approved",
                reason="ok",
                decided_by="alice",
                decided_at=NOW,
            )
        )
        session.add(
            ValidationResultTable(
                validation_id="VA-1",
                response_plan_id="RP-1",
                outcome="success",
                summary="Verified",
                checked_at=NOW,
                evidence_ids=["EV-1"],
            )
        )
    # API state must never override the relational evidence or plan records.
    store.save_state(
        investigation["investigation_id"],
        {
            "status": "completed",
            "evidence": [{"evidence_id": "forged"}],
            "response_plan": {"response_plan_id": "forged"},
        },
    )
    result = store.get_incident(incident_id)
    assert result["evidence"][0]["evidence_id"] == "EV-1"
    assert result["attack_steps"][0]["attack_step_id"] == "AS-1"
    assert result["runs"][0]["run_id"] == "AR-1"
    assert result["response_plan"]["response_plan_id"] == "RP-1"
    assert result["approval"]["approval_id"] == "AP-1"
    assert result["validation_result"]["validation_id"] == "VA-1"
    plan = store.get_plan("RP-1")
    assert plan["investigation_id"] == investigation["investigation_id"]
    assert plan["incident_id"] == incident_id


def test_evidence_detail_recomputes_postgresql_raw_hash(database: Any) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-evidence-detail"}, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    evidence_id = "EV-" + "0" * 26
    raw = {"message": "SELECT"}
    expected_sha = calculate_content_sha256(raw)
    with sessions.begin() as session:
        session.get(SecurityEventTable, "SE-1").content_sha256 = expected_sha
        session.add(
            EvidenceItemTable(
                evidence_id=evidence_id,
                incident_id=investigation["incident_id"],
                event_id="SE-1",
                source="nginx",
                observed_at=NOW,
                query={"event_id": "SE-1"},
                summary="Real source event",
                content_sha256=expected_sha,
            )
        )
    detail = store.get_evidence_detail(investigation["incident_id"], evidence_id)
    assert detail["evidence"]["evidence_id"] == evidence_id
    assert detail["evidence"]["query"] == {"event_id": "SE-1"}
    assert detail["raw_event"]["raw"] == raw
    assert detail["raw_access"] == "full"
    assert detail["integrity"]["status"] == "verified"
    assert detail["integrity"]["scope"] == "postgresql"
    assert detail["integrity"]["algorithm"] == "sha256"
    assert detail["integrity"]["canonicalization"] == "evidencesoc-json-v1"
    assert detail["integrity"]["calculated_sha256"] == expected_sha
    assert detail["integrity"]["stored_event_sha256"] == expected_sha
    assert detail["integrity"]["stored_evidence_sha256"] == expected_sha
    assert datetime.fromisoformat(detail["integrity"]["checked_at"]).tzinfo is not None

    with sessions.begin() as session:
        session.get(SecurityEventTable, "SE-1").raw = {"message": "TAMPERED"}
    changed = store.get_evidence_detail(investigation["incident_id"], evidence_id)
    assert changed["integrity"]["status"] == "mismatch"
    assert changed["integrity"]["calculated_sha256"] != expected_sha

    envelope_shaped_raw = {"_audit_encoding": "base64-json", "value": "e30="}
    with sessions.begin() as session:
        session.get(SecurityEventTable, "SE-1").raw = envelope_shaped_raw
        session.get(
            SecurityEventTable, "SE-1"
        ).content_sha256 = calculate_content_sha256(envelope_shaped_raw)
        session.get(
            EvidenceItemTable, evidence_id
        ).content_sha256 = calculate_content_sha256(envelope_shaped_raw)
    exact = store.get_evidence_detail(investigation["incident_id"], evidence_id)
    assert exact["raw_event"]["raw"] == envelope_shaped_raw
    assert exact["integrity"]["status"] == "verified"


def test_evidence_detail_never_returns_another_incidents_evidence(
    database: Any,
) -> None:
    store, sessions = database
    identities = []
    for suffix in ("one", "two"):
        alert, _ = store.ingest_alert(
            {**PAYLOAD, "alert_id": f"AL-evidence-{suffix}"}, None
        )
        investigation, _ = store.create_investigation(
            alert_id=alert["alert_id"], incident_id=None
        )
        identities.append(investigation["incident_id"])
    evidence_id = "EV-" + "1" * 26
    with sessions.begin() as session:
        session.add(
            EvidenceItemTable(
                evidence_id=evidence_id,
                incident_id=identities[0],
                event_id="SE-1",
                source="nginx",
                observed_at=NOW,
                query={"event_id": "SE-1"},
                summary="Sensitive event",
                content_sha256="a" * 64,
            )
        )
    with pytest.raises(LookupError):
        store.get_evidence_detail(identities[1], evidence_id)
    with pytest.raises(LookupError):
        store.get_evidence_detail(identities[0], "EV-missing")
    assert store.get_evidence_detail(identities[0], evidence_id)["raw_access"] == "full"


def test_source_health_reports_observed_ingestion_lag_without_guessing_source_status(
    database: Any,
) -> None:
    store, sessions = database
    with sessions.begin() as session:
        session.add(
            SecurityEventTable(
                event_id="SE-2",
                source="firewall",
                deduplication_key="id:2",
                observed_at=NOW - timedelta(minutes=12),
                ingested_at=NOW - timedelta(minutes=12),
                severity="low",
                event_type="network.connection",
                raw={"message": "connected"},
                content_sha256="b" * 64,
                index_status="indexed",
            )
        )

    health = store.source_health(now=NOW)
    assert health == {
        "checked_at": NOW.isoformat(),
        "postgresql_status": None,  # SQLite tests do not prove PostgreSQL is healthy.
        "opensearch_status": None,
        "is_stale": False,
        "sources": [
            {
                "source": "nginx",
                "last_ingested_at": NOW.isoformat(),
                "ingestion_lag_seconds": 0,
                "status": None,
                "is_stale": None,
            },
            {
                "source": "firewall",
                "last_ingested_at": (NOW - timedelta(minutes=12)).isoformat(),
                "ingestion_lag_seconds": 720,
                "status": None,
                "is_stale": None,
            },
        ],
    }
    assert store.dashboard_summary("1h", now=NOW)["source_health"] == health


def test_dashboard_summary_aggregates_window_status_and_current_pending_plan(
    database: Any,
) -> None:
    store, sessions = database
    start = NOW - timedelta(hours=1)
    alerts = {}
    for suffix, severity, created_at in (
        ("A", "high", start),
        ("B", "critical", NOW - timedelta(minutes=30)),
        ("C", "low", NOW),
        ("D", "high", NOW - timedelta(hours=2)),
    ):
        alerts[suffix], _ = store.ingest_alert(
            {
                **PAYLOAD,
                "alert_id": f"AL-dashboard-{suffix}",
                "severity": severity,
                "created_at": created_at.isoformat(),
            },
            None,
        )
    with sessions.begin() as session:
        for suffix, status, created_at in (
            ("A", "analyzing", start),
            ("B", "awaiting_approval", NOW - timedelta(minutes=30)),
            ("C", "received", NOW - timedelta(minutes=1)),
        ):
            session.add(
                IncidentTable(
                    incident_id=f"IN-dashboard-{suffix}",
                    alert_id=alerts[suffix]["alert_id"],
                    status=status,
                    created_at=created_at,
                )
            )
        session.flush()
        for suffix, status, created_at in (
            ("A", "analyzing", start),
            ("B", "awaiting_approval", NOW - timedelta(minutes=30)),
            ("C", "received", NOW - timedelta(minutes=1)),
        ):
            session.add(
                ApiInvestigationTable(
                    investigation_id=f"IV-dashboard-{suffix}",
                    incident_id=f"IN-dashboard-{suffix}",
                    trace_id=f"TRACE-dashboard-{suffix}",
                    created_at=created_at,
                    status=status,
                    state={
                        "status": status,
                        "response_plan": {"response_plan_id": "RP-dashboard-current"}
                        if suffix == "B"
                        else None,
                    },
                    last_sequence=1 if suffix == "B" else 0,
                )
            )
        for plan_id, created_at in (
            ("RP-dashboard-old", NOW - timedelta(minutes=20)),
            ("RP-dashboard-current", NOW - timedelta(minutes=10)),
        ):
            session.add(
                ResponsePlanTable(
                    response_plan_id=plan_id,
                    incident_id="IN-dashboard-B",
                    summary="Only simulate",
                    actions=[simulated_action()],
                    created_at=created_at,
                    requires_approval=True,
                    evidence_ids=["EV-1"],
                )
            )
        session.add(
            ApiInvestigationEventTable(
                investigation_id="IV-dashboard-B",
                sequence=1,
                event="approval.awaiting",
                data={"private": "must-not-leak"},
                dedup_key="approval-awaiting",
                created_at=NOW - timedelta(minutes=5),
            )
        )
    add_verified_evidence(sessions, "IN-dashboard-B")

    summary = store.dashboard_summary("1h", now=NOW)
    assert summary["window"] == "1h"
    assert summary["time_from"] == start.isoformat()
    assert summary["time_to"] == NOW.isoformat()
    assert summary["metrics"] == {
        "alerts_in_window": 2,
        "high_risk_incidents": 2,
        "running_investigations": 1,
        "pending_response_plans": 1,
    }
    assert len(summary["alert_trend"]) == 12
    assert summary["alert_trend"][0]["total"] == 1
    assert summary["alert_trend"][6]["total"] == 1
    assert sum(item["high_risk"] for item in summary["alert_trend"]) == 2
    assert {
        item["status"]: item["count"]
        for item in summary["incident_status_distribution"]
    } == {
        "analyzing": 1,
        "awaiting_approval": 1,
        "received": 1,
    }
    assert [item["alert_id"] for item in summary["recent_alerts"]] == [
        "AL-dashboard-B",
        "AL-dashboard-A",
    ]
    assert summary["recent_alerts"][0]["status"] == "awaiting_approval"
    assert summary["recent_activity"] == [
        {
            "event": "approval.awaiting",
            "occurred_at": (NOW - timedelta(minutes=5)).isoformat(),
            "incident_id": "IN-dashboard-B",
            "investigation_id": "IV-dashboard-B",
        }
    ]
    assert "must-not-leak" not in str(summary)
    assert summary["source_health"]["postgresql_status"] is None
    assert summary["source_health"]["opensearch_status"] is None
    assert summary["source_health"]["sources"][0]["status"] is None

    store.record_decision(
        "RP-dashboard-current",
        {"decision": "rejected", "reason": "Queued", "decided_by": "analyst"},
    )
    assert (
        store.dashboard_summary("1h", now=NOW)["metrics"]["pending_response_plans"] == 0
    )
    daily = store.dashboard_summary("24h", now=NOW)
    assert daily["metrics"]["alerts_in_window"] == 3
    assert len(daily["alert_trend"]) == 24
    weekly = store.dashboard_summary("7d", now=NOW)
    assert weekly["metrics"]["alerts_in_window"] == 3
    assert len(weekly["alert_trend"]) == 7


def test_response_plan_page_filters_and_uses_stable_order(database: Any) -> None:
    store, sessions = database
    identities = {}
    for suffix in ("A", "B", "C", "D"):
        alert, _ = store.ingest_alert(
            {**PAYLOAD, "alert_id": f"AL-plan-{suffix}"}, None
        )
        identities[suffix], _ = store.create_investigation(
            alert_id=alert["alert_id"], incident_id=None
        )
    created_at = datetime.now(UTC)
    with sessions.begin() as session:
        for suffix in identities:
            session.add(
                ResponsePlanTable(
                    response_plan_id=f"RP-{suffix}",
                    incident_id=identities[suffix]["incident_id"],
                    summary=f"Plan {suffix}",
                    actions=[simulated_action()],
                    created_at=created_at,
                    requires_approval=True,
                    evidence_ids=["EV-1"],
                    **(complete_review_fields(created_at) if suffix == "B" else {}),
                )
            )
        for suffix, decision in (("C", "approved"), ("D", "rejected")):
            session.add(
                ApprovalTable(
                    approval_id=f"AP-{suffix}",
                    response_plan_id=f"RP-{suffix}",
                    decision=decision,
                    reason="Reviewed",
                    decided_by="analyst",
                    decided_at=NOW,
                )
            )
    add_verified_evidence(sessions, identities["B"]["incident_id"])
    for suffix in ("A", "B"):
        store.save_state(
            identities[suffix]["investigation_id"],
            {
                "status": "awaiting_approval",
                "response_plan": {"response_plan_id": f"RP-{suffix}"},
            },
        )
    store.record_decision(
        "RP-B",
        {"decision": "approved", "reason": "Queued", "decided_by": "analyst"},
    )

    first = store.list_response_plans(1, 2, None)
    assert first["total"] == 4
    assert [item["response_plan_id"] for item in first["items"]] == ["RP-D", "RP-C"]
    assert [item["decision_state"] for item in first["items"]] == [
        "rejected",
        "approved",
    ]
    second = store.list_response_plans(2, 2, None)
    assert [item["response_plan_id"] for item in second["items"]] == ["RP-B", "RP-A"]
    assert [item["decision_state"] for item in second["items"]] == [
        "submitting",
        "pending",
    ]
    pending = store.list_response_plans(1, 20, "pending")
    assert pending["total"] == 2
    assert {item["decision_state"] for item in pending["items"]} == {
        "pending",
        "submitting",
    }
    assert store.list_response_plans(1, 20, "approved")["total"] == 1
    assert store.list_response_plans(1, 20, "rejected")["total"] == 1
    assert store.list_response_plans(3, 2, None)["items"] == []


def test_response_plan_detail_reads_exact_historical_plan(database: Any) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-history"}, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    with sessions.begin() as session:
        for plan_id, offset in (("RP-old", 0), ("RP-new", 1)):
            session.add(
                ResponsePlanTable(
                    response_plan_id=plan_id,
                    incident_id=investigation["incident_id"],
                    summary=plan_id,
                    actions=[simulated_action()],
                    created_at=NOW + timedelta(seconds=offset),
                    requires_approval=True,
                    evidence_ids=["EV-1"],
                )
            )
        session.add(
            ApprovalTable(
                approval_id="AP-old",
                response_plan_id="RP-old",
                decision="approved",
                reason="Old decision",
                decided_by="analyst",
                decided_at=NOW,
            )
        )
        session.add(
            ValidationResultTable(
                validation_id="VA-old",
                response_plan_id="RP-old",
                outcome="success",
                summary="Old validation",
                checked_at=NOW,
                evidence_ids=["EV-1"],
            )
        )
    simulated = {
        "action": "block_ip_simulated",
        "target": "203.0.113.42",
        "risk": "low",
        "impact": "none",
        "preview": "simulated only",
        "rollback": "reset simulation",
        "verification_query": {"filters": {"source_ip": "203.0.113.42"}},
        "execution_id": "RP-new:0",
        "simulated": True,
        "status": "simulated",
        "outcome": "success",
    }
    old_simulated = {**simulated, "execution_id": "RP-old:0"}
    store.save_state(
        investigation["investigation_id"],
        {
            "status": "completed",
            "response_plan": {"response_plan_id": "RP-new"},
            "simulation": [old_simulated, simulated],
        },
    )
    old = store.get_response_plan_detail("RP-old")
    assert old["summary"] == "RP-old"
    assert old["alert_id"] == alert["alert_id"]
    assert old["investigation_id"] == investigation["investigation_id"]
    assert old["approval"]["approval_id"] == "AP-old"
    assert old["validation_result"]["validation_id"] == "VA-old"
    assert old["simulation"] == []
    assert old["is_current"] is False
    assert old["available_actions"] == []

    current = store.get_response_plan_detail("RP-new")
    assert current["summary"] == "RP-new"
    assert current["approval"] is None
    assert current["validation_result"] is None
    assert current["simulation"] == [simulated]
    assert current["is_current"] is True


def test_response_plan_detail_locks_actions_while_decision_is_submitting(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-submitting"}, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    created_at = datetime.now(UTC)
    with sessions.begin() as session:
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-submitting",
                incident_id=investigation["incident_id"],
                summary="Only simulate",
                actions=[simulated_action()],
                created_at=created_at,
                requires_approval=True,
                evidence_ids=["EV-1"],
                **complete_review_fields(created_at),
            )
        )
    add_verified_evidence(sessions, investigation["incident_id"])
    store.save_state(
        investigation["investigation_id"],
        {
            "status": "awaiting_approval",
            "response_plan": {"response_plan_id": "RP-submitting"},
        },
    )
    before = store.get_response_plan_detail("RP-submitting")
    assert before["decision_state"] == "pending"
    assert before["pending_decision"] is None
    assert before["available_actions"] == ["approve", "reject"]

    store.record_decision(
        "RP-submitting",
        {"decision": "approved", "reason": "Ready", "decided_by": "analyst"},
    )
    during = store.get_response_plan_detail("RP-submitting")
    assert during["decision_state"] == "submitting"
    assert during["pending_decision"] == "approved"
    assert during["approval"] is None
    assert during["available_actions"] == []
    assert during["simulation"] == []
    with sessions.begin() as session:
        session.add(
            ApprovalTable(
                approval_id="AP-submitting",
                response_plan_id="RP-submitting",
                decision="approved",
                reason="Ready",
                decided_by="analyst",
                decided_at=NOW,
            )
        )
    persisted = store.get_response_plan_detail("RP-submitting")
    assert persisted["decision_state"] == "approved"
    assert persisted["pending_decision"] is None
    assert persisted["available_actions"] == []
    with pytest.raises(LookupError):
        store.get_response_plan_detail("RP-unknown-secret")


@pytest.mark.parametrize("corruption", ["raw", "event_hash", "evidence_hash"])
def test_approval_rechecks_cited_evidence_integrity_and_still_allows_rejection(
    database: Any,
    corruption: str,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-integrity-gate"}, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    evidence_id = "EV-" + "3" * 26
    original_sha = calculate_content_sha256({"message": "SELECT"})
    created_at = datetime.now(UTC)
    with sessions.begin() as session:
        session.get(SecurityEventTable, "SE-1").content_sha256 = original_sha
        session.add(
            EvidenceItemTable(
                evidence_id=evidence_id,
                incident_id=investigation["incident_id"],
                event_id="SE-1",
                source="nginx",
                observed_at=NOW,
                query={"event_id": "SE-1"},
                summary="Cited original event",
                content_sha256=original_sha,
            )
        )
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-integrity-gate",
                incident_id=investigation["incident_id"],
                summary="Simulate",
                actions=[simulated_action([evidence_id])],
                created_at=created_at,
                requires_approval=True,
                evidence_ids=[evidence_id],
                **complete_review_fields(created_at, [evidence_id]),
            )
        )
    store.save_state(
        investigation["investigation_id"],
        {
            "status": "awaiting_approval",
            "response_plan": {"response_plan_id": "RP-integrity-gate"},
        },
    )
    assert store.get_response_plan_detail("RP-integrity-gate")["available_actions"] == [
        "approve",
        "reject",
    ]
    with sessions.begin() as session:
        if corruption == "raw":
            session.get(SecurityEventTable, "SE-1").raw = {"message": "TAMPERED"}
        elif corruption == "event_hash":
            session.get(SecurityEventTable, "SE-1").content_sha256 = "f" * 64
        else:
            session.get(EvidenceItemTable, evidence_id).content_sha256 = "f" * 64
    assert (
        store.get_evidence_detail(investigation["incident_id"], evidence_id)[
            "integrity"
        ]["status"]
        == "mismatch"
    )
    assert store.get_response_plan_detail("RP-integrity-gate")["available_actions"] == [
        "reject"
    ]
    assert store.get_investigation_snapshot(investigation["investigation_id"])[
        "available_actions"
    ] == ["reject"]
    with pytest.raises(storage_module().StorageConflict, match="integrity"):
        store.record_decision(
            "RP-integrity-gate",
            {"decision": "approved", "reason": "Looks safe", "decided_by": "analyst"},
        )
    assert (
        store.get_investigation(investigation["investigation_id"])["state"].get(
            "pending_decision"
        )
        is None
    )
    store.record_decision(
        "RP-integrity-gate",
        {"decision": "rejected", "reason": "Hash mismatch", "decided_by": "analyst"},
    )


def test_approval_does_not_accept_missing_cited_evidence(database: Any) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-missing-citation"}, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    created_at = datetime.now(UTC)
    missing_id = "EV-" + "4" * 26
    with sessions.begin() as session:
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-missing-citation",
                incident_id=investigation["incident_id"],
                summary="Simulate",
                actions=[simulated_action([missing_id])],
                created_at=created_at,
                requires_approval=True,
                evidence_ids=[missing_id],
                **complete_review_fields(created_at, [missing_id]),
            )
        )
    store.save_state(
        investigation["investigation_id"],
        {
            "status": "awaiting_approval",
            "response_plan": {"response_plan_id": "RP-missing-citation"},
        },
    )
    assert store.get_response_plan_detail("RP-missing-citation")[
        "available_actions"
    ] == ["reject"]
    with pytest.raises(storage_module().StorageConflict, match="integrity"):
        store.record_decision(
            "RP-missing-citation",
            {"decision": "approved", "reason": "Looks safe", "decided_by": "analyst"},
        )


def test_old_plan_cannot_be_decided_when_state_has_no_plan_id(database: Any) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert({**PAYLOAD, "alert_id": "AL-old-decision"}, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    with sessions.begin() as session:
        for plan_id, offset in (("RP-older", 0), ("RP-newer", 1)):
            session.add(
                ResponsePlanTable(
                    response_plan_id=plan_id,
                    incident_id=investigation["incident_id"],
                    summary="Simulate",
                    actions=[simulated_action()],
                    created_at=NOW + timedelta(seconds=offset),
                    requires_approval=True,
                    evidence_ids=["EV-1"],
                )
            )
    store.save_state(investigation["investigation_id"], {"status": "awaiting_approval"})
    assert store.get_response_plan_detail("RP-older")["available_actions"] == []
    with pytest.raises(storage_module().StorageConflict):
        store.record_decision(
            "RP-older",
            {"decision": "approved", "reason": "stale", "decided_by": "analyst"},
        )


def test_lookup_failures_and_readiness(database: Any) -> None:
    store, _ = database
    for lookup in (
        store.get_investigation,
        store.get_incident,
        store.get_plan,
        store.evaluation,
    ):
        with pytest.raises(LookupError):
            lookup("missing")
    with pytest.raises(LookupError):
        store.append_event("missing", "status", {}, "missing")
    with pytest.raises(LookupError):
        store.save_state("missing", {"status": "failed"})
    with pytest.raises(LookupError):
        store.list_events("missing", 0)
    assert store.ready() is None


def test_evaluation_reads_existing_persistent_result(database: Any) -> None:
    store, sessions = database
    with sessions.begin() as session:
        session.add(
            EvaluationRunTable(
                evaluation_run_id="ER-1",
                dataset_name="fixture",
                configuration={"mode": "fixture"},
                metrics={"accuracy": 1},
                status="completed",
                started_at=NOW,
                finished_at=NOW,
            )
        )
    assert store.evaluation("ER-1")["metrics"] == {"accuracy": 1}


def test_api_tables_do_not_change_core_base_metadata(database: Any) -> None:
    tables = importlib.import_module("evidencesoc.api.tables")
    assert tables.ApiBase.metadata is not Base.metadata
    assert not set(tables.ApiBase.metadata.tables) & set(Base.metadata.tables)


def test_pending_approval_decision_is_persisted_once_and_requires_approval_state(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = investigation["investigation_id"]
    created_at = datetime.now(UTC)
    with sessions.begin() as session:
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-approve",
                incident_id=investigation["incident_id"],
                summary="Simulate",
                actions=[simulated_action()],
                created_at=created_at,
                requires_approval=True,
                evidence_ids=["EV-1"],
                **complete_review_fields(created_at),
            )
        )
    add_verified_evidence(sessions, investigation["incident_id"])
    decision = {"decision": "approved", "reason": "ok", "decided_by": "alice"}
    with pytest.raises(storage_module().StorageConflict):
        store.record_decision("RP-approve", decision)
    store.save_state(identity, {"status": "awaiting_approval"})
    metadata = store.record_decision("RP-approve", decision)
    assert metadata["investigation_id"] == identity
    restored = storage_module().ApiStore(sessions)
    assert restored.get_investigation(identity)["state"]["pending_decision"] == decision
    with pytest.raises(storage_module().StorageConflict):
        restored.record_decision("RP-approve", decision)
    store.save_state(identity, {"status": "rejected", "approval": decision})
    assert "pending_decision" not in restored.get_investigation(identity)["state"]


def test_storage_module_exposes_requested_repository() -> None:
    assert hasattr(storage_module(), "ApiStore")


def test_approval_rejects_an_old_plan_for_the_same_incident(database: Any) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    created_at = datetime.now(UTC)
    with sessions.begin() as session:
        for plan_id in ("RP-old", "RP-current"):
            session.add(
                ResponsePlanTable(
                    response_plan_id=plan_id,
                    incident_id=investigation["incident_id"],
                    summary="Simulate",
                    actions=[simulated_action()],
                    created_at=created_at,
                    requires_approval=True,
                    evidence_ids=["EV-1"],
                    **(
                        complete_review_fields(created_at)
                        if plan_id == "RP-current"
                        else {}
                    ),
                )
            )
    add_verified_evidence(sessions, investigation["incident_id"])
    store.save_state(
        investigation["investigation_id"],
        {
            "status": "awaiting_approval",
            "response_plan": {"response_plan_id": "RP-current"},
        },
    )
    decision = {"decision": "approved", "reason": "ok", "decided_by": "alice"}
    with pytest.raises(storage_module().StorageConflict):
        store.record_decision("RP-old", decision)
    assert (
        store.record_decision("RP-current", decision)["state"]["pending_decision"]
        == decision
    )


def test_incident_status_tracks_api_state_until_workflow_events_are_published(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    incident_id = investigation["incident_id"]
    with sessions.begin() as session:
        incident = session.get(IncidentTable, incident_id)
        incident.status = "awaiting_approval"
    assert store.get_incident(incident_id)["status"] == "received"
    store.save_state(investigation["investigation_id"], {"status": "awaiting_approval"})
    assert store.get_incident(incident_id)["status"] == "awaiting_approval"


def test_incident_without_api_investigation_uses_core_status(database: Any) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    with sessions.begin() as session:
        session.add(
            IncidentTable(
                incident_id="IN-core-only",
                alert_id=alert["alert_id"],
                status="triaged",
                created_at=NOW,
            )
        )
    assert store.get_incident("IN-core-only")["status"] == "triaged"


def test_alert_list_and_filters_use_api_status_before_core_status(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    with sessions.begin() as session:
        incident = session.get(IncidentTable, investigation["incident_id"])
        incident.status = "awaiting_approval"
    assert store.list_alerts(1, 10, None, None)["items"][0]["status"] == "received"
    assert store.list_alerts(1, 10, None, "received")["total"] == 1
    assert store.list_alerts(1, 10, None, "awaiting_approval")["total"] == 0
    store.save_state(investigation["investigation_id"], {"status": "awaiting_approval"})
    assert store.list_alerts(1, 10, None, "awaiting_approval")["total"] == 1


@pytest.mark.parametrize(
    ("incoming", "preserved"),
    [
        ({"status": "awaiting_approval"}, True),
        ({"status": "simulating", "approval": {"response_plan_id": "RP-other"}}, True),
        (
            {"status": "simulating", "approval": {"response_plan_id": "RP-pending"}},
            False,
        ),
        ({"status": "failed"}, False),
    ],
)
def test_stale_state_preserves_pending_decision_until_consumed(
    database: Any, incoming: dict[str, Any], preserved: bool
) -> None:
    store, _ = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = investigation["investigation_id"]
    pending = {
        "response_plan_id": "RP-pending",
        "decision": "approved",
        "reason": "ok",
        "decided_by": "alice",
    }
    store.save_state(
        identity, {"status": "awaiting_approval", "pending_decision": pending}
    )
    store.save_state(identity, incoming)
    current = store.get_investigation(identity)["state"]
    assert (current.get("pending_decision") == pending) is preserved


def test_finalize_commits_terminal_event_and_status_once_and_recovers_replay(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = investigation["investigation_id"]
    final_state = {"status": "completed", "origin": {"source_scope": "external"}}
    terminal = store.finalize(
        identity, final_state, "investigation.completed", {"status": "completed"}
    )
    assert terminal == {
        "id": 1,
        "event": "investigation.completed",
        "data": {"status": "completed"},
    }
    assert store.get_investigation(identity)["state"] == final_state
    assert store.get_incident(investigation["incident_id"])["status"] == "completed"
    with sessions() as session:
        assert (
            session.get(IncidentTable, investigation["incident_id"]).status
            == "completed"
        )
    # A historic terminal event may exist while an older metadata snapshot needs repair.
    tables = importlib.import_module("evidencesoc.api.tables")
    with sessions.begin() as session:
        metadata = session.get(tables.ApiInvestigationTable, identity)
        metadata.status = "received"
        metadata.state = {"status": "received"}
        session.get(IncidentTable, investigation["incident_id"]).status = "received"
    assert (
        store.finalize(
            identity, {"status": "failed"}, "investigation.failed", {"status": "failed"}
        )
        == terminal
    )
    assert store.get_investigation(identity)["status"] == "completed"
    assert store.get_investigation(identity)["state"]["status"] == "completed"
    assert store.list_events(identity, 0) == [terminal]
    assert store.list_recoverable() == []


@pytest.mark.parametrize(
    "late_status", ["received", "awaiting_approval", "failed", "completed"]
)
def test_late_state_save_preserves_terminal_status_and_complete_results(
    database: Any, late_status: str
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = investigation["investigation_id"]
    final_state = {
        "status": "completed",
        "origin": {"source_scope": "external"},
        "classification": {"attack_types": ["sql_injection"]},
        "simulation": [{"result": "simulated"}],
        "errors": [],
    }
    terminal = store.finalize(
        identity, final_state, "investigation.completed", {"status": "completed"}
    )
    expected = store.get_investigation(identity)
    store.save_state(
        identity, {"status": late_status, "errors": [{"message": "stale worker"}]}
    )
    assert store.get_investigation(identity) == expected
    assert (
        store.get_incident(investigation["incident_id"])["origin"]
        == final_state["origin"]
    )
    assert store.list_events(identity, 0) == [terminal]
    with sessions() as session:
        assert (
            session.get(IncidentTable, investigation["incident_id"]).status
            == "completed"
        )


def test_finalize_rolls_back_terminal_event_when_status_write_fails(
    database: Any,
) -> None:
    store, sessions = database
    alert, _ = store.ingest_alert(PAYLOAD, None)
    investigation, _ = store.create_investigation(
        alert_id=alert["alert_id"], incident_id=None
    )
    identity = investigation["investigation_id"]
    engine = sessions.kw["bind"]

    def fail_status_write(
        _connection: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: Any,
    ) -> None:
        if statement.startswith("UPDATE incidents"):
            raise RuntimeError("forced status write failure")

    event.listen(engine, "before_cursor_execute", fail_status_write)
    try:
        with pytest.raises(RuntimeError, match="forced status write failure"):
            store.finalize(
                identity,
                {"status": "completed"},
                "investigation.completed",
                {"status": "completed"},
            )
    finally:
        event.remove(engine, "before_cursor_execute", fail_status_write)
    assert store.list_events(identity, 0) == []
    assert store.get_investigation(identity)["status"] == "received"
    assert store.get_investigation(identity)["last_event_id"] == 0
    with sessions() as session:
        assert (
            session.get(IncidentTable, investigation["incident_id"]).status
            == "received"
        )
    assert (
        store.finalize(
            identity,
            {"status": "completed"},
            "investigation.completed",
            {"status": "completed"},
        )["id"]
        == 1
    )


@pytest.mark.skipif(
    os.getenv("EVIDENCESOC_TEST_POSTGRES") != "1",
    reason="requires opt-in local PostgreSQL connectivity",
)
def test_readiness_bounds_slow_postgres_sql_and_restores_connection_timeout() -> None:
    from evidencesoc.config import Settings

    engine = create_engine(Settings().database_url, connect_args={"connect_timeout": 1})
    sessions = sessionmaker(bind=engine)
    with sessions() as session:
        original_timeout = session.execute(text("SHOW statement_timeout")).scalar_one()

    def slow_readiness(
        _connection: Any,
        _cursor: Any,
        statement: str,
        parameters: Any,
        _context: Any,
        _executemany: Any,
    ) -> tuple[str, Any]:
        return (
            ("SELECT pg_sleep(2)", parameters)
            if statement == "SELECT 1"
            else (statement, parameters)
        )

    event.listen(engine, "before_cursor_execute", slow_readiness, retval=True)
    try:
        started = monotonic()
        with pytest.raises(DBAPIError) as failure:
            storage_module().ApiStore(sessions).ready()
        assert getattr(failure.value.orig, "sqlstate", None) == "57014"
        assert monotonic() - started < 1.8
        with sessions() as session:
            assert (
                session.execute(text("SHOW statement_timeout")).scalar_one()
                == original_timeout
            )
    finally:
        event.remove(engine, "before_cursor_execute", slow_readiness)
        engine.dispose()
