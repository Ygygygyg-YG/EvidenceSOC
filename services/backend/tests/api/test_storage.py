from __future__ import annotations

import importlib
import os
from datetime import UTC, datetime
from time import monotonic
from typing import Any

import pytest
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
                actions=[{"action": "block_ip_simulated"}],
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
    with sessions.begin() as session:
        session.add(
            ResponsePlanTable(
                response_plan_id="RP-approve",
                incident_id=investigation["incident_id"],
                summary="Simulate",
                actions=[{"action": "block_ip_simulated"}],
                created_at=NOW,
                requires_approval=True,
                evidence_ids=["EV-1"],
            )
        )
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
    with sessions.begin() as session:
        for plan_id in ("RP-old", "RP-current"):
            session.add(
                ResponsePlanTable(
                    response_plan_id=plan_id,
                    incident_id=investigation["incident_id"],
                    summary="Simulate",
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
