"""Probe orchestration tests; injected sessions are never formal G4 evidence."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import subprocess
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from evidencesoc.config import Settings
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.persistence.tables import (
    AgentRunTable,
    AlertTable,
    EvidenceItemTable,
    IncidentTable,
    InvestigationToolCallTable,
    SecurityEventTable,
    ToolCallTable,
)
from sqlalchemy import JSON, CheckConstraint, MetaData, create_engine, event, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

from evals.adapters.environment import CaseResources
from evals.contracts import WorkerRunSpec, canonical_hash
from services.backend.tests.integration import test_task12_service_acceptance as task12

task12_live_scope = task12.live_scope


@pytest.fixture
def probe_case(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite+pysqlite:///{(tmp_path / 'case.sqlite').as_posix()}"
    )

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    metadata = MetaData()
    for model in (
        AlertTable,
        IncidentTable,
        SecurityEventTable,
        AgentRunTable,
        ToolCallTable,
        EvidenceItemTable,
        InvestigationToolCallTable,
    ):
        table = model.__table__.to_metadata(metadata)
        for column in table.columns:
            if isinstance(column.type, JSONB):
                column.type = JSON()
        for constraint in list(table.constraints):
            if isinstance(constraint, CheckConstraint):
                table.constraints.remove(constraint)
    metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    at = datetime(2026, 10, 18, tzinfo=UTC)
    documents = []
    for number, offset in enumerate((0, 2000)):
        raw = {
            "dataset_id": "benign:case",
            "host": "benign.example.test",
            "message": str(number),
        }
        documents.append(
            {
                "event_id": f"SE-case-{number}",
                "source": "test",
                "external_id": str(number),
                "deduplication_key": str(number),
                "observed_at": (at + timedelta(seconds=offset)).isoformat(),
                "ingested_at": at.isoformat(),
                "severity": "info",
                "event_type": "host.health",
                "raw": raw,
                "content_sha256": calculate_content_sha256(raw),
                "index_status": "indexed",
            }
        )
    with sessions() as session, session.begin():
        for document in documents:
            values = {**document}
            for key in ("observed_at", "ingested_at"):
                values[key] = datetime.fromisoformat(values[key])
            session.add(SecurityEventTable(**values))
        session.add(
            AlertTable(
                alert_id="AL-experiment",
                title="Experiment",
                severity="info",
                created_at=at,
                event_ids=[d["event_id"] for d in documents],
            )
        )
        session.flush()
        session.add(
            IncidentTable(
                incident_id="IN-experiment",
                alert_id="AL-experiment",
                status="received",
                created_at=at,
            )
        )
        session.flush()
        session.add(
            AgentRunTable(
                run_id="AR-experiment",
                incident_id="IN-experiment",
                agent_name="collect",
                status="running",
                started_at=at,
                evidence_ids=[],
                output_summary={"model_ledger": [{"logical_call_id": "unchanged"}]},
            )
        )
    spec = WorkerRunSpec(
        run_id="worker-run", case_id="case", group="B3", config_sha256="a" * 64
    )
    settings = Settings(
        _env_file=None, database_url=str(engine.url), opensearch_index="case-index"
    )
    environment = CaseResources(
        settings,
        sessions,
        "IN-experiment",
        "fixture-case-db",
        "case-index",
        spec.run_id,
        spec.case_id,
    )
    seed = {
        "events": documents,
        "alerts": [{"alert_id": "AL-experiment", "created_at": at.isoformat()}],
        "evidence": [],
        "registry": {},
        "input_sha256": "b" * 64,
    }
    monkeypatch.setenv("TASK13_PHASE", "development")
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("TASK13_WORKER_NONCE", "fixture-only-nonce")
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", "c" * 40)
    yield SimpleNamespace(
        engine=engine,
        sessions=sessions,
        spec=spec,
        environment=environment,
        seed=seed,
        at=at,
        output=tmp_path / "artifacts",
    )
    engine.dispose()


def install_injected_mcp(
    monkeypatch,
    case,
    *,
    corrupt_hash=False,
    missing_audit=False,
    missing_evidence=False,
    mutate_experiment=False,
    transport_failure=False,
):
    """Only transport is injected; all orchestration DB effects use actual SQL."""
    probe = importlib.import_module("evals.adapters.isolation_probe")
    requests = []

    @asynccontextmanager
    async def injected(context, *, settings, backend_dir, managed_attempts):
        assert settings is case.environment.settings
        assert settings.opensearch_index == case.environment.index_name
        assert managed_attempts is True
        with case.sessions() as stored:
            owner = stored.get(AgentRunTable, context.run_id)
            assert (
                owner.incident_id == context.incident_id != case.environment.incident_id
            )
            alert = stored.get(
                AlertTable, stored.get(IncidentTable, context.incident_id).alert_id
            )
            assert alert.created_at == case.at.replace(tzinfo=None)
            assert set(alert.event_ids) == {d["event_id"] for d in case.seed["events"]}
        if transport_failure:
            raise ConnectionError("injected transport failure")

        class Session:
            async def call_tool(self, name, arguments):
                request = {"tool_name": name, "arguments": arguments}
                requests.append(request)
                code = None
                result = []
                if (
                    name == "get_alert_context"
                    and arguments["alert_id"] == alert.alert_id
                ):
                    item = case.seed["events"][0]
                    result = [
                        {
                            "evidence_id": "EV-probe",
                            "event_id": item["event_id"],
                            "content_sha256": "0" * 64
                            if corrupt_hash
                            else item["content_sha256"],
                        }
                    ]
                    with case.sessions() as stored, stored.begin():
                        if not missing_evidence:
                            stored.add(
                                EvidenceItemTable(
                                    evidence_id="EV-probe",
                                    incident_id=context.incident_id,
                                    event_id=item["event_id"],
                                    source=item["source"],
                                    observed_at=case.at,
                                    query={"alert_id": alert.alert_id},
                                    query_fingerprint="d" * 64,
                                    summary="Probe",
                                    content_sha256=item["content_sha256"],
                                )
                            )
                        if mutate_experiment:
                            stored.get(AgentRunTable, "AR-experiment").evidence_ids = [
                                "unexpected"
                            ]
                elif name == "get_alert_context":
                    with case.sessions() as stored:
                        foreign = stored.get(AlertTable, arguments["alert_id"])
                        assert (
                            foreign is not None and foreign.alert_id != "AL-experiment"
                        )
                    code = "NOT_FOUND"
                else:
                    code = "POLICY_DENIED"
                structured = {"error": {"code": code}} if code else {"result": result}
                if not missing_audit:
                    with case.sessions() as stored, stored.begin():
                        audit_result = (
                            {"trace_id": context.trace_id, "reason": code}
                            if code
                            else {
                                "trace_id": context.trace_id,
                                "result_count": len(result),
                            }
                        )
                        stored.add(
                            ToolCallTable(
                                tool_call_id=f"TC-{len(requests)}",
                                run_id=context.run_id,
                                tool_name=name,
                                arguments=arguments,
                                result=audit_result,
                                started_at=case.at,
                                finished_at=case.at,
                                success=code is None,
                                error_code=code,
                            )
                        )
                return SimpleNamespace(
                    isError=code is not None, structuredContent=structured
                )

        yield Session()

    monkeypatch.setattr(probe, "open_stdio_session", injected)
    return probe, requests


@pytest.mark.asyncio
async def test_probe_exports_bound_audit_and_cleans_only_probe_resources(
    probe_case, monkeypatch
):
    case = probe_case
    probe, requests = install_injected_mcp(monkeypatch, case)
    before_seed = canonical_hash(case.seed)
    result = await probe.run_service_probe(case.spec, case.environment, case.seed)
    assert result["status"] == "passed"
    assert result["passed"] is True
    assert len(requests) == 9
    assert all(check["passed"] for check in result["checks"])
    assert result["physical_audit_sha256"] == canonical_hash(result["physical_audit"])
    assert len(result["physical_audit"]) == len(requests)
    assert all(
        check["request_sha256"] == canonical_hash(check["request"])
        for check in result["checks"]
    )
    assert all(
        check["response_sha256"] == canonical_hash(check["response"])
        for check in result["checks"]
    )
    assert result["cleanup"]["verified"] is True
    assert result["unchanged"]["verified"] is True
    assert result["unchanged"]["before"] == result["unchanged"]["after"]
    assert canonical_hash(case.seed) == before_seed
    assert result["provenance"]["worker_nonce"] == "fixture-only-nonce"
    assert result["provenance"]["database_name"] == "fixture-case-db"
    assert result["provenance"]["index_name"] == "case-index"
    assert result["provenance"]["input_sha256"] == case.seed["input_sha256"]
    assert result["counts_as_model_evidence"] is False
    assert result["latency_ms"] >= 0
    exported = json.loads(
        (case.output / "service-isolation-probe.json").read_text(encoding="utf-8")
    )
    assert exported["physical_audit"] == result["physical_audit"]
    with case.sessions() as stored:
        assert stored.scalars(select(IncidentTable.incident_id)).all() == [
            "IN-experiment"
        ]
        assert stored.scalars(select(AlertTable.alert_id)).all() == ["AL-experiment"]
        assert stored.scalars(select(AgentRunTable.run_id)).all() == ["AR-experiment"]
        assert stored.scalars(select(ToolCallTable.tool_call_id)).all() == []
        assert stored.scalars(select(EvidenceItemTable.evidence_id)).all() == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "injection",
    [
        "corrupt_hash",
        "missing_audit",
        "missing_evidence",
        "mutate_experiment",
        "transport_failure",
    ],
)
async def test_probe_fails_closed_and_preserves_failure_artifact(
    probe_case, monkeypatch, injection
):
    case = probe_case
    probe, _ = install_injected_mcp(monkeypatch, case, **{injection: True})
    result = await probe.run_service_probe(case.spec, case.environment, case.seed)
    assert result["status"] == "failed"
    assert result["passed"] is False
    assert result["cleanup"]["verified"] is True
    assert result["errors"]
    assert (case.output / "service-isolation-probe.json").is_file()
    with case.sessions() as stored:
        assert stored.scalars(select(IncidentTable.incident_id)).all() == [
            "IN-experiment"
        ]
    if injection == "mutate_experiment":
        assert result["unchanged"]["verified"] is False


@pytest.mark.asyncio
async def test_probe_rejects_wrong_phase_before_opening_transport(
    probe_case, monkeypatch
):
    case = probe_case
    probe, requests = install_injected_mcp(monkeypatch, case)
    monkeypatch.setenv("TASK13_PHASE", "test")
    result = await probe.run_service_probe(case.spec, case.environment, case.seed)
    assert result["passed"] is False
    assert requests == []
    assert result["errors"]


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["TASK13_WORKER_NONCE", "TASK13_SOURCE_COMMIT"])
async def test_probe_requires_worker_identity_before_opening_transport(
    probe_case, monkeypatch, missing
):
    case = probe_case
    probe, requests = install_injected_mcp(monkeypatch, case)
    monkeypatch.delenv(missing)
    result = await probe.run_service_probe(case.spec, case.environment, case.seed)
    assert result["passed"] is False
    assert requests == []


@pytest.mark.asyncio
async def test_probe_uses_actual_alert_clock_when_incident_clock_differs(
    probe_case, monkeypatch
):
    case = probe_case
    with case.sessions() as stored, stored.begin():
        stored.get(IncidentTable, case.environment.incident_id).created_at = (
            case.at + timedelta(seconds=60)
        )
    probe, _ = install_injected_mcp(monkeypatch, case)
    result = await probe.run_service_probe(case.spec, case.environment, case.seed)
    assert result["passed"], result["errors"]
    assert "source_scopes" not in result["bound_scope"]
    assert result["bound_scope_sha256"]


@pytest.mark.skipif(
    os.getenv("EVIDENCESOC_TEST_POSTGRES") != "1"
    or os.getenv("EVIDENCESOC_TEST_OPENSEARCH") != "1"
    or os.getenv("TASK13_TEST_SERVICE_PROBE") != "1",
    reason="explicit model-free real PostgreSQL/OpenSearch/stdio service probe",
)
@pytest.mark.asyncio
async def test_real_service_probe_has_independent_owner_and_verified_cleanup(
    task12_live_scope, tmp_path, monkeypatch
):
    """Real services, still excluded from model-bound formal G4 acceptance."""
    from sqlalchemy.engine import make_url

    from evals.adapters.isolation_probe import run_service_probe

    live = task12_live_scope
    spec = WorkerRunSpec(
        run_id="real-service-test",
        case_id="real-case",
        group="B3",
        config_sha256="a" * 64,
    )
    with live.sessions() as stored:
        events = []
        for row in stored.scalars(
            select(SecurityEventTable).where(
                SecurityEventTable.event_id.in_(live.events[:2])
            )
        ):
            document = {
                column.key: getattr(row, column.key) for column in row.__table__.columns
            }
            for key in ("observed_at", "ingested_at", "indexed_at"):
                if document[key] is not None:
                    document[key] = document[key].isoformat()
            events.append(document)
    seed = {
        "events": events,
        "alerts": [],
        "evidence": [],
        "registry": {},
        "input_sha256": canonical_hash(events),
    }
    environment = CaseResources(
        live.settings,
        live.sessions,
        live.incidents[0],
        make_url(live.settings.database_url).database,
        live.settings.opensearch_index,
        spec.run_id,
        spec.case_id,
    )
    monkeypatch.setenv("TASK13_PHASE", "development")
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("TASK13_WORKER_NONCE", "real-service-test-not-model-evidence")
    source_commit = await asyncio.to_thread(
        subprocess.check_output, ["git", "rev-parse", "HEAD"], text=True
    )
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", source_commit.strip())
    result = await run_service_probe(spec, environment, seed)
    assert result["passed"], result["errors"]
    assert result["provenance"]["actual_database_name"] == environment.database_name
    assert result["provenance"]["database_backend"] == "postgresql"
    assert result["cleanup"]["verified"] and result["unchanged"]["verified"]
    assert len(result["physical_audit"]) == 9
    assert result["counts_as_model_evidence"] is False
