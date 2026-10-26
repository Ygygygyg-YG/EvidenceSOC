"""Free MemorySaver integration acceptance, not live service/retained evidence."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta

import pytest
from evidencesoc.agents.graph import InvestigationWorkflow, _plan_hash
from evidencesoc.config import Settings
from langgraph.checkpoint.memory import InMemorySaver

from evals.tests.test_analysis_import import artifact_source


class Services:
    def __init__(self, evidence):
        self.evidence = evidence
        self.runs, self.saved = [], []

    async def load_incident(self, incident_id):
        return {"status": "received", "alerts": []}

    async def hydrate_evidence(self, incident_id, values):
        return deepcopy(self.evidence) if values == self.evidence else []

    async def start_run(self, state, role):
        self.runs.append({"role": role, "status": "running"})
        return str(len(self.runs))

    async def finish_run(self, run_id, delta, status):
        self.runs[int(run_id) - 1].update(status=status)

    async def save_result(self, state):
        self.saved.append(deepcopy(state))


def imported_workflow(tmp_path, *, model=None, saver=None):
    from evidencesoc.agents.analysis_import import ImportDispatchJournal

    from evals.adapters.analysis_import import verify_analysis_source

    source = verify_analysis_source(artifact_source(tmp_path / "source"))
    services = Services(source.product_values()["evidence"])
    settings = Settings(_env_file=None, llm_mode="deepseek" if model else "fixture")
    flow = InvestigationWorkflow.for_analysis_import(
        imported_analysis=source,
        admission=ImportDispatchJournal(tmp_path / "dispatch.sqlite"),
        services=services,
        settings=settings,
        checkpointer=saver or InMemorySaver(),
        model=model,
    )
    return flow, source, services


@pytest.fixture
def persisted_import(tmp_path):
    """Real service hydration on a synthetic SQLite session, never live PG."""
    from evidencesoc.agents.analysis_import import ImportDispatchJournal
    from evidencesoc.agents.services import PostgresWorkflowServices
    from evidencesoc.domain.models import EvidenceItem
    from evidencesoc.persistence.tables import (
        AlertTable,
        EvidenceItemTable,
        IncidentTable,
        SecurityEventTable,
    )
    from sqlalchemy import JSON, CheckConstraint, MetaData, create_engine
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.orm import sessionmaker

    from evals.adapters.analysis_import import verify_analysis_source

    source_root = tmp_path / "source"
    anchor = artifact_source(
        source_root,
        raw={
            "host": "synthetic-host",
            "source_port": 12345,
            "destination_port": 443,
            "message": "合成观测" * 800,
        },
    )
    source = verify_analysis_source(anchor)
    seed = json.loads((source_root / "seed.json").read_bytes())
    settings = Settings(_env_file=None, llm_mode="deepseek")
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'synthetic-import.db'}")
    metadata = MetaData()
    for model in (AlertTable, IncidentTable, SecurityEventTable, EvidenceItemTable):
        table = model.__table__.to_metadata(metadata)
        for column in table.columns:
            if isinstance(column.type, JSONB):
                column.type = JSON()
        for constraint in list(table.constraints):
            if isinstance(constraint, CheckConstraint):
                table.constraints.remove(constraint)
    metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions() as session:
        for value in seed["events"]:
            event = deepcopy(value)
            for key in ("observed_at", "ingested_at"):
                event[key] = datetime.fromisoformat(event[key].replace("Z", "+00:00"))
            session.add(SecurityEventTable(**event))
        alert = deepcopy(seed["alerts"][0])
        alert["created_at"] = datetime.fromisoformat(
            alert["created_at"].replace("Z", "+00:00")
        )
        session.add(AlertTable(**alert))
        session.add(
            IncidentTable(
                incident_id="IN-new",
                alert_id=alert["alert_id"],
                status="received",
                created_at=alert["created_at"],
            )
        )
        for value in seed["evidence"]:
            session.add(
                EvidenceItemTable(
                    **EvidenceItem.model_validate(value).model_dump(),
                    incident_id="IN-new",
                )
            )
        session.commit()

    service = PostgresWorkflowServices(settings, session_factory=sessions)

    class HydratingServices(Services):
        async def load_incident(self, incident_id):
            return await service.load_incident(incident_id)

        async def hydrate_evidence(self, incident_id, values):
            return await service.hydrate_evidence(incident_id, values)

    class RecordingTape(Tape):
        async def structured(self, role, schema, state):
            self.received_state = deepcopy(state)
            return await super().structured(role, schema, state)

    services = HydratingServices(source.product_values()["evidence"])
    tape = RecordingTape()
    flow = InvestigationWorkflow.for_analysis_import(
        imported_analysis=source,
        admission=ImportDispatchJournal(tmp_path / "dispatch.sqlite"),
        services=services,
        settings=settings,
        checkpointer=InMemorySaver(),
        model=tape,
    )
    yield flow, source, services, service, sessions, tape
    engine.dispose()


@pytest.mark.asyncio
async def test_real_service_hydration_accepts_expanded_raw_without_expanding_seed(
    persisted_import,
):
    flow, source, services, service, _, tape = persisted_import
    original = source.product_values()["evidence"]
    hydrated = service._hydrate_evidence("IN-new", original)
    assert hydrated[0]["raw"]["severity"] == "info"
    assert hydrated[0]["raw"]["source_port"] == 12345
    assert hydrated[0]["raw"]["destination_port"] == 443
    assert len(hydrated[0]["raw"]["message"].encode()) > 2048
    assert len(original[0]["raw"]["message"].encode()) <= 2048
    assert {"severity", "source_port", "destination_port"}.isdisjoint(
        original[0]["raw"]
    )
    state = await flow.import_analysis("IN-new", source)
    assert state["status"] == "awaiting_approval"
    assert [run["role"] for run in services.runs] == ["analysis_import", "respond"]
    assert state["evidence"] == state["diagnostic_snapshot"]["evidence"] == original
    from evidencesoc.agents.fallback import observed_raw

    assert tape.received_state["evidence"] == [
        {**item, "raw": observed_raw(item)} for item in original
    ]
    # Check the real replay -> graph state against the independent E gate too;
    # the timing suite's synthetic import fixtures must not hide a shape drift.
    from evals.e_timing import _validate_imported_state

    _validate_imported_state(state, source.provenance)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corruption",
    [
        "ownership",
        "event_id",
        "source",
        "time",
        "hash",
        "raw",
        "rehashed_raw",
        "query",
        "summary",
    ],
)
async def test_real_service_hydration_rejects_changed_identity_or_content(
    persisted_import, corruption
):
    from evidencesoc.ingestion.normalize import calculate_content_sha256
    from evidencesoc.persistence.tables import EvidenceItemTable, SecurityEventTable

    flow, source, services, _, sessions, tape = persisted_import
    original = source.product_values()["evidence"][0]
    with sessions() as session:
        evidence = session.get(EvidenceItemTable, original["evidence_id"])
        event = session.get(SecurityEventTable, original["event_id"])
        if corruption == "ownership":
            evidence.incident_id = "IN-other"
        elif corruption == "event_id":
            evidence.event_id = "SE-substituted"
        elif corruption == "source":
            evidence.source = event.source = "substituted-source"
        elif corruption == "time":
            evidence.observed_at += timedelta(seconds=1)
        elif corruption == "hash":
            evidence.content_sha256 = event.content_sha256 = "f" * 64
        elif corruption in {"raw", "rehashed_raw"}:
            event.raw = {**event.raw, "message": "substituted event"}
            if corruption == "rehashed_raw":
                evidence.content_sha256 = event.content_sha256 = (
                    calculate_content_sha256(event.raw)
                )
        elif corruption == "query":
            evidence.query = {
                "matched_event_id": original["event_id"],
                "seed_rule": "substituted",
            }
        else:
            evidence.summary = "substituted summary"
        session.commit()
    state = await flow.import_analysis("IN-new", source)
    assert state["status"] == "failed"
    assert [run["role"] for run in services.runs] == ["analysis_import"]
    assert tape.calls == []


@pytest.mark.asyncio
async def test_real_import_node_seals_responds_saves_and_interrupts_for_approval(
    tmp_path,
):
    flow, source, services = imported_workflow(tmp_path)
    state = await flow.import_analysis("IN-new", source)
    snapshot = await flow.graph.aget_state(flow._config("IN-new"))
    assert snapshot.next == ("approval",)
    assert state["status"] == "awaiting_approval"
    assert state["diagnostic_snapshot"]["sealed_after"] == "analysis_import"
    assert state["diagnostic_snapshot_sha256"] == _plan_hash(
        state["diagnostic_snapshot"]
    )
    assert state["attack_steps"] == []
    assert state["analysis_import_provenance"]["reconstruct_executed"] is False
    assert services.saved[0]["status"] == "received"
    assert [run["role"] for run in services.runs] == ["analysis_import", "respond"]
    assert [e["node"] for e in state["events"]] == [
        "analysis_import",
        "analysis_import",
        "respond",
        "respond",
    ]
    assert state.get("approval") is None
    assert state.get("simulation_execution") is None
    assert state.get("simulation", []) == []
    assert services.saved[-1]["response_plan"] == state["response_plan"]
    before = deepcopy(state["diagnostic_snapshot"])
    reopened = await flow.import_analysis("IN-new", source)
    assert reopened["diagnostic_snapshot"] == before
    assert len(services.runs) == 2


@pytest.mark.parametrize(
    "initial",
    [{"diagnosis": {}}, {"analysis_import_provenance": {}}, {"_analysis_import": True}],
)
def test_ordinary_initial_state_diagnostic_injection_stays_forbidden(initial):
    with pytest.raises(ValueError, match="trusted seed"):
        InvestigationWorkflow(
            services=object(),
            settings=Settings(_env_file=None),
            checkpointer=InMemorySaver(),
            initial_state=initial,
        )


@pytest.mark.asyncio
async def test_import_requires_explicit_constructor_and_verified_type(tmp_path):
    flow, source, services = imported_workflow(tmp_path)
    ordinary = InvestigationWorkflow(
        services=services, settings=flow.settings, checkpointer=InMemorySaver()
    )
    with pytest.raises(PermissionError):
        await ordinary.import_analysis("IN-new", source)
    with pytest.raises((PermissionError, TypeError)):
        await flow.import_analysis("IN-new", source.product_values())
    with pytest.raises(PermissionError):
        await flow.run_investigation("IN-new")


@pytest.mark.asyncio
async def test_integrity_failure_does_not_call_respond_or_restart_new_incident(
    tmp_path,
):
    flow, source, services = imported_workflow(tmp_path)
    services.evidence = []
    state = await flow.import_analysis("IN-new", source)
    assert state["status"] == "failed"
    assert [run["role"] for run in services.runs] == ["analysis_import"]
    with pytest.raises(PermissionError):
        await flow.import_analysis("IN-another", source)


@pytest.mark.asyncio
async def test_started_unknown_journal_survives_reopen_and_refuses_dispatch(tmp_path):
    from evidencesoc.agents.analysis_import import ImportDispatchJournal

    flow, source, _ = imported_workflow(tmp_path)
    admission = ImportDispatchJournal(tmp_path / "dispatch.sqlite")
    admission.claim(source.source_identity, "IN-crashed")
    with pytest.raises(PermissionError):
        await flow.import_analysis("IN-new", source)


@pytest.mark.asyncio
async def test_pending_reopen_refuses_changed_source_and_changed_seal(tmp_path):
    flow, source, _ = imported_workflow(tmp_path)
    state = await flow.import_analysis("IN-new", source)
    changed = deepcopy(state["diagnostic_snapshot"])
    changed["diagnosis"]["verdict"] = "benign"
    await flow.graph.aupdate_state(
        flow._config("IN-new"), {"diagnostic_snapshot": changed}
    )
    with pytest.raises((PermissionError, ValueError)):
        await flow.import_analysis("IN-new", source)


@pytest.mark.asyncio
async def test_pending_reopen_revalidates_original_bytes(tmp_path):
    flow, source, _ = imported_workflow(tmp_path)
    await flow.import_analysis("IN-new", source)
    path = tmp_path / "source/seed.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        await flow.import_analysis("IN-new", source)


class Tape:
    def __init__(self, ttl=1800, null=False, error=False):
        self.ttl, self.null, self.error, self.calls = ttl, null, error, []

    async def structured(self, role, schema, state):
        from evidencesoc.agents.fallback import respond

        self.calls.append(role)
        if self.error:
            raise RuntimeError("synthetic transport failure")
        output = respond(state).model_dump(mode="json")
        if self.null:
            output["response_plan"] = None
        else:
            plan = output["response_plan"]
            created = datetime.fromisoformat(plan["created_at"].replace("Z", "+00:00"))
            plan["expires_at"] = (created + timedelta(seconds=self.ttl)).isoformat()
        return schema.model_validate(output)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ttl,null,error,expected",
    [
        (1800, False, False, "awaiting_approval"),
        (1799, False, False, "failed"),
        (1800, True, False, "manual_review"),
        (1800, False, True, "awaiting_approval"),
    ],
)
async def test_import_uses_existing_respond_and_exact_ttl_before_persist(
    tmp_path, ttl, null, error, expected
):
    model = Tape(ttl, null, error)
    flow, source, services = imported_workflow(tmp_path, model=model)
    state = await flow.import_analysis("IN-new", source)
    assert state["status"] == expected
    assert model.calls and set(model.calls) == {"respond"}
    if ttl == 1799:
        assert not any(s.get("response_plan") for s in services.saved)
    if error:
        assert state["plan_source"] == "rule_fallback"
    assert state.get("approval") is None
