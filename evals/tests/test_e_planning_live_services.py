"""FREE loopback PostgreSQL/OpenSearch acceptance; fixture decisions only.

Worker PID/source-export/budget/epoch and review-clock preflight are injected.
Actual portable source verification, dispatch journal, resources, isolation probe, services,
checkpoint, graph, persisted rows, retained reopening and cleanup are unmocked.
The decision scenario records only an explicitly synthetic fixture approval.
"""

from __future__ import annotations

import io
import json
import os
import re
import socket
import uuid
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
from dotenv import dotenv_values
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url

from evals.contracts import canonical_hash

WORKSPACE = Path("D:/传智杯")


def _json(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2),
        encoding="utf-8",
    )


@pytest.fixture
def loopback_services(monkeypatch, tmp_path):
    # Read only these two dotenv entries. Never load provider credentials.
    lines = []
    with (WORKSPACE / ".env").open(encoding="utf-8-sig") as stream:
        for line in stream:
            if re.match(r"^\s*(?:export\s+)?(?:DATABASE_URL|OPENSEARCH_URL)\s*=", line):
                lines.append(line)
    configured = dotenv_values(stream=io.StringIO("".join(lines)))
    assert set(configured) == {"DATABASE_URL", "OPENSEARCH_URL"}
    assert make_url(configured["DATABASE_URL"]).host in {
        "127.0.0.1",
        "localhost",
        "::1",
    }
    assert urlsplit(configured["OPENSEARCH_URL"]).hostname in {
        "127.0.0.1",
        "localhost",
        "::1",
    }
    for key, value in configured.items():
        monkeypatch.setenv(key, value)
    for key in (
        "DEEPSEEK_API_KEY",
        "SSLKEYLOGFILE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost,::1")
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    # case_environment consumes JSONL, one compact object per line.
    (knowledge / "knowledge_chunks.jsonl").write_text(
        json.dumps(
            {
                "knowledge_chunk_id": "synthetic-live-only",
                "source": "https://example.test/public",
                "content": "Synthetic local fixture, never retrieved",
                "chunk_metadata": {"version": "synthetic"},
                "embedding": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RAG_DATA_DIRECTORY", str(knowledge))
    original_connect = socket.socket.connect
    blocked = []

    def connect(sock, address):
        if isinstance(address, tuple):
            host = address[0]
            if host != "localhost":
                try:
                    allowed = ip_address(host).is_loopback
                except ValueError:
                    allowed = False
                if not allowed:
                    blocked.append(str(host))
                    raise AssertionError(
                        "non-loopback network prohibited by FREE acceptance"
                    )
        return original_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", connect)

    def no_http(*args, **kwargs):
        pytest.fail("provider HTTP transport prohibited by FREE acceptance")

    async def no_async_http(*args, **kwargs):
        pytest.fail("provider HTTP transport prohibited by FREE acceptance")

    monkeypatch.setattr(httpx.Client, "send", no_http)
    monkeypatch.setattr(httpx.AsyncClient, "send", no_async_http)
    from evidencesoc.config import Settings

    yield Settings(_env_file=None), blocked
    assert not blocked


@pytest.fixture(scope="module")
def portable_source(tmp_path_factory):
    from evals.adapters.analysis_import import verify_analysis_source
    from evals.adapters.analysis_package import (
        export_portable_analysis_package,
        verify_portable_analysis_package,
    )
    from evals.tests.test_analysis_package import anchored_source

    root = tmp_path_factory.mktemp("e-planning-live-source")
    anchor = anchored_source(
        root / "original",
        raw={
            "host": "synthetic-live-host",
            "source_port": 12345,
            "destination_port": 443,
            "message": "合成观测，仅用于免费本地验收。" * 400,
        },
    )
    verify_analysis_source(anchor)
    package = export_portable_analysis_package(anchor, root / "portable")
    digest = package["manifest_sha256"]
    source = verify_portable_analysis_package(root / "portable", digest)
    return source, root / "original" / "agent", root / "portable", digest


def _registration(source):
    from evals.e_planning import build_e_planning_registration
    from evals.tests.test_e_planning_contracts import (
        registration_fixture,
        selection_receipt,
    )

    baseline = registration_fixture()
    selection = selection_receipt()
    for key in selection["selected_sources"][0]:
        selection["selected_sources"][0][key] = source.provenance[key]
        selection["rows"][0][key] = source.provenance[key]
    return build_e_planning_registration(
        selection,
        registration_id=uuid.uuid4().hex,
        source_package_manifest_sha256=source.provenance[
            "source_package_manifest_sha256"
        ],
        epoch_binding=baseline["epoch_binding"],
        budget_source_receipt_sha256=baseline["epoch_binding"]["source_sha256"],
        core_config=baseline["core_config"],
        synthetic=True,
    )


class RecordedFixtureModel:
    """Local deterministic response fixture; ledger explicitly synthetic/zero cost."""

    def __init__(self, ttl=1800):
        self.ledger, self.received, self.ttl = [], [], ttl

    async def structured(self, role, schema, state):
        from evidencesoc.agents.fallback import respond

        assert role == "respond"
        self.received.append(deepcopy(state))
        output = respond(state).model_dump(mode="json")
        plan = output["response_plan"]
        plan["expires_at"] = (
            datetime.fromisoformat(plan["created_at"]) + timedelta(seconds=self.ttl)
        ).isoformat()
        value = schema.model_validate(output)
        self.ledger.append(
            {
                "role": "respond",
                "logical_call_id": "synthetic-live-one-logical",
                "physical_attempt": len(self.ledger) + 1,
                "http_status": 200,
                "raw_response": {"fixture_only": True, "provider_request_made": False},
                "parse_status": "valid",
                "cost_cny": 0.0,
                "usage": {"prompt_tokens": 0, "completion_tokens": 0},
                "evidence_role": "synthetic_recorded_fixture_no_http",
            }
        )
        return value


def _delete_owned(settings, handles):
    from evidencesoc.persistence.event_search import create_opensearch_client

    search = create_opensearch_client(settings.opensearch_url)
    admin = create_engine(
        make_url(settings.database_url).set(database="postgres"),
        isolation_level="AUTOCOMMIT",
    )
    cleanup = []
    try:
        for handle in handles:
            name, index = handle.database_name, handle.index_name
            assert re.fullmatch(r"task13_[0-9a-f]{32}", name)
            assert re.fullmatch(r"security-events-task13-[0-9a-f]{32}", index)
            with admin.connect() as connection:
                exists = connection.execute(
                    text(
                        "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=:name)"
                    ),
                    {"name": name},
                ).scalar_one()
                if exists:
                    connection.exec_driver_sql(f'DROP DATABASE "{name}" WITH (FORCE)')
            index_existed = search.indices.exists(index=index)
            if index_existed:
                search.indices.delete(index=index)
            with admin.connect() as connection:
                absent = not connection.execute(
                    text(
                        "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=:name)"
                    ),
                    {"name": name},
                ).scalar_one()
            no_index = not search.indices.exists(index=index)
            cleanup.append(
                {
                    "database_name": name,
                    "index_name": index,
                    "database_existed_before_owned_cleanup": exists,
                    "index_existed_before_owned_cleanup": index_existed,
                    "database_absent": absent,
                    "index_absent": no_index,
                }
            )
            assert absent and no_index
    finally:
        search.close()
        admin.dispose()
    return cleanup


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ttl,review_operation",
    [
        pytest.param(1800, "read_packet", id="1800"),
        pytest.param(1799, "read_packet", id="1799"),
        pytest.param(1800, "decision", id="synthetic-decision"),
    ],
)
async def test_real_pg_os_planning_pending_reopen_review_and_cleanup(
    monkeypatch, tmp_path, loopback_services, portable_source, ttl, review_operation
):
    from evidencesoc.agents.analysis_import import PlanningAdmission
    from evidencesoc.agents.checkpoint import open_checkpointer
    from evidencesoc.agents.graph import InvestigationWorkflow
    from evidencesoc.agents.services import PostgresWorkflowServices
    from evidencesoc.persistence.database import (
        create_database_engine,
        create_session_factory,
    )
    from evidencesoc.persistence.tables import (
        AgentRunTable,
        ApprovalTable,
        IncidentTable,
        ResponsePlanTable,
    )

    from evals.adapters import e_planning_review as review
    from evals.adapters import e_planning_worker as worker
    from evals.adapters import model_client
    from evals.adapters.environment import case_environment
    from evals.adapters.verification_worker import read_persisted_approval
    from evals.e_planning import planning_requests
    from evals.tests.test_e_planning_journal import open_fixture, register_fixture

    settings, blocked = loopback_services
    source, agent, _package_path, package_hash = portable_source
    source.revalidate()
    registration = _registration(source)
    request = planning_requests(registration)[0]
    journal_path = tmp_path / "synthetic-planning.sqlite"
    _, authority, _ = register_fixture(journal_path, registration)
    journal = open_fixture(journal_path, registration, authority)
    output = tmp_path / "output"
    output.mkdir()
    nonce = uuid.uuid4().hex
    monkeypatch.setenv("TASK13_WORKER_NONCE", nonce)
    monkeypatch.setenv("TASK13_PHASE", "development")
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", request.source_commit)
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(output))
    model = RecordedFixtureModel(ttl)
    handles = []

    @contextmanager
    def owned_case(spec, seed):
        with case_environment(spec, seed) as environment:
            handles.append(environment)
            yield environment

    # Deliberate boundary injection: no real source-export authority, source epoch,
    # campaign budget or PID1 container is claimed by this FREE host acceptance.
    monkeypatch.setattr(
        worker,
        "validate_planning_inputs",
        lambda *args: (
            request,
            source,
            journal,
            tmp_path / "never-opened-budget.sqlite",
        ),
    )
    monkeypatch.setattr(worker, "make_model", lambda *args, **kwargs: model)
    monkeypatch.setattr(worker, "case_environment", owned_case)
    evidence = {
        "schema_version": "task13-e-planning-live-free-acceptance-v1",
        "synthetic": True,
        "ttl": ttl,
        "review_operation": review_operation,
        "worker_nonce_sha256": sha256(nonce.encode()).hexdigest(),
        "provider_requests": 0,
        "user_decisions": 0,
        "synthetic_fixture_decisions": 0,
        "source_package_manifest_sha256": package_hash,
        "source_identity": source.source_identity,
        "registration_sha256": canonical_hash(registration),
        "planning_slot_id": request.planning_slot_id,
        "bypassed": [
            "container_PID1",
            "current_execution_source_export",
            "original_budget_epoch_preflight",
            "review_clock_window",
            "review_source_budget_epoch_preflight",
        ],
        "unmocked": [
            "portable_source_verifier",
            "dispatch_journal",
            "case_environment",
            "service_probe",
            "PostgresWorkflowServices",
            "PostgreSQL_checkpointer",
            "product_graph",
            "actual_persisted_rows",
            "resource_cleanup",
        ],
    }
    try:
        result = await worker.run_e_planning(request, agent)
        evidence["worker_result"] = result.model_dump(mode="json")
        assert len(handles) == 1
        environment = handles[0]
        assert result.isolation_evidence["service_probe"]["status"] == "passed"
        if ttl != 1800:
            assert result.execution_status == "failed"
            assert not environment.retained
            assert result.verification is None
            return
        assert result.execution_status == "completed", result.errors
        assert environment.retained and result.product_status == "awaiting_approval"
        reference = result.verification["case_reference"]
        state = json.loads(
            (output / "investigation-state.json").read_text(encoding="utf-8")
        )
        actual_db = (
            make_url(settings.database_url)
            .set(database=reference["database_name"])
            .render_as_string(hide_password=False)
        )
        engine = create_database_engine(actual_db)
        sessions = create_session_factory(engine)
        try:
            with sessions() as session:
                plans = session.scalars(
                    select(ResponsePlanTable).where(
                        ResponsePlanTable.incident_id == request.incident_id
                    )
                ).all()
                assert len(plans) == 1
                plan = plans[0]
                assert (plan.expires_at - plan.created_at).total_seconds() == 1800
                assert (
                    session.get(IncidentTable, request.incident_id).status
                    == "awaiting_approval"
                )
                roles = session.scalars(
                    select(AgentRunTable.agent_name).where(
                        AgentRunTable.incident_id == request.incident_id
                    )
                ).all()
                assert sorted(roles) == ["analysis_import", "respond"]
                evidence["persisted"] = {
                    "roles": roles,
                    "plan_id": plan.response_plan_id,
                    "ttl_seconds": 1800,
                }
            bound = worker._claim_binding(request, journal.validate_request(request))
            admission = PlanningAdmission._from_existing_claim(
                bound,
                lambda: worker._claim_binding(
                    request, journal.validate_request(request)
                ),
            )
            services = PostgresWorkflowServices(
                environment.settings, session_factory=sessions
            )
            try:
                hydrated = await services.hydrate_evidence(
                    request.incident_id, source.product_values()["evidence"]
                )
                assert len(hydrated[0]["raw"]["message"].encode()) > 2048
                assert (
                    len(
                        source.product_values()["evidence"][0]["raw"][
                            "message"
                        ].encode()
                    )
                    <= 2048
                )
                assert hydrated[0]["raw"]["source_port"] == 12345
                with pytest.raises(PermissionError, match="not owned"):
                    await services.hydrate_evidence(
                        "IN-unregistered-fixture", source.product_values()["evidence"]
                    )
                assert (
                    model.received[0]["knowledge"]
                    == source.product_values()["knowledge"]
                )
                evidence["hydrate"] = {
                    "full_message_bytes": len(hydrated[0]["raw"]["message"].encode()),
                    "model_seed_message_bytes": len(
                        source.product_values()["evidence"][0]["raw"][
                            "message"
                        ].encode()
                    ),
                    "persisted_extra_source_port": 12345,
                    "foreign_incident_rejected": True,
                }
                before_calls = len(model.ledger)
                async with open_checkpointer(actual_db) as checkpointer:
                    flow = InvestigationWorkflow.for_analysis_import(
                        imported_analysis=source,
                        planning_admission=admission,
                        services=services,
                        settings=environment.settings,
                        checkpointer=checkpointer,
                        model=model,
                        database_url=actual_db,
                    )
                    reopened = await flow.import_analysis(request.incident_id, source)
                    snapshot = await flow.graph.aget_state(
                        flow._config(request.incident_id)
                    )
                    with sessions() as session:
                        worker.validate_persisted_pending(
                            snapshot,
                            session.get(ResponsePlanTable, plan.response_plan_id),
                            session.get(IncidentTable, request.incident_id),
                            state["analysis_import_provenance"],
                        )
                    assert reopened == state and len(model.ledger) == before_calls
                evidence["reopen"] = {
                    "state_sha256": canonical_hash(reopened),
                    "additional_respond_calls": len(model.ledger) - before_calls,
                    "next": list(snapshot.next),
                }
            finally:
                await services.aclose()
        finally:
            engine.dispose()
        operation = review.build_review_request(
            request, reference, operation="read_packet"
        )
        review_output = tmp_path / "review-output"
        review_output.mkdir()
        monkeypatch.setenv("TASK13_PHASE", "verification")
        monkeypatch.setenv("TASK13_OUTPUT_DIR", str(review_output))
        monkeypatch.setattr(review.os, "getpid", lambda: 1)
        window_checks = []

        def injected_review_window(now=None):
            window_checks.append(now.isoformat() if now is not None else "clock")

        monkeypatch.setattr(review, "require_review_window", injected_review_window)

        def no_review_model(*args, **kwargs):
            pytest.fail("zero-model review constructed an account/model")

        for name in ("BudgetAccount", "TrackedModel"):
            monkeypatch.setattr(
                getattr(model_client, name), "__init__", no_review_model
            )
        monkeypatch.setattr(
            review,
            "validate_review_inputs",
            lambda *args: (
                operation,
                source,
                bound,
                lambda: worker._claim_binding(
                    request, journal.validate_request(request)
                ),
            ),
        )
        reviewed = await review.run_e_planning_review(operation, agent)
        evidence["review_result"] = reviewed
        assert reviewed["status"] == "completed", reviewed.get("error_type")
        assert reviewed["model_ledger"] == [] and reviewed["tool_ledger"] == []
        assert reviewed["approval_receipt"] is None
        assert reviewed["source"]["state"] == state
        engine = create_database_engine(actual_db)
        try:
            with create_session_factory(engine)() as session:
                assert session.scalars(select(ApprovalTable)).all() == []
        finally:
            engine.dispose()
        if review_operation == "decision":
            decision = review.build_review_request(
                request,
                reference,
                operation="decision",
                packet=reviewed["approval_packet"],
                decision="approved",
                reason="SYNTHETIC FREE acceptance only; no real user approval or trial/F8 credit",
            )
            decision_output = tmp_path / "synthetic-decision-output"
            decision_output.mkdir()
            monkeypatch.setenv("TASK13_OUTPUT_DIR", str(decision_output))
            monkeypatch.setattr(
                review,
                "validate_review_inputs",
                lambda *args: (
                    decision,
                    source,
                    bound,
                    lambda: worker._claim_binding(
                        request, journal.validate_request(request)
                    ),
                ),
            )
            decided = await review.run_e_planning_review(decision, agent)
            evidence["decision_result"] = decided
            decided_state = json.loads(
                (decision_output / "source-review-state.json").read_text(
                    encoding="utf-8"
                )
            )
            original_fields = [
                *source.product_values(),
                "analysis_import_provenance",
                "diagnostic_snapshot",
                "diagnostic_snapshot_sha256",
                "response_plan",
            ]
            preserved = {
                key: decided_state.get(key) == state.get(key) for key in original_fields
            }
            engine = create_database_engine(actual_db)
            try:
                sessions = create_session_factory(engine)
                actual_receipt = read_persisted_approval(decided_state, sessions)
                with sessions() as session:
                    approvals = session.scalars(select(ApprovalTable)).all()
                    roles = session.scalars(
                        select(AgentRunTable.agent_name).where(
                            AgentRunTable.incident_id == request.incident_id
                        )
                    ).all()
                    evidence["actual_decision_persistence"] = {
                        "approval_rows": len(approvals),
                        "approval_id": approvals[0].approval_id if approvals else None,
                        "decision": approvals[0].decision if approvals else None,
                        "decided_at": approvals[0].decided_at.isoformat()
                        if approvals
                        else None,
                        "incident_status": session.get(
                            IncidentTable, request.incident_id
                        ).status,
                        "agent_roles": roles,
                        "receipt": actual_receipt,
                    }
                    assert len(approvals) == 1
                    approval = approvals[0]
                    assert approval.decision == "approved"
                    assert approval.reason == decision.reason
                    assert (
                        approval.decided_by == "user"
                    )  # Original API contract, fixture only.
                    assert (
                        approval.approval_id == decided_state["approval"]["approval_id"]
                    )
                    assert approval.decided_at.tzinfo is not None
                    assert (
                        session.get(IncidentTable, request.incident_id).status
                        == decided_state["status"]
                    )
            finally:
                engine.dispose()
            evidence["synthetic_fixture_decisions"] = 1
            evidence["decision_invariants"] = {
                "preserved_original_fields": preserved,
                "pending_original_sha256": canonical_hash(
                    {key: state.get(key) for key in original_fields}
                ),
                "decided_original_sha256": canonical_hash(
                    {key: decided_state.get(key) for key in original_fields}
                ),
                "additional_respond_calls": len(model.ledger) - before_calls,
                "pending_evidence_count": len(state["evidence"]),
                "decided_evidence_count": len(decided_state["evidence"]),
                "window_checks_injected": window_checks,
                "verification_status": decided_state.get("verification_status"),
                "verification_call_count": decided_state.get("verification_call_count"),
                "simulation_execution": decided_state.get("simulation_execution"),
            }
            assert decided["status"] == "completed", decided.get("error_type")
            assert decided["approval_receipt"] == actual_receipt
            assert actual_receipt["status"] == "verified"
            assert actual_receipt["source"] == "original_product_database"
            assert all(preserved.values()), preserved
            assert decided["model_ledger"] == [] and decided["tool_ledger"] == []
            assert sorted(roles) == ["analysis_import", "respond", "validate"]
            assert decided_state["verification_status"] == "unverified"
            assert decided_state["verification_call_count"] == 0
            assert decided_state["validation_result"] is None
            assert decided_state["status"] == "completed"
            assert decided_state["simulation_execution"]["status"] == "completed"
            approval_time = datetime.fromisoformat(
                decided_state["approval"]["decided_at"].replace("Z", "+00:00")
            )
            assert approval_time in [
                datetime.fromisoformat(value)
                for value in window_checks
                if value != "clock"
            ]
            assert "DEEPSEEK_API_KEY" not in os.environ
        assert len(model.ledger) == 1
        assert not blocked
        assert not (tmp_path / "never-opened-budget.sqlite").exists()
    finally:
        evidence["cleanup"] = _delete_owned(settings, handles)
        evidence["fixture_containers_created"] = []
        evidence_path = Path(
            os.environ.get("TASK13_LIVE_EVIDENCE_DIR", str(tmp_path))
        ) / (
            "e-planning-live-services-synthetic-decision-20261026.json"
            if review_operation == "decision"
            else f"e-planning-live-services-ttl{ttl}.json"
        )
        _json(evidence_path, evidence)
        if ttl != 1800:
            # Do not let our explicit success-case cleanup mask a production
            # failure to automatically remove the rejected TTL case.
            assert all(
                not item["database_existed_before_owned_cleanup"]
                and not item["index_existed_before_owned_cleanup"]
                for item in evidence["cleanup"]
            )
