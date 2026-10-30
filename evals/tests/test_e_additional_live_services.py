"""FREE synthetic additional-source -> real PG/OS -> fixture decision acceptance.

The initial additional analysis uses synthetic case services and a synthetic
service probe, with actual model/account wrappers and MockTransport. Subsequent
planning/review/decision use real PG/OS, probe, graph/checkpointer and persistence;
their source/package/account/journal preflight is real with host PID1 simulated.
Planning also uses actual model/account wrappers with MockTransport. No real
user approval or timing/F8 credit is produced.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import uuid
from contextlib import contextmanager
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import url2pathname

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.engine import make_url

from evals.contracts import canonical_hash


@pytest.fixture
def additional_loopback_services(monkeypatch, tmp_path):
    """Require explicit service-only configuration; never load an env file."""
    configured = {
        key: os.environ.get(key) for key in ("DATABASE_URL", "OPENSEARCH_URL")
    }
    assert all(configured.values()), "explicit DATABASE_URL and OPENSEARCH_URL required"
    database = make_url(configured["DATABASE_URL"])
    search = urlsplit(configured["OPENSEARCH_URL"])
    loopback = {"127.0.0.1", "localhost", "::1"}
    assert database.get_backend_name() == "postgresql" and database.host in loopback
    assert search.hostname in loopback and search.port == 9201
    for key in (
        "DEEPSEEK_API_KEY",
        "SSLKEYLOGFILE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost,::1")

    knowledge = tmp_path / "synthetic-knowledge"
    knowledge.mkdir()
    (knowledge / "knowledge_chunks.jsonl").write_text(
        json.dumps(
            {
                "knowledge_chunk_id": "synthetic-additional-live-only",
                "source": "https://example.test/public",
                "content": "Synthetic background; no retrieval in this disabled-RAG test.",
                "chunk_metadata": {"version": "synthetic"},
                "embedding": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RAG_DATA_DIRECTORY", str(knowledge))
    blocked = []

    def require_loopback(host):
        if isinstance(host, bytes):
            host = host.decode("ascii")
        try:
            allowed = host == "localhost" or ip_address(host).is_loopback
        except ValueError:
            allowed = False
        if not allowed:
            blocked.append("non-loopback")
            pytest.fail("FREE acceptance prohibits non-loopback socket/DNS access")

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_getaddrinfo = socket.getaddrinfo

    def connect(sock, address):
        if isinstance(address, tuple):
            require_loopback(address[0])
        return original_connect(sock, address)

    def connect_ex(sock, address):
        if isinstance(address, tuple):
            require_loopback(address[0])
        return original_connect_ex(sock, address)

    def getaddrinfo(host, *args, **kwargs):
        if host is not None:
            require_loopback(host)
        return original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    real_send, real_async_send = httpx.Client.send, httpx.AsyncClient.send

    def mock_only(client, *args, **kwargs):
        assert isinstance(client._transport, httpx.MockTransport), (
            "real HTTP prohibited"
        )
        return real_send(client, *args, **kwargs)

    async def async_mock_only(client, *args, **kwargs):
        assert isinstance(client._transport, httpx.MockTransport), (
            "real HTTP prohibited"
        )
        return await real_async_send(client, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "send", mock_only)
    monkeypatch.setattr(httpx.AsyncClient, "send", async_mock_only)

    # Every SQLite account/journal must be this invocation's temporary fixture.
    # This blocks reads as well as writes to the real campaign account.
    real_sqlite_connect = sqlite3.connect
    sqlite_paths = set()

    def temp_sqlite_only(database, *args, **kwargs):
        location = os.fspath(database)
        if location != ":memory:":
            if location.startswith("file:"):
                location = url2pathname(urlsplit(location).path)
            path = Path(location).resolve()
            assert path.is_relative_to(tmp_path.resolve()), "non-TEMP SQLite prohibited"
            sqlite_paths.add(path)
        return real_sqlite_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", temp_sqlite_only)
    from evidencesoc.config import Settings

    yield Settings(_env_file=None), blocked, sqlite_paths
    assert not blocked
    assert all(path.is_relative_to(tmp_path.resolve()) for path in sqlite_paths)


@pytest.mark.asyncio
async def test_additional_source_real_pg_os_pending_review_decision_and_cleanup(
    tmp_path, monkeypatch, additional_loopback_services
):
    from evidencesoc.agents.fallback import respond
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
    from evals.adapters.environment import case_environment
    from evals.adapters.model_identity_runtime import verify_identity_ledger
    from evals.adapters.verification_worker import read_persisted_approval
    from evals.e_planning import planning_requests
    from evals.e_timing import ETimingCampaign, build_e_timing_registration
    from evals.tests.test_e_additional_selection import actual_fixture
    from evals.tests.test_e_planning_journal import register_fixture
    from evals.tests.test_e_planning_live_services import _delete_owned

    # Keep the real window policy: no clock injection or widened decision window.
    review.require_review_window()
    settings, blocked, sqlite_paths = additional_loopback_services
    host_pid, real_model_factory = os.getpid(), worker.make_model
    original, package, imported, _selection, registration = await actual_fixture(
        tmp_path, monkeypatch
    )
    assert (
        registration["synthetic"] is True
        and imported.provenance["source_synthetic"] is True
    )
    assert original.budget.resolve().is_relative_to(tmp_path.resolve())
    request = planning_requests(registration)[0]
    agent = original.paths["events"].parent

    # A TEMP synthetic host scope registers the journal before simulated PID1.
    monkeypatch.delenv("TASK13_WORKER_NONCE", raising=False)
    monkeypatch.setattr(os, "getpid", lambda: host_pid)
    journal_path = tmp_path / "dispatch/e-planning.sqlite"
    journal_path.parent.mkdir()
    _, authority, dispatch = register_fixture(journal_path, registration)
    monkeypatch.setattr(os, "getpid", lambda: 1)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-additional-live-only")
    monkeypatch.setenv("TASK13_IMPORT_DISPATCH_DB", str(journal_path))
    monkeypatch.setenv("TASK13_IMPORT_AUTHORITY_SHA256", canonical_hash(authority))
    monkeypatch.setenv("TASK13_IMPORT_SOURCE_DIR", str(package))
    monkeypatch.delenv("TASK13_EPOCH_HOST_BUDGET_PATH", raising=False)
    monkeypatch.delenv("TASK13_IMPORT_HOST_JOURNAL_PATH", raising=False)
    monkeypatch.setenv("TASK13_PHASE", "development")
    output = tmp_path / "planning-output"
    output.mkdir()
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(output))
    models, sent, handles = [], [], []

    def reply(http_request):
        payload = json.loads(http_request.content)
        sent.append(payload)
        context = json.loads(payload["messages"][-1]["content"])
        answer = respond(context).model_dump(mode="json")
        assert answer["response_plan"] is not None
        return httpx.Response(
            200,
            json={
                "id": "synthetic-additional-live-response",
                "model": "approved",
                "system_fingerprint": "approved-fp",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(answer)},
                    }
                ],
            },
        )

    def tracked_model(*args, **kwargs):
        model = real_model_factory(
            *args, transport=httpx.MockTransport(reply), **kwargs
        )
        models.append(model)
        return model

    @contextmanager
    def owned_case(spec, seed):
        with case_environment(spec, seed) as environment:
            handles.append(environment)
            yield environment

    monkeypatch.setattr(worker, "make_model", tracked_model)
    monkeypatch.setattr(worker, "case_environment", owned_case)
    evidence = {
        "schema_version": "task13-additional-live-services-free-v1",
        "synthetic": True,
        "provider_requests": 0,
        "real_user_decisions": 0,
        "synthetic_fixture_decisions": 0,
        "real_timing_credit": False,
        "source_package_manifest_sha256": request.source_package_manifest_sha256,
        "source_registration_sha256": request.source.source_registration_sha256,
        "registration_sha256": canonical_hash(registration),
        "planning_slot_id": request.planning_slot_id,
        "injected": [
            "host_PID1_simulation",
            "model_HTTP_MockTransport",
            "synthetic_raw_analysis_fixture",
            "initial_analysis_case_environment_and_service_probe_synthetic",
        ],
    }
    try:
        # Intentionally do not replace validate_planning_inputs or the probe.
        result = await worker.run_e_planning(request, agent)
        assert result.execution_status == "completed", result.errors
        assert result.product_status == "awaiting_approval"
        assert result.isolation_evidence["service_probe"]["status"] == "passed"
        assert len(handles) == len(models) == len(sent) == 1
        environment = handles[0]
        assert environment.retained
        assert (
            len(result.model_ledger) == 1
            and result.model_ledger[0]["role"] == "respond"
        )
        verify_identity_ledger(original.budget, request, result.model_ledger)
        reference = result.verification["case_reference"]
        pending = json.loads((output / "investigation-state.json").read_bytes())
        assert (
            pending["status"] == "awaiting_approval"
            and pending["response_plan"]["actions"]
        )
        assert pending["plan_source"] == "model" and not pending.get("fallback_used")
        assert (
            pending["analysis_import_provenance"]["source_kind"]
            == "additional-development-v1"
        )
        evidence["planning"] = {
            "case_reference": reference,
            "plan_sha256": canonical_hash(pending["response_plan"]),
            "snapshot_sha256": pending["diagnostic_snapshot_sha256"],
            "service_probe": result.isolation_evidence["service_probe"],
            "physical_model_attempts": len(result.model_ledger),
        }
        actual_db = (
            make_url(settings.database_url)
            .set(database=reference["database_name"])
            .render_as_string(hide_password=False)
        )
        engine = create_database_engine(actual_db)
        try:
            sessions = create_session_factory(engine)
            with sessions() as session:
                assert (
                    session.get(IncidentTable, request.incident_id).status
                    == "awaiting_approval"
                )
                plans = session.scalars(select(ResponsePlanTable)).all()
                assert len(plans) == 1
                assert (
                    plans[0].expires_at - plans[0].created_at
                ).total_seconds() == 1800
                assert session.scalars(select(ApprovalTable)).all() == []
                roles = session.scalars(
                    select(AgentRunTable.agent_name).where(
                        AgentRunTable.incident_id == request.incident_id
                    )
                ).all()
                assert sorted(roles) == ["analysis_import", "respond"]
        finally:
            engine.dispose()

        # Actual source/account/journal review admission, with zero model calls.
        budget_before_review = original.budget.read_bytes()
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.setenv("TASK13_PHASE", "verification")
        read_output = tmp_path / "read-output"
        read_output.mkdir()
        monkeypatch.setenv("TASK13_OUTPUT_DIR", str(read_output))
        read_request = review.build_review_request(
            request, reference, operation="read_packet"
        )
        read = await review.run_e_planning_review(read_request, agent)
        assert read["status"] == "completed", read.get("error_type")
        assert read["source"]["state"] == pending and read["approval_receipt"] is None
        assert read["model_ledger"] == read["tool_ledger"] == []

        decision_output = tmp_path / "synthetic-decision-output"
        decision_output.mkdir()
        monkeypatch.setenv("TASK13_OUTPUT_DIR", str(decision_output))
        decision = review.build_review_request(
            request,
            reference,
            operation="decision",
            packet=read["approval_packet"],
            decision="approved",
            reason="SYNTHETIC FREE fixture only; no real user approval, E timing or F8 credit",
        )
        decided = await review.run_e_planning_review(decision, agent)
        assert decided["status"] == "completed", decided.get("error_type")
        assert decided["model_ledger"] == decided["tool_ledger"] == []
        approved = decided["source"]["state"]
        assert approved["approval"]["decision"] == "approved"
        assert (
            approved["verification_status"] == "unverified"
            and approved["verification_call_count"] == 0
        )
        assert approved["simulation_execution"]["status"] == "completed"
        for field in (
            "response_plan",
            "diagnostic_snapshot",
            "diagnostic_snapshot_sha256",
            "analysis_import_provenance",
        ):
            assert approved[field] == pending[field]
        engine = create_database_engine(actual_db)
        try:
            sessions = create_session_factory(engine)
            receipt = read_persisted_approval(approved, sessions)
            assert (
                receipt == decided["approval_receipt"]
                and receipt["status"] == "verified"
            )
            with sessions() as session:
                approvals = session.scalars(select(ApprovalTable)).all()
                assert len(approvals) == 1 and approvals[0].reason == decision.reason
                assert approvals[0].approval_id == approved["approval"]["approval_id"]
        finally:
            engine.dispose()
        assert original.budget.read_bytes() == budget_before_review
        assert len(models) == len(sent) == 1 and len(models[0].ledger) == 1
        evidence["synthetic_fixture_decisions"] = 1
        evidence["approval_receipt"] = receipt

        # Exercise source admission only; never dispatch a branch or record timing.
        test_file = Path(__file__).resolve()
        timing_registration = build_e_timing_registration(
            registration,
            source_files={str(test_file): sha256(test_file.read_bytes()).hexdigest()},
            f8_plan_sha256="f" * 64,
            planning_dispatch_registration_receipt=dispatch,
        )
        timing = ETimingCampaign(
            timing_registration, tmp_path / "synthetic-timing-admission"
        )
        timing_source = {
            **{
                key: timing.identity[key]
                for key in (
                    "campaign_id",
                    "source_commit",
                    "source_sha256",
                    "config_sha256",
                )
            },
            "source_row_id": request.source_row_id,
            "case_id": request.case_id,
            "dataset": request.dataset,
            "analysis_manifest_sha256": request.original_manifest_sha256,
            "budget_source_receipt_sha256": request.budget_source_receipt_sha256,
            "planning_request": request.model_dump(mode="json"),
            "state": approved,
            "retained_state": pending,
            "retained_state_sha256": canonical_hash(pending),
            "resources": reference,
            "resources_sha256": canonical_hash(reference),
        }
        assert timing._source(request.trial_id, timing_source)[
            "planning_request"
        ] == request.model_dump(mode="json")
        progress = timing.snapshot()
        assert progress["synthetic"] is True and progress["formal_admissible"] is False
        assert progress["complete_observed_trials"] == 0
        assert all(row["status"] == "not_started" for row in progress["records"])
        assert all(trial["status"] == "not_started" for trial in progress["trials"])
        evidence["timing_admission"] = {
            "accepted": True,
            "completed_trials": 0,
            "branches_dispatched": 0,
            "formal_admissible": False,
        }
        assert not blocked and sqlite_paths
    finally:
        evidence["cleanup"] = _delete_owned(settings, handles)
        assert all(
            row["database_absent"] and row["index_absent"]
            for row in evidence["cleanup"]
        )
        evidence_bytes = json.dumps(
            evidence, ensure_ascii=False, sort_keys=True, indent=2
        ).encode()
        (tmp_path / "additional-live-services-evidence.json").write_bytes(
            evidence_bytes
        )
        retained_evidence = os.environ.get("TASK13_LIVE_EVIDENCE_DIR")
        if retained_evidence:
            directory = Path(retained_evidence)
            directory.mkdir(parents=True, exist_ok=True)
            with (directory / f"additional-live-{uuid.uuid4().hex}.json").open(
                "xb"
            ) as stream:
                stream.write(evidence_bytes)
