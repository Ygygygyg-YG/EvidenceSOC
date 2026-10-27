"""FREE real-service no-plan acceptance; all model bytes are synthetic fixtures.

Run explicitly against the loopback PostgreSQL/OpenSearch services. Source/PID1/
budget-epoch preflight is injected, while the source verifier, dispatch claim,
MCP probe, graph, PostgreSQL checkpoint and persistence and cleanup are real.
These tests cannot count as actual user approval or E timing evidence.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest
from sqlalchemy import select

from evals.contracts import canonical_hash
from evals.tests.test_e_planning_live_services import (
    WORKSPACE,
    _delete_owned,
    _json,
    _registration,
    loopback_services,  # noqa: F401 -- imported pytest fixture
    portable_source,  # noqa: F401 -- imported pytest fixture
)


class RecordedNullModel:
    """One locally recorded response and body, never an HTTP client or account."""

    def __init__(self, reason_mode):
        self.reason_mode = reason_mode
        self.ledger, self.received = [], []
        self.recorder = None

    async def structured(self, role, schema, state):
        assert role == "respond"
        assert not self.ledger, "a valid null must not trigger a second model call"
        self.received.append(deepcopy(state))
        output = {"response_plan": None}
        if self.reason_mode == "provided":
            output["no_plan_reason"] = "合成模型声明：没有可追溯的安全候选。"
        elif self.reason_mode == "blank":
            output["no_plan_reason"] = "  "
        raw_content = json.dumps(output, ensure_ascii=False)
        payload = {
            "model": "synthetic-recorded-null-no-provider",
            "messages": [
                {
                    "role": "user",
                    "content": json.dumps(state, ensure_ascii=False, default=str),
                }
            ],
        }
        body = json.dumps(payload, ensure_ascii=False).encode()
        physical_id = "synthetic-live-null-physical-" + uuid.uuid4().hex
        self.ledger.append(
            {
                "role": role,
                "logical_call_id": "synthetic-live-null-logical",
                "request_id": "synthetic-live-null-provider-id",
                "request_ordinal": 1,
                "physical_request_id": physical_id,
                "physical_attempt": 1,
                "http_status": 200,
                "raw_response": {
                    "choices": [
                        {"finish_reason": "stop", "message": {"content": raw_content}}
                    ]
                },
                "request_sha256": canonical_hash(payload),
                "parse_status": "valid",
                "cost_cny": 0.0,
                "usage": {"prompt_tokens": 0, "completion_tokens": 0},
                "evidence_role": "synthetic_recorded_fixture_no_http",
                "provider_request_made": False,
            }
        )
        self.recorder(
            {
                "physical_request_id": physical_id,
                "payload": payload,
                "http_body": body,
                "http_body_sha256": sha256(body).hexdigest(),
            }
        )
        return schema.model_validate(output)


@pytest.mark.asyncio
@pytest.mark.parametrize("reason_mode", ["missing", "provided", "blank"])
async def test_real_pg_os_no_plan_persistence_and_automatic_cleanup(
    monkeypatch,
    tmp_path,
    loopback_services,  # noqa: F811 -- pytest injects imported fixture
    portable_source,  # noqa: F811 -- pytest injects imported fixture
    reason_mode,
):
    from evidencesoc.persistence.tables import (
        AgentRunTable,
        ApprovalTable,
        IncidentTable,
        ResponsePlanTable,
    )

    from evals.adapters import e_planning_worker as worker
    from evals.adapters.environment import case_environment
    from evals.e_planning import planning_requests
    from evals.tests.test_e_planning_journal import open_fixture, register_fixture

    settings, blocked = loopback_services
    source, agent, _package, manifest_hash = portable_source
    source.revalidate()
    registration = _registration(source)
    request = planning_requests(registration)[0]
    journal_path = tmp_path / "synthetic-no-plan.sqlite"
    _, authority, _ = register_fixture(journal_path, registration)
    journal = open_fixture(journal_path, registration, authority)
    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setenv("TASK13_WORKER_NONCE", uuid.uuid4().hex)
    monkeypatch.setenv("TASK13_PHASE", "development")
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", request.source_commit)
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(output))
    model = RecordedNullModel(reason_mode)
    handles, persisted = [], []
    budget_attempts = []
    actual_budget = (WORKSPACE / "data/task13/budget/campaign.sqlite").resolve()
    original_connect = sqlite3.connect

    def no_actual_budget(database, *args, **kwargs):
        value = os.fspath(database)
        # The journal remains a real SQLite database in this unique tmp_path.
        if "campaign.sqlite" in value or (
            not value.startswith("file:") and Path(value).resolve() == actual_budget
        ):
            budget_attempts.append("actual_campaign_budget")
            raise AssertionError("actual campaign budget prohibited by FREE acceptance")
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", no_actual_budget)

    @contextmanager
    def owned_case(spec, seed):
        with case_environment(spec, seed) as environment:
            handles.append(environment)
            yield environment

    original_persisted_no_plan = worker._persisted_no_plan

    def observe_persisted_no_plan(environment, snapshot):
        # Run the original guard against its actual graph snapshot and rows.
        state = original_persisted_no_plan(environment, snapshot)
        with environment.sessions() as session:
            plans = session.scalars(select(ResponsePlanTable)).all()
            approvals = session.scalars(select(ApprovalTable)).all()
            runs = session.scalars(select(AgentRunTable)).all()
            incident = session.get(IncidentTable, request.incident_id)
            record = {
                "checkpoint_next": list(snapshot.next),
                "incident_status": incident.status,
                "response_plan_rows": len(plans),
                "approval_rows": len(approvals),
                "agent_runs": [
                    {
                        "agent_name": run.agent_name,
                        "status": run.status,
                        "output_summary": run.output_summary,
                    }
                    for run in runs
                ],
            }
        persisted.append(record)
        assert record["checkpoint_next"] == []
        assert record["incident_status"] == "manual_review"
        assert record["response_plan_rows"] == record["approval_rows"] == 0
        assert sorted(run["agent_name"] for run in record["agent_runs"]) == [
            "analysis_import",
            "respond",
        ]
        respond = next(run for run in runs if run.agent_name == "respond")
        assert respond.status == "completed"
        expected = (
            "合成模型声明：没有可追溯的安全候选。"
            if reason_mode == "provided"
            else None
        )
        assert respond.output_summary["no_plan_reason"] == expected
        assert respond.output_summary["no_plan_reason_missing"] is (expected is None)
        return state

    def make_fixture_model(*args, **kwargs):
        model.recorder = kwargs["payload_sink"]
        return model

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
    monkeypatch.setattr(worker, "make_model", make_fixture_model)
    monkeypatch.setattr(worker, "case_environment", owned_case)
    monkeypatch.setattr(worker, "_persisted_no_plan", observe_persisted_no_plan)
    evidence = {
        "schema_version": "task13-e-planning-live-no-plan-free-acceptance-v1",
        "synthetic": True,
        "reason_mode": reason_mode,
        "provider_requests": 0,
        "paid_cost_cny": 0,
        "actual_user_decisions": 0,
        "actual_timing_credit": 0,
        "source_package_manifest_sha256": manifest_hash,
        "source_identity": source.source_identity,
        "registration_sha256": canonical_hash(registration),
        "planning_slot_id": request.planning_slot_id,
        "bypassed": [
            "container_PID1",
            "current_execution_source_export",
            "original_budget_epoch_preflight",
        ],
        "unmocked": [
            "portable_source_verifier",
            "dispatch_journal",
            "case_environment",
            "service_probe_and_MCP",
            "PostgresWorkflowServices",
            "PostgreSQL_checkpointer",
            "product_graph",
            "actual_persisted_rows",
            "persisted_no_plan_guard",
            "static_no_plan_raw_payload_verification",
            "resource_cleanup",
        ],
    }
    try:
        result = await worker.run_e_planning(request, agent)
        evidence["worker_result"] = result.model_dump(mode="json")
        evidence["persisted"] = persisted
        assert result.execution_status == "completed", result.errors
        assert result.diagnosis_status == "succeeded"
        assert result.product_status == "manual_review"
        assert result.errors == []
        assert result.verification["status"] == "no_plan"
        assert result.verification["timing_eligible"] is False
        assert result.verification["no_plan_reason_missing"] is (
            reason_mode != "provided"
        )
        assert result.isolation_evidence["service_probe"]["status"] == "passed"
        assert len(handles) == len(persisted) == len(model.ledger) == 1
        assert not handles[0].retained
        assert not (output / "case-resource.json").exists()
        state = json.loads((output / "investigation-state.json").read_text("utf-8"))
        assert state["response_plan"] is None and state["approval"] is None
        assert state["response_reason"] == "model_returned_null"
        assert state["errors"] == []
        assert len(state["response_attempts"]) == 1
        assert state["response_attempts"][0]["status"] == "valid"
        assert source.product_values()["knowledge"] == model.received[0]["knowledge"]
        assert journal.validate_request(request)["status"] == "started"
        assert (output / "model-ledger.json").is_file()
        assert (output / "model-payloads.json").is_file()
        assert not (tmp_path / "never-opened-budget.sqlite").exists()
        assert "DEEPSEEK_API_KEY" not in os.environ
        assert not blocked and not budget_attempts
    finally:
        # This independent check records existence BEFORE any fallback cleanup.
        # No successful test can hide missing automatic worker cleanup.
        evidence["cleanup"] = _delete_owned(settings, handles)
        evidence["fixture_containers_created"] = []
        evidence["actual_budget_open_attempts"] = budget_attempts
        evidence_path = (
            Path(os.environ.get("TASK13_LIVE_EVIDENCE_DIR", str(tmp_path)))
            / f"e-planning-live-no-plan-{reason_mode}.json"
        )
        _json(evidence_path, evidence)
        assert all(
            not item["database_existed_before_owned_cleanup"]
            and not item["index_existed_before_owned_cleanup"]
            and item["database_absent"]
            and item["index_absent"]
            for item in evidence["cleanup"]
        )
