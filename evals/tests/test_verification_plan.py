"""Synthetic contract fixtures only; these tests never create human approvals."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from importlib import import_module

import pytest

from evals.contracts import canonical_hash
from evals.tests.test_verification_observations import approved_fixture


def cases():
    return [
        {
            "dataset": dataset,
            "case_id": dataset + "-" + f"{index:024x}",
            "agent_sha256": "c" * 64,
        }
        for dataset, count in (("ait", 22), ("dedale", 66))
        for index in range(count)
    ]


def fixture_source():
    state, _ = approved_fixture()
    state["diagnosis_execution_status"] = "completed"
    return {
        "state": state,
        "resources": {
            "database_name": "task13_" + "a" * 32,
            "index_name": "security-events-task13-" + "a" * 32,
        },
    }


def persisted_receipt(state):
    return {
        "status": "verified",
        "source": "original_product_database",
        "state_sha256": canonical_hash(state),
        "approval_sha256": canonical_hash(state["approval"]),
        "plan_sha256": state["approved_plan_sha256"],
        "plan_version": state["approved_plan_version"],
    }


def test_plan_retains_88_cases_three_conditions_and_528_independent_branches():
    module = import_module("evals.verification")
    plan = module.build_verification_plan(cases())
    assert plan["planned_pairs"] == len(plan["slots"]) == 264
    assert plan["planned_branches"] == 528
    assert {slot["condition"] for slot in plan["slots"]} == {
        "success",
        "failure",
        "no_change",
    }
    namespaces = [
        item["namespace"] for slot in plan["slots"] for item in slot["branches"]
    ]
    assert len(set(namespaces)) == 528
    assert all(len(value) == 32 for value in namespaces)
    assert {slot["case_id"] for slot in plan["slots"]} == {
        row["case_id"] for row in cases()
    }
    with pytest.raises(ValueError, match="22|66|88"):
        module.build_verification_plan(cases()[:-1])


@pytest.mark.asyncio
async def test_missing_failed_unknown_and_benign_states_are_retained_without_dispatch(
    tmp_path,
):
    module = import_module("evals.verification")
    plan = module.build_verification_plan(cases())
    sources = {}
    for row, verdict in zip(cases()[:3], ("attack", "unknown", "benign"), strict=True):
        source = fixture_source()
        source["state"]["diagnosis_execution_status"] = (
            "failed" if verdict == "attack" else "completed"
        )
        source["state"]["diagnostic_snapshot"]["diagnosis"]["verdict"] = verdict
        sources[row["case_id"]] = source
    called = []

    async def worker(request):
        called.append(request)
        raise AssertionError("ineligible rows must not dispatch")

    result = await module.run_verification_plan(
        plan, sources, worker=worker, output_dir=tmp_path
    )
    assert len(result["records"]) == 528
    assert called == []
    reasons = {row["reason"] for row in result["records"]}
    assert {
        "missing_b3_state",
        "diagnostic_failure",
        "unknown_diagnosis",
        "not_applicable",
    } <= reasons
    assert len(list((tmp_path / "branches").glob("*.json"))) == 528


@pytest.mark.asyncio
async def test_unapproved_expired_and_unpersisted_approval_never_dispatch(tmp_path):
    module = import_module("evals.verification")
    sources = {}
    for index in range(3):
        source = fixture_source()
        if index == 0:
            source["state"]["approval"] = None
        if index == 1:
            source["state"]["response_plan"]["created_at"] = (
                datetime.now(UTC) - timedelta(minutes=20)
            ).isoformat()
            source["state"]["response_plan"]["expires_at"] = (
                datetime.now(UTC) - timedelta(seconds=1)
            ).isoformat()
        sources[cases()[index]["case_id"]] = source

    async def worker(request):
        raise AssertionError("no valid persisted approval")

    result = await module.run_verification_plan(
        module.build_verification_plan(cases()),
        sources,
        worker=worker,
        output_dir=tmp_path,
    )
    reasons = {row["reason"] for row in result["records"]}
    assert {
        "approval_pending",
        "plan_expired",
        "persisted_approval_unavailable",
    } <= reasons


@pytest.mark.asyncio
async def test_pair_has_identical_approved_plan_and_measurements_with_opaque_worker_inputs(
    tmp_path,
):
    module = import_module("evals.verification")
    source = fixture_source()
    before = deepcopy(source)
    requests = []

    async def approval_verifier(current):
        return persisted_receipt(current["state"])

    async def worker(request):
        value = request.model_dump(mode="json")
        assert not {"condition", "truth", "expected_outcome", "branch"} & value.keys()
        requests.append(value)
        return {
            "status": "completed",
            "outcome": "unverified" if not value["verification_enabled"] else "success",
        }

    result = await module.run_verification_plan(
        module.build_verification_plan(cases()),
        {cases()[0]["case_id"]: source},
        worker=worker,
        approval_verifier=approval_verifier,
        output_dir=tmp_path,
    )
    assert len(requests) == 6
    for index in range(0, 6, 2):
        first, second = requests[index : index + 2]
        assert first["approved_state"] == second["approved_state"]
        assert first["observations"] == second["observations"]
        assert first["namespace"] != second["namespace"]
        assert (
            first["verification_enabled"] is True
            and second["verification_enabled"] is False
        )
    assert source == before
    # A worker's claimed outcome without the inspected live resource receipt is rejected.
    dispatched = [
        row for row in result["records"] if row["case_id"] == cases()[0]["case_id"]
    ]
    assert all(
        row["status"] == "failed" and row["outcome"] is None for row in dispatched
    )
    assert all(row["reason"] == "worker_receipt_invalid" for row in dispatched)


def test_approval_packet_comes_from_real_state_and_expiration_requires_product_renewal():
    module = import_module("evals.verification")
    source = fixture_source()
    packet = module.build_approval_packet(cases()[0], source["state"])
    assert packet["response_plan"] == source["state"]["response_plan"]
    assert packet["plan_sha256"] == source["state"]["approved_plan_sha256"]
    assert (
        packet["diagnostic_snapshot_sha256"]
        == source["state"]["diagnostic_snapshot_sha256"]
    )
    assert packet["reviewer"] == "user"
    state = deepcopy(source["state"])
    state["response_plan"]["created_at"] = (
        datetime.now(UTC) - timedelta(minutes=20)
    ).isoformat()
    state["response_plan"]["expires_at"] = (
        datetime.now(UTC) - timedelta(seconds=1)
    ).isoformat()
    assert (
        module.build_approval_packet(cases()[0], state)["status"] == "renewal_required"
    )


@pytest.mark.asyncio
async def test_controller_calls_original_workflow_for_human_decision():
    module = import_module("evals.verification")
    source = fixture_source()
    state = source["state"]
    state["status"] = "awaiting_approval"
    state["approval"] = None
    packet = module.build_approval_packet(cases()[0], state)
    calls = []

    class Workflow:
        async def get_state(self, incident_id):
            return deepcopy(state)

        async def approve(self, incident_id, **kwargs):
            calls.append(("approve", incident_id, kwargs))
            return deepcopy(state)

        async def renew_plan(self, incident_id, **kwargs):
            calls.append(("renew", incident_id, kwargs))
            return deepcopy(state)

    await module.apply_human_decision(
        Workflow(),
        packet,
        decision="approved",
        reason="User supplied decision",
        decided_by="user",
    )
    assert calls[0][0] == "approve"
    with pytest.raises(PermissionError):
        await module.apply_human_decision(
            Workflow(),
            packet,
            decision="approved",
            reason="not human",
            decided_by="Codex",
        )


@pytest.mark.asyncio
async def test_original_renewal_requires_inspected_tracked_model_workflow():
    module = import_module("evals.verification")
    state = fixture_source()["state"]
    state.update(status="awaiting_approval", approval=None)
    packet = module.build_approval_packet(cases()[0], state)
    called = []

    class Workflow:
        async def get_state(self, incident_id):
            return deepcopy(state)

        async def renew_plan(self, *args, **kwargs):
            called.append((args, kwargs))
            return state

    with pytest.raises(PermissionError, match="tracked|inspected|renewal"):
        await module.renew_expired_plan(Workflow(), packet, requested_by="user")
    assert called == []


@pytest.mark.asyncio
async def test_retained_workflow_binds_actual_stores_and_tracked_renewal_model(
    tmp_path, monkeypatch
):
    import os
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from langgraph.checkpoint.memory import InMemorySaver

    from evals.adapters.model_client import BudgetAccount, TrackedModel
    from evals.contracts import ModelConfig

    module = import_module("evals.adapters.retained_workflow")
    source = fixture_source()
    reference = {
        **source["resources"],
        "incident_id": source["state"]["incident_id"],
        "source_commit": "a" * 40,
    }
    account_path = tmp_path / "campaign.sqlite"
    tracked = TrackedModel(
        ModelConfig(),
        api_key="synthetic-never-sent",
        account=BudgetAccount(account_path),
        phase="verification",
        transport=lambda *args, **kwargs: pytest.fail("no model calls"),
    )
    monkeypatch.setattr(
        module,
        "os",
        SimpleNamespace(environ=os.environ, getpid=lambda: 1),
        raising=False,
    )
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-test-only")
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", "a" * 40)
    monkeypatch.setenv("TASK13_PHASE", "verification")
    monkeypatch.setenv("TASK13_BUDGET_DB", str(account_path))
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://fixture:fixture@localhost/base"
    )
    monkeypatch.setenv("OPENSEARCH_INDEX", "original-index")
    disposed = []
    monkeypatch.setattr(
        module,
        "create_database_engine",
        lambda url: SimpleNamespace(dispose=lambda: disposed.append(url)),
    )
    monkeypatch.setattr(module, "create_session_factory", lambda engine: None)

    @asynccontextmanager
    async def saver(database_url):
        assert database_url.endswith("/" + reference["database_name"])
        yield InMemorySaver()

    monkeypatch.setattr(module, "open_checkpointer", saver, raising=False)
    async with module.open_retained_workflow(reference, model=tracked) as workflow:
        assert workflow.settings.database_url.endswith("/" + reference["database_name"])
        assert workflow.settings.opensearch_index == reference["index_name"]
        assert workflow.services.planner_model is tracked
        assert workflow._task13_review_nodes.model is tracked
        assert os.environ["OPENSEARCH_INDEX"] == reference["index_name"]
        module._require_renewal_workflow(workflow)
        monkeypatch.setenv("TASK13_BUDGET_DB", str(tmp_path / "other.sqlite"))
        with pytest.raises(PermissionError, match="budget|account"):
            module._require_renewal_workflow(workflow)
    assert os.environ["OPENSEARCH_INDEX"] == "original-index"
    assert os.environ["DATABASE_URL"].endswith("/base")
    assert len(disposed) == 1


def test_source_review_contract_requires_explicit_bound_user_input():
    from pydantic import ValidationError

    module = import_module("evals.adapters.verification_worker")
    controller = import_module("evals.verification")
    source = fixture_source()
    packet = controller.build_approval_packet(cases()[0], source["state"])
    value = {
        "request_id": "c" * 32,
        "namespace": "d" * 32,
        "case_id": cases()[0]["case_id"],
        "dataset": "ait",
        "agent_sha256": "c" * 64,
        "source_commit": "a" * 40,
        "source_resources": source["resources"],
        "incident_id": source["state"]["incident_id"],
        "operation": "read_packet",
    }
    request = module.SourceReviewRequest.model_validate(value)
    assert request.decision is None
    assert request.reviewer == "user"
    for invalid in (
        {**value, "operation": "decision", "packet": packet},
        {
            **value,
            "operation": "decision",
            "packet": packet,
            "decision": "approved",
            "reason": "  ",
        },
        {**value, "operation": "renew_plan"},
        {**value, "decision": "approved", "reason": "unrequested"},
        {
            **value,
            "operation": "decision",
            "packet": {**packet, "incident_id": "other"},
            "decision": "approved",
            "reason": "input",
        },
    ):
        with pytest.raises(ValidationError):
            module.SourceReviewRequest.model_validate(invalid)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["approve", "renew"])
async def test_review_packet_rejects_changed_original_checkpoint(operation):
    module = import_module("evals.verification")
    state = fixture_source()["state"]
    state.update(status="awaiting_approval", approval=None)
    packet = module.build_approval_packet(cases()[0], state)
    state["errors"].append({"stage": "changed_after_review"})

    class Workflow:
        async def get_state(self, incident_id):
            return deepcopy(state)

        async def approve(self, *args, **kwargs):
            pytest.fail("changed checkpoint must not be approved")

        async def renew_plan(self, *args, **kwargs):
            pytest.fail("changed checkpoint must not be renewed")

    with pytest.raises(PermissionError, match="reviewed|checkpoint"):
        if operation == "approve":
            await module.apply_human_decision(
                Workflow(),
                packet,
                decision="approved",
                reason="explicit test input",
                decided_by="user",
            )
        else:
            await module.renew_expired_plan(Workflow(), packet, requested_by="user")


@pytest.mark.asyncio
async def test_modified_or_duplicate_plan_cannot_drop_planned_denominators(tmp_path):
    module = import_module("evals.verification")
    plan = module.build_verification_plan(cases())
    plan["slots"][0]["branches"].pop()

    async def worker(request):
        raise AssertionError("invalid plan must not run")

    with pytest.raises(ValueError, match="528|branches|complete"):
        await module.run_verification_plan(plan, {}, worker=worker, output_dir=tmp_path)


@pytest.mark.asyncio
async def test_replay_calls_only_original_validate_and_disabled_branch_never_observes(
    tmp_path, monkeypatch
):
    import json
    import uuid
    from contextlib import asynccontextmanager, contextmanager
    from dataclasses import dataclass
    from hashlib import sha256

    from evidencesoc.config import Settings
    from langgraph.checkpoint.memory import InMemorySaver

    module = import_module("evals.adapters.verification_worker")
    controller = import_module("evals.verification")
    source = fixture_source()
    normal = approved_fixture()[1]
    visited, verified, registered, checkpoint_reads = [], [], [], []

    @dataclass
    class Call:
        call_id: str

    call_rows = []

    class Ledger:
        def __init__(self, sessions):
            pass

        def calls(self, *args):
            return list(call_rows)

    @contextmanager
    def cloned(request):
        call_rows[:] = [Call("copied-original-verification")]
        suffix = uuid.uuid4().hex
        yield (
            Settings(_env_file=None),
            None,
            {
                "database_name": "task13_" + suffix,
                "index_name": "security-events-task13-" + suffix,
            },
        )

    @asynccontextmanager
    async def checkpointer(database_url):
        yield InMemorySaver()

    async def original_checkpoint(self, incident_id):
        checkpoint_reads.append(incident_id)
        return deepcopy(source["state"])

    class Services:
        def __init__(
            self, settings, *, session_factory, capabilities, verification_observer
        ):
            self.observer = verification_observer

        async def start_run(self, state, role):
            visited.append(role)
            return "AR-" + state["verification_namespace"]

        async def finish_run(self, *args):
            pass

        async def save_result(self, state):
            pass

        async def verify(self, state, run_id):
            verified.append(state["verification_namespace"])
            call_rows.append(Call("fresh-" + run_id))
            return {
                **normal,
                **await self.observer(state, run_id, normal),
                "verification_call_count": 1,
                "verification_attempts": 1,
            }

    monkeypatch.setattr(module, "cloned_resources", cloned)
    monkeypatch.setattr(module, "open_checkpointer", checkpointer)
    monkeypatch.setattr(module, "PostgresWorkflowServices", Services)
    monkeypatch.setattr(module.InvestigationWorkflow, "get_state", original_checkpoint)
    monkeypatch.setattr(module, "Ledger", Ledger, raising=False)
    monkeypatch.setattr(
        module,
        "_register_observation_evidence",
        lambda sessions, incident, items: registered.extend(items),
    )
    monkeypatch.setattr(module.os, "getpid", lambda: 1)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "fixture-only")
    agent = tmp_path / "agent"
    agent.mkdir()
    events = b"{}\n"
    (agent / "events.jsonl").write_bytes(events)
    outcomes = []
    for condition in ("success", "failure", "no_change"):
        observations = controller._measurements(
            source["state"], condition, datetime.now(UTC)
        )
        for enabled in (True, False):
            output = tmp_path / uuid.uuid4().hex
            output.mkdir()
            monkeypatch.setenv("TASK13_OUTPUT_DIR", str(output))
            receipt = persisted_receipt(source["state"])
            request = module.VerificationWorkerRequest(
                request_id=uuid.uuid4().hex,
                namespace=uuid.uuid4().hex,
                case_id=cases()[0]["case_id"],
                agent_sha256=sha256(events).hexdigest(),
                source_state_sha256=canonical_hash(source["state"]),
                approved_plan_sha256=source["state"]["approved_plan_sha256"],
                approval_receipt=receipt,
                approval_receipt_sha256=canonical_hash(receipt),
                approved_state=source["state"],
                source_resources=source["resources"],
                verification_enabled=enabled,
                observations=observations,
            )
            result = await module.run_verification(request, agent)
            assert result["model_ledger"] == []
            assert len(result["tool_ledger"]) == (1 if enabled else 0)
            outcomes.append(result["outcome"])
            stored = json.loads(
                (output / "verification-state.json").read_text(encoding="utf-8")
            )
            assert (
                stored["diagnostic_snapshot"] == source["state"]["diagnostic_snapshot"]
            )
    assert outcomes == [
        "success",
        "unverified",
        "failure",
        "unverified",
        "insufficient_evidence",
        "unverified",
    ]
    assert visited == ["validate"] * 6
    assert len(verified) == 3
    assert len(registered) == 6
    assert len(checkpoint_reads) == 6


def test_persisted_approval_verifier_reads_actual_rows_and_rejects_tampering(tmp_path):
    from evidencesoc.agents.graph import _persisted_plan_version
    from evidencesoc.domain.models import ApprovalRecord, ResponsePlan
    from evidencesoc.persistence.tables import (
        AlertTable,
        ApprovalTable,
        IncidentTable,
        ResponsePlanTable,
    )
    from sqlalchemy import JSON, CheckConstraint, MetaData, create_engine
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.orm import sessionmaker

    module = import_module("evals.adapters.verification_worker")
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'approval.db'}")
    metadata = MetaData()
    for kind in (AlertTable, IncidentTable, ResponsePlanTable, ApprovalTable):
        table = kind.__table__.to_metadata(metadata)
        for column in table.columns:
            if isinstance(column.type, JSONB):
                column.type = JSON()
        for constraint in list(table.constraints):
            if isinstance(constraint, CheckConstraint):
                table.constraints.remove(constraint)
    metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    state = fixture_source()["state"]
    state["approval"]["decided_by"] = "user"
    state["approved_plan_version"] = _persisted_plan_version(state["response_plan"])
    with sessions() as session:
        session.add(
            ResponsePlanTable(
                **ResponsePlan.model_validate(state["response_plan"]).model_dump()
            )
        )
        session.add(
            ApprovalTable(
                **ApprovalRecord.model_validate(state["approval"]).model_dump()
            )
        )
        session.commit()
    try:
        receipt = module.read_persisted_approval(state, sessions)
        assert receipt["status"] == "verified"
        assert receipt["approval_sha256"] == canonical_hash(state["approval"])
        with sessions() as session:
            session.get(
                ApprovalTable, state["approval"]["approval_id"]
            ).reason = "different decision record"
            session.commit()
        with pytest.raises(PermissionError, match="persisted"):
            module.read_persisted_approval(state, sessions)
    finally:
        engine.dispose()


def test_source_resources_cannot_mix_two_case_namespaces():
    from pydantic import ValidationError

    module = import_module("evals.adapters.verification_worker")
    with pytest.raises(ValidationError, match="same"):
        module.SourceResources(
            database_name="task13_" + "a" * 32,
            index_name="security-events-task13-" + "b" * 32,
        )


@pytest.mark.asyncio
async def test_retained_reference_metadata_is_not_forwarded_to_worker(tmp_path):
    module = import_module("evals.verification")
    source = fixture_source()
    source["resources"].update(
        schema_version="task13-case-resource-v1",
        source_commit="a" * 40,
        incident_id=source["state"]["incident_id"],
        status="awaiting_human_approval",
    )
    requests = []

    async def verifier(current):
        return persisted_receipt(current["state"])

    async def worker(request):
        requests.append(request)
        return {}

    await module.run_verification_plan(
        module.build_verification_plan(cases()),
        {cases()[0]["case_id"]: source},
        worker=worker,
        approval_verifier=verifier,
        output_dir=tmp_path,
    )
    assert len(requests) == 6
    assert all(
        set(request.source_resources.model_dump()) == {"database_name", "index_name"}
        for request in requests
    )


@pytest.mark.asyncio
async def test_synthetic_valid_receipts_admit_only_independent_fully_bound_branches(
    tmp_path,
):
    """Synthetic receipts exercise admission checks; they are not live isolation evidence."""
    import uuid

    module = import_module("evals.verification")
    source = fixture_source()

    async def verifier(current):
        return persisted_receipt(current["state"])

    async def worker(request):
        suffix, nonce = uuid.uuid4().hex, uuid.uuid4().hex
        measurement = next(iter(request.observations.values()))
        outcome = (
            (
                "failure"
                if measurement.after.error_code
                else "success"
                if measurement.after.network_blocked
                else "insufficient_evidence"
            )
            if request.verification_enabled
            else "unverified"
        )
        container = {
            "container_id": uuid.uuid4().hex,
            "hostname": suffix,
            "private_pid_namespace": True,
            "root_read_only": True,
        }
        return {
            "status": "completed",
            "outcome": outcome,
            "model_ledger": [],
            "input_sha256": canonical_hash(request),
            "source_state_sha256": request.source_state_sha256,
            "approved_plan_sha256": request.approved_plan_sha256,
            "approval_receipt_sha256": request.approval_receipt_sha256,
            "diagnostic_snapshot_sha256": request.approved_state[
                "diagnostic_snapshot_sha256"
            ],
            "validation_result": {"outcome": outcome}
            if request.verification_enabled
            else None,
            "verification_call_count": 1 if request.verification_enabled else 0,
            "verification_attempts": 1 if request.verification_enabled else 0,
            "cost": 0,
            "resource_receipt": {
                "database_name": "task13_" + suffix,
                "index_name": "security-events-task13-" + suffix,
                "worker_nonce": nonce,
                "checkpoint_id": uuid.uuid4().hex,
                "trace_id": "TRACE-" + request.namespace,
                "evidence_namespace": request.namespace,
            },
            "isolation_evidence": {
                "status": "passed",
                "source_commit": "a" * 40,
                "container": container,
                "probe": {
                    "pid": 1,
                    "nonce": nonce,
                    "hostname": suffix,
                    "agent_sha256": request.agent_sha256,
                    "boundaries": {
                        key: [{"readable": False}]
                        for key in ("scoring", "git", "other_case")
                    },
                },
            },
        }

    result = await module.run_verification_plan(
        module.build_verification_plan(cases(), source_commit="a" * 40),
        {cases()[0]["case_id"]: source},
        worker=worker,
        approval_verifier=verifier,
        output_dir=tmp_path,
    )
    completed = [row for row in result["records"] if row["status"] == "completed"]
    assert len(completed) == 6
    assert [row["outcome"] for row in completed] == [
        "success",
        "unverified",
        "failure",
        "unverified",
        "insufficient_evidence",
        "unverified",
    ]
    assert len(result["records"]) == 528
    assert len({row["resource_receipt"]["database_name"] for row in completed}) == 6
