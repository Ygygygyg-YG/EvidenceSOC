"""Host review reads are fresh, read-only and never impersonate a worker."""

import importlib
import importlib.util
from contextlib import asynccontextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest

from evals.contracts import canonical_hash
from evals.tests.test_e_participation import POLICY
from evals.tests.test_e_planning_review import reference, review_state_fixture
from evals.tests.test_e_trial_controller import host  # noqa: F401


def module():
    assert importlib.util.find_spec("evals.host_review") is not None
    return importlib.import_module("evals.host_review")


@pytest.fixture
def pending(tmp_path):
    from evals.adapters.e_planning_review import build_review_request

    planning, state, imported, binding = review_state_fixture(tmp_path, POLICY)
    resource = reference(planning)
    resource.update(
        plan_sha256=canonical_hash(state["response_plan"]),
        snapshot_sha256=state["diagnostic_snapshot_sha256"],
        state_sha256=canonical_hash(state),
    )
    return (
        build_review_request(planning, resource, operation="read_packet"),
        state,
        imported,
        binding,
    )


@pytest.mark.parametrize("fault", [None, "incident", "plan", "approval"])
def test_product_rows_must_match_actual_owned_checkpoint(pending, fault):
    from evidencesoc.domain.models import ResponsePlan

    m = module()
    request, state, _, _ = pending
    plan = ResponsePlan.model_validate(state["response_plan"])
    row = SimpleNamespace(**plan.model_dump())
    incident = SimpleNamespace(incident_id=request.incident_id, status=state["status"])
    approvals = []
    if fault == "incident":
        incident.status = "approved"
    elif fault == "plan":
        row.incident_id = "another-incident"
    elif fault == "approval":
        approvals = [SimpleNamespace(approval_id="unexpected")]
    if fault:
        with pytest.raises(PermissionError):
            m.validate_product_rows(request, state, incident, row, approvals)
    else:
        m.validate_product_rows(request, state, incident, row, approvals)


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", [False, True])
async def test_host_read_uses_readonly_factory_and_two_fresh_snapshots(
    pending, monkeypatch, drift
):
    m = module()
    request, state, _, _ = pending
    reads, opened = [], []

    async def snapshot(config):
        reads.append(config)
        value = deepcopy(state)
        if drift and len(reads) == 2:
            value["status"] = "approved"
        return SimpleNamespace(
            values=value, config={"configurable": {"checkpoint_id": "actual-1"}}
        )

    workflow = SimpleNamespace(
        graph=SimpleNamespace(aget_state=snapshot),
        _config=lambda incident: {"configurable": {"thread_id": incident}},
    )

    @asynccontextmanager
    async def retained(resources, **kwargs):
        opened.append((resources, kwargs))
        yield workflow

    monkeypatch.setattr(m, "open_retained_workflow", retained)
    monkeypatch.setattr(
        m,
        "_checkpoint_readonly",
        lambda workflow, database: {"database_name": database, "read_only": "on"},
    )
    monkeypatch.setattr(
        m,
        "_product_snapshot",
        lambda workflow, request, state: {
            "database_name": request.source_resources.database_name,
            "read_only": "on",
            "approval_receipt": None,
        },
    )
    if drift:
        with pytest.raises(PermissionError, match="checkpoint changed"):
            await m.read_retained_review_state(request)
    else:
        result = await m.read_retained_review_state(request)
        assert result["state"] == state and len(reads) == 2
        receipt = result["host_read_receipt"]
        assert receipt["origin"] == "host_original_postgresql_read"
        assert receipt["checkpoint_transaction_read_only"] == "on"
        assert receipt["business_transaction_read_only"] == "on"
        assert "isolation_evidence" not in result
        assert result["approval_packet"]["decision"] is None
    assert opened[0][1] == {
        "model": None,
        "verification_enabled": False,
        "readonly": True,
    }


@pytest.mark.asyncio
async def test_host_reader_rejects_decision_before_factory(pending, monkeypatch):
    from evals.adapters.e_planning_review import build_review_request
    from evals.adapters.retained_workflow import build_approval_packet

    m = module()
    request, state, _, _ = pending
    packet = build_approval_packet(
        {"case_id": request.case_id, "dataset": request.dataset}, state
    )
    decision = build_review_request(
        request.planning_request,
        request.case_resource,
        operation="decision",
        packet=packet,
        decision="approved",
        reason="Synthetic only",
    )
    monkeypatch.setattr(
        m, "open_retained_workflow", lambda *a, **k: pytest.fail("factory called")
    )
    with pytest.raises(PermissionError, match="read_packet"):
        await m.read_retained_review_state(decision)


@pytest.mark.asyncio
async def test_host_adapter_rechecks_source_claim_and_state(
    pending, monkeypatch, tmp_path
):
    m = module()
    request, state, imported, binding = pending
    reads = []

    def claim():
        reads.append("claim")
        return binding

    monkeypatch.setattr(m, "_host_context", lambda *a: (imported, binding, claim))

    async def read(*args):
        return {
            "state": state,
            "approval_packet": {"synthetic": True},
            "approval_receipt": None,
            "host_read_receipt": {"origin": "host_original_postgresql_read"},
        }

    monkeypatch.setattr(m, "read_retained_review_state", read)
    result = await m.read_e_planning_host_review(request, tmp_path, {})
    assert result["source"]["state"] == state
    assert result["model_ledger"] == result["tool_ledger"] == []
    assert result["input_sha256"] == canonical_hash(request)
    assert reads == ["claim", "claim"]
    assert "isolation_evidence" not in result


@pytest.mark.asyncio
async def test_controller_real_read_uses_host_and_decision_keeps_worker(
    request, monkeypatch
):
    from scripts import task13_e_trial as controller_module
    from scripts import task13_worker_runtime as runtime

    m = module()
    controller = request.getfixturevalue("host").controller
    assert (await controller.plan(1))["status"] == "awaiting_approval"
    fake_review = controller._free.review
    controller._free = None
    monkeypatch.setattr(controller, "_preflight", lambda *a, **k: None)
    routes, captures = [], []
    original_capture = controller._capture

    def capture(*args, **kwargs):
        captures.append("worker")
        return original_capture(*args, **kwargs)

    async def read(request, agent, options):
        routes.append("host_read")
        value = await fake_review(request, agent, options)
        value.pop("isolation_evidence")
        value["host_read_receipt"] = {
            "schema_version": "task13-e-host-review-read-v1",
            "origin": "host_original_postgresql_read",
            "request_sha256": canonical_hash(request),
            "state_sha256": value["source_state_sha256"],
        }
        return value

    async def decision(request, agent, options):
        routes.append("worker_decision")
        return await fake_review(request, agent, options)

    monkeypatch.setattr(controller, "_capture", capture)
    monkeypatch.setattr(m, "read_e_planning_host_review", read)
    monkeypatch.setattr(runtime, "run_e_planning_review_container", decision)
    request = controller._requests[0]
    live, retained = await controller._review(request)
    assert routes == ["host_read"] and captures == []
    assert "host_read_receipt" in retained and "runtime_result" not in retained
    await controller._review(
        request,
        operation="decision",
        packet=live["approval_packet"],
        decision="approved",
        reason="Synthetic routing test only",
    )
    assert routes == ["host_read", "worker_decision"] and captures == ["worker"]
    assert controller_module.HOST_READ_ENTRYPOINT == "evals/host_review.py"


@pytest.mark.parametrize("fault", [None, "epoch", "timing"])
def test_host_reader_implementation_must_be_frozen_in_both_manifests(fault):
    from hashlib import sha256
    from pathlib import Path

    from scripts import task13_e_trial as m

    assert callable(getattr(m, "require_host_entrypoints", None))
    root = Path(m.__file__).resolve().parents[1]
    files = {
        name: sha256((root / name).read_bytes()).hexdigest()
        for name in (m.HOST_ENTRYPOINT, "evals/host_review.py")
    }
    epoch = {"entrypoints": deepcopy(files)}
    timing = {
        "source_files": {str(root / name): digest for name, digest in files.items()}
    }
    if fault == "epoch":
        epoch["entrypoints"]["evals/host_review.py"] = "0" * 64
    elif fault == "timing":
        timing["source_files"].pop(str(root / "evals/host_review.py"))
    if fault:
        with pytest.raises(PermissionError):
            m.require_host_entrypoints(epoch, timing)
    else:
        m.require_host_entrypoints(epoch, timing)


@pytest.mark.parametrize("fault", [None, "writable", "wrong_database"])
def test_approved_product_read_uses_actual_rows_and_readonly_connection(fault):
    from evidencesoc.agents.graph import _persisted_plan_version
    from evidencesoc.domain.models import ApprovalRecord, ResponsePlan
    from evidencesoc.persistence.tables import (
        ApprovalTable,
        IncidentTable,
        ResponsePlanTable,
    )

    from evals.tests.test_verification_plan import fixture_source, persisted_receipt

    m = module()
    state = fixture_source()["state"]
    state["approval"]["decided_by"] = "user"
    state["approved_plan_version"] = _persisted_plan_version(state["response_plan"])
    database = "task13_" + "a" * 32
    request = SimpleNamespace(
        incident_id=state["incident_id"],
        source_resources=SimpleNamespace(database_name=database),
    )
    plan = SimpleNamespace(
        **ResponsePlan.model_validate(state["response_plan"]).model_dump()
    )
    approval = SimpleNamespace(
        **ApprovalRecord.model_validate(state["approval"]).model_dump()
    )
    incident = SimpleNamespace(incident_id=state["incident_id"], status=state["status"])

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, statement):
            return SimpleNamespace(
                one=lambda: (
                    "another_database" if fault == "wrong_database" else database,
                    "off" if fault == "writable" else "on",
                )
            )

        def get(self, table, key):
            return {
                IncidentTable: incident,
                ResponsePlanTable: plan,
                ApprovalTable: approval,
            }[table]

        def scalars(self, statement):
            return SimpleNamespace(all=lambda: [approval])

    workflow = SimpleNamespace(services=SimpleNamespace(_sessions=Session))
    if fault:
        with pytest.raises(PermissionError, match="owned read-only"):
            m._product_snapshot(workflow, request, state)
    else:
        result = m._product_snapshot(workflow, request, state)
        assert result["approval_receipt"] == persisted_receipt(state)
        assert result["read_only"] == "on"
