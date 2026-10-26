"""Free planning review checks; no real user decision or provider request."""

import importlib.util
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from evals.contracts import canonical_hash
from evals.e_planning import planning_requests
from evals.tests.test_e_planning_contracts import registration_fixture


def test_dedicated_zero_model_review_exists():
    assert importlib.util.find_spec("evals.adapters.e_planning_review") is not None


def reference(request):
    return {
        "schema_version": "task13-case-resource-v1",
        "database_name": "task13_" + "a" * 32,
        "index_name": "security-events-task13-" + "a" * 32,
        "incident_id": request.incident_id,
        "run_id": request.run_id,
        "case_id": request.case_id,
        "source_commit": request.source_commit,
        "status": "retained_for_human_approval",
        "planning_slot_id": request.planning_slot_id,
        "registration_sha256": request.registration_sha256,
        "request_sha256": canonical_hash(request),
        "source_identity": request.source_identity,
        "source_package_manifest_sha256": request.source_package_manifest_sha256,
        "plan_sha256": "1" * 64,
        "snapshot_sha256": "2" * 64,
        "state_sha256": "3" * 64,
        "input_sha256": "4" * 64,
    }


def test_read_request_is_exactly_bound_and_cannot_renew_or_substitute_resources():
    from evals.adapters.e_planning_review import (
        EPlanningReviewRequest,
        build_review_request,
    )

    planning = planning_requests(registration_fixture())[0]
    request = build_review_request(
        planning, reference(planning), operation="read_packet"
    )
    assert request.planning_request == planning
    assert request.operation == "read_packet"
    assert request.budget_identity == planning.budget_identity
    for field, value in [
        ("request_id", "f" * 32),
        ("incident_id", "another-incident"),
        ("operation", "renew_plan"),
        ("model", {"model": "another-model"}),
    ]:
        changed = request.model_dump(mode="json")
        changed[field] = value
        with pytest.raises(ValueError):
            EPlanningReviewRequest.model_validate(changed)
    for field in ["database_name", "case_id", "run_id", "source_commit", "status"]:
        changed = reference(planning)
        changed[field] = "forged"
        with pytest.raises(ValueError):
            build_review_request(planning, changed, operation="read_packet")


@pytest.mark.parametrize(
    "hour,allowed", [(10, False), (11, True), (15, True), (16, False)]
)
def test_window_uses_shanghai_1900_to_midnight(hour, allowed):
    from evals.adapters.e_planning_review import require_review_window

    now = datetime(2026, 10, 25, hour, 0, tzinfo=UTC)
    if allowed:
        require_review_window(now)
    else:
        with pytest.raises(PermissionError):
            require_review_window(now)


@pytest.mark.asyncio
async def test_review_host_guard_runs_before_source_services_or_keys(
    tmp_path, monkeypatch
):
    from evals.adapters import e_planning_review as review

    request = planning_requests(registration_fixture())[0]
    operation = review.build_review_request(
        request, reference(request), operation="read_packet"
    )
    monkeypatch.setattr(review.os, "getpid", lambda: 99)
    monkeypatch.setattr(
        review, "validate_review_inputs", lambda *a: pytest.fail("preflight reached")
    )
    monkeypatch.setattr(
        review, "run_source_review", lambda *a, **k: pytest.fail("workflow reached")
    )
    with pytest.raises(PermissionError):
        await review.run_e_planning_review(operation, tmp_path)


def review_state_fixture(tmp_path):
    from evidencesoc.agents.graph import _plan_hash

    from evals.adapters.e_planning_worker import _claim_binding
    from evals.tests.test_e_planning_journal import open_fixture, register_fixture
    from evals.tests.test_e_planning_worker import (
        pending_state,
        product_registration,
        product_source,
    )

    source = product_source(tmp_path)
    registration = product_registration(source)
    planning = planning_requests(registration)[0]
    registration, authority, _ = register_fixture(
        tmp_path / "e-planning.sqlite", registration
    )
    journal = open_fixture(tmp_path / "e-planning.sqlite", registration, authority)
    binding = _claim_binding(planning, journal.claim_planning_slot(planning))
    provenance = {
        **source.provenance,
        "planning_admission": {k: v for k, v in binding.items() if k != "status"},
    }
    state = {
        **pending_state(),
        **source.product_values(),
        "incident_id": planning.incident_id,
        "analysis_import_provenance": provenance,
    }
    state["response_plan"]["incident_id"] = planning.incident_id
    sealed = {
        key: deepcopy(state[key])
        for key in (
            "diagnosis",
            "origin",
            "classification",
            "evidence",
            "knowledge",
            "attack_steps",
            "claims",
            "analysis_import_provenance",
        )
    }
    sealed["sealed_after"] = "analysis_import"
    state["diagnostic_snapshot"] = sealed
    state["diagnostic_snapshot_sha256"] = _plan_hash(sealed)
    return planning, state, source, binding


@pytest.mark.parametrize(
    "tamper",
    [None, "diagnosis", "evidence", "seal", "provenance", "planning_slot", "incident"],
)
def test_review_validates_actual_original_analysis_and_claim_before_decision(
    tmp_path, tamper
):
    from evals.adapters.e_planning_review import (
        build_review_request,
        validate_review_state,
    )

    planning, state, source, binding = review_state_fixture(tmp_path)
    resource = reference(planning)
    resource.update(
        plan_sha256=canonical_hash(state["response_plan"]),
        snapshot_sha256=state["diagnostic_snapshot_sha256"],
        state_sha256=canonical_hash(state),
    )
    request = build_review_request(planning, resource, operation="read_packet")
    if tamper == "diagnosis":
        state["diagnosis"]["verdict"] = "benign"
    elif tamper == "evidence":
        state["evidence"] = []
    elif tamper == "seal":
        state["diagnostic_snapshot_sha256"] = "0" * 64
    elif tamper == "provenance":
        state["analysis_import_provenance"] = {}
    elif tamper == "planning_slot":
        state["analysis_import_provenance"]["planning_admission"][
            "planning_slot_id"
        ] = "another-slot"
    elif tamper == "incident":
        state["incident_id"] = "another-incident"
    if tamper:
        with pytest.raises((ValueError, PermissionError)):
            validate_review_state(request, state, source, binding)
    else:
        validate_review_state(request, state, source, binding)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation,tamper",
    [("read_packet", False), ("decision", False), ("decision", True)],
)
async def test_real_review_adapter_validates_before_approval_and_never_constructs_model(
    tmp_path, monkeypatch, operation, tamper
):
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from evals.adapters import e_planning_review as review
    from evals.adapters import model_client, retained_workflow
    from evals.adapters import verification_worker as original

    planning, state, source, binding = review_state_fixture(tmp_path)
    resource = reference(planning)
    resource.update(
        plan_sha256=canonical_hash(state["response_plan"]),
        snapshot_sha256=state["diagnostic_snapshot_sha256"],
        state_sha256=canonical_hash(state),
    )
    packet = retained_workflow.build_approval_packet(
        {"case_id": planning.case_id, "dataset": planning.dataset}, state
    )
    request = review.build_review_request(
        planning,
        resource,
        operation=operation,
        packet=packet if operation == "decision" else None,
        decision="approved" if operation == "decision" else None,
        reason="synthetic test decision only" if operation == "decision" else None,
    )
    decisions = []
    if tamper:
        state["diagnosis"]["verdict"] = "benign"

    class Workflow:
        services = SimpleNamespace(_sessions=object())

        async def get_state(self, incident_id):
            return deepcopy(state)

        async def approve(self, incident_id, **kwargs):
            decisions.append(kwargs)
            return {
                **deepcopy(state),
                "status": "approved",
                "approval": {
                    "synthetic": True,
                    "decided_at": "2026-10-25T12:00:00+00:00",
                },
            }

    @asynccontextmanager
    async def opened(*args, model=None, **kwargs):
        assert model is None
        yield Workflow()

    monkeypatch.setattr(retained_workflow, "open_retained_workflow", opened)
    monkeypatch.setattr(
        original, "Ledger", lambda *a: SimpleNamespace(calls=lambda *a: [])
    )
    monkeypatch.setattr(
        original,
        "read_persisted_approval",
        lambda *a: {"status": "verified", "synthetic": True},
    )
    monkeypatch.setattr(
        review,
        "validate_review_inputs",
        lambda *a: (request, source, binding, lambda: binding),
    )
    monkeypatch.setattr(review, "require_review_window", lambda *a: None)
    monkeypatch.setattr(review.os, "getpid", lambda: 1)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic")
    monkeypatch.setenv("TASK13_PHASE", "verification")
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", planning.source_commit)
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    (tmp_path / "output").mkdir()
    (tmp_path / "events.jsonl").write_bytes(b"synthetic case\n")
    # Only this unrelated agent byte check is replaced; all source/state/packet
    # validation and the original decision dispatcher above are real code.
    monkeypatch.setattr(
        original,
        "sha256",
        lambda *a: SimpleNamespace(hexdigest=lambda: planning.agent_sha256),
    )
    for name in ("BudgetAccount", "TrackedModel"):
        monkeypatch.setattr(
            model_client,
            name,
            lambda *a, **k: pytest.fail(
                "zero-model review constructed an account/model"
            ),
        )
    result = await review.run_e_planning_review(request, tmp_path)
    assert result["model_ledger"] == []
    assert result["status"] == ("failed" if tamper else "completed")
    assert len(decisions) == (1 if operation == "decision" and not tamper else 0)


@pytest.mark.asyncio
async def test_window_admitter_runs_after_awaited_packet_match_before_approval(
    tmp_path,
):
    from evals.adapters import retained_workflow
    from evals.adapters.e_planning_review import require_review_window

    planning, state, _, _ = review_state_fixture(tmp_path)
    packet = retained_workflow.build_approval_packet(
        {"case_id": planning.case_id, "dataset": planning.dataset}, state
    )
    matched = []

    class Workflow:
        async def get_state(self, incident_id):
            matched.append(True)
            return state

        async def approve(self, *a, **k):
            pytest.fail("approval after midnight")

    def admit():
        assert matched
        require_review_window(datetime(2026, 10, 25, 16, 0, tzinfo=UTC))

    with pytest.raises(PermissionError, match="window"):
        await retained_workflow.apply_human_decision(
            Workflow(),
            packet,
            decision="approved",
            reason="synthetic boundary test",
            decided_by="user",
            decision_admitter=admit,
        )
