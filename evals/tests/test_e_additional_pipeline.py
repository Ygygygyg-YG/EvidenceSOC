"""Real import/response/approval graph with fake HTTP and temporary authorities."""

import json
from copy import deepcopy
from hashlib import sha256

import httpx
import pytest

from evals.contracts import canonical_hash
from evals.e_planning import planning_requests
from evals.tests.test_e_additional_selection import actual_fixture


async def pipeline(tmp_path, monkeypatch, *, no_plan=False):
    from evidencesoc.agents.analysis_import import PlanningAdmission
    from evidencesoc.agents.capabilities import InvestigationCapabilities
    from evidencesoc.agents.fallback import respond
    from evidencesoc.agents.graph import InvestigationWorkflow
    from evidencesoc.config import Settings
    from langgraph.checkpoint.memory import InMemorySaver

    from evals.adapters import e_planning_worker as worker
    from evals.adapters.remediation_worker import PayloadRecorder
    from evals.tests.test_e_planning_journal import register_fixture
    from evals.tests.test_e_planning_worker import ProductServices

    original, package, imported, _selection, registration = await actual_fixture(
        tmp_path, monkeypatch
    )
    request = planning_requests(registration)[0]
    monkeypatch.delenv("TASK13_WORKER_NONCE")
    monkeypatch.setattr("os.getpid", lambda: 999)
    journal_path = tmp_path / "dispatch/e-planning.sqlite"
    journal_path.parent.mkdir()
    _, authority, dispatch = register_fixture(journal_path, registration)
    monkeypatch.setattr("os.getpid", lambda: 1)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-additional")
    monkeypatch.setenv("TASK13_IMPORT_DISPATCH_DB", str(journal_path))
    monkeypatch.setenv("TASK13_IMPORT_AUTHORITY_SHA256", canonical_hash(authority))
    monkeypatch.setenv("TASK13_IMPORT_SOURCE_DIR", str(package))
    monkeypatch.delenv("TASK13_EPOCH_HOST_BUDGET_PATH", raising=False)
    monkeypatch.delenv("TASK13_IMPORT_HOST_JOURNAL_PATH", raising=False)
    request, imported, journal, budget = worker.validate_planning_inputs(
        request, original.paths["events"].parent
    )
    binding = worker._claim_binding(request, journal.claim_planning_slot(request))
    admission = PlanningAdmission._from_existing_claim(
        binding,
        lambda: worker._claim_binding(request, journal.validate_request(request)),
    )
    output = tmp_path / "planning-output"
    output.mkdir()
    recorder = PayloadRecorder(output)

    def reply(http_request):
        context = json.loads(
            json.loads(http_request.content)["messages"][-1]["content"]
        )
        answer = (
            {"response_plan": None, "no_plan_reason": "synthetic abstention"}
            if no_plan
            else respond(context).model_dump(mode="json")
        )
        return httpx.Response(
            200,
            json={
                "id": "synthetic-planning-response",
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

    real_model = worker.make_model(
        request,
        budget,
        "development",
        transport=httpx.MockTransport(reply),
        payload_sink=recorder,
    )
    model = worker.RespondOnlyModel(real_model, request.planning_slot_id)
    services = ProductServices(imported.product_values()["evidence"])
    flow = InvestigationWorkflow.for_analysis_import(
        imported_analysis=imported,
        planning_admission=admission,
        services=services,
        settings=Settings(_env_file=None, llm_mode="deepseek"),
        checkpointer=InMemorySaver(),
        model=model,
        capabilities=InvestigationCapabilities(
            allowed_tools=frozenset(), rag_mode="disabled", verification_enabled=False
        ),
    )
    state = await flow.import_analysis(request.incident_id, imported)
    assert len(model.ledger) == 1 and model.ledger[0]["parse_status"] == "valid", state
    assert state["plan_source"] == "model"
    from evals.adapters.model_identity_runtime import verify_identity_ledger

    verify_identity_ledger(budget, request, model.ledger)
    return {
        "original": original,
        "package": package,
        "imported": imported,
        "registration": registration,
        "request": request,
        "journal": journal,
        "dispatch": dispatch,
        "binding": binding,
        "flow": flow,
        "services": services,
        "model": model,
        "recorder": recorder,
        "output": output,
        "state": state,
    }


@pytest.mark.asyncio
async def test_real_additional_response_and_actual_synthetic_approval_reach_timing_source_checks(
    tmp_path, monkeypatch
):
    from evals.adapters.e_planning_review import (
        build_review_request,
        validate_review_inputs,
        validate_review_state,
    )
    from evals.e_timing import ETimingCampaign, build_e_timing_registration
    from evals.tests.test_e_planning_review import reference

    data = await pipeline(tmp_path, monkeypatch)
    request, pending = data["request"], data["state"]
    assert (
        pending["status"] == "awaiting_approval" and pending["response_plan"]["actions"]
    )
    resource = reference(request)
    resource.update(
        plan_sha256=canonical_hash(pending["response_plan"]),
        snapshot_sha256=pending["diagnostic_snapshot_sha256"],
        state_sha256=canonical_hash(pending),
    )
    review = build_review_request(request, resource, operation="read_packet")
    _, replayed, binding, _ = validate_review_inputs(
        review, data["original"].paths["events"].parent
    )
    assert (
        replayed.provenance == data["imported"].provenance
        and binding == data["binding"]
    )
    validate_review_state(review, pending, data["imported"], data["binding"])
    approved = await data["flow"].approve(
        request.incident_id,
        response_plan_id=pending["response_plan"]["response_plan_id"],
        decision="approved",
        reason="synthetic fixture decision",
        decided_by="user",
    )
    assert approved["approval"]["decision"] == "approved"
    assert data["services"].saved[-1] == approved
    validate_review_state(review, approved, data["imported"], data["binding"])
    source_file = tmp_path / "synthetic-runtime.py"
    source_file.write_text("# synthetic timing source\n")
    timing = build_e_timing_registration(
        data["registration"],
        source_files={str(source_file): sha256(source_file.read_bytes()).hexdigest()},
        f8_plan_sha256="f" * 64,
        planning_dispatch_registration_receipt=data["dispatch"],
    )
    # Exercise the real source admission without writing a timing observation.
    store = object.__new__(ETimingCampaign)
    store.registration = timing
    store.identity = {
        "campaign_id": timing["campaign_id"],
        "source_commit": timing["source_commit"],
        "source_sha256": canonical_hash(timing["source_files"]),
        "config_sha256": canonical_hash(timing["core_config"]),
    }
    store.trials = {
        item["trial_id"]: {"binding": None, "status": "not_started"}
        for item in timing["trials"]
    }
    source = {
        **{
            key: store.identity[key]
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
        "resources": resource,
        "resources_sha256": canonical_hash(resource),
    }
    assert store._source(request.trial_id, source)[
        "planning_request"
    ] == request.model_dump(mode="json")
    assert all(item["status"] == "not_started" for item in store.trials.values())
    for field, value in (
        ("source_kind", None),
        ("source_registration_sha256", "0" * 64),
        ("source_package_schema_version", "task13-analysis-artifacts-v2"),
        ("source_core_sha256", "0" * 64),
        ("source_epoch_id", "wrong"),
        ("source_synthetic", 1),
        (
            "source_model_identity_binding",
            {"model_epoch_id": "wrong", "model_identity_sha256": "0" * 64},
        ),
    ):
        crossed = deepcopy(source)
        for state in (crossed["state"], crossed["retained_state"]):
            from evidencesoc.agents.graph import _plan_hash

            state["analysis_import_provenance"][field] = value
            state["diagnostic_snapshot"]["analysis_import_provenance"] = deepcopy(
                state["analysis_import_provenance"]
            )
            state["diagnostic_snapshot_sha256"] = _plan_hash(
                state["diagnostic_snapshot"]
            )
        with pytest.raises(PermissionError):
            store._source(request.trial_id, crossed)


@pytest.mark.asyncio
async def test_actual_additional_null_is_independently_verified_by_host_and_never_earns_timing(
    tmp_path, monkeypatch
):
    from evals.adapters.e_planning_no_plan import verify_no_plan
    from scripts.task13_e_trial import ETrialController

    data = await pipeline(tmp_path, monkeypatch, no_plan=True)
    request, state = data["request"], data["state"]
    expected = state["analysis_import_provenance"]
    verified = verify_no_plan(
        request=request,
        imported=data["imported"],
        expected_provenance=expected,
        state=state,
        ledger=data["model"].ledger,
        payloads=data["recorder"].records,
        output_root=data["output"],
        budget_path=data["original"].budget,
    )
    assert verified["timing_eligible"] is False and state["response_plan"] is None
    for name, value in (
        ("investigation-state.json", state),
        ("import-provenance.json", expected),
        ("model-ledger.json", data["model"].ledger),
        ("tool-ledger.json", []),
        ("model-payloads.json", data["recorder"].records),
    ):
        (data["output"] / name).write_text(json.dumps(value), encoding="utf-8")
    result = {
        "product_status": "manual_review",
        "diagnosis_status": "succeeded",
        "errors": [],
        "model_ledger": data["model"].ledger,
        "tool_ledger": [],
        "diagnostic_snapshot": state["diagnostic_snapshot"],
        "artifact_hashes": {
            "investigation_state": canonical_hash(state),
            "import_provenance": canonical_hash(expected),
        },
        "verification": verified,
    }
    host = object.__new__(ETrialController)
    host._root = tmp_path / "host"
    host._inputs = {
        "runtime_options": {
            "import_source_dir": str(data["package"]),
            "budget_dir": str(data["original"].budget.parent),
        }
    }
    host._journal = lambda: data["journal"]
    assert host._no_plan(request, result, data["output"], {}) == verified
