"""SYNTHETIC offline planning transport; no actual request or timing credit.

Only usable inside the copied SQLite namespace. The real native import,
admission, workflow, model payload recorder and budget ledger run unchanged.
ProductServices is an explicit in-memory test service, never a product SQL proof.
"""

from pathlib import Path


async def build_offline_planning(
    request,
    *,
    package_root,
    budget_path,
    journal_path,
    authority_sha256,
    output_root,
    resource_name=None,
):
    import json
    import os
    from unittest.mock import patch

    import httpx
    from evidencesoc.agents.analysis_import import PlanningAdmission
    from evidencesoc.agents.capabilities import InvestigationCapabilities
    from evidencesoc.agents.fallback import respond
    from evidencesoc.agents.graph import InvestigationWorkflow
    from evidencesoc.config import Settings
    from langgraph.checkpoint.memory import InMemorySaver

    from evals.adapters.e_planning_journal import EPlanningDispatchJournal
    from evals.adapters.e_planning_worker import RespondOnlyModel, _claim_binding
    from evals.adapters.model_identity_runtime import verify_identity_ledger
    from evals.adapters.planning_analysis import verify_planning_analysis
    from evals.adapters.remediation_worker import PayloadRecorder, make_model
    from evals.contracts import canonical_hash
    from evals.tests.pool_composite_fixture import _ISOLATED
    from evals.tests.test_e_planning_worker import ProductServices

    isolated_root = _ISOLATED.get()
    if not isolated_root:
        raise PermissionError("offline planning requires copied SQLite namespace")
    output_root = Path(output_root).resolve()
    if not output_root.is_relative_to(isolated_root):
        raise PermissionError("offline planning output must stay in fixture root")
    output_root.mkdir(parents=True)
    imported = verify_planning_analysis(request, Path(package_root), Path(budget_path))
    journal = EPlanningDispatchJournal.open_existing(
        Path(journal_path),
        expected_registration_sha256=request.registration_sha256,
        expected_authority_sha256=authority_sha256,
    )
    journal.validate_request(request)
    binding = _claim_binding(request, journal.claim_planning_slot(request))
    admission = PlanningAdmission._from_existing_claim(
        binding, lambda: _claim_binding(request, journal.validate_request(request))
    )
    recorder = PayloadRecorder(output_root)
    calls = []
    expected = request.model_identity_binding
    from evals.adapters.model_identities import require_registered_model_identity

    registered = require_registered_model_identity(
        Path(budget_path),
        expected.model_epoch_id,
        epoch_id=request.epoch_id,
        source_sha256=request.source_sha256,
        config_sha256=request.config_sha256,
        purpose=request.purpose,
        manifest_sha256=expected.model_identity_sha256,
        latest=True,
    )
    identity = registered["expected_model"]

    def reply(http_request):
        calls.append(json.loads(http_request.content))
        context = json.loads(calls[-1]["messages"][-1]["content"])
        answer = respond(context).model_dump(mode="json")
        return httpx.Response(
            200,
            json={
                "id": "SYNTHETIC-OFFLINE-" + request.planning_slot_id,
                "model": identity["response_model"],
                "system_fingerprint": identity["fingerprint"],
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(answer)},
                    }
                ],
            },
        )

    with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "SYNTHETIC-OFFLINE-NEVER-ACTUAL"}):
        tracked = make_model(
            request,
            Path(budget_path),
            "development",
            transport=httpx.MockTransport(reply),
            payload_sink=recorder,
        )
    model = RespondOnlyModel(tracked, request.planning_slot_id)
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
    verify_identity_ledger(Path(budget_path), request, model.ledger)
    assert len(calls) == 1 and len(model.ledger) == 1
    assert model.ledger[0]["parse_status"] == "valid", state
    assert state["status"] == "awaiting_approval", state
    assert state.get("approval") is None
    # Keep naming overridable for the offline I/O adapter; these names assert no
    # actual service creation. A resource proof must be supplied by its caller.
    resources = {
        "database_name": "SYNTHETIC_OFFLINE_"
        + (resource_name or request.planning_slot_id),
        "index_name": "synthetic-offline-"
        + (resource_name or request.planning_slot_id),
        "incident_id": request.incident_id,
        "source_commit": request.source_commit,
        "planning_slot_id": request.planning_slot_id,
        "registration_sha256": request.registration_sha256,
        "request_sha256": canonical_hash(request),
        "source_identity": imported.source_identity,
        "source_package_manifest_sha256": request.source_package_manifest_sha256,
        "plan_sha256": canonical_hash(state["response_plan"]),
        "snapshot_sha256": state["diagnostic_snapshot_sha256"],
        "state_sha256": canonical_hash(state),
    }
    artifacts = {
        "investigation-state.json": state,
        "import-provenance.json": state["analysis_import_provenance"],
        "model-ledger.json": model.ledger,
        "tool-ledger.json": [],
        "model-payloads.json": recorder.records,
        "case-resource.json": resources,
    }
    for name, value in artifacts.items():
        (output_root / name).write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return {
        "request": request,
        "imported": imported,
        "journal": journal,
        "binding": binding,
        "claim": journal.validate_request(request),
        "flow": flow,
        "services": services,
        "model": model,
        "recorder": recorder,
        "state": state,
        "resources": resources,
        "provenance": state["analysis_import_provenance"],
        "output": output_root,
        "output_root": output_root,
        "artifacts": artifacts,
        "http_payloads": calls,
        "actual_provider_requests": 0,
        "actual_user_approval": False,
    }
