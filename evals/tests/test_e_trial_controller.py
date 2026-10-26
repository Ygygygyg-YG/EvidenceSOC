"""Free synthetic host orchestration only; no actual consent, model or services."""

import importlib.util
import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.contracts import canonical_hash
from evals.e_timing import ETimingCampaign, build_e_timing_registration
from evals.tests.test_e_planning_journal import authority_fixture
from evals.tests.test_e_timing import Clock, lifecycle, value_for
from evals.tests.test_e_timing_replicates import approved_source, registration
from evals.tests.test_verification_plan import persisted_receipt


def pin(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return {
        "path": str(path.resolve()),
        "sha256": sha256(path.read_bytes()).hexdigest(),
    }


@pytest.fixture
def host(tmp_path):
    from evals.adapters.e_planning_journal import register_planning_slots
    from evals.adapters.retained_workflow import build_approval_packet
    from scripts.task13_e_trial import SCOPE, ETrialController, FreeDependencies

    timing = registration(tmp_path)
    from evals.e_planning import validate_e_planning_registration

    planning = deepcopy(timing["planning_registration"])
    planning["core_config"]["original_observed_model_binding"] = {
        "response_model": "deepseek-flash",
        "fingerprint": "e72d3c7f663d3e1383b00b3884cb4501",
    }
    planning["core_config_sha256"] = canonical_hash(planning["core_config"])
    planning = validate_e_planning_registration(planning)
    clock = Clock()
    scope_packet = pin(tmp_path / "scope.json", {"synthetic": True, "scope": SCOPE})
    scope_record = {
        "schema_version": "task13-e-user-scope-decision-v1",
        "role": "user",
        "scope": SCOPE,
        "decision": "approved",
        "scope_packet_sha256": scope_packet["sha256"],
        "record_id": "synthetic-scope-message",
        "text": "Synthetic scope fixture only.",
        "decided_at": clock.now().isoformat(),
    }
    scope_decision = pin(tmp_path / "scope-decision.json", scope_record)
    authority = authority_fixture(tmp_path / "dispatch.sqlite", planning)
    authority.update(
        scope_packet_sha256=scope_packet["sha256"],
        decision_record_sha256=scope_decision["sha256"],
    )
    dispatch = register_planning_slots(
        tmp_path / "dispatch.sqlite",
        planning,
        authority=authority,
        expected_registration_sha256=canonical_hash(planning),
        expected_authority_sha256=canonical_hash(authority),
    )
    timing = build_e_timing_registration(
        planning,
        source_files=timing["source_files"],
        f8_plan_sha256=timing["f8_plan_sha256"],
        planning_dispatch_registration_receipt=dispatch,
    )
    store = ETimingCampaign(timing, tmp_path / "fixture-store", now=clock.now)
    source = approved_source(store, 0, clock)
    source["resources"]["plan_sha256"] = canonical_hash(
        source["state"]["response_plan"]
    )
    source["resources_sha256"] = canonical_hash(source["resources"])
    from evals.adapters.model_client import BudgetAccount

    budget = BudgetAccount(tmp_path / "original-budget" / "campaign.sqlite")
    budget.bind_model(**planning["core_config"]["original_observed_model_binding"])
    runtime = {
        "phase": "development",
        "output_dir": str(tmp_path / "runtime"),
        "source_dir": str(tmp_path / "export"),
        "source_commit": "a" * 40,
        "budget_dir": str(tmp_path / "original-budget"),
        "budget_identity": planning["epoch_binding"]["budget_identity"],
        "import_dispatch_path": str(tmp_path / "dispatch.sqlite"),
        "planning_authority_sha256": canonical_hash(authority),
        "import_source_dir": str(tmp_path / "package"),
    }
    agent = tmp_path / "agent"
    agent.mkdir()
    refs = {
        "planning_registration": pin(tmp_path / "planning.json", planning),
        "timing_registration": pin(tmp_path / "timing.json", timing),
        "planning_authority": pin(tmp_path / "authority.json", authority),
        "scope_packet": scope_packet,
        "scope_decision": scope_decision,
        "runtime_options": pin(tmp_path / "runtime.json", runtime),
    }
    ready = {
        "schema_version": "task13-e-host-readiness-v1",
        "status": "verified",
        "scope": SCOPE,
        "synthetic": True,
        "bindings": {key: value["sha256"] for key, value in refs.items()},
        "agent_dir": str(agent),
        "output_dir": str(tmp_path / "host"),
        "host_termination_dir": str(tmp_path / "terminations"),
    }
    refs["readiness"] = pin(tmp_path / "ready.json", ready)
    manifest = {
        "schema_version": "task13-e-host-controller-v1",
        "synthetic": True,
        "inputs": refs,
        "agent_dir": str(agent),
        "output_dir": str(tmp_path / "host"),
        "host_termination_dir": str(tmp_path / "terminations"),
    }
    binding = pin(tmp_path / "host-inputs.json", manifest)
    calls = []
    live = {"state": deepcopy(source["retained_state"])}
    faults = {}

    def capture(value, request, options, *, planning_worker=False):
        nonce = f"{len(calls):032x}"
        out = (
            Path(options["output_dir"])
            / request.run_id
            / request.case_id
            / "B3"
            / nonce
            if planning_worker
            else Path(options["output_dir"])
            / "source_review"
            / request.case_id
            / request.request_id
            / nonce
        )
        out.mkdir(parents=True)
        if planning_worker:
            for filename, content in (
                ("investigation-state.json", source["retained_state"]),
                (
                    "import-provenance.json",
                    source["retained_state"]["analysis_import_provenance"],
                ),
                ("case-resource.json", source["resources"]),
            ):
                pin(out / filename, content)
        raw = json.dumps(value).encode()
        folder = out.with_name(out.name + ".controller")
        folder.mkdir()
        path = folder / "worker-stdout.bin"
        path.write_bytes(raw)
        value["isolation_evidence"] = {
            "status": "passed",
            "source_commit": "a" * 40,
            "probe": {"pid": 1, "nonce": nonce},
            "container": {"container_id": "c" * 64},
            "raw_stdout": {
                "schema_version": "task13-worker-stdout-v1",
                "path": str(path),
                "sha256": sha256(raw).hexdigest(),
                "bytes": len(raw),
            },
        }
        return value

    async def plan(request, agent_dir, options):
        calls.append(("plan", request.model_dump(mode="json"), deepcopy(options)))
        if faults.get("raise"):
            raise TimeoutError("Synthetic lost reply")
        from evals.adapters.e_planning_journal import EPlanningDispatchJournal

        journal = EPlanningDispatchJournal.open_existing(
            Path(options["import_dispatch_path"]),
            expected_registration_sha256=request.registration_sha256,
            expected_authority_sha256=options["planning_authority_sha256"],
        )
        journal.claim_planning_slot(request)
        observed = planning["core_config"]["original_observed_model_binding"]
        model_call = {
            "synthetic": True,
            "http_status": 200,
            "response_model": observed["response_model"],
            "system_fingerprint": observed["fingerprint"],
            "raw_response": {
                "model": observed["response_model"],
                "system_fingerprint": observed["fingerprint"],
            },
            "cost_cny": 0.001,
        }
        model_call.update(deepcopy(faults.get("model_call", {})))
        value = {
            "execution_status": "completed",
            "product_status": "awaiting_approval",
            "model_ledger": deepcopy(faults.get("model_ledger", [model_call])),
            "artifact_hashes": {
                "investigation_state": canonical_hash(source["retained_state"]),
                "import_provenance": canonical_hash(
                    source["retained_state"]["analysis_import_provenance"]
                ),
                "case_resource": canonical_hash(source["resources"]),
            },
        }
        if faults.get("failed"):
            value.update(execution_status="failed", product_status="failed")
        if faults.get("wrong_product"):
            value["product_status"] = "completed"
        if faults.get("wrong_source"):
            source["retained_state"]["analysis_import_provenance"]["source_row_id"] = (
                "substituted"
            )
        result = capture(value, request, options, planning_worker=True)
        if faults.get("bad_stdout"):
            Path(result["isolation_evidence"]["raw_stdout"]["path"]).write_bytes(
                b"changed"
            )
        if faults.get("wrong_nonce"):
            result["isolation_evidence"]["probe"]["nonce"] = "f" * 32
        if faults.get("bad_resource"):
            path = Path(result["isolation_evidence"]["raw_stdout"]["path"])
            out = path.parent.with_name(path.parent.name.removesuffix(".controller"))
            pin(
                out / "case-resource.json",
                {**source["resources"], "incident_id": "substituted"},
            )
        return result

    async def review(request, agent_dir, options):
        calls.append(
            (request.operation, request.model_dump(mode="json"), deepcopy(options))
        )
        if request.operation == "decision":
            if faults.get("decision_lost"):
                raise TimeoutError("Synthetic decision reply lost")
            live["state"] = deepcopy(source["state"])
            live["state"]["approval"].update(
                decision=request.decision, reason=request.reason
            )
        state = deepcopy(live["state"])
        packet = build_approval_packet(
            {"case_id": request.case_id, "dataset": request.dataset},
            state,
            now=clock.now(),
        )
        receipt = (
            persisted_receipt(state)
            if request.operation == "decision" and request.decision == "approved"
            else None
        )
        value = {
            "status": "completed",
            "operation": request.operation,
            "request_id": request.request_id,
            "input_sha256": canonical_hash(request),
            "source_state_sha256": canonical_hash(state),
            "approval_packet": packet,
            "approval_receipt": receipt,
            "source": {
                "state": state,
                "resources": {
                    key: source["resources"][key]
                    for key in (
                        "database_name",
                        "index_name",
                        "incident_id",
                        "source_commit",
                    )
                },
            },
            "planning_slot_id": request.planning_request.planning_slot_id,
            "registration_sha256": request.planning_request.registration_sha256,
            "selected_source_lineage_sha256": request.planning_request.selected_source_lineage_sha256,
            "model_ledger": [{"forbidden": True}] if faults.get("review_model") else [],
        }
        if faults.get("review_input"):
            value["input_sha256"] = "0" * 64
        if faults.get("bad_receipt") and receipt:
            receipt["state_sha256"] = "0" * 64
        return capture(value, request, options)

    async def worker(request, agent_dir, options):
        calls.append(("branch", request.model_dump(mode="json"), deepcopy(options)))
        clock.advance(1)
        if faults.get("branch_lost"):
            raise TimeoutError("Synthetic branch reply lost")
        return value_for(request)

    def terminate(request, *, timed_out):
        if faults.get("lifecycle_unknown"):
            return {"status": "unknown"}
        return lifecycle(request, timed_out=timed_out)

    deps = FreeDependencies(
        plan=plan,
        review=review,
        verification=worker,
        preflight=lambda *a: None,
        approval_verifier=lambda s: persisted_receipt(s["state"]),
        lifecycle_verifier=terminate,
        now=clock.now,
        monotonic_ns=clock.monotonic_ns,
    )
    controller = ETrialController(
        binding["path"], binding["sha256"], free_dependencies=deps
    )
    return SimpleNamespace(
        controller=controller,
        calls=calls,
        source=source,
        live=live,
        faults=faults,
        clock=clock,
        manifest=manifest,
        binding=binding,
        deps=deps,
        tmp=tmp_path,
        timing=timing,
    )


def chat_record(host, packet, **changes):
    from scripts.task13_e_trial import SCOPE

    request = host.timing["trials"][0]["planning_request"]
    record = {
        "schema_version": "task13-e-user-plan-decision-v1",
        "role": "user",
        "scope": SCOPE,
        "record_id": "synthetic-user-plan-message",
        "text": "Approve this exact synthetic plan.",
        "decided_at": host.clock.now().isoformat(),
        "case_id": request["case_id"],
        "incident_id": request["incident_id"],
        "packet_sha256": canonical_hash(packet),
        "decision": "approved",
        "reason": "Synthetic free fixture only.",
    }
    record.update(changes)
    return pin(host.tmp / "actual-message.json", record)


@pytest.mark.asyncio
async def test_plan_once_preserves_pending_bytes_and_full_request(host):
    first = await host.controller.plan(1)
    assert first["status"] == "awaiting_approval"
    assert (await host.controller.plan(1)) == first
    assert [c[0] for c in host.calls] == ["plan"]
    assert host.calls[0][1] == host.timing["trials"][0]["planning_request"]
    assert (
        host.controller.status()["slots"][0]["planning_status"] == "awaiting_approval"
    )
    assert (
        json.loads(Path(first["retained_state"]["path"]).read_bytes())
        == host.source["retained_state"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault,status",
    [("raise", "unknown"), ("failed", "failed"), ("bad_resource", "unknown")],
)
async def test_failed_or_unknown_plan_never_redispatches(host, fault, status):
    host.faults[fault] = True
    assert (await host.controller.plan(1))["status"] == status
    assert (await host.controller.plan(1))["status"] == status
    assert [c[0] for c in host.calls] == ["plan"]
    if fault == "failed":
        assert host.controller.status()["slots"][0]["planning"]["runtime_result"]


@pytest.mark.asyncio
async def test_scope_consent_cannot_approve_and_unbound_chat_is_rejected(host):
    await host.controller.plan(1)
    packet = (await host.controller.read(1))["packet"]
    with pytest.raises((PermissionError, ValueError)):
        await host.controller.decision(
            1,
            packet_sha256=canonical_hash(packet),
            chat_record=host.manifest["inputs"]["scope_decision"],
        )
    for change in (
        {"packet_sha256": "0" * 64},
        {"incident_id": "wrong"},
        {"role": "assistant"},
        {"text": ""},
    ):
        evidence = chat_record(host, packet, **change)
        with pytest.raises((PermissionError, ValueError)):
            await host.controller.decision(
                1, packet_sha256=canonical_hash(packet), chat_record=evidence
            )
    assert all(c[0] != "decision" for c in host.calls)


@pytest.mark.asyncio
async def test_live_packet_drift_and_review_model_use_reject_before_decision(host):
    await host.controller.plan(1)
    packet = (await host.controller.read(1))["packet"]
    evidence = chat_record(host, packet)
    host.live["state"]["errors"].append({"synthetic": "changed"})
    with pytest.raises((PermissionError, ValueError)):
        await host.controller.decision(
            1, packet_sha256=canonical_hash(packet), chat_record=evidence
        )
    host.live["state"] = deepcopy(host.source["retained_state"])
    host.faults["review_model"] = True
    with pytest.raises((PermissionError, ValueError)):
        await host.controller.read(1)
    assert all(c[0] != "decision" for c in host.calls)


@pytest.mark.asyncio
async def test_trial_requires_actual_decision_then_uses_six_fixed_zero_model_branches(
    host,
):
    await host.controller.plan(1)
    with pytest.raises(PermissionError):
        await host.controller.trial(1)
    packet = (await host.controller.read(1))["packet"]
    evidence = chat_record(host, packet)
    result = await host.controller.decision(
        1, packet_sha256=canonical_hash(packet), chat_record=evidence
    )
    assert result["status"] == "approved"
    before = deepcopy(host.source["retained_state"])
    progress = await host.controller.trial(1)
    assert progress["complete_observed_trials"] == 1
    assert len([c for c in host.calls if c[0] == "branch"]) == 6
    assert host.source["retained_state"] == before
    assert all(
        c[2]["host_termination_dir"] == host.manifest["host_termination_dir"]
        for c in host.calls
        if c[0] == "branch"
    )
    assert (await host.controller.trial(1))["complete_observed_trials"] == 1
    assert len([c for c in host.calls if c[0] == "branch"]) == 6


@pytest.mark.asyncio
async def test_lost_decision_is_unknown_and_not_reissued(host):
    await host.controller.plan(1)
    packet = (await host.controller.read(1))["packet"]
    evidence = chat_record(host, packet)
    host.faults["decision_lost"] = True
    result = await host.controller.decision(
        1, packet_sha256=canonical_hash(packet), chat_record=evidence
    )
    assert result["status"] == "unknown"
    assert (
        await host.controller.decision(
            1, packet_sha256=canonical_hash(packet), chat_record=evidence
        )
        == result
    )
    assert len([c for c in host.calls if c[0] == "decision"]) == 1


@pytest.mark.asyncio
async def test_pins_readiness_original_journal_and_sequential_plans_fail_before_wrapper(
    host,
):
    with pytest.raises(PermissionError):
        await host.controller.plan(2)
    runtime_pin = host.manifest["inputs"]["runtime_options"]
    Path(runtime_pin["path"]).write_text("{}", encoding="utf-8")
    assert host.controller.readiness()["status"] == "PENDING"
    with pytest.raises((PermissionError, ValueError)):
        await host.controller.plan(1)
    assert host.calls == []


@pytest.mark.asyncio
async def test_preclaimed_worker_slot_without_host_marker_is_unknown(host):
    from evals.adapters.e_planning_journal import EPlanningDispatchJournal
    from evals.e_planning import planning_requests

    planning = host.timing["planning_registration"]
    dispatch = host.timing["planning_dispatch_registration_receipt"]
    journal = EPlanningDispatchJournal.open_existing(
        Path(dispatch["journal_path"]),
        expected_registration_sha256=canonical_hash(planning),
        expected_authority_sha256=dispatch["authority_sha256"],
    )
    journal.claim_planning_slot(planning_requests(planning)[0])
    assert (await host.controller.plan(1))["status"] == "unknown"
    assert host.controller.status()["slots"][0]["planning_status"] == "unknown"
    assert host.calls == []


@pytest.mark.asyncio
async def test_host_window_is_checked_before_review_wrapper(host):
    await host.controller.plan(1)
    host.clock.advance(-6 * 3600)
    with pytest.raises(PermissionError):
        await host.controller.read(1)
    assert [c[0] for c in host.calls] == ["plan"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ["wrong_product", "wrong_source", "bad_stdout", "wrong_nonce"]
)
async def test_planning_protocol_or_original_provenance_cannot_produce_retention(
    host, fault
):
    host.faults[fault] = True
    result = await host.controller.plan(1)
    assert result["status"] == "unknown"
    with pytest.raises(PermissionError):
        await host.controller.read(1)
    assert [call[0] for call in host.calls] == ["plan"]


@pytest.mark.asyncio
async def test_review_input_binding_and_bad_persisted_receipt_are_rejected(host):
    await host.controller.plan(1)
    host.faults["review_input"] = True
    with pytest.raises(PermissionError):
        await host.controller.read(1)
    host.faults.pop("review_input")
    packet = (await host.controller.read(1))["packet"]
    host.faults["bad_receipt"] = True
    result = await host.controller.decision(
        1, packet_sha256=canonical_hash(packet), chat_record=chat_record(host, packet)
    )
    assert result["status"] == "unknown"
    with pytest.raises(PermissionError):
        await host.controller.trial(1)
    assert all(call[0] != "branch" for call in host.calls)


@pytest.mark.asyncio
async def test_missing_original_journal_fails_before_dispatch_without_recreating_it(
    host,
):
    journal = Path(
        host.timing["planning_dispatch_registration_receipt"]["journal_path"]
    )
    journal.unlink()
    assert host.controller.readiness()["status"] == "PENDING"
    with pytest.raises((ValueError, PermissionError)):
        await host.controller.plan(1)
    assert not journal.exists()
    assert host.calls == []


@pytest.mark.asyncio
async def test_frozen_source_drift_is_rejected_before_first_verification_branch(host):
    await host.controller.plan(1)
    packet = (await host.controller.read(1))["packet"]
    await host.controller.decision(
        1, packet_sha256=canonical_hash(packet), chat_record=chat_record(host, packet)
    )
    Path(next(iter(host.timing["source_files"]))).write_text(
        "changed", encoding="utf-8"
    )
    with pytest.raises(PermissionError):
        await host.controller.trial(1)
    assert all(call[0] != "branch" for call in host.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["branch_lost", "lifecycle_unknown"])
async def test_unknown_trial_and_missing_host_termination_proof_never_replay(
    host, fault
):
    await host.controller.plan(1)
    packet = (await host.controller.read(1))["packet"]
    await host.controller.decision(
        1, packet_sha256=canonical_hash(packet), chat_record=chat_record(host, packet)
    )
    host.faults[fault] = True
    result = await host.controller.trial(1)
    assert result["complete_observed_trials"] == 0
    assert result["trials"][0]["status"] == "unknown"
    attempts = len([call for call in host.calls if call[0] == "branch"])
    assert attempts == 1
    assert (await host.controller.trial(1))["complete_observed_trials"] == 0
    assert len([call for call in host.calls if call[0] == "branch"]) == attempts


def test_readiness_is_read_only_and_cli_needs_independent_manifest_pin(host, capsys):
    from scripts.task13_e_trial import main

    assert host.controller.readiness()["status"] == "verified"
    assert not Path(host.manifest["output_dir"]).exists()
    assert (
        main(
            [
                "--manifest",
                host.binding["path"],
                "--manifest-sha256",
                "0" * 64,
                "readiness",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["status"] == "PENDING"
    assert not Path(host.manifest["output_dir"]).exists()


def real_metadata_manifest(host, *, model_binding=True):
    """Unregistered real-shaped negative inputs in tmp only; never confer consent."""
    planning = deepcopy(host.timing["planning_registration"])
    planning["synthetic"] = False
    if not model_binding:
        planning["core_config"].pop("original_observed_model_binding")
        planning["core_config_sha256"] = canonical_hash(planning["core_config"])
    dispatch = deepcopy(host.timing["planning_dispatch_registration_receipt"])
    dispatch.update(synthetic=False, registration_sha256=canonical_hash(planning))
    timing = build_e_timing_registration(
        planning,
        source_files=host.timing["source_files"],
        f8_plan_sha256=host.timing["f8_plan_sha256"],
        planning_dispatch_registration_receipt=dispatch,
    )
    manifest = deepcopy(host.manifest)
    manifest["synthetic"] = False
    manifest["inputs"]["planning_registration"] = pin(
        host.tmp / "unregistered-real-planning.json", planning
    )
    manifest["inputs"]["timing_registration"] = pin(
        host.tmp / "unregistered-real-timing.json", timing
    )
    return pin(host.tmp / "unregistered-real-manifest.json", manifest)


def test_real_registration_categorically_rejects_free_dependency_injection(host):
    from scripts.task13_e_trial import ETrialController

    binding = real_metadata_manifest(host)
    with pytest.raises(PermissionError, match="cannot inject"):
        ETrialController(
            binding["path"], binding["sha256"], free_dependencies=host.deps
        )


@pytest.mark.asyncio
async def test_real_defaults_fail_closed_without_external_real_registration(
    host, monkeypatch
):
    from scripts import task13_worker_runtime
    from scripts.task13_e_trial import ETrialController

    binding = real_metadata_manifest(host)
    controller = ETrialController(binding["path"], binding["sha256"])
    monkeypatch.setattr(
        task13_worker_runtime,
        "run_e_planning_container",
        lambda *a: pytest.fail("actual runtime must not be dispatched"),
    )
    assert controller.readiness()["status"] == "PENDING"
    with pytest.raises((PermissionError, ValueError)):
        await controller.plan(1)
    assert not Path(host.manifest["output_dir"]).exists()


@pytest.mark.asyncio
async def test_cancellation_after_host_start_remains_unknown_without_redispatch(host):
    import asyncio
    from dataclasses import replace

    from scripts.task13_e_trial import ETrialController

    started = asyncio.Event()

    async def suspended(*args):
        started.set()
        await asyncio.Event().wait()

    controller = ETrialController(
        host.binding["path"],
        host.binding["sha256"],
        free_dependencies=replace(host.deps, plan=suspended),
    )
    task = asyncio.create_task(controller.plan(1))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert controller.status()["slots"][0]["planning_status"] == "unknown"
    assert (await controller.plan(1))["status"] == "unknown"
    assert host.calls == []


@pytest.mark.asyncio
async def test_decision_explicit_rejection_cannot_enter_timing(host):
    await host.controller.plan(1)
    packet = (await host.controller.read(1))["packet"]
    result = await host.controller.decision(
        1,
        packet_sha256=canonical_hash(packet),
        chat_record=chat_record(host, packet, decision="rejected"),
    )
    assert result["status"] == "rejected"
    with pytest.raises(PermissionError):
        await host.controller.trial(1)
    assert all(call[0] != "branch" for call in host.calls)


def test_concrete_host_controller_is_available():
    assert importlib.util.find_spec("scripts.task13_e_trial") is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"response_model": "different-model"},
        {"system_fingerprint": "different-version"},
        {"system_fingerprint": None},
        {"raw_response": {"model": "deepseek-flash"}},
        {
            "raw_response": {
                "model": "different-model",
                "system_fingerprint": "e72d3c7f663d3e1383b00b3884cb4501",
            }
        },
    ],
)
@pytest.mark.parametrize("capture_fault", [None, "wrong_nonce", "bad_stdout"])
async def test_actual_model_drift_preserves_paid_result_and_stops_host(
    host, change, capture_fault
):
    from scripts.task13_e_trial import ETrialController

    host.faults["model_call"] = change
    if capture_fault:
        host.faults[capture_fault] = True
    result = await host.controller.plan(1)
    assert result["status"] == "unknown"
    actual = json.loads(Path(result["runtime_result"]["path"]).read_bytes())
    assert actual["model_ledger"][0]["cost_cny"] == 0.001
    assert all(actual["model_ledger"][0].get(k) == v for k, v in change.items())
    if capture_fault != "bad_stdout":
        original_stdout = json.loads(Path(result["stdout"]["path"]).read_bytes())
        assert original_stdout["model_ledger"] == actual["model_ledger"]
    halt = json.loads(
        (Path(host.manifest["output_dir"]) / "model-runtime-halt.json").read_bytes()
    )
    assert halt["runtime_result"] == result["runtime_result"]
    if capture_fault != "bad_stdout":
        assert halt["stdout"] == result["stdout"]
    restarted = ETrialController(
        host.binding["path"], host.binding["sha256"], free_dependencies=host.deps
    )
    assert restarted.readiness()["status"] == "PENDING"
    with pytest.raises(PermissionError, match="model runtime"):
        await restarted.plan(2)
    with pytest.raises(PermissionError, match="model runtime"):
        await restarted.trial(1)
    assert [call[0] for call in host.calls] == ["plan"]


@pytest.mark.asyncio
async def test_non200_transport_failure_does_not_claim_observed_model_drift(host):
    host.faults.update(
        failed=True,
        model_ledger=[
            {
                "synthetic": True,
                "http_status": 503,
                "response_model": None,
                "system_fingerprint": None,
                "parse_status": "not_received",
                "cost_cny": None,
            }
        ],
    )
    result = await host.controller.plan(1)
    assert result["status"] == "failed"
    assert not (Path(host.manifest["output_dir"]) / "model-runtime-halt.json").exists()
    assert host.controller.readiness()["status"] == "verified"


def test_real_host_requires_frozen_observed_model_binding(host):
    from scripts.task13_e_trial import ETrialController

    binding = real_metadata_manifest(host, model_binding=False)
    with pytest.raises(PermissionError, match="observed model"):
        ETrialController(binding["path"], binding["sha256"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "key,value",
    [
        ("halt", "observable model version changed"),
        ("response_model", "different-model"),
        ("fingerprint", "different-version"),
        ("fingerprint", None),
    ],
)
async def test_fresh_budget_model_guard_stops_dispatch_without_mutating_ledger(
    host, key, value
):
    import sqlite3

    path = host.tmp / "original-budget" / "campaign.sqlite"
    with sqlite3.connect(path) as db:
        if value is None:
            db.execute("DELETE FROM config WHERE key=?", (key,))
        else:
            db.execute("INSERT OR REPLACE INTO config VALUES (?,?)", (key, value))
        before = list(db.iterdump())
    assert host.controller.readiness()["status"] == "PENDING"
    with pytest.raises(PermissionError, match="model runtime"):
        await host.controller.plan(1)
    with pytest.raises(PermissionError, match="model runtime"):
        await host.controller.trial(1)
    assert host.calls == []
    with sqlite3.connect(path) as db:
        assert list(db.iterdump()) == before
