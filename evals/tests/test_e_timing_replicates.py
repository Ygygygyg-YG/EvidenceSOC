"""Synthetic E2 timing evidence; no live services, approvals or timing credit."""

from copy import deepcopy
from datetime import timedelta

import pytest

from evals.contracts import ModelConfig, canonical_hash
from evals.e_planning import build_e_planning_registration, planning_requests
from evals.tests.test_e_planning_contracts import selection_receipt
from evals.tests.test_e_timing import (
    Clock,
    admit,
    imported_fixture_source,
    lifecycle,
    value_for,
    verify,
)
from evals.tests.test_verification_plan import fixture_source


def registration(tmp_path):
    from evals.e_timing import build_e_timing_registration

    selection = selection_receipt()
    state = imported_fixture_source()["state"]
    from evals.e_timing import ANALYSIS_KEYS, IMPORTED_KEYS

    values = {key: state[key] for key in IMPORTED_KEYS}
    digests = {
        "analysis_output_sha256": canonical_hash(
            {key: state[key] for key in ANALYSIS_KEYS}
        ),
        "imported_values_sha256": canonical_hash(values),
        "agent_sha256": "c" * 64,
    }
    selection["rows"][0].update(digests)
    selection["selected_sources"][0].update(digests)
    planning = build_e_planning_registration(
        selection,
        registration_id="1" * 32,
        source_package_manifest_sha256="d" * 64,
        budget_source_receipt_sha256="2" * 64,
        epoch_binding={
            "epoch_id": "synthetic-timing-epoch",
            "epoch_manifest_sha256": "e" * 64,
            "source_commit": "a" * 40,
            "source_sha256": "2" * 64,
            "budget_identity": {
                "schema_version": "task13-original-budget-identity-v1",
                "baseline_count": 1,
                "baseline_max_rowid": 1,
                "baseline_sha256": "3" * 64,
            },
        },
        core_config={
            "model": ModelConfig().model_dump(mode="json"),
            "synthetic": True,
            "f8_plan_sha256": "f" * 64,
        },
        synthetic=True,
    )
    requests = planning_requests(planning)
    dispatch = {
        "schema_version": "task13-e-planning-dispatch-registration-v1",
        "campaign_id": planning["campaign_id"],
        "registration_sha256": canonical_hash(planning),
        "authority_sha256": "4" * 64,
        "journal_path": str(tmp_path / "synthetic-planning.sqlite"),
        "synthetic": True,
        "planning_slot_ids": [q.planning_slot_id for q in requests],
    }
    source_file = tmp_path / "synthetic-runtime.py"
    source_file.write_text("# synthetic timing v2\n", encoding="utf-8")
    from hashlib import sha256

    return build_e_timing_registration(
        planning,
        source_files={str(source_file): sha256(source_file.read_bytes()).hexdigest()},
        f8_plan_sha256="f" * 64,
        planning_dispatch_registration_receipt=dispatch,
    )


def approved_source(store, index, clock):
    """Build an original pending retain record and separate synthetic live approval."""
    from evidencesoc.agents.graph import _plan_hash, _seal_diagnosis

    planning = store.registration["planning_registration"]
    request = planning_requests(planning)[index]
    source = imported_fixture_source()
    state = source["state"]
    state["incident_id"] = request.incident_id
    state["response_plan"].update(
        incident_id=request.incident_id,
        response_plan_id=f"RP-synthetic-E2-{index}",
        created_at=(clock.now() - timedelta(seconds=60)).isoformat(),
        expires_at=(clock.now() + timedelta(seconds=1740)).isoformat(),
    )
    selected = planning["source"]
    provenance = {
        "schema_version": "task13-analysis-import-provenance-v1",
        "entry": "analysis_import",
        **{
            key: selected[key]
            for key in (
                "source_row_id",
                "order_index",
                "case_id",
                "dataset",
                "agent_sha256",
                "manifest_sha256",
                "request_sha256",
                "analysis_output_sha256",
                "imported_values_sha256",
                "source_package_manifest_sha256",
            )
        },
        "source_package_schema_version": "task13-analysis-artifacts-v2",
        "original_manifest_sha256": selected["manifest_sha256"],
        "reconstruct_executed": False,
        "planning_admission": {
            "planning_slot_id": request.planning_slot_id,
            "request_sha256": canonical_hash(request),
            "registration_sha256": request.registration_sha256,
            "authority_sha256": store.registration[
                "planning_dispatch_registration_receipt"
            ]["authority_sha256"],
            "source_identity": request.source_identity,
            "analysis_output_sha256": request.analysis_output_sha256,
            "incident_id": request.incident_id,
            **{
                key: getattr(request, key)
                for key in (
                    "source_package_manifest_sha256",
                    "original_request_sha256",
                    "original_manifest_sha256",
                    "imported_values_sha256",
                    "source_selection_receipt_sha256",
                    "epoch_id",
                    "epoch_manifest_sha256",
                    "selected_source_lineage_sha256",
                    "budget_source_receipt_sha256",
                )
            },
            "selected_source_lineage": request.selected_source_lineage.model_dump(
                mode="json"
            ),
        },
    }
    if request.model_identity_binding is not None:
        provenance["planning_admission"]["model_identity_binding"] = (
            request.model_identity_binding.model_dump(mode="json")
        )
    state["analysis_import_provenance"] = provenance
    state["diagnostic_snapshot"] = None
    state.update(_seal_diagnosis(state, "analysis_import"))
    plan_hash = _plan_hash(state["response_plan"])
    state.update(approved_plan_sha256=plan_hash, approved_plan_version=plan_hash)
    state["simulation_execution"]["plan_version"] = plan_hash
    state["simulation_execution"]["response_plan_id"] = state["response_plan"][
        "response_plan_id"
    ]
    state["approval"].update(
        approval_id=f"AP-synthetic-E2-{index}",
        response_plan_id=state["response_plan"]["response_plan_id"],
        decided_by="user",
        decided_at=(clock.now() - timedelta(seconds=1)).isoformat(),
    )
    pending = deepcopy(state)
    pending.update(
        status="awaiting_approval",
        approval=None,
        approved_plan_sha256=None,
        approved_plan_version=None,
    )
    pending.pop("simulation", None)
    pending.pop("simulation_execution", None)
    suffix = f"{index + 10:032x}"
    reference = {
        "schema_version": "task13-case-resource-v1",
        "database_name": "task13_" + suffix,
        "index_name": "security-events-task13-" + suffix,
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
        "plan_sha256": plan_hash,
        "snapshot_sha256": state["diagnostic_snapshot_sha256"],
        "state_sha256": canonical_hash(pending),
        "input_sha256": "9" * 64,
    }
    source.update(
        **{
            key: store.identity[key]
            for key in (
                "campaign_id",
                "source_commit",
                "source_sha256",
                "config_sha256",
            )
        },
        source_row_id=request.source_row_id,
        case_id=request.case_id,
        dataset=request.dataset,
        analysis_manifest_sha256=request.original_manifest_sha256,
        budget_source_receipt_sha256=request.budget_source_receipt_sha256,
        planning_request=request.model_dump(mode="json"),
        resources=reference,
        resources_sha256=canonical_hash(reference),
        retained_state=pending,
        retained_state_sha256=canonical_hash(pending),
    )
    return source


def refresh_plan(source):
    """Update both independent fixture records after a synthetic plan mutation."""
    from evidencesoc.agents.graph import _plan_hash

    state, retained, reference = (
        source["state"],
        source["retained_state"],
        source["resources"],
    )
    retained["response_plan"] = deepcopy(state["response_plan"])
    state["approved_plan_sha256"] = state["approved_plan_version"] = _plan_hash(
        state["response_plan"]
    )
    state["simulation_execution"]["plan_version"] = state["approved_plan_sha256"]
    reference["plan_sha256"] = canonical_hash(state["response_plan"])
    reference["state_sha256"] = source["retained_state_sha256"] = canonical_hash(
        retained
    )
    source["resources_sha256"] = canonical_hash(reference)


@pytest.fixture
def setup(tmp_path):
    from evals.e_timing import ETimingCampaign

    clock = Clock()
    reg = registration(tmp_path)
    store = ETimingCampaign(
        reg,
        tmp_path / "synthetic-E2-timing",
        execution_admitter=admit,
        approval_verifier=verify,
        worker_lifecycle_verifier=lifecycle,
        now=clock.now,
        monotonic_ns=clock.monotonic_ns,
    )
    return store, clock, reg


def test_registration_preserves_shortage_full_receipts_and_deterministic_slots(
    tmp_path,
):
    from evals.e_timing import validate_registration

    reg = registration(tmp_path)
    validate_registration(reg)
    assert reg["schema_version"] == "task13-e-timing-registration-v2"
    assert reg["mode"] == "same-source-replicates-v1"
    assert reg["distinct_source_count"] == reg["distinct_case_count"] == 1
    assert reg["replicate_count"] == 3 and reg["f8_approval_credit"] == 0
    assert reg["source_selection_receipt"]["status"] == "insufficient_qualified_sources"
    assert len(reg["source_selection_receipt"]["selected_sources"]) == 1
    assert (
        canonical_hash(reg["planning_registration"])
        == reg["planning_registration_sha256"]
    )
    assert (
        canonical_hash(reg["selected_source_lineage"])
        == reg["selected_source_lineage_sha256"]
    )
    assert len({t["planning_slot_id"] for t in reg["trials"]}) == 3
    assert len({t["incident_id"] for t in reg["trials"]}) == 3
    assert len({b["namespace"] for t in reg["trials"] for b in t["branches"]}) == 18


@pytest.mark.asyncio
async def test_three_new_plans_complete_eighteen_bound_branches_without_f8_credit(
    setup,
):
    store, clock, reg = setup
    requests = []

    async def worker(request):
        requests.append(request)
        clock.advance(3)
        return value_for(request)

    for index, trial in enumerate(reg["trials"]):
        source = approved_source(store, index, clock)
        result = await store.run_trial(trial["trial_id"], source, run_worker=worker)
        assert result["trials"][index]["status"] == "completed"
        assert result["distinct_source_count"] == result["distinct_case_count"] == 1
        assert result["replicate_count"] == 3 and result["f8_approval_credit"] == 0
        assert result["complete_observed_trials"] == index + 1
        if index < 2:
            with pytest.raises(PermissionError, match="three"):
                store.export_timing_receipt()
    receipt = store.export_timing_receipt()
    assert receipt["observed_max_seconds"] == 18
    assert receipt["synthetic"] is True
    assert receipt["distinct_case_count"] == 1 and receipt["f8_approval_credit"] == 0
    assert (
        receipt["planning_registration_sha256"] == reg["planning_registration_sha256"]
    )
    assert len({r.approved_plan_sha256 for r in requests}) == 3
    assert (
        len({r.request_id for r in requests})
        == len({r.namespace for r in requests})
        == 18
    )
    for offset in range(0, 18, 6):
        assert len({r.approved_plan_sha256 for r in requests[offset : offset + 6]}) == 1
    before = len(requests)
    await store.run_trial(reg["trials"][2]["trial_id"], source, run_worker=worker)
    assert len(requests) == before
    binding = store.trials[reg["trials"][2]["trial_id"]]["binding"]
    saved = store._blob("sources", binding["source_sha256"])
    assert saved["resources"] == source["resources"]
    assert saved["retained_state"] == source["retained_state"]


@pytest.mark.asyncio
async def test_unicode_plan_retention_hash_is_distinct_from_product_approval_version(
    setup,
):
    store, clock, reg = setup
    source = approved_source(store, 0, clock)
    source["state"]["response_plan"]["summary"] = "隔离受影响主机"
    refresh_plan(source)
    assert source["resources"]["plan_sha256"] != source["state"]["approved_plan_sha256"]

    async def worker(request):
        clock.advance(2)
        return value_for(request)

    result = await store.run_trial(
        reg["trials"][0]["trial_id"], source, run_worker=worker
    )
    assert result["complete_observed_trials"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "remaining,ttl,reason",
    [
        (1500, 1800, "bootstrap_remaining"),
        (1740, 1799, "plan_ttl"),
    ],
)
async def test_replicates_keep_bootstrap_remaining_and_exact_ttl(
    setup, remaining, ttl, reason
):
    store, clock, reg = setup
    source = approved_source(store, 0, clock)
    source["state"]["response_plan"].update(
        created_at=(clock.now() + timedelta(seconds=remaining - ttl)).isoformat(),
        expires_at=(clock.now() + timedelta(seconds=remaining)).isoformat(),
    )
    refresh_plan(source)
    called = []

    async def worker(request):
        called.append(request)

    result = await store.run_trial(
        reg["trials"][0]["trial_id"], source, run_worker=worker
    )
    assert result["trials"][0]["status"] == "rejected"
    assert reason in result["trials"][0]["reason"]
    assert not called


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["partial", "clock_drift", "zero_duration", "wall_timeout"]
)
async def test_replicates_preserve_partial_unknown_and_clock_walltime_gates(
    setup, failure
):
    store, clock, reg = setup
    called = []

    async def worker(request):
        called.append(request)
        if failure == "partial" and len(called) == 3:
            raise RuntimeError("synthetic result lost")
        if failure == "wall_timeout":
            clock.advance(181)
        elif failure == "clock_drift":
            clock.advance(2, utc_seconds=8)
        elif failure != "zero_duration":
            clock.advance(2)
        return value_for(request)

    trial_id = reg["trials"][0]["trial_id"]
    source = approved_source(store, 0, clock)
    result = await store.run_trial(trial_id, source, run_worker=worker)
    assert result["complete_observed_trials"] == 0
    assert result["observed_max_seconds"] is None
    assert result["trials"][0]["status"] == (
        "unknown" if failure == "partial" else "failed"
    )
    count = len(called)
    await store.run_trial(trial_id, source, run_worker=worker)
    assert len(called) == count
    with pytest.raises(PermissionError, match="three"):
        store.export_timing_receipt()


def test_v2_journal_reader_is_read_only_and_checks_planning_registration(setup):
    from evals.e_timing import read_timing_journal

    store, _, _ = setup
    before = {
        p.relative_to(store.root): p.read_bytes()
        for p in store.root.rglob("*")
        if p.is_file()
    }
    snapshot = read_timing_journal(store.root)
    assert len(snapshot["cases"]) == 3 and len(snapshot["records"]) == 18
    assert before == {
        p.relative_to(store.root): p.read_bytes()
        for p in store.root.rglob("*")
        if p.is_file()
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "lineage_rebound",
        "registration_hash",
        "dispatch_receipt",
        "reused_slot",
        "reused_incident",
        "reused_branch",
        "unknown_field",
        "false_independence",
    ],
)
def test_strict_registration_refuses_rebound_lineage_or_slot_mappings(
    tmp_path, mutation
):
    from evals.e_timing import validate_registration

    reg = registration(tmp_path)
    if mutation == "lineage_rebound":
        reg["selected_source_lineage"]["selected_sources"][0][
            "original_request_sha256"
        ] = "5" * 64
        reg["selected_source_lineage_sha256"] = canonical_hash(
            reg["selected_source_lineage"]
        )
    elif mutation == "registration_hash":
        reg["planning_registration_sha256"] = "5" * 64
    elif mutation == "dispatch_receipt":
        reg["planning_dispatch_registration_receipt"]["planning_slot_ids"][0] = (
            "another-slot"
        )
        reg["planning_dispatch_registration_receipt_sha256"] = canonical_hash(
            reg["planning_dispatch_registration_receipt"]
        )
    elif mutation in {"reused_slot", "reused_incident"}:
        key = "planning_slot_id" if mutation == "reused_slot" else "incident_id"
        reg["trials"][1][key] = reg["trials"][0][key]
    elif mutation == "reused_branch":
        reg["trials"][1]["branches"][0] = deepcopy(reg["trials"][0]["branches"][0])
    elif mutation == "unknown_field":
        reg["admitted"] = True
    else:
        reg["distinct_case_count"] = 3
    with pytest.raises(ValueError):
        validate_registration(reg)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "ordinary",
        "live_diagnosis_reseal",
        "bounded_input_reseal",
        "lineage_swap",
        "admission_hash_rebound",
        "admission_request",
        "admission_epoch",
        "admission_authority",
        "admission_extra",
        "missing_seal_provenance",
        "wrong_seal",
        "resource_plan",
        "resource_incident",
        "resource_run",
        "resource_hash",
        "resource_state_rebound",
        "planning_request_rebound",
        "missing_retained",
        "resource_extra",
    ],
)
async def test_actual_live_source_binding_fails_before_first_dispatch(setup, mutation):
    from evidencesoc.agents.graph import _plan_hash

    store, clock, reg = setup
    source = approved_source(store, 0, clock)
    state = source["state"]
    if mutation == "ordinary":
        source["state"] = fixture_source()["state"]
    elif mutation in {"live_diagnosis_reseal", "bounded_input_reseal"}:
        if mutation == "live_diagnosis_reseal":
            state["diagnosis"]["evidence_ids"] = []
            state["diagnostic_snapshot"]["diagnosis"] = deepcopy(state["diagnosis"])
        else:
            state["knowledge"].append(
                {"knowledge_chunk_id": "synthetic-swapped-knowledge"}
            )
            state["diagnostic_snapshot"]["knowledge"] = deepcopy(state["knowledge"])
        state["diagnostic_snapshot_sha256"] = _plan_hash(state["diagnostic_snapshot"])
    elif mutation == "lineage_swap":
        state["analysis_import_provenance"] = approved_source(store, 1, clock)["state"][
            "analysis_import_provenance"
        ]
    elif mutation.startswith("admission_"):
        admission = state["analysis_import_provenance"]["planning_admission"]
        if mutation == "admission_hash_rebound":
            admission["selected_source_lineage"]["selected_sources"][0][
                "source_analysis_output_sha256"
            ] = "5" * 64
            admission["selected_source_lineage_sha256"] = canonical_hash(
                admission["selected_source_lineage"]
            )
        else:
            key = {
                "admission_request": "request_sha256",
                "admission_epoch": "epoch_id",
                "admission_authority": "authority_sha256",
                "admission_extra": "trusted",
            }[mutation]
            admission[key] = "5" * 64
        state["diagnostic_snapshot"]["analysis_import_provenance"] = deepcopy(
            state["analysis_import_provenance"]
        )
        state["diagnostic_snapshot_sha256"] = _plan_hash(state["diagnostic_snapshot"])
    elif mutation == "missing_seal_provenance":
        state["diagnostic_snapshot"].pop("analysis_import_provenance")
        state["diagnostic_snapshot_sha256"] = _plan_hash(state["diagnostic_snapshot"])
    elif mutation == "wrong_seal":
        state["diagnostic_snapshot"]["sealed_after"] = "reconstruct"
        state["diagnostic_snapshot_sha256"] = _plan_hash(state["diagnostic_snapshot"])
    elif mutation == "resource_hash":
        source["resources_sha256"] = "5" * 64
    elif mutation == "planning_request_rebound":
        source["planning_request"] = planning_requests(reg["planning_registration"])[
            1
        ].model_dump(mode="json")
    elif mutation == "missing_retained":
        source.pop("retained_state")
    else:
        resource = source["resources"]
        if mutation == "resource_state_rebound":
            source["retained_state"]["knowledge"].append({"forged": True})
            source["retained_state_sha256"] = canonical_hash(source["retained_state"])
            resource["state_sha256"] = canonical_hash(source["retained_state"])
        else:
            key = {
                "resource_plan": "plan_sha256",
                "resource_incident": "incident_id",
                "resource_run": "run_id",
                "resource_extra": "admitted",
            }[mutation]
            resource[key] = "5" * 64
        source["resources_sha256"] = canonical_hash(resource)
    called = []

    async def worker(request):
        called.append(request)
        raise AssertionError("invalid import dispatched")

    with pytest.raises(PermissionError):
        await store.run_trial(reg["trials"][0]["trial_id"], source, run_worker=worker)
    assert not called


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reuse", ["approval", "database", "index", "incident", "planning_slot"]
)
async def test_cross_trial_approval_incident_run_and_source_resource_reuse_rejected(
    setup, reuse
):
    store, clock, reg = setup

    async def worker(request):
        clock.advance(2)
        return value_for(request)

    first = approved_source(store, 0, clock)
    await store.run_trial(reg["trials"][0]["trial_id"], first, run_worker=worker)
    second = approved_source(store, 1, clock)
    if reuse == "approval":
        second["state"]["approval"]["approval_id"] = first["state"]["approval"][
            "approval_id"
        ]
    elif reuse in {"database", "index"}:
        # Both names are internally consistent; independent source reuse is the issue.
        for key in ("database_name", "index_name"):
            second["resources"][key] = first["resources"][key]
        second["resources_sha256"] = canonical_hash(second["resources"])
    elif reuse == "incident":
        second["state"]["incident_id"] = first["state"]["incident_id"]
    else:
        second["state"]["analysis_import_provenance"]["planning_admission"] = deepcopy(
            first["state"]["analysis_import_provenance"]["planning_admission"]
        )
    with pytest.raises(PermissionError):
        await store.run_trial(reg["trials"][1]["trial_id"], second, run_worker=worker)


@pytest.mark.asyncio
@pytest.mark.parametrize("host_proof", [None, "unknown"])
async def test_missing_independent_host_proof_never_completes_or_replays(
    setup, host_proof
):
    store, clock, reg = setup
    store.worker_lifecycle_verifier = (
        None if host_proof is None else lambda *a, **k: {"status": "unknown"}
    )
    called = []

    async def worker(request):
        called.append(request)
        clock.advance(2)
        return value_for(request)

    trial_id = reg["trials"][0]["trial_id"]
    source = approved_source(store, 0, clock)
    if host_proof is None:
        with pytest.raises(PermissionError, match="independent host"):
            await store.run_trial(trial_id, source, run_worker=worker)
        assert not called
    else:
        result = await store.run_trial(trial_id, source, run_worker=worker)
        assert result["complete_observed_trials"] == 0
        assert result["trials"][0]["status"] == "unknown"
        await store.run_trial(trial_id, source, run_worker=worker)
        assert len(called) == 1
    with pytest.raises(PermissionError, match="three"):
        store.export_timing_receipt()


def test_explicit_identity_timing_rejects_crossed_admission(tmp_path):
    from types import SimpleNamespace

    from evidencesoc.agents.graph import _plan_hash

    from evals.e_timing import _validate_replicate_source, build_e_timing_registration

    base = registration(tmp_path)
    planning = deepcopy(base["planning_registration"])
    reference = {"model_epoch_id": "model-1", "model_identity_sha256": "9" * 64}
    planning["core_config"]["model_identity"] = {
        "id": "model-1",
        "response_model": "synthetic",
        "fingerprint": "synthetic-fp",
    }
    planning["core_config_sha256"] = canonical_hash(planning["core_config"])
    planning["epoch_binding"]["model_identity_binding"] = reference
    dispatch = deepcopy(base["planning_dispatch_registration_receipt"])
    dispatch["registration_sha256"] = canonical_hash(planning)
    reg = build_e_timing_registration(
        planning,
        source_files=base["source_files"],
        f8_plan_sha256=base["f8_plan_sha256"],
        planning_dispatch_registration_receipt=dispatch,
    )
    clock = Clock()
    store = SimpleNamespace(
        registration=reg,
        identity={
            "campaign_id": reg["campaign_id"],
            "source_commit": reg["source_commit"],
            "source_sha256": canonical_hash(reg["source_files"]),
            "config_sha256": canonical_hash(reg["core_config"]),
        },
    )
    source = approved_source(store, 0, clock)
    _validate_replicate_source(reg, reg["trials"][0], source)
    for current in (source["state"], source["retained_state"]):
        current["analysis_import_provenance"]["planning_admission"][
            "model_identity_binding"
        ]["model_identity_sha256"] = "8" * 64
        current["diagnostic_snapshot"]["analysis_import_provenance"] = deepcopy(
            current["analysis_import_provenance"]
        )
        current["diagnostic_snapshot_sha256"] = _plan_hash(
            current["diagnostic_snapshot"]
        )
    with pytest.raises(PermissionError):
        _validate_replicate_source(reg, reg["trials"][0], source)
