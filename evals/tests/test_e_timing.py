"""Synthetic controller tests; no real approval, measured M, model, or container."""

from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from importlib import import_module, util
from uuid import uuid4

import pytest

from evals.contracts import canonical_hash
from evals.tests.test_verification_plan import fixture_source, persisted_receipt
from evals.tests.test_verification_v2 import worker_value

IMPORTED_KEYS = (
    "origin",
    "classification",
    "diagnosis",
    "alerts",
    "evidence",
    "knowledge",
    "attack_steps",
    "claims",
)


def imported_fixture_source():
    """Synthetic import shape only; neither original artifacts nor a real import."""
    from evidencesoc.agents.diagnosis import Diagnosis
    from evidencesoc.agents.graph import _seal_diagnosis

    source = fixture_source()
    state = source["state"]
    state["evidence"][0]["observed_at"] = "2026-10-22T00:00:00Z"
    state["origin"]["first_seen_at"] = "2026-10-22T00:00:00Z"
    state.update(
        diagnosis=Diagnosis(
            verdict="attack",
            taxonomy_status="out_of_taxonomy",
            evidence_ids=[state["evidence"][0]["evidence_id"]],
        ).model_dump(mode="json"),
        alerts=[],
        attack_steps=[],
        claims=[],
        diagnostic_snapshot=None,
    )
    state.update(_seal_diagnosis(state, "analysis_import"))
    return source


def module():
    assert util.find_spec("evals.e_timing"), (
        "independent E bootstrap controller missing"
    )
    return import_module("evals.e_timing")


class Clock:
    def __init__(self):
        self.utc = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
        self.ns = 1_000_000_000

    def now(self):
        return self.utc

    def monotonic_ns(self):
        return self.ns

    def advance(self, seconds, *, utc_seconds=None):
        self.utc += timedelta(seconds=seconds if utc_seconds is None else utc_seconds)
        self.ns += int(seconds * 1_000_000_000)


def selection():
    state = imported_fixture_source()["state"]
    values = {key: state[key] for key in IMPORTED_KEYS}
    analysis = {key: values[key] for key in ("origin", "classification", "diagnosis")}
    rows = [
        {
            "source_row_id": f"synthetic-row-{i}",
            "order_index": i,
            "case_id": "ait-" + "0" * 24,
            "dataset": "ait",
            "agent_sha256": "c" * 64,
            "manifest_sha256": str(i % 10) * 64,
            "request_sha256": "d" * 64,
            "analysis_output_sha256": canonical_hash(analysis),
            "imported_values_sha256": canonical_hash(values),
            "status": "selected" if i < 3 else "rejected",
            "source_status": "completed",
            "reason": None if i < 3 else "benign",
        }
        for i in range(36)
    ]
    rule = "first-three-qualified-original-36-v1"
    return {
        "schema_version": "task13-analysis-source-selection-v1",
        "rule": rule,
        "rule_sha256": canonical_hash(rule),
        "status": "selected",
        "original_bundle_sha256": "b" * 64,
        "rows": rows,
        "selected_sources": deepcopy(rows[:3]),
        "related_case_duplicates": [
            {
                "case_id": rows[0]["case_id"],
                "source_row_ids": [row["source_row_id"] for row in rows[:3]],
            }
        ],
    }


def registration(tmp_path):
    source_file = tmp_path / "synthetic-runtime.py"
    source_file.write_text("# synthetic only\n", encoding="utf-8")
    source_files = {
        str(source_file): import_module("hashlib")
        .sha256(source_file.read_bytes())
        .hexdigest()
    }
    selected = selection()
    return {
        "schema_version": "task13-e-timing-registration-v1",
        "synthetic": True,
        "campaign_id": "task13-repair-202610-v2",
        "mode": "bootstrap",
        "source_commit": "a" * 40,
        "source_files": source_files,
        "core_config": {"synthetic": True, "f8_plan_sha256": "f" * 64},
        "f8_plan_sha256": "f" * 64,
        "budget_source_receipt_sha256": "e" * 64,
        "source_selection_receipt": selected,
        "source_selection_receipt_sha256": canonical_hash(selected),
        "trials": [
            {
                "trial_id": uuid4().hex,
                **{
                    key: row[key]
                    for key in (
                        "source_row_id",
                        "case_id",
                        "dataset",
                        "agent_sha256",
                        "manifest_sha256",
                        "request_sha256",
                        "analysis_output_sha256",
                        "imported_values_sha256",
                    )
                },
                "branches": [
                    {
                        "request_id": uuid4().hex,
                        "namespace": uuid4().hex,
                        "condition": condition,
                        "verification_enabled": enabled,
                    }
                    for condition in ("success", "failure", "no_change")
                    for enabled in (True, False)
                ],
            }
            for row in selected["selected_sources"]
        ],
    }


def approved_source(store, index, clock, *, remaining=1740, ttl=1800):
    source = imported_fixture_source()
    trial = store.registration["trials"][index]
    state = source["state"]
    state["analysis_import_provenance"] = {
        "schema_version": "task13-analysis-import-provenance-v1",
        "entry": "analysis_import",
        **{
            key: trial[key]
            for key in (
                "source_row_id",
                "case_id",
                "dataset",
                "agent_sha256",
                "manifest_sha256",
                "request_sha256",
                "analysis_output_sha256",
                "imported_values_sha256",
            )
        },
        "order_index": index,
        "source_run_id": f"synthetic-analysis-run-{index}",
        "source_commit": "b" * 40,
        "source_sha256": "0" * 64,
        "original_analysis_at": "2026-10-22T00:01:00Z",
        "successful_physical_request_id": f"synthetic-analysis-physical-{index}",
        "replay_validation_source_sha256": {},
        "original_source_receipt_sha256": "0" * 64,
        "original_validation_source_sha256": {},
        "original_validator_equivalence": "ast-with-fixed-scope-tuple-v1",
        "reconstruct_executed": False,
        "artifacts": {},
    }
    state["approval"].update(
        approval_id=f"AP-synthetic-E-{index}",
        decided_by="user",
        decided_at=(clock.now() - timedelta(seconds=1)).isoformat(),
    )
    state["response_plan"].update(
        created_at=(clock.now() + timedelta(seconds=remaining - ttl)).isoformat(),
        expires_at=(clock.now() + timedelta(seconds=remaining)).isoformat(),
    )
    from evidencesoc.agents.graph import _plan_hash

    plan_hash = _plan_hash(state["response_plan"])
    state.update(approved_plan_sha256=plan_hash, approved_plan_version=plan_hash)
    state["simulation_execution"]["plan_version"] = plan_hash
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
        source_row_id=trial["source_row_id"],
        case_id=trial["case_id"],
        dataset=trial["dataset"],
        analysis_manifest_sha256=trial["manifest_sha256"],
        budget_source_receipt_sha256=store.registration["budget_source_receipt_sha256"],
    )
    return source


def admit(identity):
    return {
        "schema_version": "task13-v2-execution-gate-v1",
        "status": "verified",
        **identity,
    }


async def verify(source):
    return persisted_receipt(source["state"])


def lifecycle(request, *, timed_out):
    """Synthetic host fixture; worker self-report is never trusted by controller."""
    return {
        "schema_version": "task13-host-worker-termination-v1",
        "status": "verified",
        "request_sha256": canonical_hash(request),
        "host_process_exited": True,
        "container_absent": True,
        "container_id": request.namespace,
        "worker_nonce": request.request_id,
        "receipt_binding_sha256": "9" * 64,
    }


@pytest.fixture
def setup(tmp_path):
    m, clock = module(), Clock()
    reg = registration(tmp_path)
    store = m.ETimingCampaign(
        reg,
        tmp_path / "synthetic-E",
        execution_admitter=admit,
        approval_verifier=verify,
        worker_lifecycle_verifier=lifecycle,
        now=clock.now,
        monotonic_ns=clock.monotonic_ns,
    )
    return m, store, clock, reg


def test_first_trial_has_no_observed_max_and_two_cannot_export(setup):
    _, store, _, _ = setup
    assert store.snapshot()["observed_max_seconds"] is None
    assert store.snapshot()["complete_observed_trials"] == 0
    with pytest.raises(PermissionError, match="three"):
        store.export_timing_receipt()


def value_for(request):
    result = worker_value(request)
    result["isolation_evidence"]["container"]["container_id"] = request.namespace
    result["isolation_evidence"]["probe"]["nonce"] = request.request_id
    result["resource_receipt"]["worker_nonce"] = request.request_id
    return result


@pytest.mark.asyncio
async def test_ordinary_approved_source_with_top_level_annotations_cannot_dispatch(
    setup,
):
    """A live approval verifier cannot prove that a diagnosis was imported."""
    _, store, clock, reg = setup
    source = approved_source(store, 0, clock)
    source["state"] = fixture_source()["state"]
    called = []

    async def worker(request):
        called.append(request)
        clock.advance(2)
        return value_for(request)

    with pytest.raises(PermissionError, match="import|source"):
        await store.run_trial(reg["trials"][0]["trial_id"], source, run_worker=worker)
    assert not called


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "missing_provenance",
        "another_selected_source",
        "entry",
        "source_row_id",
        "order_index",
        "case_id",
        "dataset",
        "agent_sha256",
        "request_sha256",
        "manifest_sha256",
        "analysis_output_sha256",
        "imported_values_sha256",
        "ordinary_seal",
        "seal_hash",
        "live_diagnosis",
        "live_origin",
        "live_classification",
        "resealed_diagnosis",
        "resealed_evidence",
        "resealed_knowledge",
    ],
)
async def test_import_lineage_and_original_content_are_checked_before_dispatch(
    setup, mutation
):
    _, store, clock, reg = setup
    source = approved_source(store, 0, clock)
    state = source["state"]
    provenance = state["analysis_import_provenance"]
    if mutation == "missing_provenance":
        state.pop("analysis_import_provenance")
    elif mutation == "another_selected_source":
        state["analysis_import_provenance"] = approved_source(store, 1, clock)["state"][
            "analysis_import_provenance"
        ]
    elif mutation in provenance:
        provenance[mutation] = 99 if mutation == "order_index" else "wrong-source"
    elif mutation == "ordinary_seal":
        state["diagnostic_snapshot"]["sealed_after"] = "reconstruct"
    elif mutation == "seal_hash":
        state["diagnostic_snapshot_sha256"] = "0" * 64
    else:
        if mutation.endswith("diagnosis"):
            state["diagnosis"]["claims"].append(
                {
                    "claim_id": "invented",
                    "text": "Different original analysis",
                    "evidence_ids": [],
                }
            )
        elif mutation.endswith("origin"):
            state["origin"]["confidence"] = 0.4
        elif mutation.endswith("classification"):
            state["classification"]["confidence"] = 0.4
        elif mutation.endswith("evidence"):
            state["evidence"][0]["raw"]["message"] = "Different source evidence"
        else:
            state["knowledge"].append({"chunk_id": "invented"})
        if mutation.startswith("resealed"):
            from evidencesoc.agents.graph import _seal_diagnosis

            state["diagnostic_snapshot"] = None
            state.update(_seal_diagnosis(state, "analysis_import"))

    called, verified = [], []

    async def trusted_approval_verifier(current):
        verified.append(current)
        return persisted_receipt(current["state"])

    async def worker(request):
        called.append(request)
        clock.advance(2)
        return value_for(request)

    with pytest.raises(PermissionError, match="import|source|seal|analysis"):
        await store.run_trial(
            reg["trials"][0]["trial_id"],
            source,
            run_worker=worker,
            approval_verifier=trusted_approval_verifier,
        )
    assert not called
    assert not verified


@pytest.mark.parametrize(
    "field", ["request_sha256", "analysis_output_sha256", "imported_values_sha256"]
)
def test_missing_trusted_original_digest_cannot_be_registered(tmp_path, field):
    m, reg = module(), registration(tmp_path)
    for row in reg["source_selection_receipt"]["rows"]:
        row.pop(field)
    for row in reg["source_selection_receipt"]["selected_sources"]:
        row.pop(field)
    for trial in reg["trials"]:
        trial.pop(field)
    reg["source_selection_receipt_sha256"] = canonical_hash(
        reg["source_selection_receipt"]
    )
    with pytest.raises(ValueError, match="source|hash|digest"):
        m.validate_registration(reg)


@pytest.mark.parametrize(
    "field", ["request_sha256", "analysis_output_sha256", "imported_values_sha256"]
)
def test_original_digests_must_match_rows_selection_and_trial(tmp_path, field):
    m, reg = module(), registration(tmp_path)
    reg["source_selection_receipt"]["selected_sources"][0][field] = "9" * 64
    reg["trials"][0][field] = "9" * 64
    reg["source_selection_receipt_sha256"] = canonical_hash(
        reg["source_selection_receipt"]
    )
    with pytest.raises(ValueError, match="first three|source"):
        m.validate_registration(reg)


@pytest.mark.asyncio
async def test_three_synthetic_trials_export_original_parser_format(setup):
    _m, store, clock, reg = setup
    requests = []

    async def worker(request):
        requests.append(request)
        clock.advance(5)
        return value_for(request)

    for index in range(3):
        result = await store.run_trial(
            reg["trials"][index]["trial_id"],
            approved_source(store, index, clock),
            run_worker=worker,
        )
        assert result["trials"][index]["status"] == "completed"
        if index < 2:
            with pytest.raises(PermissionError, match="three"):
                store.export_timing_receipt()
    receipt = store.export_timing_receipt()
    assert receipt["synthetic"] is True
    assert (
        import_module("evals.verification_v2").observed_six_branch_max(
            receipt, store.identity
        )
        == 30
    )
    assert (
        len({r.request_id for r in requests})
        == len({r.namespace for r in requests})
        == 18
    )
    for offset in range(0, 18, 6):
        batch = requests[offset : offset + 6]
        assert [r.verification_enabled for r in batch] == [True, False] * 3
        assert len({r.approval_receipt_sha256 for r in batch}) == 1
        for branch in range(0, 6, 2):
            assert batch[branch].observations == batch[branch + 1].observations
    assert not list(store.root.glob("final-freeze*"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "remaining,ttl,reason",
    [
        (1500, 1800, "bootstrap_remaining"),
        (1499, 1800, "bootstrap_remaining"),
        (1740, 1799, "plan_ttl"),
    ],
)
async def test_bootstrap_boundaries_preserve_rejected_trial_without_dispatch(
    setup, remaining, ttl, reason
):
    _, store, clock, reg = setup
    called = []

    async def worker(request):
        called.append(request)

    result = await store.run_trial(
        reg["trials"][0]["trial_id"],
        approved_source(store, 0, clock, remaining=remaining, ttl=ttl),
        run_worker=worker,
    )
    assert not called
    assert reason in result["trials"][0]["reason"]
    assert result["trials"][0]["status"] == "rejected"


@pytest.mark.asyncio
async def test_provisional_remaining_equality_is_rejected(setup):
    _, store, clock, reg = setup

    async def slow(request):
        clock.advance(150)
        return value_for(request)

    await store.run_trial(
        reg["trials"][0]["trial_id"], approved_source(store, 0, clock), run_worker=slow
    )
    assert store.snapshot()["observed_max_seconds"] == 900
    result = await store.run_trial(
        reg["trials"][1]["trial_id"],
        approved_source(store, 1, clock, remaining=1650),
        run_worker=slow,
    )
    assert result["trials"][1]["status"] == "rejected"
    assert result["trials"][1]["reason"] == "provisional_remaining"


@pytest.mark.asyncio
async def test_partial_unknown_is_never_replayed_or_stitched(setup):
    _, store, clock, reg = setup
    called = []

    async def worker(request):
        called.append(request)
        if len(called) == 4:
            raise RuntimeError("synthetic lost result")
        clock.advance(2)
        return value_for(request)

    source = approved_source(store, 0, clock)
    trial = reg["trials"][0]["trial_id"]
    result = await store.run_trial(trial, source, run_worker=worker)
    assert result["trials"][0]["status"] == "unknown"
    await store.run_trial(trial, source, run_worker=worker)
    assert len(called) == 4
    changed = deepcopy(source)
    changed["state"]["approval"]["approval_id"] += "renewed"
    with pytest.raises(PermissionError, match="source|stitch"):
        await store.run_trial(trial, changed, run_worker=worker)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [
        "timeout",
        "expired",
        "clock_inconsistent",
        "resource_reuse",
        "model_called",
        "nonzero_cost",
        "termination_unknown",
    ],
)
async def test_invalid_branch_cannot_be_timing_evidence(setup, kind):
    _, store, clock, reg = setup
    called, previous = [], None
    if kind == "termination_unknown":
        store.worker_lifecycle_verifier = lambda request, **kwargs: {
            "status": "unknown"
        }

    async def worker(request):
        nonlocal previous
        called.append(request)
        result = value_for(request)
        if kind == "timeout":
            clock.advance(181)
        elif kind == "expired":
            clock.advance(2, utc_seconds=1800)
        elif kind == "clock_inconsistent":
            clock.advance(2, utc_seconds=5)
        else:
            clock.advance(2)
        if kind == "model_called":
            result["model_ledger"] = [{"synthetic": True}]
        if kind == "nonzero_cost":
            result["cost"] = 1
        if kind == "resource_reuse" and previous:
            result["resource_receipt"]["database_name"] = previous["resource_receipt"][
                "database_name"
            ]
        previous = result
        return result

    result = await store.run_trial(
        reg["trials"][0]["trial_id"],
        approved_source(store, 0, clock),
        run_worker=worker,
    )
    assert result["trials"][0]["status"] != "completed"
    assert result["complete_observed_trials"] == 0
    with pytest.raises(PermissionError):
        store.export_timing_receipt()


@pytest.mark.asyncio
async def test_hard_timeout_cancels_task_and_requires_host_proof(setup, monkeypatch):
    m, store, clock, reg = setup
    cancelled = []
    real_wait = asyncio.wait

    async def fast_wait(tasks, *, timeout):
        return await real_wait(tasks, timeout=min(timeout, 0.005))

    monkeypatch.setattr(m.asyncio, "wait", fast_wait)

    async def hanging(request):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(request.request_id)

    result = await store.run_trial(
        reg["trials"][0]["trial_id"],
        approved_source(store, 0, clock),
        run_worker=hanging,
    )
    assert len(cancelled) == 1
    assert result["trials"][0]["reason"] == "worker_timeout"
    assert result["trials"][0]["status"] == "failed"


@pytest.mark.asyncio
async def test_late_receipt_does_not_complete_unknown_trial(setup):
    _, store, clock, reg = setup
    called = []

    async def lost(request):
        called.append(request)
        raise RuntimeError("synthetic crash")

    source = approved_source(store, 0, clock)
    await store.run_trial(reg["trials"][0]["trial_id"], source, run_worker=lost)
    clock.advance(1800)
    result = await store.merge_result(called[0].request_id, value_for(called[0]))
    assert result["trials"][0]["status"] != "completed"
    assert result["records"][0]["status"] == "expired"
    assert len(called) == 1


def test_registration_rejects_resource_slot_reuse_bad_selection_and_mutable_m(
    setup, tmp_path
):
    m, _, clock, reg = setup
    for mutation in (
        "reused_request",
        "reused_namespace",
        "wrong_first_three",
        "fake_m",
    ):
        bad = deepcopy(reg)
        if mutation == "reused_request":
            bad["trials"][1]["branches"][0]["request_id"] = bad["trials"][0][
                "branches"
            ][0]["request_id"]
        elif mutation == "reused_namespace":
            bad["trials"][1]["branches"][0]["namespace"] = bad["trials"][0]["branches"][
                0
            ]["namespace"]
        elif mutation == "wrong_first_three":
            bad["source_selection_receipt"]["selected_sources"].reverse()
            bad["source_selection_receipt_sha256"] = canonical_hash(
                bad["source_selection_receipt"]
            )
        else:
            bad["observed_max_seconds"] = 0
        with pytest.raises((ValueError, PermissionError)):
            m.ETimingCampaign(bad, tmp_path / mutation, now=clock.now)


@pytest.mark.asyncio
async def test_approval_ids_independent_and_execution_gates_mandatory(setup):
    _, store, clock, reg = setup

    async def worker(request):
        clock.advance(2)
        return value_for(request)

    await store.run_trial(
        reg["trials"][0]["trial_id"],
        approved_source(store, 0, clock),
        run_worker=worker,
    )
    source = approved_source(store, 1, clock)
    source["state"]["approval"]["approval_id"] = "AP-synthetic-E-0"
    with pytest.raises(PermissionError, match="independent"):
        await store.run_trial(reg["trials"][1]["trial_id"], source, run_worker=worker)
    store.execution_admitter = None
    with pytest.raises(PermissionError, match="execution"):
        await store.run_trial(
            reg["trials"][1]["trial_id"],
            approved_source(store, 1, clock),
            run_worker=worker,
        )


def test_lock_source_config_and_journal_tampering_are_rejected(setup):
    _, store, _, _ = setup
    lock = store.root / ".writer-lock"
    lock.mkdir()
    with pytest.raises(PermissionError, match="writer|stale"):
        store.snapshot()
    lock.rmdir()
    store.registration["core_config"]["changed"] = True
    with pytest.raises(PermissionError, match="registration|config"):
        store.snapshot()
    store.registration["core_config"].pop("changed")
    path = next(iter(store.registration["source_files"]))
    from pathlib import Path

    Path(path).write_text("# drift\n", encoding="utf-8")
    with pytest.raises(PermissionError, match="source"):
        store.snapshot()
    Path(path).write_text("# synthetic only\n", encoding="utf-8")
    event = next((store.root / "events").glob("*.json"))
    value = json.loads(event.read_text(encoding="utf-8"))
    value["previous_sha256"] = "bad"
    event.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(PermissionError, match="journal"):
        store.snapshot()


@pytest.mark.asyncio
async def test_crash_after_durable_dispatch_recovers_unknown_without_replay(setup):
    m, store, clock, reg = setup
    seen = []

    class SimulatedPowerLoss(BaseException):
        pass

    async def crash(request):
        seen.append(request)
        raise SimulatedPowerLoss()

    source = approved_source(store, 0, clock)
    with pytest.raises(SimulatedPowerLoss):
        await store.run_trial(reg["trials"][0]["trial_id"], source, run_worker=crash)
    assert any(
        event["payload"]["kind"] == "branch.dispatched" for event in store.events
    )
    reopened = m.ETimingCampaign(
        reg,
        store.root,
        execution_admitter=admit,
        approval_verifier=verify,
        worker_lifecycle_verifier=lifecycle,
        now=clock.now,
        monotonic_ns=clock.monotonic_ns,
    )
    result = await reopened.run_trial(
        reg["trials"][0]["trial_id"], source, run_worker=crash
    )
    assert len(seen) == 1
    assert result["trials"][0]["status"] == "unknown"


@pytest.mark.asyncio
async def test_trial_start_equals_first_dispatch_and_unknown_output_is_preserved(setup):
    _, store, clock, reg = setup
    # Disk/validation time must be included from the durable first dispatch.
    original_save = store._save

    def slow_save(category, value):
        clock.advance(0.05)
        return original_save(category, value)

    store._save = slow_save

    async def worker(request):
        clock.advance(2)
        return value_for(request)

    result = await store.run_trial(
        reg["trials"][0]["trial_id"],
        approved_source(store, 0, clock),
        run_worker=worker,
    )
    trial = result["trials"][0]
    rows = result["records"][:6]
    assert trial["started_at"] == rows[0]["dispatched_at"]
    assert trial["started_monotonic_ns"] == rows[0]["dispatched_monotonic_ns"]
    assert trial["completed_at"] == rows[-1]["completed_at"]
    store.worker_lifecycle_verifier = lambda request, **kwargs: {"status": "unknown"}
    result = await store.run_trial(
        reg["trials"][1]["trial_id"],
        approved_source(store, 1, clock),
        run_worker=worker,
    )
    assert result["records"][6]["output_sha256"]


def test_prepare_approval_only_in_window_and_never_decides(setup):
    _, store, clock, reg = setup
    source = approved_source(store, 0, clock)
    clock.utc = clock.utc.replace(hour=10)
    with pytest.raises(PermissionError, match="19:00"):
        store.prepare_approval(reg["trials"][0]["trial_id"], source)
    clock.utc = clock.utc.replace(hour=12)
    before = deepcopy(source)
    packet = store.prepare_approval(reg["trials"][0]["trial_id"], source)
    assert source == before
    assert packet["reviewer"] == "user"
    assert store.snapshot()["trials"][0]["status"] == "not_started"


@pytest.mark.asyncio
async def test_no_zero_duration_or_unverified_host_can_export(setup):
    _, store, clock, reg = setup

    async def instant(request):
        return value_for(request)

    result = await store.run_trial(
        reg["trials"][0]["trial_id"],
        approved_source(store, 0, clock),
        run_worker=instant,
    )
    assert result["trials"][0]["status"] == "failed"
    assert result["observed_max_seconds"] is None


@pytest.mark.asyncio
async def test_fourth_branch_expiry_preserves_first_three_and_remaining_slots(setup):
    _, store, clock, reg = setup
    called = []

    async def worker(request):
        called.append(request)
        clock.advance(2, utc_seconds=1800 if len(called) == 4 else 2)
        return value_for(request)

    result = await store.run_trial(
        reg["trials"][0]["trial_id"],
        approved_source(store, 0, clock),
        run_worker=worker,
    )
    assert [row["status"] for row in result["records"][:6]] == ["completed"] * 3 + [
        "expired",
        "not_started",
        "not_started",
    ]
    assert result["trials"][0]["status"] == "expired"
    assert len(called) == 4


@pytest.mark.asyncio
async def test_trial_deadline_includes_interbranch_approval_work(setup):
    _, store, clock, reg = setup
    called, verification_reads = [], 0

    async def delayed_verifier(source):
        nonlocal verification_reads
        verification_reads += 1
        if verification_reads == 3:
            clock.advance(1200)
        return persisted_receipt(source["state"])

    store.approval_verifier = delayed_verifier

    async def worker(request):
        called.append(request)
        clock.advance(2)
        return value_for(request)

    result = await store.run_trial(
        reg["trials"][0]["trial_id"],
        approved_source(store, 0, clock),
        run_worker=worker,
    )
    assert result["trials"][0]["status"] == "failed"
    assert result["trials"][0]["reason"] == "trial_hard_deadline"
    assert len(called) == 1


@pytest.mark.asyncio
async def test_real_host_verifier_adapter_accepts_only_bound_synthetic_host_capture(
    setup, tmp_path, monkeypatch
):
    """Uses real host verifier/capture code with synthetic Docker/process replies."""
    from types import SimpleNamespace

    from evals import worker_lifecycle as host

    _, store, clock, reg = setup
    directory = tmp_path / "synthetic-host-receipts"
    directory.mkdir()
    store.worker_lifecycle_verifier = host.HostWorkerLifecycleVerifier(directory)

    async def empty():
        return b"", b""

    async def spawn(*args, **kwargs):
        return SimpleNamespace(returncode=0, communicate=empty)

    monkeypatch.setattr(host.asyncio, "create_subprocess_exec", spawn)

    async def worker(request):
        clock.advance(2)
        result = value_for(request)
        container_id = request.namespace * 2
        result["isolation_evidence"]["container"]["container_id"] = container_id
        await host.capture_worker_termination(
            process=SimpleNamespace(returncode=0),
            name="task13-worker-" + request.request_id,
            nonce=request.request_id,
            container_id=container_id,
            request_sha256=canonical_hash(request),
            source_commit=store.identity["source_commit"],
            environment={},
            receipt_dir=directory,
        )
        return result

    result = await store.run_trial(
        reg["trials"][0]["trial_id"],
        approved_source(store, 0, clock),
        run_worker=worker,
    )
    assert result["trials"][0]["status"] == "completed"
    for row in result["records"][:6]:
        evidence = store._blob("host-receipts", row["host_receipt_sha256"])
        assert (
            evidence["resource_cleanup"] == "not_established_by_container_termination"
        )
