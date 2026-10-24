"""Synthetic offline contracts only: no real approval, worker, or F8 coverage."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from importlib import import_module, util
from uuid import uuid4

import pytest

from evals.contracts import canonical_hash
from evals.tests.test_verification_plan import cases, fixture_source, persisted_receipt

CAMPAIGN = "task13-repair-202610-v2"


def module():
    assert util.find_spec("evals.verification_v2"), "independent rolling v2 is missing"
    return import_module("evals.verification_v2")


def registration():
    legacy = import_module("evals.verification").build_verification_plan(cases())
    legacy.update(
        schema_version="task13-v2-f8-candidate-registration-v1",
        campaign_id=CAMPAIGN,
        executable=False,
        plan_ttl_minutes=30,
        one_pending_approval_max=1,
        minimum_complete_ait_cases=4,
        minimum_complete_dedale_cases=4,
        minimum_complete_pairs=24,
        minimum_real_approvals=8,
    )
    for index, slot in enumerate(legacy["slots"]):
        slot.update(
            sequence=index + 1,
            case_order=index // 3 + 1,
            status="not_started",
            plan_id=None,
            plan_sha256=None,
            approval_id=None,
        )
        for branch in slot["branches"]:
            branch.update(
                branch_id="f8-branch-" + uuid4().hex[:24],
                status="not_started",
                dispatched_at=None,
                output_sha256=None,
            )
    legacy["order_sha256"] = canonical_hash(
        [
            (
                slot["case_id"],
                slot["condition"],
                [branch["branch"] for branch in slot["branches"]],
            )
            for slot in legacy["slots"]
        ]
    )
    return legacy


def worker_value(request, *, suffix=None):
    """Claim-shaped synthetic data, never live isolation evidence."""
    suffix, nonce = suffix or uuid4().hex, uuid4().hex
    measured = next(iter(request.observations.values()))
    outcome = (
        (
            "failure"
            if measured.after.error_code
            else "success"
            if measured.after.network_blocked
            else "insufficient_evidence"
        )
        if request.verification_enabled
        else "unverified"
    )
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
        "verification_call_count": int(request.verification_enabled),
        "verification_attempts": int(request.verification_enabled),
        "cost": 0,
        "resource_receipt": {
            "database_name": "task13_" + suffix,
            "index_name": "security-events-task13-" + suffix,
            "worker_nonce": nonce,
            "checkpoint_id": uuid4().hex,
            "trace_id": "TRACE-" + request.namespace,
            "evidence_namespace": request.namespace,
        },
        "isolation_evidence": {
            "status": "passed",
            "source_commit": "a" * 40,
            "container": {
                "container_id": uuid4().hex,
                "hostname": suffix,
                "private_pid_namespace": True,
                "root_read_only": True,
            },
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


@pytest.fixture
def setup(tmp_path):
    m = module()
    source_file = tmp_path / "synthetic-source.py"
    source_file.write_text("# synthetic offline source\n", encoding="utf-8")
    plan = registration()
    options = {
        "source_commit": "a" * 40,
        "source_files": {str(source_file): m.file_sha256(source_file)},
        "config": {"fixture_description": "synthetic offline only"},
        "execution_admitter": synthetic_execution_admitter,
    }
    store = m.VerificationCampaign(plan, tmp_path / "journal", **options)
    source = fixture_source()
    source["state"]["approval"]["decided_by"] = "user"
    source.update(
        campaign_id=CAMPAIGN,
        case_id=cases()[0]["case_id"],
        dataset="ait",
        source_commit=options["source_commit"],
        source_sha256=store.identity["source_sha256"],
        config_sha256=store.identity["config_sha256"],
    )
    now = datetime.now(UTC)
    return m, store, source, now, plan, options


async def verifier(source):
    return persisted_receipt(source["state"])


def synthetic_execution_admitter(identity):
    """Injected offline evidence, not an authorization or measured gate result."""
    return {
        "schema_version": "task13-v2-execution-gate-v1",
        "status": "verified",
        **identity,
    }


def timing(store, source, now, *, durations=(30, 40, 50)):
    """Synthetic E-receipt shape only; no trial actually ran."""
    old = import_module("evals.verification")
    request_type = import_module(
        "evals.adapters.verification_worker"
    ).VerificationWorkerRequest
    trials = []
    for index, duration in enumerate(durations):
        current = deepcopy(source)
        current["state"]["approval"]["approval_id"] = f"AP-synthetic-trial-{index}"
        start = now - timedelta(minutes=10, seconds=index * 100)
        trial_state = current["state"]
        trial_state["response_plan"]["created_at"] = (
            start - timedelta(seconds=60)
        ).isoformat()
        trial_state["response_plan"]["expires_at"] = (
            start + timedelta(minutes=29)
        ).isoformat()
        from evidencesoc.agents.graph import _plan_hash

        trial_hash = _plan_hash(trial_state["response_plan"])
        trial_state.update(
            approved_plan_sha256=trial_hash, approved_plan_version=trial_hash
        )
        trial_state["simulation_execution"]["plan_version"] = trial_hash
        trial_state["approval"]["decided_at"] = (
            start - timedelta(seconds=1)
        ).isoformat()
        receipt = persisted_receipt(current["state"])
        branches = []
        for branch_index in range(6):
            request = request_type(
                request_id=uuid4().hex,
                namespace=uuid4().hex,
                case_id=current["case_id"],
                agent_sha256="c" * 64,
                source_state_sha256=canonical_hash(current["state"]),
                approved_plan_sha256=current["state"]["approved_plan_sha256"],
                approval_receipt=receipt,
                approval_receipt_sha256=canonical_hash(receipt),
                approved_state=current["state"],
                source_resources=current["resources"],
                verification_enabled=branch_index % 2 == 0,
                observations=old._measurements(
                    current["state"], old.CONDITIONS[branch_index // 2], start
                ),
            )
            branches.append(
                {
                    "request": request.model_dump(mode="json"),
                    "result": worker_value(request),
                    "dispatched_at": (
                        start + timedelta(seconds=duration * branch_index / 6)
                    ).isoformat(),
                    "completed_at": (
                        start + timedelta(seconds=duration * (branch_index + 1) / 6)
                    ).isoformat(),
                }
            )
        trials.append({"trial_id": uuid4().hex, "branches": branches})
    return {
        "schema_version": "task13-v2-six-branch-timing-v1",
        **store.identity,
        "trials": trials,
    }


def records_for(result, source):
    return [row for row in result["records"] if row["case_id"] == source["case_id"]]


def test_registration_preserves_complete_denominators_and_rejects_v1(tmp_path):
    m = module()
    with pytest.raises(ValueError, match="v2|campaign"):
        m.validate_registration(
            import_module("evals.verification").build_verification_plan(cases())
        )
    plan = registration()
    m.validate_registration(plan)
    plan["slots"].pop()
    with pytest.raises(ValueError, match="264|528"):
        m.validate_registration(plan)


def test_initial_snapshot_is_all_264_pairs_528_branches_without_claimed_coverage(setup):
    _, store, _, _, _, _ = setup
    result = store.snapshot()
    assert len(result["planned_slots"]) == 264
    assert len(result["records"]) == 528
    assert {row["status"] for row in result["records"]} == {"not_started"}
    assert result["coverage"] == {
        "complete_ait_cases": 0,
        "complete_dedale_cases": 0,
        "complete_pairs": 0,
        "approved_cases": 0,
        "minimum_met": False,
        "minimum_required": {
            "ait_cases": 4,
            "dedale_cases": 4,
            "pairs": 24,
            "real_approvals": 8,
        },
    }


@pytest.mark.asyncio
async def test_six_branches_share_real_contract_bindings_and_resume_idempotently(setup):
    m, store, source, now, plan, options = setup
    requests = []

    async def worker(request):
        requests.append(request)
        return worker_value(request)

    result = await store.run_case(
        source["case_id"],
        source,
        worker=worker,
        approval_verifier=verifier,
        timing_receipt=timing(store, source, now),
        now=lambda: now,
    )
    assert len(requests) == 6
    assert all(row["status"] == "completed" for row in records_for(result, source))
    assert len({request.source_state_sha256 for request in requests}) == 1
    assert len({request.approval_receipt_sha256 for request in requests}) == 1
    assert len({request.approved_plan_sha256 for request in requests}) == 1
    assert len({request.namespace for request in requests}) == 6
    assert all(
        not {"condition", "truth", "branch", "expected_outcome"}
        & request.model_dump().keys()
        for request in requests
    )
    restored = m.VerificationCampaign(plan, store.root, **options)
    again = await restored.run_case(
        source["case_id"],
        source,
        worker=worker,
        approval_verifier=verifier,
        timing_receipt=None,
        now=lambda: now,
    )
    assert again == result
    assert len(requests) == 6
    assert result["coverage"]["complete_pairs"] == 3
    assert result["coverage"]["complete_ait_cases"] == 1
    assert result["coverage"]["minimum_met"] is False


@pytest.mark.asyncio
async def test_ttl_guard_is_strict_and_missing_timing_never_dispatches(setup):
    _, store, source, now, _, _ = setup
    calls = []

    async def worker(request):
        calls.append(request)
        return worker_value(request)

    with pytest.raises(PermissionError, match="timing"):
        await store.run_case(
            source["case_id"],
            source,
            worker=worker,
            approval_verifier=verifier,
            timing_receipt=None,
            now=lambda: now,
        )
    expires = datetime.fromisoformat(source["state"]["response_plan"]["expires_at"])
    boundary = expires - timedelta(seconds=375)
    with pytest.raises(PermissionError, match="TTL"):
        await store.run_case(
            source["case_id"],
            source,
            worker=worker,
            approval_verifier=verifier,
            timing_receipt=timing(store, source, now),
            now=lambda: boundary,
        )
    assert calls == []
    assert {row["status"] for row in records_for(store.snapshot(), source)} == {
        "not_started"
    }
    await store.run_case(
        source["case_id"],
        source,
        worker=worker,
        approval_verifier=verifier,
        timing_receipt=timing(store, source, now),
        now=lambda: boundary - timedelta(microseconds=1),
    )
    assert len(calls) == 6


@pytest.mark.asyncio
@pytest.mark.parametrize("crash", [RuntimeError, SystemExit])
async def test_dispatched_exception_stays_unknown_and_is_never_automatically_replayed(
    setup, crash
):
    m, store, source, now, plan, options = setup
    calls = []

    async def worker(request):
        calls.append(request)
        raise crash("synthetic interruption")

    if crash is SystemExit:
        with pytest.raises(SystemExit):
            await store.run_case(
                source["case_id"],
                source,
                worker=worker,
                approval_verifier=verifier,
                timing_receipt=timing(store, source, now),
                now=lambda: now,
            )
    else:
        await store.run_case(
            source["case_id"],
            source,
            worker=worker,
            approval_verifier=verifier,
            timing_receipt=timing(store, source, now),
            now=lambda: now,
        )
    restored = m.VerificationCampaign(plan, store.root, **options)
    result = await restored.run_case(
        source["case_id"],
        source,
        worker=worker,
        approval_verifier=verifier,
        timing_receipt=None,
        now=lambda: now,
    )
    assert len(calls) == 1
    assert [row["status"] for row in records_for(result, source)] == ["unknown"] + [
        "not_started"
    ] * 5
    # A later determinate result may be merged without redispatching the request.
    receipt = worker_value(calls[0])
    merged = restored.merge_result(calls[0].request_id, receipt, now=now)
    assert records_for(merged, source)[0]["status"] == "completed"
    assert restored.merge_result(calls[0].request_id, receipt, now=now) == merged
    with pytest.raises(PermissionError, match="terminal"):
        restored.merge_result(calls[0].request_id, worker_value(calls[0]), now=now)


@pytest.mark.asyncio
async def test_expiry_keeps_partial_case_and_new_approval_cannot_stitch(setup):
    _, store, source, now, _, _ = setup
    clock = [now]
    calls = []

    async def worker(request):
        calls.append(request)
        value = worker_value(request)
        clock[0] = datetime.fromisoformat(
            source["state"]["response_plan"]["expires_at"]
        ) + timedelta(seconds=1)
        return value

    result = await store.run_case(
        source["case_id"],
        source,
        worker=worker,
        approval_verifier=verifier,
        timing_receipt=timing(store, source, now),
        now=lambda: clock[0],
    )
    assert [row["status"] for row in records_for(result, source)] == ["expired"] * 6
    assert records_for(result, source)[0]["output_sha256"]
    changed = deepcopy(source)
    changed["state"]["approval"]["approval_id"] = "AP-new-synthetic-approval"
    with pytest.raises(PermissionError, match="binding|stitch|source"):
        await store.run_case(
            source["case_id"],
            changed,
            worker=worker,
            approval_verifier=verifier,
            timing_receipt=None,
            now=lambda: now,
        )
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_approval_absence_and_v1_source_fail_closed(setup):
    _, store, source, now, _, _ = setup

    async def worker(request):
        pytest.fail("must not dispatch")

    with pytest.raises(PermissionError, match="campaign"):
        await store.run_case(
            source["case_id"],
            fixture_source(),
            worker=worker,
            timing_receipt=None,
            now=lambda: now,
        )
    with pytest.raises(PermissionError, match="persisted"):
        await store.run_case(
            source["case_id"],
            source,
            worker=worker,
            approval_verifier=None,
            timing_receipt=timing(store, source, now),
            now=lambda: now,
        )
    source["state"]["approval"] = None
    result = await store.run_case(
        source["case_id"],
        source,
        worker=worker,
        approval_verifier=verifier,
        timing_receipt=None,
        now=lambda: now,
    )
    assert {row["status"] for row in records_for(result, source)} == {"not_started"}
    assert result["cases"][source["case_id"]]["reason"] == "approval_pending"


@pytest.mark.asyncio
async def test_reused_worker_resources_are_rejected_across_branches_and_recovery(setup):
    m, store, source, now, plan, options = setup
    suffix = uuid4().hex
    calls = []

    async def worker(request):
        calls.append(request)
        return worker_value(request, suffix=suffix)

    result = await store.run_case(
        source["case_id"],
        source,
        worker=worker,
        approval_verifier=verifier,
        timing_receipt=timing(store, source, now),
        now=lambda: now,
    )
    assert [row["status"] for row in records_for(result, source)][:2] == [
        "completed",
        "failed",
    ]
    assert len(calls) == 2
    assert m.VerificationCampaign(plan, store.root, **options).snapshot() == result


@pytest.mark.asyncio
async def test_last_branch_late_determinate_receipt_restores_whole_case_coverage(setup):
    m, store, source, now, plan, options = setup
    calls = []

    async def worker(request):
        calls.append(request)
        if len(calls) == 6:
            raise RuntimeError("synthetic last-branch interruption")
        return worker_value(request)

    result = await store.run_case(
        source["case_id"],
        source,
        worker=worker,
        timing_receipt=timing(store, source, now),
        approval_verifier=verifier,
        now=lambda: now,
    )
    assert result["cases"][source["case_id"]]["status"] == "unknown"
    restored = m.VerificationCampaign(plan, store.root, **options)
    receipt = worker_value(calls[-1])
    merged = restored.merge_result(calls[-1].request_id, receipt, now=now)
    assert merged["cases"][source["case_id"]]["status"] == "completed"
    assert merged["coverage"]["complete_ait_cases"] == 1
    assert merged["coverage"]["complete_pairs"] == 3
    assert len(calls) == 6


def test_drift_and_corrupt_journal_fail_closed(setup):
    m, store, _, _, plan, options = setup
    changed = deepcopy(options)
    changed["config"]["fixture_description"] = "changed"
    with pytest.raises(PermissionError, match="drift|immutable"):
        m.VerificationCampaign(plan, store.root, **changed)
    plan["slots"][0]["agent_sha256"] = "b" * 64
    with pytest.raises(PermissionError, match="drift|immutable"):
        m.VerificationCampaign(plan, store.root, **options)
    source_file = next(iter(options["source_files"]))
    with open(source_file, "a", encoding="utf-8") as stream:
        stream.write("# drift\n")
    with pytest.raises(PermissionError, match="source.*drift"):
        store.snapshot()


def test_one_pending_real_review_packet_and_review_window(setup):
    _, store, source, now, _, _ = setup
    source["state"].update(status="awaiting_approval", approval=None)
    evening = now.replace(hour=12, minute=0)
    packet = store.prepare_approval(source["case_id"], source, now=evening)
    assert packet["campaign_id"] == CAMPAIGN
    assert packet["packet"]["reviewer"] == "user"
    assert store.prepare_approval(source["case_id"], source, now=evening) == packet
    second = deepcopy(source)
    second["case_id"] = cases()[1]["case_id"]
    with pytest.raises(PermissionError, match="pending"):
        store.prepare_approval(second["case_id"], second, now=evening)
    with pytest.raises(PermissionError, match="19:00|window"):
        store.prepare_approval(source["case_id"], source, now=evening.replace(hour=2))


@pytest.mark.asyncio
async def test_rejection_and_not_applicable_are_retained_without_dispatch(setup):
    _, store, source, now, _, _ = setup

    async def worker(request):
        pytest.fail("terminal ineligible cases must never dispatch")

    source["state"]["approval"]["decision"] = "rejected"
    result = await store.run_case(
        source["case_id"], source, worker=worker, timing_receipt=None, now=lambda: now
    )
    assert {row["status"] for row in records_for(result, source)} == {"rejected"}
    benign = deepcopy(source)
    benign["case_id"] = cases()[1]["case_id"]
    benign["state"]["diagnostic_snapshot"]["diagnosis"]["verdict"] = "benign"
    result = await store.run_case(
        benign["case_id"], benign, worker=worker, timing_receipt=None, now=lambda: now
    )
    assert {row["status"] for row in records_for(result, benign)} == {"not_applicable"}
    assert len(result["records"]) == 528


def test_timing_receipt_validates_all_six_bound_results_and_three_real_trial_contracts(
    setup,
):
    m, store, source, now, _, _ = setup
    receipt = timing(store, source, now)
    assert m.observed_six_branch_max(receipt, store.identity) == 50
    invalid = deepcopy(receipt)
    invalid["trials"] = invalid["trials"][:2]
    with pytest.raises(PermissionError, match="three|3|timing"):
        m.observed_six_branch_max(invalid, store.identity)
    invalid = deepcopy(receipt)
    invalid["trials"][0]["branches"][0]["result"]["input_sha256"] = "f" * 64
    with pytest.raises(PermissionError, match="timing"):
        m.observed_six_branch_max(invalid, store.identity)


def test_projection_is_disposable_and_journal_is_hash_verified(setup):
    m, store, _, _, plan, options = setup
    projection = store.root / "projection.json"
    projection.write_text("{}", encoding="utf-8")
    restored = m.VerificationCampaign(plan, store.root, **options)
    assert len(restored.snapshot()["records"]) == 528
    events = sorted((store.root / "events").glob("*.json"))
    event = json.loads(events[0].read_text(encoding="utf-8"))
    event["payload"]["identity"]["campaign_id"] = "v1"
    events[0].write_text(json.dumps(event), encoding="utf-8")
    with pytest.raises(PermissionError, match="journal|hash"):
        m.VerificationCampaign(plan, store.root, **options)


@pytest.mark.asyncio
async def test_registration_is_not_execution_authorization(setup):
    m, store, source, now, plan, options = setup
    options.pop("execution_admitter")
    restored = m.VerificationCampaign(plan, store.root, **options)

    async def worker(request):
        pytest.fail("registered executable=false is not authorization")

    with pytest.raises(PermissionError, match="execution.*gate"):
        await restored.run_case(
            source["case_id"],
            source,
            worker=worker,
            timing_receipt=timing(store, source, now),
            approval_verifier=verifier,
            now=lambda: now,
        )


@pytest.mark.asyncio
async def test_crash_after_durable_receipt_recovers_it_without_worker_replay(
    setup, monkeypatch
):
    m, store, source, now, plan, options = setup
    original = store._append
    calls = []

    def interrupt(payload):
        if any(
            patch.get("output_sha256") for patch in payload.get("branches", {}).values()
        ):
            raise SystemExit("synthetic crash after receipt before event")
        return original(payload)

    async def worker(request):
        calls.append(request)
        return worker_value(request)

    monkeypatch.setattr(store, "_append", interrupt)
    with pytest.raises(SystemExit):
        await store.run_case(
            source["case_id"],
            source,
            worker=worker,
            timing_receipt=timing(store, source, now),
            approval_verifier=verifier,
            now=lambda: now,
        )
    restored = m.VerificationCampaign(plan, store.root, **options)
    rows = records_for(restored.snapshot(), source)
    assert rows[0]["status"] == "completed"
    assert len(calls) == 1
    await restored.run_case(
        source["case_id"], source, worker=worker, timing_receipt=None, now=lambda: now
    )
    assert len(calls) == 1


def test_mutating_manifest_in_memory_cannot_bypass_runtime_source_drift(setup):
    _, store, _, _, _, _ = setup
    path = next(iter(store.source_files))
    with open(path, "a", encoding="utf-8") as stream:
        stream.write("# drift\n")
    store.source_files[path] = module().file_sha256(path)
    with pytest.raises(PermissionError, match="source.*drift"):
        store.snapshot()


@pytest.mark.asyncio
async def test_pending_approval_remains_pending_after_unapproved_run_attempt(setup):
    _, store, source, now, _, _ = setup
    source["state"].update(status="awaiting_approval", approval=None)
    store.prepare_approval(source["case_id"], source, now=now.replace(hour=12))

    async def worker(request):
        pytest.fail("unapproved")

    await store.run_case(
        source["case_id"], source, worker=worker, timing_receipt=None, now=lambda: now
    )
    second = deepcopy(source)
    second["case_id"] = cases()[1]["case_id"]
    with pytest.raises(PermissionError, match="pending"):
        store.prepare_approval(second["case_id"], second, now=now.replace(hour=12))


def test_live_store_detects_registration_file_drift(setup):
    _, store, _, _, _, _ = setup
    (store.root / "registration.json").write_text("{}", encoding="utf-8")
    with pytest.raises(PermissionError, match="registration|immutable"):
        store.snapshot()


def test_timing_cannot_use_observations_from_one_condition_six_times(setup):
    m, store, source, now, _, _ = setup
    receipt = timing(store, source, now)
    trial = receipt["trials"][0]
    request_type = import_module(
        "evals.adapters.verification_worker"
    ).VerificationWorkerRequest
    for index in (2, 3, 4, 5):
        raw = trial["branches"][index]["request"]
        raw["observations"] = deepcopy(
            trial["branches"][index % 2]["request"]["observations"]
        )
        request = request_type.model_validate(raw)
        trial["branches"][index]["result"] = worker_value(request)
    with pytest.raises(PermissionError, match="timing"):
        m.observed_six_branch_max(receipt, store.identity)


def test_timing_timestamps_must_follow_actual_plan_creation(setup):
    m, store, source, now, _, _ = setup
    receipt = timing(store, source, now)
    row = receipt["trials"][0]["branches"][0]
    row["dispatched_at"] = (now - timedelta(days=1)).isoformat()
    with pytest.raises(PermissionError, match="timing"):
        m.observed_six_branch_max(receipt, store.identity)


@pytest.mark.parametrize(
    "field", ["order_sha256", "branch_id", "approval_id", "case_order"]
)
def test_registration_rejects_order_and_started_slot_drift(field):
    m = module()
    plan = registration()
    if field == "order_sha256":
        plan[field] = "0" * 64
    elif field == "branch_id":
        plan["slots"][0]["branches"][0][field] = "readable-case-branch"
    else:
        plan["slots"][0][field] = "changed"
    with pytest.raises(ValueError, match="registration|order|initial|branch"):
        m.validate_registration(plan)


@pytest.mark.parametrize("reason", ["budget_stopped", "deadline_stopped"])
def test_stop_preserves_all_registered_denominators_and_reason_idempotently(
    setup, reason
):
    m, store, _, _, plan, options = setup
    assert hasattr(store, "stop_remaining"), (
        "campaign needs a durable unexecuted stop API"
    )
    result = store.stop_remaining(reason, detail="Synthetic stop contract only")
    assert len(result["records"]) == 528
    assert {row["status"] for row in result["records"]} == {reason}
    assert store.stop_remaining(reason, detail="Synthetic stop contract only") == result
    assert m.VerificationCampaign(plan, store.root, **options).snapshot() == result


@pytest.mark.asyncio
async def test_expired_valid_receipt_resources_cannot_be_reused_after_reopen(setup):
    m, store, source, now, plan, options = setup
    expires = datetime.fromisoformat(source["state"]["response_plan"]["expires_at"])
    late = expires + timedelta(seconds=1)
    ticks = iter([now, now, now, late, late])
    previous = {}

    async def expired_worker(request):
        value = worker_value(request)
        previous.update(deepcopy(value))
        return value

    result = await store.run_case(
        source["case_id"],
        source,
        worker=expired_worker,
        approval_verifier=verifier,
        timing_receipt=timing(store, source, now),
        now=lambda: next(ticks),
    )
    assert result["cases"][source["case_id"]]["status"] == "expired"
    assert records_for(result, source)[0]["status"] == "expired"
    assert (
        records_for(result, source)[0]["resource_receipt"]
        == previous["resource_receipt"]
    )
    assert records_for(result, source)[0]["outcome"] is None

    later = late + timedelta(seconds=1)
    second = deepcopy(source)
    second["case_id"] = cases()[1]["case_id"]
    state = second["state"]
    state["response_plan"].update(
        created_at=later.isoformat(),
        expires_at=(later + timedelta(minutes=30)).isoformat(),
    )
    from evidencesoc.agents.graph import _plan_hash

    plan_hash = _plan_hash(state["response_plan"])
    state.update(approved_plan_sha256=plan_hash, approved_plan_version=plan_hash)
    state["simulation_execution"]["plan_version"] = plan_hash
    state["approval"].update(
        approval_id="AP-new-case-after-expiry", decided_at=later.isoformat()
    )
    calls = []

    async def reused_worker(request):
        value = worker_value(request)
        for key in ("database_name", "index_name", "checkpoint_id", "worker_nonce"):
            value["resource_receipt"][key] = previous["resource_receipt"][key]
        value["isolation_evidence"]["probe"]["nonce"] = previous["resource_receipt"][
            "worker_nonce"
        ]
        value["isolation_evidence"]["container"] = deepcopy(
            previous["isolation_evidence"]["container"]
        )
        value["isolation_evidence"]["probe"]["hostname"] = value["isolation_evidence"][
            "container"
        ]["hostname"]
        calls.append(request)
        return value

    restored = m.VerificationCampaign(plan, store.root, **options)
    result = await restored.run_case(
        second["case_id"],
        second,
        worker=reused_worker,
        approval_verifier=verifier,
        timing_receipt=timing(restored, second, later),
        now=lambda: later,
    )
    assert len(calls) == 1
    assert records_for(result, second)[0]["status"] == "failed"
    assert result["cases"][second["case_id"]]["status"] == "failed"
    assert result["coverage"]["complete_ait_cases"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        (),
        ("isolation_evidence",),
        ("isolation_evidence", "probe"),
        ("isolation_evidence", "container"),
        ("resource_receipt",),
        ("isolation_evidence", "probe", "boundaries"),
        ("isolation_evidence", "probe", "boundaries", "scoring", 0),
        ("validation_result",),
    ],
)
async def test_invalid_receipt_object_shapes_are_terminal_and_reopenable(setup, path):
    m, store, source, now, plan, options = setup
    calls = []

    async def worker(request):
        calls.append(request)
        value = worker_value(request)
        if not path:
            return []
        parent = value
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = []
        return value

    result = await store.run_case(
        source["case_id"],
        source,
        worker=worker,
        approval_verifier=verifier,
        timing_receipt=timing(store, source, now),
        now=lambda: now,
    )
    assert len(calls) == 1
    assert result["cases"][source["case_id"]]["status"] == "failed"
    assert records_for(result, source)[0]["status"] == "failed"
    assert records_for(result, source)[0]["reason"] == "worker_receipt_invalid"
    assert len(result["records"]) == 528
    restored = m.VerificationCampaign(plan, store.root, **options)
    assert restored.snapshot() == result
    await restored.run_case(
        source["case_id"],
        source,
        worker=worker,
        approval_verifier=verifier,
        timing_receipt=None,
        now=lambda: now,
    )
    assert len(calls) == 1
