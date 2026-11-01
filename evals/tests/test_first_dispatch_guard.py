"""Free synthetic reproduction against unchanged frozen 2f360b77 source."""

from datetime import datetime

import pytest

from evals.e_timing import ETimingCampaign
from evals.tests.test_e_timing import Clock, admit, lifecycle, verify
from evals.tests.test_e_timing_replicates import approved_source, registration
from evals.timing_pool_controller import FirstDispatchClock


@pytest.mark.asyncio
@pytest.mark.parametrize("pool_clock", [False, True])
async def test_expired_bootstrap_is_known_native_terminal(tmp_path, pool_clock):
    clock = Clock()
    reg = registration(tmp_path)
    campaign = ETimingCampaign(
        reg,
        tmp_path / "native",
        execution_admitter=admit,
        approval_verifier=verify,
        worker_lifecycle_verifier=lifecycle,
        now=clock.now,
        monotonic_ns=clock.monotonic_ns,
    )
    source = approved_source(campaign, 0, clock)
    expires = datetime.fromisoformat(source["state"]["response_plan"]["expires_at"])
    clock.advance(301)
    if pool_clock:
        campaign.now = FirstDispatchClock(
            clock.now, expires_at=expires, shared_max=384.562
        )
    workers = []

    async def worker(request):
        workers.append(request)
        raise AssertionError("no worker should run")

    try:
        result = await campaign.run_trial(
            reg["trials"][0]["trial_id"], source, run_worker=worker
        )
    finally:
        assert workers == []
        state = campaign.snapshot()
        print(
            "REPRO",
            pool_clock,
            state["trials"][0]["status"],
            state["trials"][0]["binding"],
            len(campaign.events),
        )
    assert result["trials"][0]["status"] == "rejected"
    assert result["trials"][0]["reason"] == "bootstrap_remaining_must_exceed_1500"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "delay,maximum", [(90, 900), (151, 900), (240, 800), (240, 799), (241, 900)]
)
async def test_guard_after_input_write_known_zero_dispatch(
    tmp_path, monkeypatch, delay, maximum
):
    from evals.timing_pool_controller import run_first_dispatch_guarded

    clock = Clock()
    reg = registration(tmp_path)
    campaign = ETimingCampaign(
        reg,
        tmp_path / "native",
        execution_admitter=admit,
        approval_verifier=verify,
        worker_lifecycle_verifier=lifecycle,
        now=clock.now,
        monotonic_ns=clock.monotonic_ns,
    )
    source = approved_source(campaign, 0, clock)
    gate = FirstDispatchClock(
        clock.now,
        expires_at=datetime.fromisoformat(
            source["state"]["response_plan"]["expires_at"]
        ),
        shared_max=maximum,
    )
    campaign.now = gate
    save = campaign._save

    def slow(category, value):
        result = save(category, value)
        if category == "inputs":
            clock.advance(delay)
        return result

    monkeypatch.setattr(campaign, "_save", slow)
    calls = []

    async def worker(request):
        calls.append(request)
        raise AssertionError("no worker")

    result = await run_first_dispatch_guarded(
        campaign, reg["trials"][0]["trial_id"], source, worker, gate
    )
    assert calls == []
    if maximum > 800 and delay < 240:
        assert result["status"] == "ttl_guard_rejected"
        assert campaign.snapshot()["trials"][0]["status"] == "dispatched"
        assert result["guard"]["remaining_seconds"] == 1740 - delay
    else:
        assert result["trials"][0]["status"] == "rejected"
        assert result["trials"][0]["reason"] == "remaining_changed_before_dispatch"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "maximum,delay,settlement_fault",
    [
        (384.562, 301, None),
        (900, 100, None),
        (900, 0, None),
        (900, 100, "live_worker"),
        (900, 100, "cost_drift"),
    ],
)
async def test_parent_settles_new_guard_and_never_clears_old_unknown(
    tmp_path, monkeypatch, request, maximum, delay, settlement_fault
):
    from decimal import Decimal

    from evals.contracts import canonical_hash
    from evals.tests.test_e_trial_controller import chat_record
    from evals.tests.test_e_trial_controller import host as host_fixture
    from evals.timing_pool_controller import GUARD_FORMULA, PoolJournal
    from scripts.task13_timing_pool import NativePoolController

    fixture = host_fixture.__wrapped__(tmp_path, monkeypatch, request)
    host = fixture.controller
    planned = await host.plan(1)
    read = await host.read(1)
    decided = await host.decision(
        1,
        packet_sha256=read["packet_sha256"],
        chat_record=chat_record(fixture, read["packet"]),
    )
    trial = host._requests[0].trial_id
    pool = {
        "execution_journal_path": str(tmp_path / "pool-journal.jsonl"),
        "children": [{"child_id": "a", "registration": host._timing}],
        "attempt_order": [
            {"trial_id": r.trial_id, "child_id": "a"} for r in host._requests
        ]
        + [{"trial_id": f"later{i}", "child_id": "a"} for i in range(3)],
    }
    journal = PoolJournal.prepare(
        pool["execution_journal_path"],
        pool_sha256=canonical_hash(pool),
        attempts=[a["trial_id"] for a in pool["attempt_order"]],
        imported_trial_id="old",
        now=fixture.clock.now(),
        imported_max_seconds=maximum,
    )
    if maximum > 800:
        with journal.lock():
            journal._append(
                "guard_review",
                {
                    "schema_version": "task13-pool-guard-review-v1",
                    "pool_registration_sha256": canonical_hash(pool),
                    "journal_head_sha256": journal.status()["journal_head"],
                    "checked_at": fixture.clock.now().isoformat(),
                    "formula_version": GUARD_FORMULA,
                    "observations": [
                        {
                            "trial_id": "old",
                            "duration_wall_seconds": maximum,
                            "duration_monotonic_seconds": maximum,
                        }
                    ],
                    "settlement_evidence_sha256": [],
                    "observed_max_seconds": maximum,
                },
                journal._events(),
            )
    journal.begin(trial, now=fixture.clock.now(), quiescent=True, reserved_yuan=".5")
    for phase, result in [("plan", planned), ("read", read), ("decision", decided)]:
        with journal.lock():
            journal._append(
                "phase_claim", {"trial_id": trial, "phase": phase}, journal._events()
            )
            journal._append(
                "phase_finish",
                {
                    "trial_id": trial,
                    "phase": phase,
                    "result_sha256": canonical_hash(result),
                },
                journal._events(),
            )
    host._inputs["pool_authority"] = pool
    monkeypatch.setattr(
        host, "_scope", lambda: None
    )  # only isolate new classification, not scope tests
    parent = object.__new__(NativePoolController)
    parent.pool = pool
    parent.journal = journal
    parent.hosts = {"a": host}
    parent.guard = lambda: None
    budget_reads = []

    def budget():
        budget_reads.append(1)
        return (
            Decimal(".1")
            if settlement_fault == "cost_drift" and len(budget_reads) >= 3
            else Decimal(0)
        )

    parent.budget = budget

    async def quiet():
        return {"proofs": [], "inspected_at": fixture.clock.now().isoformat()}

    parent.quiescence = quiet

    async def docker(arguments, environment):
        from hashlib import sha256

        if settlement_fault == "live_worker":
            return {"returncode": 0}, "owned-container"
        return {
            "argv": ["docker", *arguments],
            "returncode": 0,
            "stdout_sha256": sha256(b"").hexdigest(),
            "stderr_sha256": sha256(b"").hexdigest(),
        }, ""

    monkeypatch.setattr("scripts.task13_timing_pool._docker", docker)
    fixture.clock.advance(delay)
    if delay == 0:
        save = ETimingCampaign._save

        def slow(self, category, value):
            result = save(self, category, value)
            if category == "inputs":
                fixture.clock.advance(100)
            return result

        monkeypatch.setattr(ETimingCampaign, "_save", slow)
    if settlement_fault:
        with pytest.raises(PermissionError):
            await parent.run("trial")
        assert journal.status()["stopped"] == "unknown_native_execution"
        assert journal.status()["pending"] == trial
        with pytest.raises(PermissionError):
            await parent.resume()
        return
    result = await parent.run("trial")
    assert journal.status()["stopped"] == "ttl_infrastructure_failure"
    assert journal.status()["pending"] is None
    assert not any(c[0] == "branch" for c in fixture.calls)
    if maximum > 800:
        assert result["status"] == "ttl_guard_rejected"
        assert host._campaign().snapshot()["trials"][0]["status"] == (
            "not_started" if delay else "dispatched"
        )
        from copy import deepcopy

        from evals.timing_pool import _view
        from evals.timing_pool_evidence import validate_first_dispatch_guard_evidence
        from scripts.task13_e_trial import _bytes, _decode, _read_pin

        original_request = host._requests[0]
        actual = _decode(_read_pin(decided["runtime_result"]))
        retained, resources = host._retained(original_request)
        source = host._source(
            original_request, actual["source"]["state"], retained, resources
        )
        settled = journal._events()[-1]["payload"]
        validate_first_dispatch_guard_evidence(
            {"reader": host},
            original_request,
            _view(host._root / "timing"),
            source,
            settled,
            maximum,
        )
        for field, value in [
            ("native_head_sha256", "b" * 64),
            ("source_sha256", "c" * 64),
            ("observed_max_seconds", 899),
            ("approval_receipt", {"unknown": True}),
        ]:
            forged = deepcopy(settled)
            proof = _decode(_read_pin(forged["evidence"]["guard_receipt"]))
            proof[field] = value
            forged["evidence"]["guard_receipt"] = host._save(
                "first-dispatch-guard", _bytes(proof)
            )
            with pytest.raises(PermissionError):
                validate_first_dispatch_guard_evidence(
                    {"reader": host},
                    original_request,
                    _view(host._root / "timing"),
                    source,
                    forged,
                    maximum,
                )
    await parent.resume()
    assert journal.status()["attempted"] == 1
    if maximum > 800:
        from types import SimpleNamespace

        from evals.timing_pool_controller import PoolPhaseLease

        with journal.lock():
            proof = dict(
                next(
                    e["payload"]
                    for e in journal._events()
                    if e["kind"] == "guard_review"
                )
            )
            proof.update(
                journal_head_sha256=journal.status()["journal_head"],
                checked_at=fixture.clock.now().isoformat(),
                settlement_evidence_sha256=[settled["evidence_sha256"]],
            )
            journal._append("guard_review", proof, journal._events())
        next_trial = host._requests[1].trial_id
        journal.begin(
            next_trial, now=fixture.clock.now(), quiescent=True, reserved_yuan=".5"
        )
        identity = {
            k: fixture.source[k]
            for k in ("campaign_id", "source_commit", "source_sha256", "config_sha256")
        }
        replacement = approved_source(
            SimpleNamespace(registration=host._timing, identity=identity),
            1,
            fixture.clock,
        )
        replacement["resources"]["plan_sha256"] = canonical_hash(
            replacement["state"]["response_plan"]
        )
        replacement["resources_sha256"] = canonical_hash(replacement["resources"])
        fixture.source.clear()
        fixture.source.update(replacement)
        with journal.lock() as owner:
            journal._append(
                "phase_claim",
                {"trial_id": next_trial, "phase": "plan", "child_id": "a"},
                journal._events(),
            )
            host._pool_lease = PoolPhaseLease(
                journal.path,
                owner["nonce"],
                journal.status()["journal_head"],
                "a",
                next_trial,
                "plan",
            )
            next_result = await host.plan(2)
            host._pool_lease = None
        assert next_result["status"] == "awaiting_approval"
        assert len([c for c in fixture.calls if c[0] == "plan"]) == 2
        with pytest.raises(PermissionError, match="lease"):
            await host.plan(2)
    journal.stop("unknown_native_execution")
    with pytest.raises(PermissionError, match="hard|unknown"):
        await parent.resume()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ["unknown_approval", "generic_guard", "foreign_typed"]
)
async def test_guard_does_not_reclassify_unknown_or_unowned_exception(tmp_path, fault):
    from evals.timing_pool_controller import (
        FirstDispatchTTLGuard,
        PoolStopped,
        run_first_dispatch_guarded,
    )

    clock = Clock()
    reg = registration(tmp_path)

    async def verifier(source):
        if fault == "unknown_approval":
            raise RuntimeError("unknown actual approval")
        if fault == "generic_guard":
            raise PoolStopped("shared M first dispatch remaining TTL insufficient")
        raise FirstDispatchTTLGuard(clock.now())

    campaign = ETimingCampaign(
        reg,
        tmp_path / "native",
        execution_admitter=admit,
        approval_verifier=verifier,
        worker_lifecycle_verifier=lifecycle,
        now=clock.now,
        monotonic_ns=clock.monotonic_ns,
    )
    source = approved_source(campaign, 0, clock)
    gate = FirstDispatchClock(
        clock.now,
        expires_at=datetime.fromisoformat(
            source["state"]["response_plan"]["expires_at"]
        ),
        shared_max=900,
    )
    campaign.now = gate
    clock.advance(100)

    async def worker(request):
        raise AssertionError("no worker")

    with pytest.raises((RuntimeError, PoolStopped)):
        await run_first_dispatch_guarded(
            campaign, reg["trials"][0]["trial_id"], source, worker, gate
        )
    assert len(campaign.events) == 1


def test_impossible_shared_margin_1000_never_enters_native():
    from evals.timing_pool_controller import PoolStopped

    with pytest.raises(PoolStopped, match="1800"):
        FirstDispatchClock(Clock().now, shared_max=1000)
