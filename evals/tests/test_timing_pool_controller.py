"""Free controller durability and bounded-pool tests; no provider dispatch."""

import importlib.util
import json
from datetime import datetime, timezone

import pytest


def api():
    assert importlib.util.find_spec("evals.timing_pool_controller"), (
        "bounded pool controller is missing"
    )
    from evals.timing_pool_controller import PoolJournal, PoolStopped

    return PoolJournal, PoolStopped


def journal(tmp_path):
    cls, _ = api()
    return cls.prepare(
        tmp_path / "pool.jsonl",
        pool_sha256="a" * 64,
        attempts=[f"t{i}" for i in range(6)],
        imported_trial_id="C10-1",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )


def begin(j, trial="t0", **kw):
    return j.begin(
        trial,
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        quiescent=True,
        reserved_yuan="0.50",
        **kw,
    )


def test_bounded_sequence_single_pending_and_no_replay(tmp_path):
    j = journal(tmp_path)
    _, stop = api()
    with pytest.raises(stop, match="sequence"):
        begin(j, "t1")
    begin(j)
    with pytest.raises(stop, match="pending|unknown"):
        begin(j)
    assert j.status()["consumed_logical"] == 8
    assert j.status()["physical_upper_bound"] == 24


def test_target_three_stops_early(tmp_path):
    j = journal(tmp_path)
    _, stop = api()
    for i in range(2):
        begin(j, f"t{i}")
        j.settle(
            f"t{i}",
            outcome="qualified",
            actual_yuan="0.25",
            quiescent=True,
            observed_max_seconds=100,
            evidence_sha256=str(i) * 64,
        )
    assert j.status()["qualified"] == 3
    with pytest.raises(stop, match="target"):
        begin(j, "t2")


def test_ttl_requires_audit_and_free_fresh_guard(tmp_path):
    j = journal(tmp_path)
    _, stop = api()
    begin(j)
    j.settle(
        "t0",
        outcome="ttl_infrastructure_failure",
        actual_yuan="0.25",
        quiescent=True,
        observed_max_seconds=100,
        evidence_sha256="b" * 64,
    )
    with pytest.raises(stop, match="STOP"):
        begin(j, "t1")
    with pytest.raises(stop, match="free"):
        j.resume(quiescent=True, fresh_guard_sha256="c" * 64, guard_cost_yuan="0.01")
    j.resume(quiescent=True, fresh_guard_sha256="c" * 64, guard_cost_yuan="0")
    begin(j, "t1")


@pytest.mark.parametrize(
    "reason", ["unknown_cost", "user_rejected", "empty_plan", "identity_changed"]
)
def test_hard_stop_cannot_resume(tmp_path, reason):
    j = journal(tmp_path)
    _, stop = api()
    begin(j)
    j.stop(reason)
    with pytest.raises(stop, match="hard"):
        j.resume(quiescent=True, fresh_guard_sha256="c" * 64, guard_cost_yuan="0")


def test_shared_m_budget_deadline_and_quiescence_guards(tmp_path):
    j = journal(tmp_path)
    _, stop = api()
    with pytest.raises(stop, match="budget"):
        j.begin(
            "t0",
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
            quiescent=True,
            reserved_yuan="6.01",
        )
    with pytest.raises(stop, match="quiescen"):
        j.begin(
            "t0",
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
            quiescent=False,
            reserved_yuan="0.5",
        )
    with pytest.raises(stop, match="deadline"):
        j.begin(
            "t0",
            now=datetime(2026, 11, 3, tzinfo=timezone.utc),
            quiescent=True,
            reserved_yuan="0.5",
        )
    begin(j)
    j.settle(
        "t0",
        outcome="qualified",
        actual_yuan="0.25",
        quiescent=True,
        observed_max_seconds=801,
        evidence_sha256="b" * 64,
    )
    with pytest.raises(stop, match="guard review"):
        begin(j, "t1")


def test_hashchain_and_lock_fail_closed(tmp_path):
    j = journal(tmp_path)
    _, stop = api()
    j.lock_path.write_text("crashed owner")
    with pytest.raises(stop, match="lock"):
        begin(j)
    j.lock_path.unlink()
    begin(j)
    rows = j.path.read_text().splitlines()
    event = json.loads(rows[-1])
    event["payload"]["trial_id"] = "t5"
    rows[-1] = json.dumps(event)
    j.path.write_text("\n".join(rows) + "\n")
    with pytest.raises(stop, match="hash"):
        j.status()


def test_crash_reopen_preserves_pending(tmp_path):
    j = journal(tmp_path)
    cls, stop = api()
    begin(j)
    reopened = cls(j.path, pool_sha256="a" * 64)
    with pytest.raises(stop, match="pending|unknown"):
        begin(reopened)


def test_duplicate_evidence_claim_rejected(tmp_path):
    j = journal(tmp_path)
    _, stop = api()
    begin(j)
    j.settle(
        "t0",
        outcome="qualified",
        actual_yuan="0.2",
        quiescent=True,
        observed_max_seconds=100,
        evidence_sha256="b" * 64,
    )
    begin(j, "t1")
    with pytest.raises(stop, match="duplicate"):
        j.settle(
            "t1",
            outcome="qualified",
            actual_yuan="0.2",
            quiescent=True,
            observed_max_seconds=100,
            evidence_sha256="b" * 64,
        )


def test_parent_membership_is_explicit_and_exact(tmp_path):
    from evals.contracts import canonical_hash
    from evals.tests.test_e_timing_replicates import registration
    from evals.timing_pool_controller import pool_scope_proposal
    from scripts import task13_e_trial as host

    timing = registration(tmp_path)
    pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "children": [{"child_id": "a", "registration": timing}],
    }
    proposal = pool_scope_proposal(pool)
    packet = {
        "pool_proposal": proposal,
        "pool_proposal_sha256": canonical_hash(proposal),
    }
    host.require_pool_membership(pool, packet, timing)
    with pytest.raises(PermissionError):
        host.require_pool_membership(
            pool, packet, {"planning_registration": {"id": "other"}}
        )
    packet["pool_proposal_sha256"] = "f" * 64
    with pytest.raises(PermissionError):
        host.require_pool_membership(pool, packet, timing)


def test_native_pool_controller_is_available_without_provider_side_effects():
    import scripts.task13_timing_pool as module

    assert hasattr(module, "NativePoolController")
    assert callable(module.main)


def test_native_payload_bound_uses_frozen_client_and_schema(tmp_path):
    from types import SimpleNamespace

    from scripts.task13_timing_pool import derive_next_three_bound

    # Missing native request/model evidence must never become a caller-supplied cost.
    with pytest.raises((PermissionError, AttributeError, KeyError)):
        derive_next_three_bound(
            SimpleNamespace(_timing={"source_files": {}}, _requests=[])
        )


def test_actual_budget_preserves_historical_halt_and_two_unknown(tmp_path):
    import sqlite3

    from scripts.task13_timing_pool import NativePoolController

    controller = object.__new__(NativePoolController)
    controller.budget_path = tmp_path / "campaign.sqlite"
    with sqlite3.connect(controller.budget_path) as db:
        db.executescript(
            "CREATE TABLE config(key TEXT,value TEXT); CREATE TABLE reservations(id TEXT,request_key TEXT,phase TEXT,upper REAL,actual REAL,settled INTEGER); CREATE TABLE supplement_requests(reservation_id TEXT,purpose TEXT,request_id TEXT,role TEXT);"
        )
        db.executemany(
            "INSERT INTO config VALUES (?,?)",
            [("total", "100"), ("development", "15"), ("halt", "historical preserved")],
        )
        db.executemany(
            "INSERT INTO reservations VALUES (?,?,?,?,?,?)",
            [
                ("old1", "old1", "formal", 1, None, 0),
                ("old2", "old2", "formal", 1, None, 0),
                ("new", "new", "development", 0.5, 0.2, 1),
            ],
        )
        db.execute(
            "INSERT INTO supplement_requests VALUES ('new','development','r1','respond')"
        )
    from hashlib import sha256

    from evals.adapters.remediation_worker import _budget_snapshot

    values, baseline_rows = _budget_snapshot(controller.budget_path)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "config": values,
                "legacy_unknown_rows": [list(row) for row in baseline_rows[:2]],
            }
        )
    )
    controller.manifest = {
        "original_account_baseline": {
            "path": str(baseline_path),
            "sha256": sha256(baseline_path.read_bytes()).hexdigest(),
        }
    }
    assert str(controller.budget()) == "0.2"
    with sqlite3.connect(controller.budget_path) as db:
        db.execute("UPDATE config SET value='new identity halt' WHERE key='halt'")
    with pytest.raises(PermissionError, match="halt changed"):
        controller.budget()
    with sqlite3.connect(controller.budget_path) as db:
        db.execute("UPDATE config SET value='historical preserved' WHERE key='halt'")

    with sqlite3.connect(controller.budget_path) as db:
        db.execute("UPDATE reservations SET actual=NULL WHERE id='new'")
    with pytest.raises(PermissionError, match="unknown supplement"):
        controller.budget()


@pytest.mark.asyncio
async def test_native_known_ttl_settles_then_free_resume(tmp_path):
    from decimal import Decimal
    from types import SimpleNamespace

    from scripts.task13_timing_pool import NativePoolController

    j = journal(tmp_path)
    begin(j)
    controller = object.__new__(NativePoolController)
    controller.journal = j
    controller.guard = lambda: None
    controller.budget = lambda: Decimal("0.25")

    async def quiet():
        return {"fresh": True}

    controller.quiescence = quiet
    controller.pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "attempt_order": [{"trial_id": "t0", "child_id": "a"}],
    }
    terminal = {
        "trial_id": "t0",
        "status": "rejected",
        "reason": "bootstrap_remaining_must_exceed_1500",
    }

    async def trial(ordinal):
        return {"trials": [terminal]}

    controller.hosts = {
        "a": SimpleNamespace(
            _requests=[SimpleNamespace(trial_id="t0", ordinal=1)],
            trial=trial,
            _campaign=lambda: SimpleNamespace(snapshot=lambda: {"trials": [terminal]}),
        )
    }
    await controller.run("trial")
    assert j.status()["stopped"] == "ttl_infrastructure_failure"
    assert j.status()["pending"] is None
    assert j.status()["spent_yuan"] == "0.25"
    await controller.resume()
    assert j.status()["stopped"] is None
    begin(j, "t1")


@pytest.mark.asyncio
async def test_completed_reads_can_poll_but_decisions_cannot_replay(tmp_path):
    from decimal import Decimal
    from types import SimpleNamespace

    from scripts.task13_timing_pool import NativePoolController

    j = journal(tmp_path)
    begin(j)
    controller = object.__new__(NativePoolController)
    controller.journal = j
    controller.guard = lambda: None
    controller.budget = lambda: Decimal(0)

    async def quiet():
        return {"fresh": True}

    async def read(ordinal):
        return {"status": "pending"}

    async def decision(ordinal, **kw):
        return {"status": "approved"}

    controller.quiescence = quiet
    controller.pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "attempt_order": [{"trial_id": "t0", "child_id": "a"}],
    }
    controller.hosts = {
        "a": SimpleNamespace(
            _requests=[SimpleNamespace(trial_id="t0", ordinal=1)],
            read=read,
            decision=decision,
        )
    }
    await controller.run("read")
    await controller.run("read")
    await controller.run("decision")
    with pytest.raises(PermissionError, match="already claimed"):
        await controller.run("decision")


def test_persistent_server_keeps_one_preloaded_instance_and_eof_pending(tmp_path):
    import io
    from types import SimpleNamespace

    from scripts.task13_timing_pool import serve

    j = journal(tmp_path)
    begin(j)
    controller = SimpleNamespace(digest="a" * 64, journal=j)
    output = io.StringIO()
    assert serve(controller, io.StringIO('{"operation":"status"}\n'), output) == 0
    lines = [json.loads(line) for line in output.getvalue().splitlines()]
    assert lines[0]["status"] == "ready"
    assert lines[1]["pending"] == "t0"
    assert j.status()["pending"] == "t0"


def test_persistent_server_never_turns_raw_text_into_approval(tmp_path):
    import io
    from types import SimpleNamespace

    from scripts.task13_timing_pool import serve

    output = io.StringIO()
    serve(SimpleNamespace(digest="a" * 64), io.StringIO("yes approve\n"), output)
    assert json.loads(output.getvalue().splitlines()[-1])["status"] == "STOP"


def test_proposal_masks_only_runtime_authority_and_rebuilds_native_hashes(tmp_path):
    from copy import deepcopy

    from evals.contracts import canonical_hash
    from evals.e_timing import build_e_timing_registration
    from evals.tests.test_e_timing_replicates import registration
    from evals.timing_pool_controller import pool_scope_proposal

    timing = registration(tmp_path)
    pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "children": [{"child_id": "a", "registration": timing}],
        "limits": {"logical": 6},
    }
    original = pool_scope_proposal(pool)
    changed = deepcopy(pool)
    planning = changed["children"][0]["registration"]["planning_registration"]
    planning["epoch_binding"]["epoch_manifest_sha256"] = "e" * 64
    dispatch = deepcopy(timing["planning_dispatch_registration_receipt"])
    dispatch["registration_sha256"] = canonical_hash(planning)
    dispatch["authority_sha256"] = "f" * 64
    changed["children"][0]["registration"] = build_e_timing_registration(
        planning,
        source_files=timing["source_files"],
        f8_plan_sha256=timing["f8_plan_sha256"],
        planning_dispatch_registration_receipt=dispatch,
    )
    assert pool_scope_proposal(changed) == original
    changed["children"][0]["registration"]["source_files"][
        next(iter(timing["source_files"]))
    ] = "d" * 64
    assert pool_scope_proposal(changed) != original
    changed = deepcopy(pool)
    changed["limits"]["logical"] = 7
    assert pool_scope_proposal(changed) != original


def test_capacity_cannot_use_forged_payload_bound(tmp_path, monkeypatch):
    from decimal import Decimal
    from hashlib import sha256
    from pathlib import Path
    from types import SimpleNamespace

    from evals.e_planning import planning_requests
    from evals.tests.test_e_timing_replicates import registration
    from scripts import task13_timing_pool as module

    timing = registration(tmp_path)
    root = Path(module.__file__).resolve().parents[1]
    relatives = (
        "evals/adapters/model_client.py",
        "services/backend/src/evidencesoc/agents/models.py",
        "services/backend/src/evidencesoc/agents/diagnosis.py",
        "services/backend/src/evidencesoc/domain/models.py",
        "services/backend/src/evidencesoc/domain/response_action.py",
    )
    timing["source_files"] = {
        str(root / name): sha256((root / name).read_bytes()).hexdigest()
        for name in relatives
    }
    host = SimpleNamespace(
        _timing=timing, _requests=planning_requests(timing["planning_registration"])
    )
    derived = module.derive_next_three_bound(host)
    assert Decimal("0.8") < derived < Decimal(2)
    controller = object.__new__(module.NativePoolController)
    controller.hosts = {"a": host}
    controller.digest = "a" * 64
    support = tmp_path / "support"
    support.write_text("native-support")
    proof = {
        "schema_version": "task13-pool-next-three-capacity-v1",
        "pool_registration_sha256": controller.digest,
        "physical_requests": 3,
        "max_tokens": 4096,
        "peak_input_cny_per_million": 2,
        "peak_output_cny_per_million": 8,
        "supporting_refs": [
            {"path": str(support), "sha256": sha256(support.read_bytes()).hexdigest()}
        ],
        "bound_basis": "forged tiny bound",
        "payload_bytes_upper_bound": 0,
        "next_three_upper_cny": str(
            (Decimal(4096) * 2 + Decimal(4096) * 8) / 1000000 * 3
        ),
    }
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(proof))
    controller.manifest = {
        "capacity_proof": {
            "path": str(path),
            "sha256": sha256(path.read_bytes()).hexdigest(),
        }
    }
    with pytest.raises(PermissionError, match="freshly derived"):
        controller.reserve_bound()


def test_receipt_journal_verifier_rejects_hashvalid_double_claim(tmp_path):
    from hashlib import sha256

    from evals.contracts import canonical_hash
    from evals.timing_pool_controller import PoolJournal, validate_pool_journal_evidence

    pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "attempt_order": [{"trial_id": f"t{i}"} for i in range(6)],
        "imported_observations": [{"trial_id": "C10-1"}],
    }
    j = PoolJournal.prepare(
        tmp_path / "pool.jsonl",
        pool_sha256=canonical_hash(pool),
        attempts=[f"t{i}" for i in range(6)],
        imported_trial_id="C10-1",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    begin(j)
    j._append("begin", {"trial_id": "t1", "reserved_yuan": "0.5"}, j._events())
    proof = {
        "pool_journal": {
            "path": str(j.path),
            "sha256": sha256(j.path.read_bytes()).hexdigest(),
            "head_sha256": j._events()[-1]["sha256"],
        }
    }
    with pytest.raises(PermissionError, match="pending|sequence"):
        validate_pool_journal_evidence(proof, pool)


@pytest.mark.asyncio
async def test_fresh_quiescence_checks_only_owned_container_and_excludes_keys(
    tmp_path, monkeypatch
):
    from hashlib import sha256
    from types import SimpleNamespace

    from scripts import task13_timing_pool as module

    controller = object.__new__(module.NativePoolController)
    controller.pool = {"schema_version": "task13-e-timing-pool-registration-v1"}
    directory = tmp_path / "request"
    directory.mkdir()
    nonce = "a" * 32
    container = "b" * 64
    value = {
        "worker_nonce": nonce,
        "container_id": container,
        "status": "verified",
        "host_process_exited": True,
        "container_name": "task13-worker-" + nonce,
    }
    raw = json.dumps(value).encode()
    (directory / (nonce + "-" + sha256(raw).hexdigest() + ".json")).write_bytes(raw)
    controller.hosts = {"a": SimpleNamespace(_termination=tmp_path)}
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-secret-do-not-log")
    calls = []

    async def absent(arguments, environment):
        calls.append((arguments, environment))
        return {"returncode": 0}, b""

    monkeypatch.setattr(module, "_docker", absent)
    proof = await controller.quiescence()
    assert len(proof["proofs"]) == 1
    assert "id=" + container in calls[0][0]
    assert "DEEPSEEK_API_KEY" not in calls[0][1]

    async def present(arguments, environment):
        return {"returncode": 0}, container.encode()

    monkeypatch.setattr(module, "_docker", present)
    with pytest.raises(PermissionError, match="freshly absent"):
        await controller.quiescence()


def test_hard_stop_cannot_be_relabelled_as_ttl(tmp_path):
    j = journal(tmp_path)
    j.stop("identity_changed")
    with pytest.raises(PermissionError, match="TTL|hard"):
        j.stop("ttl_infrastructure_failure")


def test_receipt_journal_validates_complete_prefix_and_stops_after_target(tmp_path):
    from hashlib import sha256

    from evals.contracts import canonical_hash
    from evals.timing_pool_controller import PoolJournal, validate_pool_journal_evidence

    pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "attempt_order": [{"trial_id": f"t{i}"} for i in range(6)],
        "imported_observations": [{"trial_id": "C10-1"}],
    }
    j = PoolJournal.prepare(
        tmp_path / "full.jsonl",
        pool_sha256=canonical_hash(pool),
        attempts=[f"t{i}" for i in range(6)],
        imported_trial_id="C10-1",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    for index in range(2):
        trial = f"t{index}"
        begin(j, trial)
        for phase in ("plan", "read", "decision", "trial"):
            claim = {"trial_id": trial, "phase": phase, "quiescence": {"fixture": True}}
            if phase == "decision":
                claim.update(
                    chat_record={"path": "fixture", "sha256": "a" * 64},
                    packet_sha256="b" * 64,
                )
            j._append("phase_claim", claim, j._events())
            j._append(
                "phase_finish",
                {"trial_id": trial, "phase": phase, "result_sha256": "c" * 64},
                j._events(),
            )
        evidence = {"native": {"fixture_trial": trial}, "quiescence": {"fixture": True}}
        j.settle(
            trial,
            outcome="qualified",
            actual_yuan="0.1",
            quiescent=True,
            observed_max_seconds=100,
            evidence_sha256=canonical_hash(evidence),
            evidence=evidence,
        )

    def proof():
        return {
            "pool_journal": {
                "path": str(j.path),
                "sha256": sha256(j.path.read_bytes()).hexdigest(),
                "head_sha256": j._events()[-1]["sha256"],
            }
        }

    audited = validate_pool_journal_evidence(proof(), pool)
    assert audited["state"]["qualified"] == 3
    assert len(audited["settlements"]) == 2
    j._append(
        "begin",
        {
            "trial_id": "t2",
            "reserved_yuan": "0.1",
            "started_at": "2026-11-01T00:00:00+00:00",
        },
        j._events(),
    )
    with pytest.raises(PermissionError, match="sequence"):
        validate_pool_journal_evidence(proof(), pool)


def test_pool_phase_lease_requires_live_owned_lock_and_exact_child_phase(tmp_path):
    from evals.contracts import canonical_hash
    from evals.timing_pool_controller import PoolPhaseLease, require_pool_phase_lease

    pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "execution_journal_path": str(tmp_path / "pool-journal.jsonl"),
        "children": [
            {"child_id": "a", "registration": {"trials": [{"trial_id": "t0"}]}}
        ],
    }
    cls, _ = api()
    j = cls.prepare(
        pool["execution_journal_path"],
        pool_sha256=canonical_hash(pool),
        attempts=[f"t{i}" for i in range(6)],
        imported_trial_id="old",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    begin(j)
    with j.lock() as owner:
        j._append(
            "phase_claim",
            {"trial_id": "t0", "child_id": "a", "phase": "plan"},
            j._events(),
        )
        lease = PoolPhaseLease(
            j.path, owner["nonce"], j._events()[-1]["sha256"], "a", "t0", "plan"
        )
        require_pool_phase_lease(pool, "a", "t0", "plan", lease)
        for child, phase in [("b", "plan"), ("a", "trial")]:
            with pytest.raises(PermissionError):
                require_pool_phase_lease(pool, child, "t0", phase, lease)
    with pytest.raises((PermissionError, FileNotFoundError)):
        require_pool_phase_lease(pool, "a", "t0", "plan", lease)


def test_pool_companion_fences_native_adoption_and_rejects_unlisted_pending(tmp_path):
    from contextlib import ExitStack

    from evals.adapters.source_epochs import _lock_controller_roots
    from evals.timing_pool_controller import PoolJournal, pool_quiescence

    j = PoolJournal.prepare(
        tmp_path / "pool-journal.jsonl",
        pool_sha256="a" * 64,
        attempts=[f"t{i}" for i in range(6)],
        imported_trial_id="old",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    roots = [str(tmp_path.resolve())]
    with pool_quiescence([j], roots):
        with ExitStack() as stack:
            _lock_controller_roots(roots, stack)
        with pytest.raises(PermissionError, match="adoption"):
            begin(j)
    with pytest.raises(PermissionError, match="unlisted"), pool_quiescence([], roots):
        pass
    begin(j)
    with pytest.raises(PermissionError, match="pending"), pool_quiescence([j], roots):
        pass


@pytest.mark.parametrize("cutoff_delta_microseconds", [0, 1])
def test_first_dispatch_clock_rejects_cutoff_but_preserves_admitted_real_times(
    cutoff_delta_microseconds,
):
    from datetime import timedelta

    from evals.timing_pool_controller import DEADLINE, FirstDispatchClock

    current = [DEADLINE - timedelta(seconds=1)]
    clock = FirstDispatchClock(lambda: current[0])
    assert clock() == current[0]
    current[0] = DEADLINE + timedelta(microseconds=cutoff_delta_microseconds)
    with pytest.raises(PermissionError, match="deadline"):
        clock()
    current[0] = DEADLINE - timedelta(seconds=1)
    clock = FirstDispatchClock(lambda: current[0])
    assert clock() == current[0]
    clock.admit()
    current[0] = DEADLINE + timedelta(seconds=180)
    assert clock() == current[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["plan", "read", "decision", "trial"])
async def test_native_pool_public_phase_cannot_bypass_parent_lease(phase):
    from types import SimpleNamespace

    from scripts.task13_e_trial import ETrialController

    host = object.__new__(ETrialController)
    host._inputs = {"pool_authority": {"children": []}}
    host._request = lambda ordinal: SimpleNamespace(trial_id="t0")
    with pytest.raises(PermissionError, match="lease"):
        if phase == "decision":
            await host.decision(1, packet_sha256="a" * 64, chat_record={})
        else:
            await getattr(host, phase)(1)


@pytest.mark.asyncio
async def test_native_clock_catches_expiry_during_input_write_before_first_worker(
    tmp_path, monkeypatch
):
    from datetime import timedelta

    from evals.e_timing import ETimingCampaign
    from evals.tests.test_e_timing import Clock, admit, lifecycle, verify
    from evals.tests.test_e_timing_replicates import approved_source, registration
    from evals.timing_pool_controller import DEADLINE, FirstDispatchClock

    clock = Clock()
    clock.utc = DEADLINE - timedelta(seconds=1)
    gate = FirstDispatchClock(clock.now)
    reg = registration(tmp_path)
    store = ETimingCampaign(
        reg,
        tmp_path / "native",
        execution_admitter=admit,
        approval_verifier=verify,
        worker_lifecycle_verifier=lifecycle,
        now=gate,
        monotonic_ns=clock.monotonic_ns,
    )
    source = approved_source(store, 0, clock)
    save = store._save

    def delayed_save(category, value):
        result = save(category, value)
        if category == "inputs":
            clock.advance(2)
        return result

    monkeypatch.setattr(store, "_save", delayed_save)
    called = []

    async def worker(request):
        called.append(request)
        raise AssertionError("worker must not dispatch")

    with pytest.raises(PermissionError, match="deadline"):
        await store.run_trial(reg["trials"][0]["trial_id"], source, run_worker=worker)
    assert called == []


@pytest.mark.asyncio
async def test_admitted_native_clock_finishes_six_original_branches_after_cutoff(
    tmp_path,
):
    from datetime import timedelta

    from evals.e_timing import ETimingCampaign
    from evals.tests.test_e_timing import Clock, admit, lifecycle, value_for, verify
    from evals.tests.test_e_timing_replicates import approved_source, registration
    from evals.timing_pool_controller import DEADLINE, FirstDispatchClock

    clock = Clock()
    clock.utc = DEADLINE - timedelta(seconds=1)
    gate = FirstDispatchClock(clock.now)
    reg = registration(tmp_path)
    store = ETimingCampaign(
        reg,
        tmp_path / "native",
        execution_admitter=admit,
        approval_verifier=verify,
        worker_lifecycle_verifier=lifecycle,
        now=gate,
        monotonic_ns=clock.monotonic_ns,
    )
    source = approved_source(store, 0, clock)
    called = []

    async def worker(request):
        if not gate.admitted:
            gate.admit()
        called.append(request)
        clock.advance(1)
        return value_for(request)

    result = await store.run_trial(
        reg["trials"][0]["trial_id"], source, run_worker=worker
    )
    assert len(called) == 6
    assert result["complete_observed_trials"] == 1
    assert clock.now() > DEADLINE


@pytest.mark.asyncio
async def test_real_native_plan_runs_only_under_wrapper_parent_lease(
    tmp_path, monkeypatch, request
):
    from decimal import Decimal

    from evals.contracts import canonical_hash
    from evals.tests.test_e_trial_controller import host as host_fixture
    from evals.timing_pool_controller import PoolJournal
    from scripts.task13_timing_pool import NativePoolController

    fixture = host_fixture.__wrapped__(tmp_path, monkeypatch, request)
    host = fixture.controller
    trial = host._requests[0].trial_id
    pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "execution_journal_path": str(tmp_path / "pool-journal.jsonl"),
        "children": [{"child_id": "a", "registration": host._timing}],
        "attempt_order": [{"trial_id": trial, "child_id": "a"}]
        + [{"trial_id": f"later{i}", "child_id": "a"} for i in range(5)],
    }
    j = PoolJournal.prepare(
        pool["execution_journal_path"],
        pool_sha256=canonical_hash(pool),
        attempts=[a["trial_id"] for a in pool["attempt_order"]],
        imported_trial_id="old",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    host._inputs["pool_authority"] = pool
    # Scope migration is tested separately; keep actual native fixture journals,
    # request bindings, captured worker evidence, model checks and public method.
    monkeypatch.setattr(host, "_scope", lambda: None)
    controller = object.__new__(NativePoolController)
    controller.pool = pool
    controller.journal = j
    controller.hosts = {"a": host}
    controller.guard = lambda: None
    controller.budget = lambda: Decimal(0)
    controller.reserve_bound = lambda: Decimal("0.5")

    async def quiet():
        return {"fixture": "free"}

    controller.quiescence = quiet
    # This integration test isolates lease enforcement; real gate verification
    # has its own raw-artifact tests and is mandatory in the production entrypoint.
    monkeypatch.setattr(
        "scripts.task13_timing_pool.require_free_admission",
        lambda *args, **kwargs: {"fixture": "free"},
    )
    controller.digest = canonical_hash(pool)
    monkeypatch.setattr(
        "scripts.task13_timing_pool.recheck_free_admission_claim", lambda *args: None
    )
    result = await controller.run("plan", free_admission_pin={"fixture": "free"})
    assert result["status"] == "awaiting_approval"
    assert len([c for c in fixture.calls if c[0] == "plan"]) == 1
    assert host._pool_lease is None
    with pytest.raises(PermissionError, match="lease"):
        await host.plan(1)


def test_persistent_journal_rechecks_hardlinks_on_every_read(tmp_path):
    import os

    j = journal(tmp_path)
    os.link(j.path, tmp_path / "alias.jsonl")
    with pytest.raises(PermissionError, match="link"):
        j.status()


@pytest.mark.parametrize("fault", ["missing", "stale", "wrong_trial", "paid"])
def test_each_plan_requires_fresh_bound_zero_provider_admission(tmp_path, fault):
    from datetime import timedelta
    from decimal import Decimal
    from hashlib import sha256
    from types import SimpleNamespace

    from evals.contracts import canonical_hash
    from evals.e_planning import planning_requests
    from evals.tests.test_e_timing_replicates import registration
    from scripts.task13_timing_pool import require_free_admission

    timing = registration(tmp_path)
    request = planning_requests(timing["planning_registration"])[0]
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "free_admission": {"gate_root": str(tmp_path)},
    }
    host = SimpleNamespace(_manifest_pin={"path": "host", "sha256": "a" * 64})
    gate = {
        "schema_version": "task13-host-readonly-paid-dispatch-gate-v1",
        "status": "passed",
        "phase": "pre_plan_no_new_case",
        "pool_registration_sha256": canonical_hash(pool),
        "trial_id": request.trial_id,
        "planning_request_sha256": canonical_hash(request),
        "source_commit": request.source_commit,
        "ordinal": request.ordinal,
        "host_manifest": host._manifest_pin,
        "checked_at": now.isoformat(),
        "valid_until": (now + timedelta(minutes=5)).isoformat(),
        "provider_requests": 0,
        "plan_approvals": 0,
        "timing_credit": 0,
        "plan_ttl_or_branch_budget_changes": False,
        "automatic_retry": False,
        "actual_new_case_reader_measured": False,
        "actual_six_branch_timing_measured": False,
    }
    if fault == "stale":
        gate["valid_until"] = (now - timedelta(seconds=1)).isoformat()
    if fault == "wrong_trial":
        gate["trial_id"] = "different"
    if fault == "paid":
        gate["provider_requests"] = 1
    gate_dir = tmp_path / request.trial_id
    gate_dir.mkdir()
    path = gate_dir / ("f" * 32 + ".json")
    path.write_text(json.dumps(gate))
    pin = (
        None
        if fault == "missing"
        else {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}
    )
    with pytest.raises(PermissionError, match="admission"):
        require_free_admission(
            pin,
            pool=pool,
            host=host,
            request=request,
            now=now,
            spent=Decimal(0),
            reserve=Decimal(1),
        )


def test_locked_begin_rechecks_gate_before_consuming_attempt(tmp_path):
    j = journal(tmp_path)

    def stale():
        raise PermissionError("free admission expired under lock")

    with pytest.raises(PermissionError, match="expired"):
        j.begin(
            "t0",
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
            quiescent=True,
            reserved_yuan="0.5",
            before_claim=stale,
        )
    assert j.status()["attempted"] == 0
    assert j.status()["pending"] is None


def expiry_fixture(now):
    from datetime import timedelta

    from evals.contracts import canonical_hash

    state = {
        "response_plan": {"expires_at": (now - timedelta(seconds=1)).isoformat()},
        "approval": None,
        "simulation": None,
        "simulation_execution": None,
    }
    review = {"planning_request": {"trial_id": "t0"}, "request_id": "read-1"}
    return {
        "schema_version": "task13-pool-pre-timing-expiry-v1",
        "trial_id": "t0",
        "checked_at": now.isoformat(),
        "review_request": review,
        "retained_state": state,
        "host_review_result": {
            "status": "completed",
            "operation": "read_packet",
            "input_sha256": canonical_hash(review),
            "source": {"state": state},
            "source_state_sha256": canonical_hash(state),
            "approval_receipt": None,
            "model_ledger": [],
            "host_read_receipt": {
                "origin": "host_original_postgresql_read",
                "request_sha256": canonical_hash(review),
                "state_sha256": canonical_hash(state),
                "checkpoint_transaction_read_only": "on",
                "business_transaction_read_only": "on",
                "provider_calls": 0,
                "model_calls": 0,
                "mcp_calls": 0,
                "decisions_written": 0,
            },
        },
        "native_snapshot": {
            "trials": [{"trial_id": "t0", "status": "not_started", "binding": None}],
            "records": [],
        },
        "decision_records": [],
        "planning_ledger_rows": [{"settled": 1, "actual": 0.1, "expected_cost": 0.1}],
        "budget_before_yuan": "0.1",
        "budget_after_yuan": "0.1",
    }


@pytest.mark.parametrize("reply", [None, "approved"])
def test_expiry_audit_accepts_no_reply_or_unpersisted_approval(reply):
    from evals.timing_pool_controller import validate_pre_timing_expiry_audit

    audit = expiry_fixture(datetime(2026, 11, 1, tzinfo=timezone.utc))
    if reply:
        audit["decision_records"] = [{"record": {"decision": reply}}]
    validate_pre_timing_expiry_audit(audit)


@pytest.mark.parametrize("simulation", [None, [], [{}], {}, False, ""])
def test_expiry_audit_accepts_only_native_absent_simulation(simulation):
    from evals.contracts import canonical_hash
    from evals.timing_pool_controller import validate_pre_timing_expiry_audit

    audit = expiry_fixture(datetime(2026, 11, 1, tzinfo=timezone.utc))
    state = audit["retained_state"]
    state["simulation"] = simulation
    live = audit["host_review_result"]
    live["source_state_sha256"] = canonical_hash(state)
    live["host_read_receipt"]["state_sha256"] = canonical_hash(state)
    if simulation is None or type(simulation) is list and simulation == []:
        validate_pre_timing_expiry_audit(audit)
    else:
        with pytest.raises(PermissionError):
            validate_pre_timing_expiry_audit(audit)


@pytest.mark.parametrize(
    "fault", ["rejected", "checkpoint", "ledger", "execution", "approval"]
)
def test_expiry_audit_refuses_relabelled_rejection_or_unknown_state(fault):
    from copy import deepcopy

    from evals.timing_pool_controller import validate_pre_timing_expiry_audit

    audit = deepcopy(expiry_fixture(datetime(2026, 11, 1, tzinfo=timezone.utc)))
    if fault == "rejected":
        audit["decision_records"] = [{"record": {"decision": "rejected"}}]
    if fault == "checkpoint":
        audit["host_review_result"]["host_read_receipt"][
            "checkpoint_transaction_read_only"
        ] = "off"
    if fault == "ledger":
        audit["planning_ledger_rows"][0]["actual"] = None
    if fault == "execution":
        audit["native_snapshot"]["trials"][0]["binding"] = {"unknown": True}
    if fault == "approval":
        audit["host_review_result"]["approval_receipt"] = {"status": "verified"}
    with pytest.raises(PermissionError):
        validate_pre_timing_expiry_audit(audit)


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", [None, "approved", "rejected", "unknown_terminal"])
async def test_readonly_expiry_auditor_then_next_native_slot_without_replaying(
    tmp_path, monkeypatch, request, reply
):
    from copy import deepcopy
    from decimal import Decimal
    from types import SimpleNamespace

    from evals.adapters.retained_workflow import build_approval_packet
    from evals.contracts import canonical_hash
    from evals.tests.test_e_timing_replicates import approved_source
    from evals.tests.test_e_trial_controller import chat_record
    from evals.tests.test_e_trial_controller import host as host_fixture
    from evals.timing_pool_controller import PoolJournal
    from scripts.task13_timing_pool import NativePoolController

    fixture = host_fixture.__wrapped__(tmp_path, monkeypatch, request)
    host = fixture.controller
    actual = [r.trial_id for r in host._requests]
    pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "execution_journal_path": str(tmp_path / "pool-journal.jsonl"),
        "children": [{"child_id": "a", "registration": host._timing}],
        "attempt_order": [
            {"trial_id": t, "child_id": "a"}
            for t in actual + ["unused4", "unused5", "unused6"]
        ],
    }
    j = PoolJournal.prepare(
        pool["execution_journal_path"],
        pool_sha256=canonical_hash(pool),
        attempts=[a["trial_id"] for a in pool["attempt_order"]],
        imported_trial_id="old",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    host._inputs["pool_authority"] = pool
    monkeypatch.setattr(host, "_scope", lambda: None)
    ctl = object.__new__(NativePoolController)
    ctl.pool = pool
    ctl.digest = canonical_hash(pool)
    ctl.journal = j
    ctl.hosts = {"a": host}
    ctl.guard = lambda: None
    ctl.budget = lambda: Decimal("0.1")
    ctl.reserve_bound = lambda: Decimal("0.5")

    async def quiet():
        return {
            "inspected_at": datetime(2026, 11, 1, tzinfo=timezone.utc).isoformat(),
            "proofs": [],
        }

    ctl.quiescence = quiet
    monkeypatch.setattr(
        "scripts.task13_timing_pool.require_free_admission",
        lambda *args, **kwargs: {"fixture": "free"},
    )
    monkeypatch.setattr(
        "scripts.task13_timing_pool.recheck_free_admission_claim", lambda *args: None
    )
    await ctl.run("plan", free_admission_pin={"fixture": "free"})
    ctl._expiry_planning_ledger = lambda *args: [
        {"settled": 1, "actual": 0.1, "expected_cost": 0.1}
    ]

    async def readonly(review, *args):
        state = deepcopy(fixture.source["retained_state"])
        return {
            "status": "completed",
            "operation": "read_packet",
            "input_sha256": canonical_hash(review),
            "source_state_sha256": canonical_hash(state),
            "source": {
                "state": state,
                "resources": {
                    k: fixture.source["resources"][k]
                    for k in (
                        "database_name",
                        "index_name",
                        "incident_id",
                        "source_commit",
                    )
                },
            },
            "model_ledger": [],
            "approval_receipt": None,
            "host_read_receipt": {
                "origin": "host_original_postgresql_read",
                "request_sha256": canonical_hash(review),
                "resources_sha256": canonical_hash(review.case_resource),
                "state_sha256": canonical_hash(state),
                "checkpoint_transaction_read_only": "on",
                "business_transaction_read_only": "on",
                "provider_calls": 0,
                "model_calls": 0,
                "mcp_calls": 0,
                "decisions_written": 0,
            },
        }

    monkeypatch.setattr("evals.host_review.read_e_planning_host_review", readonly)
    chats = []
    if reply:
        packet = build_approval_packet(
            {
                "case_id": host._requests[0].case_id,
                "dataset": host._requests[0].dataset,
            },
            fixture.source["retained_state"],
            now=fixture.clock.now(),
        )
        chats = [
            chat_record(
                fixture,
                packet,
                decision="approved" if reply == "unknown_terminal" else reply,
            )
        ]
    if reply == "unknown_terminal":
        import json

        current = host._requests[0]
        started = {
            "request_sha256": canonical_hash(current),
            "chat_record": chats[0],
        }
        (host._slot(current) / "decision-started.json").write_text(
            json.dumps(started), encoding="utf-8"
        )
        (host._slot(current) / "decision-terminal.json").write_text(
            json.dumps({"start_sha256": canonical_hash(started), "status": "unknown"}),
            encoding="utf-8",
        )
        with pytest.raises(PermissionError, match="unknown"):
            await ctl.audit_expiry(chat_records=chats)
        assert j.status()["pending"] == actual[0]
        assert j.status()["stopped"] == "expiry_audit_unproven"
        return
    if reply == "rejected":
        with pytest.raises(PermissionError, match="rejection"):
            await ctl.audit_expiry(chat_records=chats)
        assert j.status()["pending"] == actual[0]
        assert j.status()["stopped"] == "expiry_audit_unproven"
        return
    result = await ctl.audit_expiry(chat_records=chats)
    assert (
        result["pending"] is None and result["stopped"] == "ttl_infrastructure_failure"
    )
    assert not (host._root / "timing" / "registration.json").exists()
    await ctl.resume()
    identity = {
        k: fixture.source[k]
        for k in ("campaign_id", "source_commit", "source_sha256", "config_sha256")
    }
    replacement = approved_source(
        SimpleNamespace(registration=host._timing, identity=identity), 1, fixture.clock
    )
    replacement["resources"]["plan_sha256"] = canonical_hash(
        replacement["state"]["response_plan"]
    )
    replacement["resources_sha256"] = canonical_hash(replacement["resources"])
    fixture.source.clear()
    fixture.source.update(replacement)
    second = await ctl.run("plan", free_admission_pin={"fixture": "free"})
    assert second["status"] == "awaiting_approval"
    assert len([c for c in fixture.calls if c[0] == "plan"]) == 2
    assert j.status()["pending"] == actual[1]
    assert not (host._root / "timing" / "registration.json").exists()
    with pytest.raises(PermissionError, match="lease"):
        await host.plan(2)


def test_inventory_accepts_only_proved_pre_timing_expiry_without_native_rewrite():
    from evals.timing_pool_evidence import validate_attempt_inventory

    order = [f"t{i}" for i in range(6)]
    states = {t: {"status": "not_started", "binding": None} for t in order}
    states["t1"] = {"status": "completed"}
    states["t2"] = {"status": "completed"}
    audit = expiry_fixture(datetime(2026, 11, 1, tzinfo=timezone.utc))
    settlements = [
        {
            "trial_id": "t0",
            "outcome": "ttl_infrastructure_failure",
            "evidence": {"subtype": "pre_timing_expired", "audit": audit},
        },
        {"trial_id": "t1", "outcome": "qualified"},
        {"trial_id": "t2", "outcome": "qualified"},
    ]
    assert validate_attempt_inventory(order, order[:3], states, settlements) == [
        "t1",
        "t2",
    ]
    settlements[0]["evidence"]["audit"]["decision_records"] = [
        {"record": {"decision": "rejected"}}
    ]
    with pytest.raises(PermissionError):
        validate_attempt_inventory(order, order[:3], states, settlements)


def test_shared_m_review_required_fresh_bound_and_impossible_cutoff(tmp_path):
    from evals.timing_pool_controller import validate_guard_review

    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    j = journal(tmp_path)
    events = j._events()
    proof = {
        "schema_version": "task13-pool-guard-review-v1",
        "pool_registration_sha256": j.pool_sha256,
        "journal_head_sha256": events[-1]["sha256"],
        "checked_at": now.isoformat(),
        "formula_version": "remaining-strict-max-1500-1.5M-plus300-v1",
        "observations": [
            {
                "trial_id": "C10-1",
                "duration_wall_seconds": 900,
                "duration_monotonic_seconds": 899,
            }
        ],
        "settlement_evidence_sha256": [],
        "observed_max_seconds": 900,
    }
    assert validate_guard_review(proof, j.pool_sha256, events, now, 900) == 1650
    for field, value in [
        ("observed_max_seconds", 899),
        ("journal_head_sha256", "b" * 64),
        ("formula_version", "other"),
    ]:
        forged = {**proof, field: value}
        with pytest.raises(PermissionError):
            validate_guard_review(forged, j.pool_sha256, events, now, 900)
    from datetime import timedelta

    with pytest.raises(PermissionError, match="fresh"):
        validate_guard_review(
            proof, j.pool_sha256, events, now + timedelta(seconds=301), 900
        )
    with pytest.raises(PermissionError, match="1800|impossible"):
        validate_guard_review(proof, j.pool_sha256, events, now, 1000)


def test_shared_dispatch_clock_checks_actual_remaining_strictly_and_finishes():
    from datetime import timedelta

    from evals.timing_pool_controller import FirstDispatchClock

    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    clock = FirstDispatchClock(
        lambda: now, expires_at=now + timedelta(seconds=1650), shared_max=900
    )
    with pytest.raises(PermissionError, match="remaining"):
        clock()
    clock = FirstDispatchClock(
        lambda: now, expires_at=now + timedelta(seconds=1650.001), shared_max=900
    )
    assert clock() == now
    clock.admit()
    now += timedelta(seconds=1700)
    assert clock() == now


@pytest.mark.parametrize(
    "field",
    [
        "source",
        "approval_packet",
        "approval_receipt",
        "operation",
        "request_id",
        "source_state_sha256",
        "planning_slot_id",
        "registration_sha256",
        "selected_source_lineage_sha256",
    ],
)
def test_host_capture_rejects_resigned_review_wrapper(tmp_path, field):
    from hashlib import sha256
    from types import SimpleNamespace

    from scripts.task13_e_trial import ETrialController

    request = SimpleNamespace(
        schema_version="review", case_id="case", request_id="request"
    )
    nonce = "a" * 32
    root = tmp_path / "source_review" / "case" / "request" / (nonce + ".controller")
    root.mkdir(parents=True)
    raw = json.dumps({field: "actual"}).encode()
    path = root / "worker-stdout.bin"
    path.write_bytes(raw)
    host = object.__new__(ETrialController)
    host._requests = [SimpleNamespace(source_commit="commit")]
    host._save = lambda category, data: {
        "sha256": sha256(data).hexdigest(),
        "path": str(tmp_path / category),
    }
    value = {
        field: "forged",
        "isolation_evidence": {
            "raw_stdout": {
                "path": str(path),
                "sha256": sha256(raw).hexdigest(),
                "bytes": len(raw),
            },
            "status": "passed",
            "source_commit": "commit",
            "probe": {"pid": 1, "nonce": nonce},
            "container": {"container_id": "owned"},
        },
    }
    with pytest.raises(PermissionError, match="original worker stdout"):
        host._capture(value, {"output_dir": str(tmp_path)}, request)


def test_guard_review_unlocks_only_same_fresh_closed_prefix(tmp_path):
    from evals.contracts import canonical_hash
    from evals.timing_pool_controller import (
        GUARD_FORMULA,
        PoolJournal,
        validate_pool_journal_evidence,
    )

    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "attempt_order": [{"trial_id": f"t{i}"} for i in range(6)],
        "imported_observations": [{"trial_id": "old"}],
    }
    j = PoolJournal.prepare(
        tmp_path / "journal.jsonl",
        pool_sha256=canonical_hash(pool),
        attempts=[f"t{i}" for i in range(6)],
        imported_trial_id="old",
        now=now,
        imported_max_seconds=900,
    )
    with pytest.raises(PermissionError, match="guard review"):
        begin(j)
    proof = {
        "schema_version": "task13-pool-guard-review-v1",
        "pool_registration_sha256": j.pool_sha256,
        "journal_head_sha256": j.status()["journal_head"],
        "checked_at": now.isoformat(),
        "formula_version": GUARD_FORMULA,
        "observations": [
            {
                "trial_id": "old",
                "duration_wall_seconds": 900,
                "duration_monotonic_seconds": 899,
            }
        ],
        "settlement_evidence_sha256": [],
        "observed_max_seconds": 900,
    }
    with j.lock():
        j._append("guard_review", proof, j._events())
    review = j.status()["journal_head"]
    begin(j)
    assert j._events()[-1]["payload"]["guard_review_sha256"] == review
    from hashlib import sha256

    result = validate_pool_journal_evidence(
        {
            "pool_journal": {
                "path": str(j.path),
                "sha256": sha256(j.path.read_bytes()).hexdigest(),
                "head_sha256": j.status()["journal_head"],
            }
        },
        pool,
    )
    assert result["state"]["pending"] == "t0"
    with pytest.raises(PermissionError, match="pending"):
        begin(j)


@pytest.mark.asyncio
async def test_shared_m_last_native_clock_rejects_after_slow_input_write(
    tmp_path, monkeypatch
):
    from datetime import datetime

    from evals.e_timing import ETimingCampaign
    from evals.tests.test_e_timing import Clock, admit, lifecycle, verify
    from evals.tests.test_e_timing_replicates import approved_source, registration
    from evals.timing_pool_controller import FirstDispatchClock

    clock = Clock()
    reg = registration(tmp_path)
    store = ETimingCampaign(
        reg,
        tmp_path / "native",
        execution_admitter=admit,
        approval_verifier=verify,
        worker_lifecycle_verifier=lifecycle,
        now=clock.now,
        monotonic_ns=clock.monotonic_ns,
    )
    source = approved_source(store, 0, clock)
    gate = FirstDispatchClock(
        clock.now,
        expires_at=datetime.fromisoformat(
            source["state"]["response_plan"]["expires_at"]
        ),
        shared_max=900,
    )
    store.now = gate
    save = store._save

    def delayed(category, value):
        result = save(category, value)
        if category == "inputs":
            clock.advance(151)
        return result

    monkeypatch.setattr(store, "_save", delayed)
    called = []

    async def worker(request):
        called.append(request)
        raise AssertionError("must not execute")

    with pytest.raises(PermissionError, match="remaining"):
        await store.run_trial(reg["trials"][0]["trial_id"], source, run_worker=worker)
    assert called == []


@pytest.fixture(scope="module")
def native_guard_review_evidence():
    from evals.timing_pool import C10_EVIDENCE_ROOT, C10_REGISTRATION, C10_TRIAL
    from evals.timing_pool_evidence import guard_observations

    pool = {
        "schema_version": "task13-e-timing-pool-registration-v1",
        "imported_observations": [
            {
                "evidence_root": str(C10_EVIDENCE_ROOT),
                "trial_id": C10_TRIAL,
                "registration_sha256": C10_REGISTRATION,
            }
        ],
        "children": [],
    }
    # Cache the independent full native read once. Every test below still uses
    # the real journal reader and replays the original completed six branches.
    return pool, guard_observations(pool, [])


@pytest.mark.parametrize("change", ["source", "duration", "head", "completion"])
def test_public_guard_review_recomputes_original_native_facts(
    monkeypatch, change, native_guard_review_evidence
):
    from copy import deepcopy

    from evals.timing_pool_evidence import validate_native_guard_reviews

    pool, observed = native_guard_review_evidence
    monkeypatch.setattr(
        "evals.timing_pool_evidence.guard_observations",
        lambda pool, ids: deepcopy(observed),
    )
    proof = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "observations": deepcopy(observed),
    }
    validate_native_guard_reviews([{"kind": "guard_review", "payload": proof}], pool)
    supplied = proof["observations"][0]
    if change == "source":
        supplied["observation"]["identity"]["source_commit"] = "forged"
    if change == "duration":
        supplied["duration_wall_seconds"] = 850
    if change == "head":
        supplied["native_journal_head_sha256"] = "b" * 64
    if change == "completion":
        proof["checked_at"] = "2026-10-31T23:59:59+00:00"
    with pytest.raises(PermissionError):
        validate_native_guard_reviews(
            [{"kind": "guard_review", "payload": proof}], pool
        )
