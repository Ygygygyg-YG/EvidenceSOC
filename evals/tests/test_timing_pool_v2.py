"""Free synthetic v2 bounded pool tests; never dispatches work."""

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from evals import timing_pool
from evals.tests.test_e_planning_limited_authority import limited_fixture
from evals.timing_pool_controller import PoolJournal
from evals.timing_pool_evidence import validate_attempt_inventory


def native_genesis_fixture(tmp_path):
    """Real native registration events; SQL holds no planning claims."""
    import sqlite3
    from types import SimpleNamespace

    from evals.e_planning import planning_requests
    from evals.e_timing import ETimingCampaign, file_sha256

    pool = pool_fixture(tmp_path)
    runtime = tmp_path / "runtime.py"
    runtime.write_text("# synthetic native genesis only\n", encoding="utf-8")
    contexts = {}
    for child in pool["children"]:
        root = tmp_path / child["child_id"] / "timing"
        child["evidence_root"] = str(root)
        child["registration"]["source_files"] = {str(runtime): file_sha256(runtime)}
        ETimingCampaign(child["registration"], root)
        journal = root.parent / "claims.sqlite"
        with sqlite3.connect(journal) as db:
            db.execute(
                "CREATE TABLE analysis_import_planning_claims(planning_slot_id TEXT)"
            )
        requests = planning_requests(child["registration"]["planning_registration"])
        host = SimpleNamespace(
            _root=root.parent,
            _requests=requests,
            _inputs={"planning_authority": {"journal_path": str(journal)}},
            _manifest={"inputs": {"scope_packet": {}, "scope_decision": {}}},
            _preflight=lambda request: None,
            _journal=lambda: None,
        )
        contexts[child["child_id"]] = {
            "reader": host,
            "claims": {r.trial_id: {"status": "unclaimed"} for r in requests},
            "planning_journal_path": str(journal),
        }
    return pool, contexts


def test_native_genesis_passes_denied_slot_parent_guard_and_evidence(
    tmp_path, monkeypatch
):
    """Keep native loading and both consumer call sites real; stop after inventory."""
    from evals import timing_pool_evidence
    from evals.contracts import canonical_hash
    from scripts import task13_timing_pool as native
    from scripts.task13_pool_prepare import Documents

    pool, contexts = native_genesis_fixture(tmp_path)
    docs = Documents(tmp_path / "documents")
    marker = docs.stage("marker.json", {})
    scope = docs.stage("scope.json", {})
    pool["quarantine_record"] = marker
    pool["quarantined_predecessor"]["quarantine_record"] = marker
    pool["migration_grant"]["quarantine_record_sha256"] = marker["sha256"]
    pool["migration_grant_sha256"] = canonical_hash(pool["migration_grant"])
    # Scope/equivalence host semantics are separate from native structural state.
    monkeypatch.setattr(timing_pool, "validate_migration_marker", lambda *args: None)
    pool["original_account_baseline"] = scope
    pool["imported_observations"][0]["evidence_root"] = pool["children"][0][
        "evidence_root"
    ]
    pool_pin = docs.stage("pool.json", pool)
    hosts = {}
    for child in pool["children"]:
        hosts[child["child_id"]] = docs.stage(
            child["child_id"] + ".json",
            {
                "output_dir": str(
                    __import__("pathlib").Path(child["evidence_root"]).parent
                ),
                "inputs": {
                    "pool_authority": pool_pin,
                    "timing_registration": docs.stage(
                        child["child_id"] + "-registration.json", child["registration"]
                    ),
                    "scope_packet": scope,
                    "scope_decision": scope,
                },
            },
        )
    manifest = {
        "schema_version": "task13-e-timing-pool-host-v2",
        "pool_registration": pool_pin,
        "hosts": hosts,
        "journal_path": pool["execution_journal_path"],
        "migration_marker": marker,
        "original_account_baseline": scope,
    }
    manifest_pin = docs.stage("host.json", manifest)
    docs.publish()
    journal = PoolJournal.prepare(
        pool["execution_journal_path"],
        pool_sha256=canonical_hash(pool),
        attempts=[a["trial_id"] for a in pool["attempt_order"]],
        imported_trial_id=timing_pool.C10_TRIAL,
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        policy=policy(),
        migration_grant=pool["migration_grant"],
        quarantined_predecessor=pool["quarantined_predecessor"],
    )
    controller = object.__new__(native.NativePoolController)
    controller.pin, controller.raw = manifest_pin, native._read_pin(manifest_pin)
    controller.manifest, controller.pool = manifest, pool
    controller.hosts = {cid: ctx["reader"] for cid, ctx in contexts.items()}
    controller.guard()
    monkeypatch.setattr(
        timing_pool,
        "_validate_host_semantics",
        lambda view, host, inputs: next(
            c for c in contexts.values() if c["reader"]._root == view.root.parent
        ),
    )

    class InventoryChecked(Exception):
        pass

    def after_inventory(*args):
        raise InventoryChecked

    monkeypatch.setattr(timing_pool, "_branches", after_inventory)
    evidence = {
        "pool_host_manifest": manifest_pin,
        "host_manifests": hosts,
        "migration_marker": marker,
        "pool_journal": {
            "path": str(journal.path),
            "sha256": timing_pool.file_sha256(journal.path),
            "head_sha256": journal.status()["journal_head"],
        },
        "parent_scope_packets": [scope, scope],
        "parent_scope_decisions": [scope, scope],
    }
    with pytest.raises(InventoryChecked):
        timing_pool_evidence.validate_controller_evidence(
            evidence, pool, {}, require_complete=False
        )


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "extra",
        "request_id",
        "trial_id",
        "status",
        "reason",
        "input_sha256",
        "output_sha256",
        "started_at",
        "worker_nonce",
        "review_pending",
        "trial_reason",
        "trial_binding",
        "trial_review",
        "branch_configuration",
        "branch_type",
        "trial_journal_event",
        "branch_journal_event",
    ],
)
def test_denied_native_genesis_rejects_every_structural_or_evidence_change(
    tmp_path, change
):
    pool, contexts = native_genesis_fixture(tmp_path)
    denied = pool["denied_attempts"][0]
    context = contexts[denied["child_id"]]
    request = next(
        r for r in context["reader"]._requests if r.trial_id == denied["trial_id"]
    )
    view = timing_pool._view(context["reader"]._root / "timing")
    keys = [
        key for key, row in view.records.items() if row["trial_id"] == request.trial_id
    ]
    assert len(view.events) == 1 and len(keys) == 6
    timing_pool.validate_denied_native_slot(context, request, view)
    if change == "missing":
        del view.records[keys[0]]
    elif change == "extra":
        view.records["unexpected"] = deepcopy(view.records[keys[0]])
    elif change == "trial_journal_event":
        view._append({"kind": "trial.activity", "trial_id": request.trial_id})
    elif change == "branch_journal_event":
        view._append({"kind": "branch.activity", "request_id": keys[0]})
    elif change.startswith("trial_") and change != "trial_id":
        field = {
            "trial_reason": "reason",
            "trial_binding": "binding",
            "trial_review": "review_pending",
        }[change]
        view.trials[request.trial_id][field] = "unexpected"
    elif change == "branch_configuration":
        row = view.records[keys[0]]
        row["verification_enabled"] = not row["verification_enabled"]
    elif change == "branch_type":
        row = view.records[keys[0]]
        row["verification_enabled"] = int(row["verification_enabled"])
    else:
        view.records[keys[0]][change] = "unexpected"
    with pytest.raises(PermissionError, match="denied"):
        timing_pool.validate_denied_native_slot(context, request, view)


def policy(version=2):
    function = getattr(timing_pool, "pool_policy", None)
    assert callable(function), "explicit pool policy dispatch is required"
    return function(f"task13-e-timing-pool-registration-v{version}")


def bindings(tmp_path):
    _, authorities = limited_fixture(tmp_path)
    grant = authorities[0]["migration_grant"]
    predecessor = {
        key: {
            "path": str(tmp_path / (key + ".json")),
            "sha256": grant["predecessor_" + key + "_sha256"],
        }
        for key in ("pool_registration", "pool_journal")
    }
    predecessor["pool_head_sha256"] = grant["predecessor_pool_head_sha256"]
    predecessor["quarantine_record"] = {
        "path": str(tmp_path / "quarantine.json"),
        "sha256": grant["quarantine_record_sha256"],
    }
    return grant, predecessor


def prepare(tmp_path):
    grant, predecessor = bindings(tmp_path)
    return PoolJournal.prepare(
        tmp_path / "pool-journal.jsonl",
        pool_sha256="a" * 64,
        attempts=[f"t{i}" for i in range(5)],
        imported_trial_id="C10",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        policy=policy(),
        migration_grant=grant,
        quarantined_predecessor=predecessor,
    )


def test_policy_is_explicit_and_legacy_limits_stay_fixed():
    assert (
        policy(1).future_logical_limit,
        policy(1).historical_logical,
        policy(1).historical_physical,
    ) == (6, 7, 21)
    assert (
        policy().future_logical_limit,
        policy().future_physical_limit,
        policy().historical_logical,
        policy().historical_physical,
    ) == (5, 15, 8, 24)
    for unknown in (None, {}, "task13-e-timing-pool-registration-v4"):
        with pytest.raises(PermissionError):
            timing_pool.pool_policy(unknown)


def test_recovery_journal_binds_genesis_and_counts_old_unknown(tmp_path):
    j = prepare(tmp_path)
    assert j.status()["consumed_logical"] == 8
    assert j.status()["physical_upper_bound"] == 24
    j.begin(
        "t0",
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        quiescent=True,
        reserved_yuan="0.5",
    )
    assert j.status()["consumed_logical"] == 9
    assert j.status()["physical_upper_bound"] == 27
    assert j.status()["analysis_inclusive_upper_bound"] == 28
    legacy = PoolJournal(j.path, pool_sha256="a" * 64)
    with pytest.raises(PermissionError, match="policy|genesis"):
        legacy.status()


def test_recovery_journal_requires_full_matching_grant(tmp_path):
    grant, pred = bindings(tmp_path)
    pred["pool_head_sha256"] = "b" * 64
    with pytest.raises(PermissionError, match="quarantine|predecessor"):
        PoolJournal.prepare(
            tmp_path / "pool-journal.jsonl",
            pool_sha256="a" * 64,
            attempts=[f"t{i}" for i in range(5)],
            imported_trial_id="C10",
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
            policy=policy(),
            migration_grant=grant,
            quarantined_predecessor=pred,
        )


def test_v2_inventory_rejects_activity_in_excluded_sixth_native_slot():
    order = [f"t{i}" for i in range(5)]
    states = {
        trial: {"status": "not_started", "binding": None}
        for trial in order + ["denied"]
    }
    settlements = [{"trial_id": t, "outcome": "qualified"} for t in order[:2]]
    for t in order[:2]:
        states[t]["status"] = "completed"
    assert (
        validate_attempt_inventory(
            order,
            order[:2],
            states,
            settlements,
            policy=policy(),
            denied_trial_ids=["denied"],
        )
        == order[:2]
    )
    states["denied"]["review_pending"] = True
    with pytest.raises(PermissionError, match="denied|excluded"):
        validate_attempt_inventory(
            order,
            order[:2],
            states,
            settlements,
            policy=policy(),
            denied_trial_ids=["denied"],
        )


def pool_fixture(tmp_path):
    from evals.contracts import canonical_hash
    from evals.e_planning import planning_requests
    from evals.e_timing import BOOTSTRAP, ORDER, build_e_timing_registration

    regs, authorities = limited_fixture(tmp_path)
    grant, predecessor = bindings(tmp_path)
    for i, reg in enumerate(regs):
        reg["core_config"]["f8_plan_sha256"] = "f" * 64
        reg["core_config_sha256"] = canonical_hash(reg["core_config"])
        authority = authorities[i]
        authority["registration_sha256"] = canonical_hash(reg)
        authority["request_sha256s"] = [
            canonical_hash(q) for q in planning_requests(reg)
        ]
        authority["authorized_request_sha256s"] = authority["request_sha256s"][: 3 - i]
        authority["denied_request_sha256s"] = authority["request_sha256s"][3 - i :]
        grant["children"][i] = {key: authority[key] for key in grant["children"][i]}
    for authority in authorities:
        authority["migration_grant"] = deepcopy(grant)
        authority["migration_grant_sha256"] = canonical_hash(grant)
    children = []
    for i, (reg, authority) in enumerate(zip(regs, authorities, strict=True)):
        requests = planning_requests(reg)
        dispatch = {
            "schema_version": "task13-e-planning-dispatch-registration-v1",
            "campaign_id": reg["campaign_id"],
            "registration_sha256": canonical_hash(reg),
            "authority_sha256": canonical_hash(authority),
            "journal_path": authority["journal_path"],
            "synthetic": True,
            "planning_slot_ids": [q.planning_slot_id for q in requests],
        }
        timing = build_e_timing_registration(
            reg,
            source_files={str(tmp_path / "runtime.py"): "a" * 64},
            f8_plan_sha256="f" * 64,
            planning_dispatch_registration_receipt=dispatch,
        )
        children.append({"child_id": f"child-{i}", "registration": timing})
    order = [
        {"child_id": c["child_id"], "trial_id": t["trial_id"]}
        for c in children
        for t in c["registration"]["trials"]
    ]
    return {
        "schema_version": timing_pool.RECOVERY_REGISTRATION_SCHEMA,
        "target_qualified": 3,
        "future_logical_limit": 5,
        "future_physical_limit": 15,
        "measurement_constants": {
            "bootstrap": BOOTSTRAP,
            "order": [list(x) for x in ORDER],
        },
        "execution_journal_path": str(tmp_path / "pool-journal.jsonl"),
        "children": children,
        "imported_observations": [
            {
                "trial_id": timing_pool.C10_TRIAL,
                "registration_sha256": timing_pool.C10_REGISTRATION,
                "evidence_root": str(tmp_path / "c10"),
            }
        ],
        "attempt_order": order[:5],
        "denied_attempts": order[5:],
        "recovery_plan": {
            "path": str(tmp_path / "recovery-plan.json"),
            "sha256": grant["recovery_plan_sha256"],
        },
        "migration_grant": grant,
        "migration_grant_sha256": canonical_hash(grant),
        "quarantined_predecessor": predecessor,
        "quarantine_record": predecessor["quarantine_record"],
        "recovery_equivalence": {
            "original_execution": {},
            "candidate_execution": {},
            "policy_pin": {"path": str(tmp_path / "policy.json"), "sha256": "b" * 64},
        },
        "measurement_files": {},
        "original_measurement_files": {},
    }


def test_v2_structure_keeps_two_three_slot_children_and_exact_denied_slot(tmp_path):
    pool = pool_fixture(tmp_path)
    assert timing_pool.validate_pool_structure(pool) == pool
    for mutate in ("sixth", "denied", "grant", "rawpin", "child"):
        bad = deepcopy(pool)
        if mutate == "sixth":
            bad["attempt_order"] += bad["denied_attempts"]
        elif mutate == "denied":
            bad["denied_attempts"] = []
        elif mutate == "grant":
            bad["migration_grant_sha256"] = "0" * 64
        elif mutate == "rawpin":
            bad["quarantine_record"]["sha256"] = "0" * 64
        else:
            bad["children"].reverse()
        with pytest.raises(PermissionError):
            timing_pool.validate_pool_structure(bad)


def test_receipt_consumers_route_v2_only_through_pool_validator(monkeypatch):
    from evals import verification_v2

    receipt = {"schema_version": "task13-e-timing-pool-receipt-v2"}
    seen = []
    monkeypatch.setattr(
        timing_pool, "validate_pool_receipt", lambda r, i: seen.append((r, i)) or 391.0
    )
    assert verification_v2.observed_timing_max(receipt, {"actual": "identity"}) == 391.0
    assert seen == [(receipt, {"actual": "identity"})]


def test_v2_scope_projection_normalizes_only_future_authority_derivatives(tmp_path):
    from evals.contracts import canonical_hash
    from evals.e_planning import planning_requests
    from evals.timing_pool_controller import pool_scope_proposal

    pool = pool_fixture(tmp_path)
    proposal = pool_scope_proposal(pool)
    assert proposal["migration_grant"]["scope_packet_sha256"] == "0" * 64
    assert proposal["migration_grant"]["decision_record_sha256"] == "0" * 64
    assert proposal["migration_grant_sha256"] == canonical_hash(
        proposal["migration_grant"]
    )
    for child, grant in zip(
        proposal["children"], proposal["migration_grant"]["children"], strict=True
    ):
        native = child["registration"]["planning_registration"]
        assert grant["registration_sha256"] == canonical_hash(native)
        assert grant["request_sha256s"] == [
            canonical_hash(q) for q in planning_requests(native)
        ]
    assert proposal["quarantined_predecessor"] == pool["quarantined_predecessor"]
    assert proposal["recovery_equivalence"] == pool["recovery_equivalence"]
    assert proposal["recovery_plan"] == pool["recovery_plan"]


def test_denied_slot_verifier_checks_native_claim_directory_records_and_sql(tmp_path):
    from types import SimpleNamespace

    helper = getattr(timing_pool, "validate_denied_native_slot", None)
    assert callable(helper), "excluded native slot requires explicit all-channel check"
    request = SimpleNamespace(
        trial_id="denied", planning_slot_id="slot", incident_id="incident"
    )
    root = tmp_path / "host"
    root.mkdir()
    view = SimpleNamespace(
        trials={"denied": {"status": "not_started", "binding": None}}, records={}
    )
    reader = SimpleNamespace(_root=root)
    context = {
        "reader": reader,
        "claims": {"denied": {"status": "unclaimed"}},
        "planning_journal_path": str(tmp_path / "claims.sqlite"),
    }
    import sqlite3

    with sqlite3.connect(context["planning_journal_path"]) as db:
        db.execute(
            "CREATE TABLE analysis_import_planning_claims(planning_slot_id TEXT)"
        )
    helper(context, request, view)
    slot = root / "slots" / "slot"
    slot.mkdir(parents=True)
    (slot / "read-started.json").write_text("{}")
    with pytest.raises(PermissionError, match="denied|excluded"):
        helper(context, request, view)
    (slot / "read-started.json").unlink()
    view.records = {"x": {"trial_id": "denied"}}
    with pytest.raises(PermissionError, match="denied|excluded"):
        helper(context, request, view)
    view.records = {}
    with sqlite3.connect(context["planning_journal_path"]) as db:
        db.execute("INSERT INTO analysis_import_planning_claims VALUES ('slot')")
    with pytest.raises(PermissionError, match="denied|excluded"):
        helper(context, request, view)


@pytest.mark.asyncio
async def test_native_pool_prepare_uses_recovery_policy_and_complete_genesis(
    tmp_path, monkeypatch
):
    from evals.contracts import canonical_hash
    from scripts import task13_timing_pool as native

    pool = pool_fixture(tmp_path)
    controller = object.__new__(native.NativePoolController)
    controller.pool = pool
    controller.digest = canonical_hash(pool)
    controller.journal = PoolJournal(
        tmp_path / "pool-journal.jsonl", pool_sha256=controller.digest, policy=policy()
    )
    controller.guard = lambda: None
    controller.budget = lambda: 0

    async def quiet():
        return {}

    controller.quiescence = quiet
    monkeypatch.setattr(
        native,
        "read_native_observation",
        lambda *a, **k: {
            "trial_id": timing_pool.C10_TRIAL,
            "duration_wall_seconds": 384.562,
            "duration_monotonic_seconds": 384.562,
        },
    )
    state = await controller.prepare()
    assert state["consumed_logical"] == 8
    assert (
        controller.journal._events()[0]["payload"]["migration_grant"]
        == pool["migration_grant"]
    )


def test_v2_migration_validation_binds_actual_parent_scope_and_quarantine(
    tmp_path, monkeypatch
):
    pool = pool_fixture(tmp_path)
    seen = []
    monkeypatch.setattr(
        timing_pool,
        "validate_recovery_quarantine",
        lambda p: seen.append(p) or {"schema_version": "quarantine-fixture"},
    )
    packet = {
        "path": str(tmp_path / "packet.json"),
        "sha256": pool["migration_grant"]["scope_packet_sha256"],
    }
    decision = {
        "path": str(tmp_path / "decision.json"),
        "sha256": pool["migration_grant"]["decision_record_sha256"],
    }
    timing_pool.validate_migration_marker(
        {"schema_version": "quarantine-fixture"}, pool, packet, decision
    )
    assert seen == [pool]
    packet["sha256"] = "0" * 64
    with pytest.raises(PermissionError):
        timing_pool.validate_migration_marker({}, pool, packet, decision)


def test_recovery_equivalence_join_rejects_declared_or_native_source_drift(
    tmp_path, monkeypatch
):
    join = getattr(timing_pool, "validate_recovery_equivalence_join", None)
    identity = getattr(timing_pool, "recovery_execution_identity", None)
    assert callable(join) and callable(identity), (
        "scope-only proof requires independent native join"
    )
    pool = pool_fixture(tmp_path)
    old = deepcopy(pool["children"][0]["registration"])
    for reg in [old] + [c["registration"] for c in pool["children"]]:
        reg["planning_registration"]["epoch_binding"]["model_identity_binding"] = {
            "model_epoch_id": "native-model",
            "model_identity_sha256": "e" * 64,
        }
        reg["core_config"]["model_identity"] = {
            "id": "native-model",
            "expected_response_model": "real-model",
        }
    conditions = {
        "received_model": {"response_model": "real-model", "fingerprint": "fp"},
        "image_id": "image",
        "dependencies_lock_sha256": "a" * 64,
        "dependencies_tree_sha256": "b" * 64,
        "knowledge_sha256": "c" * 64,
    }
    files = {f"file{i}.py": "a" * 64 for i in range(117)}
    pool["measurement_files"] = files
    pool["original_measurement_files"] = files
    pool["measurement_root"] = str(tmp_path / "new")
    for c in pool["children"]:
        c["registration"]["source_files"] = {
            str(tmp_path / "new" / "native.py"): "a" * 64
        }
        c["disclosed_control_changes"] = {}
    old["source_files"] = {str(tmp_path / "old" / "native.py"): "a" * 64}
    pool["condition_identity"] = {
        "core_config": old["core_config"],
        "actual_conditions": conditions,
    }
    old_record = {
        "root": str(tmp_path / "old"),
        "measurement_files": files,
        "native_measurement_files": {"native.py": "a" * 64},
        "identity": identity(old),
        "core_config": old["core_config"],
        "disclosed_control_changes": {},
        "candidate_conditions": conditions,
        "measurement_constants": pool["measurement_constants"],
    }
    current = pool["children"][0]["registration"]
    new_record = {
        **deepcopy(old_record),
        "root": pool["measurement_root"],
        "identity": identity(current),
        "core_config": current["core_config"],
    }
    pool["recovery_equivalence"].update(
        original_execution=old_record, candidate_execution=new_record
    )
    proof = {
        "schema_version": "task13-recovery-equivalence-proof-v1",
        "scope": "source-and-declared-conditions-only",
        "authorization": False,
        "timing_credit": False,
        "original_measurement_files": files,
        "candidate_measurement_files": files,
        "native_measurement_files": {"native.py": "a" * 64},
        "candidate_native_measurement_files": {"native.py": "a" * 64},
        "declared_candidate_conditions": conditions,
    }
    monkeypatch.setattr(
        timing_pool, "validate_recovery_measurement_equivalence", lambda p: proof
    )
    original = {"registration": old, "actual_conditions": conditions}
    assert join(pool, original) == proof
    for key in ("candidate_conditions", "identity", "native_measurement_files"):
        bad = deepcopy(pool)
        bad["recovery_equivalence"]["candidate_execution"][key] = {
            "invented": "different"
        }
        with pytest.raises(PermissionError):
            join(bad, original)


@pytest.mark.asyncio
async def test_v2_quiescence_freshly_rechecks_quarantined_workers(
    tmp_path, monkeypatch
):
    from evals import timing_pool_recovery as recovery
    from scripts import task13_timing_pool as native

    pool = pool_fixture(tmp_path)
    controller = object.__new__(native.NativePoolController)
    controller.pool = pool
    controller.hosts = {}
    seen = []
    monkeypatch.setattr(
        timing_pool, "validate_recovery_quarantine", lambda p: {"old": "quarantine"}
    )
    monkeypatch.setattr(
        recovery,
        "fresh_quarantine_workers_absent",
        lambda value: seen.append(value) or {"status": "verified", "workers": []},
    )
    proof = await controller.quiescence()
    assert seen == [{"old": "quarantine"}]
    assert proof["quarantined_predecessor_workers"] == {
        "status": "verified",
        "workers": [],
    }


def test_v2_worker_absence_evidence_requires_exact_owned_worker_ids(
    tmp_path, monkeypatch
):
    from hashlib import sha256
    from types import SimpleNamespace

    from evals.timing_pool_evidence import _quiescence

    pool = pool_fixture(tmp_path)
    container = "f" * 64
    monkeypatch.setattr(
        timing_pool,
        "validate_recovery_quarantine",
        lambda p: {"workers": [{"container_id": container}]},
    )
    root = tmp_path / "termination"
    root.mkdir()
    context = {
        "child": {
            "reader": SimpleNamespace(
                _termination=root, _inputs={"pool_authority": pool}
            )
        }
    }
    proof = {"inspected_at": "2026-11-01T00:00:00+00:00", "proofs": []}
    with pytest.raises(PermissionError, match="quarantine|predecessor"):
        _quiescence(proof, context)
    record = {
        "argv": [
            "docker",
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            "id=" + container,
            "--format",
            "{{.ID}}",
        ],
        "returncode": 0,
        "stdout_sha256": sha256(b"").hexdigest(),
        "stderr_sha256": sha256(b"").hexdigest(),
    }
    proof["quarantined_predecessor_workers"] = {
        "schema_version": "task13-manual-quarantine-worker-absence-v1",
        "status": "verified",
        "workers": [{"container_id": container, "inspection": record}],
    }
    _quiescence(proof, context)
    proof["quarantined_predecessor_workers"]["workers"][0]["container_id"] = "0" * 64
    with pytest.raises(PermissionError, match="quarantine|predecessor"):
        _quiescence(proof, context)


def test_native_host_v2_rejects_wrong_quarantine_raw_ref_before_child_creation(
    tmp_path, monkeypatch
):
    import json

    from scripts import task13_timing_pool as native

    pool = pool_fixture(tmp_path)
    pool["original_account_baseline"] = {"path": "baseline", "sha256": "b" * 64}
    manifest = {
        "schema_version": "task13-e-timing-pool-host-v2",
        "pool_registration": {"path": "pool", "sha256": "c" * 64},
        "original_account_baseline": pool["original_account_baseline"],
        "migration_marker": {
            "path": str(tmp_path / "other-quarantine.json"),
            "sha256": pool["quarantine_record"]["sha256"],
        },
        "journal_path": pool["execution_journal_path"],
        "hosts": {
            c["child_id"]: {"path": "child", "sha256": "e" * 64}
            for c in pool["children"]
        },
    }
    monkeypatch.setattr(
        native,
        "_read_pin",
        lambda pin: json.dumps(manifest).encode() if pin["path"] == "host" else b"{}",
    )
    monkeypatch.setattr(native, "validate_pool_registration", lambda value: pool)
    monkeypatch.setattr(
        native,
        "ETrialController",
        lambda *a: (_ for _ in ()).throw(
            AssertionError("quarantine must be checked before creating children")
        ),
    )
    with pytest.raises(PermissionError, match="quarantine"):
        native.NativePoolController("host", "d" * 64)


def test_v2_journal_receipt_rejects_rehashed_genesis_grant_rebinding(tmp_path):
    import json
    from hashlib import sha256

    from evals.contracts import canonical_hash
    from evals.timing_pool_controller import _raw, validate_pool_journal_evidence

    pool = pool_fixture(tmp_path)
    j = PoolJournal.prepare(
        tmp_path / "pool-journal.jsonl",
        pool_sha256=canonical_hash(pool),
        attempts=[a["trial_id"] for a in pool["attempt_order"]],
        imported_trial_id=timing_pool.C10_TRIAL,
        now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        policy=policy(),
        migration_grant=pool["migration_grant"],
        quarantined_predecessor=pool["quarantined_predecessor"],
    )

    def evidence():
        return {
            "pool_journal": {
                "path": str(j.path),
                "sha256": sha256(j.path.read_bytes()).hexdigest(),
                "head_sha256": json.loads(j.path.read_bytes())["sha256"],
            }
        }

    assert (
        validate_pool_journal_evidence(evidence(), pool)["state"]["consumed_logical"]
        == 8
    )
    event = json.loads(j.path.read_bytes())
    event["payload"]["migration_grant"]["decision_record_sha256"] = "e" * 64
    event.pop("sha256")
    event["sha256"] = sha256(_raw(event)).hexdigest()
    j.path.write_bytes(_raw(event) + b"\n")
    with pytest.raises(PermissionError, match="genesis|grant"):
        validate_pool_journal_evidence(evidence(), pool)


def test_recovery_child_authority_cannot_switch_to_other_granted_child(tmp_path):
    from evals.contracts import canonical_hash

    pool = pool_fixture(tmp_path)
    _, authorities = limited_fixture(tmp_path)
    rebuilt = []
    for authority, child in zip(
        authorities, pool["migration_grant"]["children"], strict=True
    ):
        authority.update(child)
        authority["migration_grant"] = deepcopy(pool["migration_grant"])
        authority["migration_grant_sha256"] = pool["migration_grant_sha256"]
        rebuilt.append(authority)
    timing = pool["children"][0]["registration"]
    timing["planning_dispatch_registration_receipt"]["authority_sha256"] = (
        canonical_hash(rebuilt[0])
    )
    timing_pool.require_recovery_child_authority(pool, timing, rebuilt[0])
    timing["planning_dispatch_registration_receipt"]["authority_sha256"] = (
        canonical_hash(rebuilt[1])
    )
    with pytest.raises(PermissionError, match="child|grant|registration"):
        timing_pool.require_recovery_child_authority(pool, timing, rebuilt[1])
