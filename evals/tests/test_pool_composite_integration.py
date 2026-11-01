"""SYNTHETIC OFFLINE ONLY: no actual user, model, E3 or F8 approval credit."""

import sqlite3
from hashlib import sha256

import pytest

from evals.tests.pool_composite_fixture import isolated_native_io


def test_fixture_cannot_register_without_copy_namespace():
    from evals.tests.pool_composite_fixture import register_fixture_metadata

    with pytest.raises(PermissionError, match="isolated database namespace"):
        register_fixture_metadata({})


def test_historical_ledger_is_exact_native_code_except_two_latest_leaves():
    import ast
    import inspect
    import textwrap

    from evals.adapters.planning_recovery import verify_historical_identity_ledger
    from evals.timing_pool_history import _historical_identity_ledger

    original = ast.parse(
        textwrap.dedent(inspect.getsource(verify_historical_identity_ledger))
    )
    historical = ast.parse(
        textwrap.dedent(inspect.getsource(_historical_identity_ledger))
    )
    original.body[0].name = historical.body[0].name
    changes = 0
    for node in ast.walk(original):
        if (
            isinstance(node, ast.keyword)
            and node.arg == "latest"
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
        ):
            node.value.value = False
            changes += 1
    assert changes == 2
    assert ast.dump(original, include_attributes=False) == ast.dump(
        historical, include_attributes=False
    )


def test_shared_parent_authority_is_rooted_and_exact_child_bound(tmp_path):
    from copy import deepcopy
    from pathlib import Path
    from types import SimpleNamespace

    from evals.tests.pool_composite_prepare_fixture import compile_fixture_documents
    from evals.timing_pool import _json, _load_host_inputs

    fixture = compile_fixture_documents(tmp_path, {"SYNTHETIC_FIXTURE_ONLY": True})
    m = fixture["materialization"]
    manifest = _json(m["pool_host_manifest"]["path"])
    child = m["pool"]["children"][0]
    host = _json(manifest["hosts"][child["child_id"]]["path"])
    view = SimpleNamespace(
        root=Path(child["evidence_root"]), registration=child["registration"]
    )
    result = _load_host_inputs(view, host)
    assert result["pool_authority"] == m["pool"]
    crossed = SimpleNamespace(
        root=fixture["root"] / "other-child/host-output/timing",
        registration=child["registration"],
    )
    with pytest.raises((PermissionError, ValueError)):
        _load_host_inputs(crossed, host)
    moved = deepcopy(host)
    # Only the three explicit parent authority inputs can live above the child.
    moved["inputs"]["runtime_options"] = host["inputs"]["scope_decision"]
    with pytest.raises((PermissionError, ValueError)):
        _load_host_inputs(view, moved)


def test_historical_native_locks_exist_only_in_private_namespace(tmp_path):
    original_root = tmp_path / "pretend-original-controller"
    original_root.mkdir()
    lock = original_root / ".writer-lock"
    native_stat = type(lock).stat
    with isolated_native_io(tmp_path / "isolated") as proof:
        lock.mkdir()
        with pytest.raises(FileNotFoundError):
            native_stat(lock)
        target = proof["lock_targets"][lock.resolve()]
        assert target.is_dir()
        assert (lock.stat().st_dev, lock.stat().st_ino) == (
            target.stat().st_dev,
            target.stat().st_ino,
        )
        with pytest.raises(FileExistsError):
            lock.mkdir()
        lock.rmdir()
        assert not target.exists()
    assert not lock.exists()


def test_historical_lock_transport_never_hides_actual_lock(tmp_path):
    original_root = tmp_path / "pretend-original-controller"
    original_root.mkdir()
    lock = original_root / ".writer-lock"
    lock.mkdir()
    before = lock.stat()
    with isolated_native_io(tmp_path / "isolated"):
        with pytest.raises(PermissionError, match="existing actual lock"):
            lock.stat()
        with pytest.raises(PermissionError, match="existing actual lock"):
            lock.mkdir()
    assert lock.stat().st_ino == before.st_ino


def test_database_namespace_routes_path_and_readonly_uri_to_same_copy(tmp_path):
    original = tmp_path / "pretend-original.sqlite"
    with sqlite3.connect(original) as db:
        db.execute("CREATE TABLE evidence (value TEXT)")
        db.execute("INSERT INTO evidence VALUES ('historical')")
    before = sha256(original.read_bytes()).hexdigest()
    with isolated_native_io(tmp_path / "isolated") as proof:
        with sqlite3.connect(original) as db:
            db.execute("INSERT INTO evidence VALUES ('fixture-only')")
        with sqlite3.connect(original.as_uri() + "?mode=ro", uri=True) as db:
            assert db.execute("SELECT value FROM evidence").fetchall() == [
                ("historical",),
                ("fixture-only",),
            ]
        assert len(proof["originals"]) == 1
        with pytest.raises(PermissionError, match="external database"):
            sqlite3.connect(tmp_path / "must-not-create.sqlite")
    assert sha256(original.read_bytes()).hexdigest() == before


@pytest.mark.asyncio
async def test_full_native_metadata_join_in_copied_namespace(tmp_path):
    import builtins

    from evals.tests.pool_composite_fixture import enter_mirrored_test

    mirror = await enter_mirrored_test(tmp_path, "full_native_metadata_join")
    if mirror is None:
        return

    from evals.adapters import additional_analysis, planning_analysis, planning_recovery
    from evals.e_planning import planning_requests
    from evals.tests.pool_composite_fixture import (
        original_account_baseline,
        register_fixture_metadata,
    )
    from evals.tests.pool_composite_prepare_fixture import (
        compile_fixture_documents,
        original_templates,
    )
    from evals.timing_pool import C10_EVIDENCE_ROOT, C10_TRIAL, read_native_observation
    from scripts.task13_timing_pool import NativePoolController

    original = read_native_observation(C10_EVIDENCE_ROOT, C10_TRIAL)
    native_functions = (
        additional_analysis._ledger,
        additional_analysis._verify,
        planning_analysis.verify_planning_analysis,
        planning_recovery.verify_historical_identity_ledger,
        builtins.__import__,
    )
    with isolated_native_io(tmp_path) as proof:
        data = original_templates()
        from evals.tests.pool_composite_fixture import reconstruct_historical_databases

        reconstruct_historical_databases(data)
        fixture = compile_fixture_documents(
            tmp_path,
            original["actual_conditions"],
            data_override=data,
            baseline=original_account_baseline(data["source"]["budget_path"]),
        )
        pin = fixture["materialization"]["pool_host_manifest"]
        # Admission validation also runs before native adoption in production.
        # Construct then append the isolated epochs so later native guards can be
        # exercised independently of the historical replay regression below.
        controller = NativePoolController(pin["path"], pin["sha256"])
        register_fixture_metadata(fixture["materialization"])
        controller.guard()
        assert controller.budget() > 0
        assert proof["redirected"]
        # A later current epoch must not invalidate a pinned historical import.
        historical = read_native_observation(C10_EVIDENCE_ROOT, C10_TRIAL)
        assert historical["registration_sha256"] == original["registration_sha256"]
        old_request = planning_requests(data["planning"])[0]
        with pytest.raises(ValueError, match="retired"):
            planning_analysis.verify_planning_analysis(
                old_request,
                data["runtime"]["import_source_dir"],
                data["source"]["budget_path"],
            )
        assert native_functions == (
            additional_analysis._ledger,
            additional_analysis._verify,
            planning_analysis.verify_planning_analysis,
            planning_recovery.verify_historical_identity_ledger,
            builtins.__import__,
        )
        from pathlib import Path

        from evals.tests.pool_composite_fixture import corrupt_copied_field
        from evals.timing_pool_history import read_historical_planning_analysis

        for table, key, row_id in (
            ("supplement_source_epochs", "epoch_id", old_request.epoch_id),
            (
                "supplement_model_epochs",
                "model_epoch_id",
                old_request.model_identity_binding.model_epoch_id,
            ),
        ):
            with (
                corrupt_copied_field(
                    data["source"]["budget_path"],
                    table,
                    key,
                    row_id,
                    "manifest_json",
                    "{}",
                ),
                pytest.raises((PermissionError, ValueError, KeyError)),
            ):
                read_historical_planning_analysis(
                    old_request,
                    Path(data["runtime"]["import_source_dir"]),
                    Path(data["source"]["budget_path"]),
                )
        for host in controller.hosts.values():
            with host._lock():
                snapshot = host._campaign().snapshot()
            assert all(row["status"] == "not_started" for row in snapshot["trials"])


@pytest.mark.asyncio
async def test_complete_offline_public_pool_receipt(tmp_path, monkeypatch):
    """Actual-only schemas exercised by synthetic I/O; grants no actual credit."""
    import asyncio
    import importlib.util
    import os
    import subprocess
    import sys
    from pathlib import Path

    from evals.tests.pool_composite_fixture import (
        mirrored_fixture_compiler,
        original_account_baseline,
        register_fixture_metadata,
    )
    from evals.tests.pool_composite_prepare_fixture import original_templates
    from evals.tests.pool_composite_runtime_fixture import (
        OfflineRuntime,
        fixture_plan_chat,
    )
    from evals.tests.test_pool_admission_helper import (
        build_fixture_admission,
        fixture_free_policy,
    )
    from evals.timing_pool import (
        C10_EVIDENCE_ROOT,
        C10_TRIAL,
        read_native_observation,
        validate_pool_receipt,
    )
    from evals.verification_v2 import observed_timing_max
    from scripts.task13_timing_pool import NativePoolController

    marker = "TASK13_SYNTHETIC_TEST_SOURCE_MIRROR"
    if marker not in os.environ:
        _, mirror = mirrored_fixture_compiler(tmp_path)
        # Run the unchanged native modules from their frozen files so __file__
        # guards remain genuine. Never alter production module filenames/globals.
        code = (
            "import sys;sys.path[:0]="
            + repr([str(mirror), str(mirror / "services/backend/src")])
            + ";import pytest;raise SystemExit(pytest.main("
            + repr(
                [
                    str(mirror / "evals/tests/test_pool_composite_integration.py"),
                    "-vv",
                    "-k",
                    "complete_offline_public",
                    "--basetemp=" + str(tmp_path / "mirror-run"),
                ]
            )
            + "))"
        )
        completed = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, "-I", "-B", "-X", "utf8", "-c", code],
            cwd=mirror,
            env={**os.environ, marker: str(mirror)},
            capture_output=True,
            encoding="utf8",
            timeout=1800,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        return

    mirror = Path(os.environ[marker])
    assert Path(__file__).resolve().parents[2] == mirror
    from evals.tests.pool_composite_prepare_fixture import compile_fixture_documents

    original = read_native_observation(C10_EVIDENCE_ROOT, C10_TRIAL)
    with isolated_native_io(tmp_path):
        data = original_templates()
        from evals.tests.pool_composite_fixture import reconstruct_historical_databases

        reconstruct_historical_databases(data)
        policy = fixture_free_policy(tmp_path / "SYNTHETIC-free-gates", mirror)
        fixture = compile_fixture_documents(
            tmp_path,
            original["actual_conditions"],
            data_override=data,
            baseline=original_account_baseline(data["source"]["budget_path"]),
            free_policy=policy,
        )
        register_fixture_metadata(fixture["materialization"])
        pin = fixture["materialization"]["pool_host_manifest"]
        controller = NativePoolController(pin["path"], pin["sha256"])
        runtime = OfflineRuntime(controller)
        runtime.install(monkeypatch)
        await controller.prepare()
        for attempt in controller.pool["attempt_order"][:2]:
            host = controller.hosts[attempt["child_id"]]
            request = next(
                r for r in host._requests if r.trial_id == attempt["trial_id"]
            )
            admission = await asyncio.to_thread(
                build_fixture_admission, controller, request, tmp_path
            )
            result = await controller.run("plan", free_admission_pin=admission)
            assert result["status"] == "awaiting_approval", result
            read = await controller.run("read")
            chat = fixture_plan_chat(
                tmp_path / "SYNTHETIC-chat" / request.trial_id, request, read["packet"]
            )
            decision = await controller.run(
                "decision", packet_sha256=read["packet_sha256"], chat_record=chat
            )
            assert decision["status"] == "approved", decision
            await controller.run("trial")
        receipt = controller.export()
        maximum = validate_pool_receipt(receipt, controller.pool["identity"])
        assert maximum >= 384.562
        assert observed_timing_max(receipt, controller.pool["identity"]) == maximum
        spec = importlib.util.spec_from_file_location(
            "synthetic_mirrored_regression_host",
            mirror / "scripts/task13_regression.py",
        )
        module = importlib.util.module_from_spec(spec)
        # Dataclass annotations require a module entry, isolated from production.
        import sys

        monkeypatch.setitem(sys.modules, spec.name, module)
        spec.loader.exec_module(module)
        regression = object.__new__(module.RegressionHost)
        regression._manifest = {"synthetic": False}
        child = controller.pool["children"][0]["registration"]
        regression._timing(
            {
                "e_timing_receipt": receipt,
                "core_config": child["core_config"],
                "bundle": {
                    **controller.pool["identity"],
                    **controller.pool["formal_binding"],
                },
                "final_freeze": {"source_files": child["source_files"]},
            }
        )
        from copy import deepcopy
        from datetime import UTC, datetime

        from evals.tests.pool_composite_runtime_fixture import write_json
        from evals.timing_pool import _json

        write_json(
            tmp_path / "SYNTHETIC-PUBLIC-CONSUMER-RESULT.json",
            {
                "fixture_only_header": "SYNTHETIC OFFLINE; NO ACTUAL USER/MODEL/E3/F8 CREDIT",
                "maximum": maximum,
                "receipt": receipt,
                "actual_provider_calls": 0,
                "actual_approval_credit": 0,
            },
        )
        swapped = deepcopy(receipt)
        swapped["observations"][1:] = reversed(swapped["observations"][1:])
        with pytest.raises(PermissionError):
            validate_pool_receipt(swapped, controller.pool["identity"])
        smaller = deepcopy(receipt)
        smaller["observed_max_seconds"] = maximum - 1
        with pytest.raises(PermissionError):
            validate_pool_receipt(smaller, controller.pool["identity"])
        # Re-sign a real journal suffix: hash-chain validity cannot permit work
        # after the frozen target. No model/worker is invoked by this mutation.
        journal_raw = controller.journal.path.read_bytes()
        try:
            controller.journal._append(
                "begin",
                {
                    "trial_id": controller.pool["attempt_order"][2]["trial_id"],
                    "reserved_yuan": "0.01",
                    "started_at": datetime.now(UTC).isoformat(),
                },
                controller.journal._events(),
            )
            extra = deepcopy(receipt)
            extra["controller_evidence"] = controller.controller_evidence()
            with pytest.raises((PermissionError, RuntimeError)):
                validate_pool_receipt(extra, controller.pool["identity"])
        finally:
            controller.journal.path.write_bytes(journal_raw)
        first = receipt["observations"][1]
        native = read_native_observation(first["evidence_root"], first["trial_id"])
        evidence = Path(first["evidence_root"])
        # Both missing approvals and modified resource/retry artifacts must be
        # rejected through the full public reader, not just helper predicates.
        approval = (
            evidence
            / "approvals"
            / (native["binding"]["approval_receipt_sha256"] + ".json")
        )
        if not approval.exists():
            approval = approval.with_suffix("")
        saved = approval.read_bytes()
        approval.unlink()
        try:
            with pytest.raises(PermissionError):
                validate_pool_receipt(receipt, controller.pool["identity"])
        finally:
            approval.write_bytes(saved)
        branch_path = (
            evidence / "outputs" / (native["branches"][0]["output_sha256"] + ".json")
        )
        if not branch_path.exists():
            branch_path = branch_path.with_suffix("")
        saved = branch_path.read_bytes()
        changed = _json(branch_path)
        changed["resource_receipt"]["worker_nonce"] = native["branches"][1]["result"][
            "resource_receipt"
        ]["worker_nonce"]
        write_json(branch_path, changed)
        try:
            with pytest.raises(PermissionError):
                validate_pool_receipt(receipt, controller.pool["identity"])
        finally:
            branch_path.write_bytes(saved)
        terminal = _json(
            evidence.parent
            / "slots"
            / native["binding"]["planning_slot_id"]
            / "plan-terminal.json"
        )
        runtime_path = Path(terminal["runtime_result"]["path"])
        saved = runtime_path.read_bytes()
        changed = _json(runtime_path)
        changed["model_ledger"].append(deepcopy(changed["model_ledger"][0]))
        write_json(runtime_path, changed)
        try:
            with pytest.raises(PermissionError):
                validate_pool_receipt(receipt, controller.pool["identity"])
        finally:
            runtime_path.write_bytes(saved)


@pytest.mark.asyncio
async def test_complete_offline_expiry_closed_prefix(tmp_path, monkeypatch):
    """Native expiry audit and resume, without fabricated timing or approval."""
    import asyncio
    from datetime import UTC, datetime, timedelta

    from evals import host_review, timing_pool_controller
    from evals.adapters import retained_workflow
    from evals.tests.pool_composite_fixture import (
        corrupt_copied_field,
        enter_mirrored_test,
        original_account_baseline,
        register_fixture_metadata,
    )
    from evals.tests.pool_composite_prepare_fixture import (
        compile_fixture_documents,
        original_templates,
    )
    from evals.tests.pool_composite_runtime_fixture import OfflineRuntime, write_json
    from evals.tests.test_pool_admission_helper import (
        build_fixture_admission,
        fixture_free_policy,
    )
    from evals.timing_pool import C10_EVIDENCE_ROOT, C10_TRIAL, read_native_observation
    from evals.timing_pool_evidence import validate_controller_evidence
    from scripts import task13_timing_pool

    mirror = await enter_mirrored_test(
        tmp_path, "complete_offline_expiry_closed_prefix"
    )
    if mirror is None:
        return
    original = read_native_observation(C10_EVIDENCE_ROOT, C10_TRIAL)
    with isolated_native_io(tmp_path):
        data = original_templates()
        from evals.tests.pool_composite_fixture import reconstruct_historical_databases

        reconstruct_historical_databases(data)
        fixture = compile_fixture_documents(
            tmp_path,
            original["actual_conditions"],
            data_override=data,
            baseline=original_account_baseline(data["source"]["budget_path"]),
            free_policy=fixture_free_policy(tmp_path / "SYNTHETIC-free-gates", mirror),
        )
        register_fixture_metadata(fixture["materialization"])
        pin = fixture["materialization"]["pool_host_manifest"]
        controller = task13_timing_pool.NativePoolController(pin["path"], pin["sha256"])
        runtime = OfflineRuntime(controller)
        runtime.install(monkeypatch)
        await controller.prepare()
        host = next(iter(controller.hosts.values()))
        request = host._requests[0]
        admission = await asyncio.to_thread(
            build_fixture_admission, controller, request, tmp_path
        )
        result = await controller.run("plan", free_admission_pin=admission)
        assert result["status"] == "awaiting_approval"
        plan = runtime.plans[request.incident_id]["state"]["response_plan"]
        created, expires = (
            datetime.fromisoformat(plan[k]) for k in ("created_at", "expires_at")
        )
        assert (expires - created).total_seconds() == 1800
        clock_offset = expires - datetime.now(UTC) + timedelta(seconds=5)

        class ExpiryClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(tz) + clock_offset

        # Time is the sole altered boundary here: retained state/TTL is untouched,
        # and the actual copied model ledger has already settled before this jump.
        for module in (
            task13_timing_pool,
            timing_pool_controller,
            host_review,
            retained_workflow,
        ):
            monkeypatch.setattr(module, "datetime", ExpiryClock)
        for child_host in controller.hosts.values():
            child_host._now = lambda: ExpiryClock.now(UTC)
        await controller.audit_expiry()
        await controller.resume()
        evidence = controller.controller_evidence()
        verified = validate_controller_evidence(
            evidence, controller.pool, original, require_complete=False
        )
        assert verified["qualified_trial_ids"] == []
        assert controller.journal.status()["attempted"] == 1
        assert not (host._root / "timing/registration.json").exists()
        assert plan == runtime.plans[request.incident_id]["state"]["response_plan"]
        # A decision that may have executed can never be relabelled as this
        # never-started subtype, even if no approval appears in the checkpoint.
        started = host._slot(request) / "decision-started.json"
        write_json(started, {"operation": "decision", "fixture_only": True})
        try:
            with pytest.raises(PermissionError):
                validate_controller_evidence(
                    evidence, controller.pool, original, require_complete=False
                )
        finally:
            started.unlink()
        reservation = runtime.plans[request.incident_id]["model"].ledger[0][
            "reservation_id"
        ]
        with (
            corrupt_copied_field(
                controller.budget_path, "reservations", "id", reservation, "settled", 0
            ),
            pytest.raises(PermissionError),
        ):
            validate_controller_evidence(
                evidence, controller.pool, original, require_complete=False
            )
