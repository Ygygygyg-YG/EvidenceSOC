"""Opt-in v2 native integration in a disclosed virtualized COW namespace.

Consumes a private preliminary v2 preparation pin built with pure compile_preparation
and explicitly synthetic bootstrap acceptance; this avoids an actual-prepare/proof cycle. It never sends a provider
request or writes original metadata. Separate original-path audit is mandatory.
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from time import monotonic_ns, time_ns
from types import FunctionType
from unittest.mock import patch

import pytest

from evals.tests.manual_recovery_cow_namespace import CowNamespace, sql_snapshot

pytest_plugins = ["evals.tests.test_e_planning_live_services"]

REHEARSAL_HELPERS = (
    "evals/tests/manual_recovery_cow_namespace.py",
    "evals/tests/test_manual_recovery_cow_transport.py",
    "evals/tests/test_manual_recovery_native_rehearsal.py",
    "evals/tests/test_pool_native_services.py",
    "evals/tests/test_e_planning_live_services.py",
)


def validate_harness_files(incoming):
    tree = Path(__file__).resolve().parents[2]
    assert incoming["harness_files"] == {
        name: sha256((tree / name).read_bytes()).hexdigest()
        for name in REHEARSAL_HELPERS
    }, "rehearsal helper bytes differ from independently pinned input freeze"


class CrashAfterWrite(RuntimeError):
    pass


def write(path, value):
    from scripts.task13_pool_prepare import Documents

    docs = Documents(Path(path).parent)
    result = docs.stage(Path(path).name, value)
    docs.publish()
    return result


@contextmanager
def recorded_cow_namespace(namespace, report, output):
    """Publish success only after every final preservation invariant succeeds."""
    report["status"] = "failed"
    try:
        with namespace:
            yield namespace
        assert namespace.report()["original_preservation_verified"] is True
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["failure_type"] = type(error).__name__
        raise
    finally:
        report["namespace"] = namespace.report()
        write(output, report)


def event(events, stage, **fields):
    events.append(
        {
            "stage": stage,
            "sequence": len(events),
            "utc": datetime.now(UTC).isoformat(),
            "wall_time_ns": time_ns(),
            "monotonic_ns": monotonic_ns(),
            **fields,
        }
    )


def inputs():
    from scripts.task13_pool_prepare import read

    text = os.environ.get("TASK13_V2_REHEARSAL_INPUT_PIN")
    if not text:
        pytest.skip(
            "root must provide private preliminary synthetic v2 preparation pin"
        )
    value = read(json.loads(text))
    assert value["schema_version"] == "task13-synthetic-v2-cow-harness-input-v1"
    assert value["synthetic_only"] is True
    validate_harness_files(value)
    assert not any(key in os.environ for key in ("DEEPSEEK_API_KEY", "SSLKEYLOGFILE"))
    return value


@pytest.mark.skipif(
    os.environ.get("TASK13_SYNTHETIC_V2_RECOVERY_REHEARSAL") != "1",
    reason="explicit zero-provider COW integration opt-in required",
)
def test_v2_adopt_resume_each_durable_boundary(tmp_path, monkeypatch):
    from evals.adapters import e_planning_journal, model_identities, source_epochs
    from evals.contracts import canonical_hash
    from evals.timing_pool_controller import PoolJournal
    from scripts import task13_manual_recovery as manual
    from scripts.task13_pool_prepare import read, validate_epoch_prefix

    incoming = inputs()
    if incoming.get("run_nogo"):
        assert os.environ.get("TASK13_MANUAL_RECOVERY_NATIVE_NOGO") == "1", (
            "native Docker NoGO needs separate explicit opt-in"
        )
    preparation_pin = incoming["preparation"]
    prepared = read(preparation_pin)
    assert prepared["schema_version"] == "task13-manual-recovery-preparation-v1"
    candidate = Path(preparation_pin["path"]).parent.parent
    assert prepared["source"]["epoch_number"] == 11
    assert prepared["model"]["model_epoch_number"] == 8
    assert prepared["pool"]["future_logical_limit"] == 5
    assert not Path(prepared["pool"]["execution_journal_path"]).exists()
    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "0")
    roots = prepared["source"]["controller_state_roots"]
    namespace = CowNamespace(tmp_path / "namespace", [candidate, *roots])
    report = {
        "schema_version": "task13-synthetic-v2-cow-integration-v1",
        "synthetic_control_fixture": True,
        "actual_user_approval": False,
        "provider_requests": 0,
        "timing_credit": 0,
        "f8_credit": 0,
        "planning_credit": 0,
        "status": "failed",
        "events": [],
        "preparation": preparation_pin,
        "crash_boundaries": [],
    }
    report["helper_pins"] = [
        {"path": str(Path(__file__).resolve().parents[2] / name), "sha256": value}
        for name, value in incoming["harness_files"].items()
    ]
    stages = report["crash_boundaries"]
    with recorded_cow_namespace(
        namespace, report, tmp_path / "SYNTHETIC-v2-integration-report.json"
    ):
        question = read(prepared["prepared_question"])
        consent_root = namespace.root / "SYNTHETIC-NO-HUMAN-CREDIT"
        delivery = {
            "schema_version": "task13-pool-question-delivery-v1",
            "scope_packet": prepared["scope_packet"],
            "prepared_question": prepared["prepared_question"],
            "question_item_id": '["request_user_input_async","SYNTHETIC-COW-V2-NO-HUMAN-CREDIT",0]',
        }
        request_pin = write(consent_root / "question.json", delivery)
        event(report["events"], "synthetic_scope_reply_available")
        chat_pin = write(
            consent_root / "reply.json",
            {
                "role": "user",
                "source": "actual_current_send_user_message_question_reply",
                "captured_at": datetime.now(UTC).isoformat(),
                "synthetic_test_not_human_approval": True,
                "question_reply": [
                    {
                        "questionItemId": delivery["question_item_id"],
                        "question": question["question"],
                        "answer": question["approved_answer"],
                    }
                ],
            },
        )
        event(report["events"], "synthetic_scope_reply_captured", pin=chat_pin)
        spec = {
            "preparation": preparation_pin,
            "authorization_request": request_pin,
            "actual_scope_chat": chat_pin,
        }
        review_pin = write(
            consent_root / "independent-synthetic-review.json",
            {
                "schema_version": "task13-manual-recovery-actual-scope-review-v1",
                "status": "passed",
                "review_kind": "independent_actual_scope",
                "reviewer_identity": incoming["synthetic_reviewer_identity"],
                "critical": 0,
                "important": 0,
                **spec,
                "scope_packet": prepared["scope_packet"],
                "controller_manifest": prepared["controller_manifest"],
                "synthetic_only_no_approval_credit": True,
            },
        )
        spec["actual_scope_review"] = review_pin
        docs, material, _ = manual.compile_adoption(
            prepared, preparation_pin, request_pin, chat_pin
        )
        budget = material["source"]["budget_path"]
        before = sql_snapshot(budget)
        budget_baseline = prepared["database_snapshots"][budget]
        publish = manual.Documents.publish
        publish_missing = manual.Documents.publish_missing

        def marker_crash(document):
            result = publish(document)
            if candidate / "activation/adoption-started.json" in document.values:
                raise CrashAfterWrite("start-marker")
            return result

        with (
            patch.object(manual.Documents, "publish", marker_crash),
            pytest.raises(CrashAfterWrite, match="start-marker"),
        ):
            manual.adopt(spec)
        stages.append("start-marker")

        for module, name, target in (
            (source_epochs, "register_source_epoch", "source"),
            (model_identities, "register_model_identity", "model"),
        ):
            actual = getattr(module, name)

            def append_then_crash(*args, _actual=actual, _target=target, **kwargs):
                _actual(*args, **kwargs)
                raise CrashAfterWrite(_target)

            with (
                patch.object(module, name, append_then_crash),
                pytest.raises(CrashAfterWrite, match=target),
            ):
                manual.adopt(spec, resume=True)
            stages.append(target)

        for index, child in enumerate(material["children"]):
            actual_register = e_planning_journal.register_planning_slots
            wanted = child["authority"]["journal_path"]

            def child_then_crash(
                path, *args, _wanted=wanted, _actual=actual_register, **kwargs
            ):
                result = _actual(path, *args, **kwargs)
                if str(path) == _wanted:
                    raise CrashAfterWrite("child")
                return result

            with (
                patch.object(
                    e_planning_journal, "register_planning_slots", child_then_crash
                ),
                pytest.raises(CrashAfterWrite, match="child"),
            ):
                manual.adopt(spec, resume=True)
            stages.append("child-" + str(index + 1))

        material_targets = set(docs.values)

        def partial_documents(document):
            if set(document.values) == material_targets:
                target, payload = next(iter(document.values.items()))
                one = manual.Documents(target.parent)
                one.stage(target.name, payload)
                publish_missing(one)
                raise CrashAfterWrite("partial-documents")
            return publish_missing(document)

        with (
            patch.object(manual.Documents, "publish_missing", partial_documents),
            pytest.raises(CrashAfterWrite, match="partial-documents"),
        ):
            manual.adopt(spec, resume=True)
        stages.append("partial-documents")

        initialize = manual.initialize_timing_genesis
        for index, child in enumerate(material["pool"]["children"]):
            wanted = child["evidence_root"]

            def genesis_then_crash(value, _wanted=wanted):
                initialize(value)
                if value["evidence_root"] == _wanted:
                    raise CrashAfterWrite("timing-genesis")

            with (
                patch.object(manual, "initialize_timing_genesis", genesis_then_crash),
                pytest.raises(CrashAfterWrite, match="timing-genesis"),
            ):
                manual.adopt(spec, resume=True)
            stages.append("timing-genesis-" + str(index + 1))

        prepare_parent = PoolJournal.prepare

        def parent_then_crash(*args, **kwargs):
            prepare_parent(*args, **kwargs)
            raise CrashAfterWrite("parent-genesis")

        with (
            patch.object(PoolJournal, "prepare", parent_then_crash),
            pytest.raises(CrashAfterWrite, match="parent-genesis"),
        ):
            manual.adopt(spec, resume=True)
        stages.append("parent-genesis")

        def result_then_crash(document):
            publish_missing(document)
            if candidate / "activation/adoption-result.json" in document.values:
                raise CrashAfterWrite("result")

        with (
            patch.object(manual.Documents, "publish_missing", result_then_crash),
            pytest.raises(CrashAfterWrite, match="result"),
        ):
            manual.adopt(spec, resume=True)
        stages.append("result")
        complete = manual.adopt(spec, resume=True)
        assert complete["new_unclaimed_logical_slots"] == 5
        final = sql_snapshot(budget)
        assert validate_epoch_prefix(budget_baseline, final, material) == (
            True,
            True,
        )
        assert final["schema"] == before["schema"]
        for name, rows in before["tables"].items():
            if name not in {"supplement_source_epochs", "supplement_model_epochs"}:
                assert final["tables"][name] == rows
                assert final["rowids"].get(name) == before["rowids"].get(name)
        manual.adopt(spec, resume=True)
        assert sql_snapshot(budget) == final
        with pytest.raises(PermissionError):
            manual.adopt(spec, resume=False)
        assert len(stages) == 10
        assert [
            len(child["authority"]["authorized_request_sha256s"])
            for child in material["children"]
        ] == [3, 2]
        from evals.e_planning import planning_requests

        second = material["children"][1]
        journal = e_planning_journal.EPlanningDispatchJournal.open_existing(
            second["authority"]["journal_path"],
            expected_registration_sha256=canonical_hash(second["planning"]),
            expected_authority_sha256=canonical_hash(second["authority"]),
        )
        denied = next(
            value
            for value in planning_requests(second["planning"])
            if canonical_hash(value) in second["authority"]["denied_request_sha256s"]
        )
        denied_before = sql_snapshot(journal.path)
        for operation in (journal.validate_request, journal.claim_planning_slot):
            with pytest.raises(PermissionError, match="not authorized"):
                operation(denied)
        assert sql_snapshot(journal.path) == denied_before
        manual.require_inert_outputs(material["pool"])
        if incoming.get("run_nogo"):
            from scripts import task13_pool_admission as admission
            from scripts.task13_timing_pool import NativePoolController

            ref = material["pool_host_manifest"]
            controller = NativePoolController(ref["path"], ref["sha256"])
            asyncio.run(controller.prepare())
            attempt = controller.pool["attempt_order"][0]
            host = controller.hosts[attempt["child_id"]]
            request = next(
                value
                for value in host._requests
                if value.trial_id == attempt["trial_id"]
            )
            out = namespace.root / "native-v2-nogo"
            out.mkdir()
            assert out.resolve() == out and out.is_relative_to(namespace.root)
            post_adoption_budget = sql_snapshot(budget)
            post_adoption_dispatch = sql_snapshot(
                host._inputs["planning_authority"]["journal_path"]
            )
            event(report["events"], "native_v2_nogo_started")
            receipt = asyncio.run(admission.native_probe(host, request, out))
            native_receipt = admission.checked(receipt)
            admission.validate_native_artifacts(native_receipt, host, request, root=out)
            assert sql_snapshot(out / "budget/campaign.sqlite") == post_adoption_budget
            assert (
                sql_snapshot(out / "dispatch/e-planning.sqlite")
                == post_adoption_dispatch
            )
            process = admission.checked(native_receipt["artifacts"]["process.json"])
            argv = process["argv"]
            mounts = [
                argv[index + 1]
                for index, value in enumerate(argv)
                if value == "--mount"
            ]
            assert (
                "type=bind,source="
                + str(out / "budget")
                + ",target=/app/budget,readonly"
                in mounts
            )
            assert (
                "type=bind,source="
                + str(out / "dispatch")
                + ",target=/app/import-dispatch"
                in mounts
            )
            report["native_docker_mount_transport"] = {
                "docker_argv_proxy": False,
                "budget_physical_mount": str(out / "budget"),
                "dispatch_physical_mount": str(out / "dispatch"),
                "copied_budget_equals_post_adoption_source11_model8_shadow": True,
                "copied_dispatch_equals_limited_authority_shadow": True,
                "native_mount_binding_validator_unchanged": True,
                "readonly_worker_source": host._inputs["runtime_options"]["source_dir"],
            }
            event(report["events"], "native_v2_nogo_finished")
            report["native_nogo"] = receipt
        report.update(
            completed_adoption=complete,
            new_authorized_logical_slots=5,
            denied_structural_slots=1,
        )


def pin(path):
    return {
        "path": str(path.resolve()),
        "sha256": sha256(path.read_bytes()).hexdigest(),
    }


def emit(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode()
        )
        stream.flush()
        os.fsync(stream.fileno())
    return pin(path)


def sample(events, stage, **fields):
    event = {
        "sequence": len(events),
        "stage": stage,
        "utc": datetime.now(UTC).isoformat(),
        "wall_time_ns": time_ns(),
        "monotonic_ns": monotonic_ns(),
        **fields,
    }
    events.append(event)
    return event


def interval(first, last):
    wall = (last["wall_time_ns"] - first["wall_time_ns"]) / 1e9
    monotonic = (last["monotonic_ns"] - first["monotonic_ns"]) / 1e9
    assert wall >= 0 and monotonic >= 0
    return {
        "wall_seconds": wall,
        "monotonic_seconds": monotonic,
        "conservative_seconds": max(wall, monotonic),
    }


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.environ.get("TASK13_NATIVE_V2_HANDOFF_REHEARSAL") != "1",
    reason="explicit native zero-provider handoff opt-in required",
)
async def test_final_native_six_branches_and_handoff(
    tmp_path, loopback_services, monkeypatch
):
    from evals.tests import test_pool_native_services as native
    from scripts import task13_worker_runtime as runtime
    from scripts.task13_pool_prepare import read

    input_pin = json.loads(os.environ["TASK13_V2_REHEARSAL_INPUT_PIN"])
    incoming = read(input_pin)
    assert incoming["schema_version"] == "task13-synthetic-v2-cow-harness-input-v1"
    assert incoming["synthetic_only"] is True
    validate_harness_files(incoming)
    runtime_pin = incoming["native_runtime_options"]
    read(runtime_pin)
    run = tmp_path / "native-v2-handoff"
    run.mkdir()
    fixture_candidate = run / "SYNTHETIC-FIXTURE-CANDIDATE"
    emit(
        fixture_candidate / "activation/materialization.json",
        {"runtime_options": runtime_pin},
    )
    monkeypatch.setenv("TASK13_NATIVE_FREE_RUN_DIR", str(run / "native"))
    assert "DEEPSEEK_API_KEY" not in os.environ and "SSLKEYLOGFILE" not in os.environ
    assert str(Path(runtime.__file__).resolve().parents[1]) == incoming["source_tree"]
    report = {
        "schema_version": "task13-native-v2-synthetic-handoff-v1",
        "synthetic_control_fixture": True,
        "actual_user_approval": False,
        "provider_requests": 0,
        "timing_credit": 0,
        "f8_credit": 0,
        "planning_credit": 0,
        "status": "failed",
        "events": [],
        "route": "synthetic generic native decision to first native verification container",
        "v2_parent_controller_eplanning_route_tested": False,
        "real_ui_reply_capture_latency_tested": False,
        "reply_poll_seconds": 5,
        "runtime_options": runtime_pin,
        "source_tree": incoming["source_tree"],
        "test_fixture_CANDIDATE_override_only": str(fixture_candidate),
        "production_validator_patches": [],
        "native_guard_patches": [],
        "instrumentation": [
            "delegating native runtime calls",
            "delegating asyncio subprocess calls",
        ],
        "helper_pins": [
            pin(Path(__file__)),
            pin(Path(native.__file__)),
            pin(Path(runtime.__file__)),
            pin(Path(__file__).with_name("manual_recovery_cow_namespace.py")),
        ],
    }
    events = report["events"]
    source_call, verification_call = (
        runtime.run_source_review_container,
        runtime.run_verification_container,
    )
    create = asyncio.create_subprocess_exec
    observed = {"phase": None, "first_request": None, "first_inspection": None}

    class ProcessObserver:
        def __init__(self, process, phase):
            self.process, self.phase = process, phase

        def __getattr__(self, name):
            return getattr(self.process, name)

        async def communicate(self, *args, **kwargs):
            stdout, stderr = await self.process.communicate(*args, **kwargs)
            if self.phase == "first_branch" and observed["first_inspection"] is None:
                info = json.loads(stdout)[0]
                raw_path = run / "first-branch-docker-inspect.bin"
                raw_path.write_bytes(stdout)
                observed["first_inspection"] = sample(
                    events,
                    "first_branch_native_inspection_observed",
                    container_id=info["Id"],
                    started_at=info["State"]["StartedAt"],
                    raw_inspection=pin(raw_path),
                )
            return stdout, stderr

    async def observed_create(*args, **kwargs):
        phase = observed["phase"]
        docker = len(args) > 1 and str(args[0]).lower() == "docker"
        if docker and args[1] == "run" and phase in {"decision", "first_branch"}:
            sample(events, phase + "_docker_run_invoked")
        result = await create(*args, **kwargs)
        if docker and args[1] == "run" and phase in {"decision", "first_branch"}:
            sample(events, phase + "_docker_client_created", pid=result.pid)
        if docker and args[1] == "inspect" and phase == "first_branch":
            return ProcessObserver(result, phase)
        return result

    async def observed_source(request, agent, options):
        operation = request.operation
        if operation == "read_packet":
            pending = json.loads(
                (run / "native/synthetic-pending-state.json").read_bytes()
            )
            plan = pending["response_plan"]
            assert (
                datetime.fromisoformat(plan["expires_at"])
                - datetime.fromisoformat(plan["created_at"])
            ).total_seconds() == 1800
            sample(
                events,
                "prewarmed_synthetic_plan_ready",
                created_at=plan["created_at"],
                expires_at=plan["expires_at"],
            )
        if operation == "decision":
            sample(events, "synthetic_reply_available")
            # This tests one root-owned poll interval; it is not a real chat reply.
            await asyncio.sleep(5)
            reply_pin = emit(
                run / "SYNTHETIC-reply-no-human-credit.json",
                {
                    "synthetic_control_fixture": True,
                    "actual_user_approval": False,
                    "captured_at": datetime.now(UTC).isoformat(),
                    "packet": request.packet,
                    "decision": request.decision,
                    "reason": request.reason,
                },
            )
            sample(events, "synthetic_reply_captured_fsync", reply=reply_pin)
            observed["phase"] = "decision"
            sample(events, "native_decision_dispatched")
        try:
            value = await source_call(request, agent, options)
        finally:
            observed["phase"] = None
        if operation == "decision":
            sample(
                events,
                "native_decision_returned_persisted",
                result_sha256=sha256(
                    json.dumps(value, sort_keys=True, default=str).encode()
                ).hexdigest(),
            )
        return value

    async def observed_verification(request, agent, options):
        first = observed["first_request"] is None
        if first:
            observed["first_request"] = request.request_id
            observed["phase"] = "first_branch"
            sample(
                events,
                "first_branch_native_call_invoked",
                request_id=request.request_id,
            )
        try:
            result = await verification_call(request, agent, options)
        finally:
            if first:
                observed["phase"] = None
        sample(
            events,
            "native_branch_completed",
            request_id=request.request_id,
            verification_enabled=request.verification_enabled,
        )
        return result

    # Reuse the actual complete test body. Only its fixture metadata root changes;
    # its source/PID/worker/approval/cleanup assertions execute without alteration.
    actual_test = native.test_native_generic_review_and_all_six_branches
    body = FunctionType(
        actual_test.__code__,
        {**actual_test.__globals__, "CANDIDATE": fixture_candidate},
        actual_test.__name__,
        actual_test.__defaults__,
        actual_test.__closure__,
    )
    body.__kwdefaults__ = actual_test.__kwdefaults__
    try:
        with (
            patch.object(runtime, "run_source_review_container", observed_source),
            patch.object(runtime, "run_verification_container", observed_verification),
            patch.object(asyncio, "create_subprocess_exec", observed_create),
        ):
            await body(tmp_path, loopback_services, monkeypatch)
        facts = json.loads(
            (run / "native/native-free-rehearsal-proof.json").read_bytes()
        )
        assert facts["status"] == "passed" and facts["completed_branches"] == 6
        by_stage = {item["stage"]: item for item in events}
        capture = by_stage["synthetic_reply_captured_fsync"]
        available = by_stage["synthetic_reply_available"]
        first = by_stage["first_branch_native_inspection_observed"]
        plan = by_stage["prewarmed_synthetic_plan_ready"]
        started = datetime.fromisoformat(first["started_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(plan["expires_at"])
        created = datetime.fromisoformat(plan["created_at"])
        remaining = (expires - started).total_seconds()
        assert remaining > 1500
        assert (started - created).total_seconds() < 300
        # Observation is later than container start; monotonic elapsed to this
        # observation is a conservative upper bound, not a fabricated start tick.
        measured = interval(available, first)
        assert measured["conservative_seconds"] < 300
        assert interval(capture, first)["conservative_seconds"] < 300
        report.update(
            status="passed",
            first_container_started_at=started.isoformat(),
            first_dispatch_remaining_seconds=remaining,
            plan_creation_to_native_container_start_seconds=(
                started - created
            ).total_seconds(),
            reply_available_to_first_container_inspection_upper_bound=measured,
            reply_available_to_capture=interval(available, capture),
            capture_to_native_decision_return=interval(
                capture, by_stage["native_decision_returned_persisted"]
            ),
            decision_return_to_first_container_inspection_upper_bound=interval(
                by_stage["native_decision_returned_persisted"], first
            ),
            capture_to_first_container_inspection_upper_bound=interval(capture, first),
            native_proof=pin(run / "native/native-free-rehearsal-proof.json"),
            native_measurement_credit=0,
            actual_plan_approval_credit=0,
        )
    finally:
        sample(events, "rehearsal_finished")
        emit(run / "SYNTHETIC-native-handoff-report.json", report)
