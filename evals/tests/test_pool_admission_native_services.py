"""Opt-in actual FREE admission rehearsal; synthetic authority exists only in COW.

No model dispatch, GO, actual user approval, original registration or timing credit.
The actual producer, raw consumers, Docker native worker and two public GETs run.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.environ.get("TASK13_RUN_ACTUAL_POOL_ADMISSION") != "1",
    reason="explicit actual free COW admission opt-in required",
)
def test_actual_cow_admission_native_services_public(tmp_path):
    from evals.tests.pool_composite_fixture import (
        isolated_native_io,
        mirrored_fixture_compiler,
        original_account_baseline,
        register_fixture_metadata,
    )
    from evals.tests.pool_composite_prepare_fixture import (
        compile_fixture_documents,
        original_templates,
    )
    from evals.timing_pool import C10_EVIDENCE_ROOT, C10_TRIAL, read_native_observation
    from scripts import task13_pool_admission as admission
    from scripts.task13_timing_pool import NativePoolController, require_free_admission

    marker = "TASK13_ACTUAL_ADMISSION_SOURCE_MIRROR"
    if marker not in os.environ:
        _, mirror = mirrored_fixture_compiler(tmp_path)
        code = (
            "import sys;sys.path[:0]="
            + repr([str(mirror), str(mirror / "services/backend/src")])
            + ";import pytest;raise SystemExit(pytest.main("
            + repr(
                [
                    str(mirror / "evals/tests/test_pool_admission_native_services.py"),
                    "-vv",
                    "-s",
                    "--basetemp=" + str(tmp_path / "actual-run"),
                    "--junitxml=" + str(tmp_path / "actual-child-junit.xml"),
                ]
            )
            + "))"
        )
        environment = admission.clean_environment()
        environment.update(
            {marker: str(mirror), "TASK13_RUN_ACTUAL_POOL_ADMISSION": "1"}
        )
        with (
            (tmp_path / "actual-child-stdout.txt").open("xb") as stdout,
            (tmp_path / "actual-child-stderr.txt").open("xb") as stderr,
        ):
            completed = subprocess.run(
                [sys.executable, "-I", "-B", "-X", "utf8", "-c", code],
                cwd=mirror,
                env=environment,
                stdout=stdout,
                stderr=stderr,
                timeout=900,
                check=False,
            )
        assert completed.returncode == 0, "See retained actual-child-stdout/stderr.txt"
        return

    mirror = Path(os.environ[marker])
    assert Path(__file__).resolve().parents[2] == mirror
    assert "DEEPSEEK_API_KEY" not in os.environ and "SSLKEYLOGFILE" not in os.environ
    report = {
        "schema_version": "task13-SYNTHETIC-COW-actual-free-admission-v1",
        "synthetic_authority_only": True,
        "original_registrations": 0,
        "provider_calls": 0,
        "actual_user_approvals": 0,
        "timing_credit": 0,
        "started_at": datetime.now(UTC).isoformat(),
        "source_mirror": str(mirror),
        "status": "failed",
    }
    proof = None
    try:
        old_gate = admission.checked(
            admission.pin(
                C10_EVIDENCE_ROOT.parent.parent
                / "activation/ordinal-1-paid-dispatch-gate-20261101.json"
            )
        )
        old_refs = old_gate["evidence"]
        gate_root = tmp_path / "SYNTHETIC-COW-ACTUAL-FREE-GATES"
        gate_root.mkdir()
        helper_pin = admission.pin(admission.__file__)
        policy = {
            "gate_root": str(gate_root),
            "helpers": dict.fromkeys(
                ("assembler", "native_probe", "services"), helper_pin
            ),
            "reader_regression": old_refs["reader-regression"],
            "reader_lowlevel": old_refs["reader-lowlevel"],
            "public_reference": old_refs["public-check"],
        }
        reader_tests = admission.checked(policy["reader_regression"])["tests"]
        for name in ("regression", "final-neighbor"):
            admission.validate_junit_check(reader_tests[name])
        with isolated_native_io(tmp_path) as proof:
            print("SYNTHETIC-COW stage=original-observation-in-copy", flush=True)
            original = read_native_observation(C10_EVIDENCE_ROOT, C10_TRIAL)
            data = original_templates()
            fixture = compile_fixture_documents(
                tmp_path,
                original["actual_conditions"],
                data_override=data,
                baseline=original_account_baseline(data["source"]["budget_path"]),
                free_policy=policy,
            )
            materialization = fixture["materialization"]
            assert materialization["source"]["epoch_number"] == 10
            assert materialization["model"]["model_epoch_number"] == 7
            register_fixture_metadata(materialization)
            print("SYNTHETIC-COW stage=source10-model7-registered-in-copy", flush=True)
            reference = materialization["pool_host_manifest"]
            controller = NativePoolController(reference["path"], reference["sha256"])
            asyncio.run(controller.prepare())
            print(
                "SYNTHETIC-COW stage=prepared-starting-actual-free-producer", flush=True
            )
            attempt = controller.pool["attempt_order"][0]
            host = controller.hosts[attempt["child_id"]]
            request = next(
                r for r in host._requests if r.trial_id == attempt["trial_id"]
            )
            report.update(
                pool_host_manifest=reference,
                source_epoch=10,
                model_epoch=7,
                trial_id=request.trial_id,
            )
            before = controller.budget()
            gate = admission.produce(
                controller, request.trial_id, Path("D:/传智杯/.env")
            )
            require_free_admission(
                gate,
                pool=controller.pool,
                host=host,
                request=request,
                now=datetime.now(UTC),
                spent=before,
                reserve=controller.reserve_bound(),
            )
            assert controller.budget() == before
            state = controller.journal.status()
            assert state["attempted"] == 0 and not state["pending"]
            report.update(
                status="passed",
                free_admission=gate,
                actual_probes=[
                    "native-preGO",
                    "services-SELECT1-rootGET",
                    "two-official-documents",
                ],
                copied_budget_unchanged=True,
                pool_attempts=0,
            )
            print("SYNTHETIC-COW stage=actual-free-gate-passed", flush=True)
    finally:
        if proof is not None:
            report["original_sqlite_preservation"] = [
                {
                    "path": str(source),
                    "before_sha256": before,
                    "after_sha256": sha256(source.read_bytes()).hexdigest(),
                    "copy_path": str(target),
                }
                for source, (target, before) in proof["originals"].items()
            ]
            report["original_locks_absent"] = not any(
                path.exists() for path in proof["lock_targets"]
            )
        report["finished_at"] = datetime.now(UTC).isoformat()
        admission.write_json(
            tmp_path / "SYNTHETIC-COW-actual-admission-report.json", report
        )
