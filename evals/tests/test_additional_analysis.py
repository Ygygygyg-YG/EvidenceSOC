"""A new synthetic development run, real model wrappers and a temporary account."""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import shutil
import sqlite3
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from evals.contracts import canonical_hash


def additional_module():
    assert importlib.util.find_spec("evals.adapters.additional_analysis") is not None, (
        "additional development requires a separate strictly verified package"
    )
    return importlib.import_module("evals.adapters.additional_analysis")


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )
    return path


async def additional_source(
    tmp_path,
    monkeypatch,
    *,
    verdict="attack",
    no_target=False,
    invalid_attempts=0,
    invalid_kind="null",
    duplicate_success=False,
):
    from evals.adapters import remediation_worker as worker
    from evals.tests import test_epoch_development as epoch_tests
    from evals.tests import test_remediation_worker as worker_tests

    repository = Path(__file__).resolve().parents[2]
    source_names = {
        p.relative_to(repository).as_posix()
        for p in (repository / "services/backend/src/evidencesoc").rglob("*.py")
    } | {"evals/adapters/seed.py", "evals/adapters/diagnosis.py"}
    request_factory = worker_tests.request_for

    def request_for(*args, **kwargs):
        request, agent, source = request_factory(*args, **kwargs)
        if no_target:
            event = json.loads((agent / "events.jsonl").read_text())
            event.pop("host")
            event["account"] = "synthetic-account"
            (agent / "events.jsonl").write_text(
                json.dumps(event) + "\n", encoding="utf-8"
            )
            request = type(request).model_validate(
                {
                    **request.model_dump(mode="json"),
                    "agent_sha256": sha256(
                        (agent / "events.jsonl").read_bytes()
                    ).hexdigest(),
                }
            )
        return request, agent, source

    monkeypatch.setattr(worker_tests, "request_for", request_for)
    module, request, agent, source, budget, epoch = epoch_tests.development_inputs(
        tmp_path, monkeypatch, extra_source_entries=source_names
    )
    epoch_tests.set_worker(monkeypatch, request, source, budget, epoch)
    output = tmp_path / "output"
    output.mkdir()
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(output))
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-never-sent")

    @contextmanager
    def environment(spec, seed):
        yield SimpleNamespace(incident_id="synthetic", sessions=None)

    async def probe(*args):
        return {"status": "passed", "latency_ms": 0}

    sent = []

    def respond(http_request):
        payload = json.loads(http_request.content)
        sent.append(payload)
        state = json.loads(payload["messages"][-1]["content"])
        answer = (
            worker_tests.analysis_answer(state, verdict)
            if verdict is not None
            else {"diagnosis": None}
        )
        if len(sent) <= invalid_attempts:
            if invalid_kind == "null":
                answer = {"diagnosis": None}
            elif invalid_kind == "citation":
                answer["diagnosis"]["evidence_ids"] = ["EV-" + "Z" * 26]
            else:
                answer["origin"] = {
                    "observed_source_ip": None,
                    "entry_host": "not-observed",
                    "entry_service": None,
                    "first_seen_at": None,
                    "source_scope": "unknown",
                    "confidence": 0.5,
                    "evidence_ids": answer["diagnosis"]["evidence_ids"],
                }
        return httpx.Response(
            200,
            json={
                "id": "synthetic-provider-request",
                "model": "approved",
                "system_fingerprint": "approved-fp",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(answer)},
                    }
                ],
            },
        )

    factory = worker.make_model
    monkeypatch.setattr(
        worker,
        "make_model",
        lambda *args, **kwargs: factory(
            *args, transport=httpx.MockTransport(respond), **kwargs
        ),
    )
    monkeypatch.setattr(worker, "case_environment", environment)
    monkeypatch.setattr(worker, "run_service_probe", probe)
    monkeypatch.setattr(worker, "export_tool_ledger", lambda _: [])
    if duplicate_success:
        one = worker.one_development_analysis

        async def twice(*args, **kwargs):
            await one(*args, **kwargs)
            return await one(*args, **kwargs)

        monkeypatch.setattr(worker, "one_development_analysis", twice)
    result = await module.run_epoch_development(request, agent)
    assert len(result.model_ledger) == (
        2 if duplicate_success else 1 + invalid_attempts if verdict is not None else 3
    ), result.errors
    policy = {
        "schema_version": "synthetic-selection-v1",
        "candidate_case_ids": [request.case_id],
        "rule": "only-listed-case",
        "stop_after": 1,
    }
    registration = {
        "schema_version": "task13-additional-development-registration-v1",
        "registration_id": "additional-development-synthetic-1",
        "synthetic": True,
        "request": request.model_dump(mode="json"),
        "request_sha256": canonical_hash(request),
        "raw_case_id": request.case_id,
        "raw_agent_sha256": request.agent_sha256,
        "selection_policy": policy,
        "selection_policy_sha256": canonical_hash(policy),
        "core_sha256": request.config_sha256,
        "epoch_id": request.epoch_id,
        "epoch_manifest_sha256": request.epoch_manifest_sha256,
        "model_identity_binding": request.model_identity_binding.model_dump(
            mode="json"
        ),
    }
    registration_sha = canonical_hash(registration)
    binding = {
        "registration_id": registration["registration_id"],
        "registration_sha256": registration_sha,
        "request_sha256": canonical_hash(request),
        "slot_id": request.slot_id,
    }
    seed = worker.development_seed(request, agent)
    paths = {
        "registration": write_json(output / "registration.json", registration),
        "request": write_json(output / "request.json", request.model_dump(mode="json")),
        "started": write_json(
            output / "started.json",
            {"schema_version": "task13-additional-development-started-v1", **binding},
        ),
        "result": write_json(output / "result.json", result.model_dump(mode="json")),
        "stdout": write_json(output / "stdout.json", result.model_dump(mode="json")),
        "seed": write_json(output / "seed.json", seed),
        "registry": write_json(output / "registry.json", seed["registry"]),
        "events": agent / "events.jsonl",
        "knowledge": output / "returned-knowledge.json",
        "condition": output / "development-condition.json",
        "source_receipt": source / "source_receipt.json",
    }
    paths["attempt"] = write_json(
        output / "attempt.json",
        {
            "schema_version": "task13-additional-development-attempt-v1",
            **binding,
            "status": result.execution_status,
            "result_sha256": sha256(paths["result"].read_bytes()).hexdigest(),
        },
    )
    for name in json.loads(paths["source_receipt"].read_bytes())["files"]:
        paths["original_source:" + name] = source / name
    for index in range(1, len(result.model_ledger) + 1):
        paths["payload_" + str(index)] = output / f"model-http-{index:02d}.json"
        paths["body_" + str(index)] = output / f"model-http-{index:02d}.body.json"
    return SimpleNamespace(
        registration=registration,
        registration_sha=registration_sha,
        request=request,
        budget=budget,
        paths=paths,
        result=result,
        epoch=epoch,
    )


def export(source, destination):
    return additional_module().export_additional_analysis_package(
        registration=source.registration,
        expected_registration_sha256=source.registration_sha,
        expected_request_sha256=canonical_hash(source.request),
        artifact_paths=source.paths,
        artifact_sha256={
            name: sha256(path.read_bytes()).hexdigest()
            for name, path in source.paths.items()
        },
        budget_path=source.budget,
        destination=destination,
    )


def verify(source, package, pin):
    return additional_module().verify_additional_analysis_package(
        package,
        pin,
        source.registration_sha,
        canonical_hash(source.request),
        source.budget,
    )


@pytest.mark.asyncio
async def test_real_development_chain_exports_and_revalidates(tmp_path, monkeypatch):
    source = await additional_source(tmp_path / "run", monkeypatch)
    before = source.budget.read_bytes()
    receipt = export(source, tmp_path / "package")
    imported = verify(source, tmp_path / "package", receipt["manifest_sha256"])
    assert imported.provenance["source_kind"] == "additional-development-v1"
    assert imported.provenance["source_registration_sha256"] == source.registration_sha
    assert (
        imported.provenance["source_package_manifest_sha256"]
        == receipt["manifest_sha256"]
    )
    assert imported.provenance["order_index"] == 0
    assert imported.provenance["source_core_sha256"] == source.request.config_sha256
    assert imported.provenance["source_epoch_id"] == source.request.epoch_id
    assert (
        imported.provenance["source_epoch_manifest_sha256"]
        == source.request.epoch_manifest_sha256
    )
    assert imported.provenance[
        "source_model_identity_binding"
    ] == source.request.model_identity_binding.model_dump(mode="json")
    assert imported.provenance["original_manifest_sha256"] == receipt["manifest_sha256"]
    imported.revalidate()
    assert source.budget.read_bytes() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_kind", ["null", "citation", "origin"])
async def test_real_retries_before_first_valid_analysis_are_replayed(
    tmp_path, monkeypatch, invalid_kind
):
    source = await additional_source(
        tmp_path / "run", monkeypatch, invalid_attempts=2, invalid_kind=invalid_kind
    )
    assert all(call["parse_status"] == "valid" for call in source.result.model_ledger)
    receipt = export(source, tmp_path / "package")
    verify(source, tmp_path / "package", receipt["manifest_sha256"]).revalidate()


@pytest.mark.asyncio
async def test_another_physical_send_after_a_valid_analysis_is_rejected(
    tmp_path, monkeypatch
):
    source = await additional_source(
        tmp_path / "run", monkeypatch, duplicate_success=True
    )
    with pytest.raises(ValueError, match="continued"):
        export(source, tmp_path / "package")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verdict,no_target",
    [(None, False), ("unknown", False), ("benign", False), ("attack", True)],
)
async def test_non_actionable_real_replies_never_export(
    tmp_path, monkeypatch, verdict, no_target
):
    source = await additional_source(
        tmp_path / "run", monkeypatch, verdict=verdict, no_target=no_target
    )
    with pytest.raises(ValueError):
        export(source, tmp_path / "package")
    assert not (tmp_path / "package").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("raw_case_id", "ait-" + "1" * 24),
        ("raw_agent_sha256", "1" * 64),
        ("request_sha256", "1" * 64),
        ("core_sha256", "1" * 64),
        ("epoch_id", "wrong"),
        ("epoch_manifest_sha256", "1" * 64),
        ("selection_policy_sha256", "1" * 64),
        ("synthetic", "true"),
        (
            "model_identity_binding",
            {"model_epoch_id": "wrong", "model_identity_sha256": "1" * 64},
        ),
    ],
)
async def test_registration_is_explicit_and_consistent(
    tmp_path, monkeypatch, field, value
):
    source = await additional_source(tmp_path / "run", monkeypatch)
    with pytest.raises(ValueError):
        additional_module().validate_additional_development_registration(
            {**source.registration, field: value}
        )


def refresh_terminal(source):
    attempt = json.loads(source.paths["attempt"].read_bytes())
    attempt["result_sha256"] = sha256(source.paths["result"].read_bytes()).hexdigest()
    write_json(source.paths["attempt"], attempt)


def edit_results(source, edit):
    for name in ("result", "stdout"):
        result = json.loads(source.paths[name].read_bytes())
        edit(result)
        write_json(source.paths[name], result)
    refresh_terminal(source)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("initial_query", "changed query"),
        ("initial_query_sha256", "0" * 64),
        ("repeat", 2),
        ("entry_prompt_sha256", "0" * 64),
        ("retrieval_requests", 1),
    ],
)
async def test_condition_is_checked_after_all_outer_hashes_rebound(
    tmp_path, monkeypatch, field, value
):
    source = await additional_source(tmp_path / "run", monkeypatch)
    condition = json.loads(source.paths["condition"].read_bytes())
    condition[field] = value
    write_json(source.paths["condition"], condition)

    def edit(result):
        result["resources"]["development"] = condition
        result["artifact_hashes"]["development_condition"] = sha256(
            source.paths["condition"].read_bytes()
        ).hexdigest()

    edit_results(source, edit)
    with pytest.raises(ValueError):
        export(source, tmp_path / "package")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    ["seed", "knowledge", "snapshot", "stdout", "payload", "body", "events", "source"],
)
async def test_science_rejects_rehashed_artifact_changes(tmp_path, monkeypatch, kind):
    source = await additional_source(tmp_path / "run", monkeypatch)
    if kind == "snapshot":
        edit_results(
            source,
            lambda result: result["diagnostic_snapshot"]["diagnosis"].update(
                verdict="benign", taxonomy_status="not_applicable"
            ),
        )
    elif kind == "stdout":
        result = json.loads(source.paths["stdout"].read_bytes())
        result["resources"]["latency_ms"] += 1
        write_json(source.paths["stdout"], result)
    elif kind == "events":
        source.paths["events"].write_bytes(source.paths["events"].read_bytes() + b"\n")
    elif kind == "source":
        key = "original_source:evals/adapters/seed.py"
        source.paths[key].write_bytes(
            source.paths[key].read_bytes()
            + b"\nraise RuntimeError('must never execute')\n"
        )
    else:
        key = {"payload": "payload_1", "body": "body_1"}.get(kind, kind)
        value = json.loads(source.paths[key].read_bytes())
        if kind in {"payload", "body"}:
            value["messages"][-1]["content"] = "{}"
        elif kind == "seed":
            value["evidence"] = []
        else:
            value.append({"knowledge_chunk_id": "forged"})
        write_json(source.paths[key], value)
    with pytest.raises(ValueError):
        export(source, tmp_path / "package")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE reservations SET settled=0 WHERE phase='development'",
        "UPDATE reservations SET actual=NULL WHERE phase='development'",
        "UPDATE supplement_requests SET duration_ms=duration_ms+1",
        "UPDATE supplement_request_epochs SET epoch_id='synthetic-epoch-0'",
        "UPDATE supplement_request_models SET model_epoch_id='wrong'",
        "UPDATE supplement_requests SET request_sha256='wrong'",
    ],
)
async def test_original_account_reservations_and_metadata_are_required(
    tmp_path, monkeypatch, mutation
):
    source = await additional_source(tmp_path / "run", monkeypatch)
    with sqlite3.connect(source.budget) as db:
        # Attack only this test's temporary DB, restoring the exact immutable
        # triggers afterwards so the test reaches row-mapping verification.
        trigger = {
            "UPDATE supplement_request_epochs SET epoch_id='synthetic-epoch-0'": "supplement_request_epochs_no_update",
            "UPDATE supplement_request_models SET model_epoch_id='wrong'": "supplement_request_models_no_update",
        }.get(mutation)
        if trigger:
            sql = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
                (trigger,),
            ).fetchone()[0]
            db.execute('DROP TRIGGER "' + trigger + '"')
        db.execute(mutation)
        if trigger:
            db.execute(sql)
    before = source.budget.read_bytes()
    with pytest.raises(ValueError):
        export(source, tmp_path / "package")
    assert source.budget.read_bytes() == before


@pytest.mark.asyncio
async def test_stable_analysis_identity_is_derived_from_the_request_slot(
    tmp_path, monkeypatch
):
    source = await additional_source(tmp_path / "run", monkeypatch)
    edit_results(
        source,
        lambda result: result["model_ledger"][0].update(
            stable_logical_call_id="v2-" + "0" * 64
        ),
    )
    with pytest.raises(ValueError, match="slot"):
        export(source, tmp_path / "package")


def rewrite_manifest(package, edit):
    path = package / "manifest.json"
    manifest = json.loads(path.read_bytes())
    edit(manifest)
    write_json(path, manifest)
    return sha256(path.read_bytes()).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [
        "extra",
        "missing",
        "traversal",
        "validator",
        "old_schema",
        "extra_artifact",
        "hardlink",
    ],
)
async def test_exact_portable_inventory_and_version_are_required(
    tmp_path, monkeypatch, kind
):
    source = await additional_source(tmp_path / "run", monkeypatch)
    package = tmp_path / "package"
    pin = export(source, package)["manifest_sha256"]
    if kind == "extra":
        (package / "extra.txt").write_text("extra")
    elif kind == "missing":
        (package / "artifacts/seed.json").unlink()
    elif kind == "hardlink":
        os.link(package / "artifacts/seed.json", tmp_path / "second-link.json")
    else:

        def edit(manifest):
            if kind == "traversal":
                manifest["artifacts"]["seed"]["path"] = "../seed.json"
            elif kind == "validator":
                manifest["validation_source_sha256"]["artifact_verifier"] = "0" * 64
            elif kind == "old_schema":
                manifest["schema_version"] = "task13-analysis-artifacts-v2"
            else:
                path = write_json(package / "artifacts/extra.json", {})
                manifest["artifacts"]["extra"] = {
                    "path": "artifacts/extra.json",
                    "size": path.stat().st_size,
                    "sha256": sha256(path.read_bytes()).hexdigest(),
                }

        pin = rewrite_manifest(package, edit)
    with pytest.raises((ValueError, OSError)):
        verify(source, package, pin)


@pytest.mark.asyncio
async def test_independent_pins_legacy_crossing_and_revalidation(tmp_path, monkeypatch):
    from evals.adapters.analysis_package import verify_portable_analysis_package

    source = await additional_source(tmp_path / "run", monkeypatch)
    package = tmp_path / "package"
    pin = export(source, package)["manifest_sha256"]
    for pins in [
        ("0" * 64, source.registration_sha, canonical_hash(source.request)),
        (pin, "0" * 64, canonical_hash(source.request)),
        (pin, source.registration_sha, "0" * 64),
    ]:
        with pytest.raises(ValueError):
            additional_module().verify_additional_analysis_package(
                package, *pins, source.budget
            )
    with pytest.raises(ValueError):
        verify_portable_analysis_package(package, pin)
    with pytest.raises(FileExistsError):
        export(source, package)
    imported = verify(source, package, pin)
    (package / "extra.json").write_text("{}")
    with pytest.raises(ValueError):
        imported.revalidate()


@pytest.mark.asyncio
async def test_budget_clone_does_not_gain_authority_from_worker_nonce(
    tmp_path, monkeypatch
):
    source = await additional_source(tmp_path / "run", monkeypatch)
    package = tmp_path / "package"
    pin = export(source, package)["manifest_sha256"]
    clone = tmp_path / "clone.sqlite"
    shutil.copyfile(source.budget, clone)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-cannot-grant-authority")
    with pytest.raises(ValueError):
        additional_module().verify_additional_analysis_package(
            package, pin, source.registration_sha, canonical_hash(source.request), clone
        )


@pytest.mark.parametrize(
    "pid,nonce,path,trusted,host",
    [
        (
            1,
            "nonce",
            "/app/budget/campaign.sqlite",
            "D:/original/budget.sqlite",
            "D:/original/budget.sqlite",
        ),
        (
            2,
            "nonce",
            "/app/budget/campaign.sqlite",
            "D:/original/budget.sqlite",
            "D:/original/budget.sqlite",
        ),
        (
            1,
            "",
            "/app/budget/campaign.sqlite",
            "D:/original/budget.sqlite",
            "D:/original/budget.sqlite",
        ),
        (
            1,
            "nonce",
            "/tmp/clone.sqlite",
            "D:/original/budget.sqlite",
            "D:/original/budget.sqlite",
        ),
        (
            1,
            "nonce",
            "/app/budget/campaign.sqlite",
            "wrong",
            "D:/original/budget.sqlite",
        ),
        (1, "nonce", "/app/budget/campaign.sqlite", None, "D:/original/budget.sqlite"),
    ],
)
def test_worker_mount_requires_inspected_pid1_nonce_and_independent_host_pin(
    monkeypatch, pid, nonce, path, trusted, host
):
    module = additional_module()
    monkeypatch.setattr(
        module,
        "os",
        SimpleNamespace(
            name="posix", getpid=lambda: pid, environ={"TASK13_WORKER_NONCE": nonce}
        ),
    )
    from pathlib import PurePosixPath

    value = PurePosixPath(path) if trusted is not None else Path(path)
    valid = (
        pid == 1 and nonce and path == "/app/budget/campaign.sqlite" and trusted == host
    )
    if valid:
        module._budget_location(value, {"budget_path": host}, trusted)
    else:
        with pytest.raises(ValueError):
            module._budget_location(value, {"budget_path": host}, trusted)


@pytest.mark.asyncio
async def test_export_cannot_create_files_inside_an_original_artifact_directory(
    tmp_path, monkeypatch
):
    source = await additional_source(tmp_path / "run", monkeypatch)
    with pytest.raises(ValueError, match="original"):
        export(source, source.paths["source_receipt"].parent / "new-package")


@pytest.mark.asyncio
async def test_relocated_package_never_opens_its_original_artifact_paths(
    tmp_path, monkeypatch
):
    source = await additional_source(tmp_path / "run", monkeypatch)
    receipt = export(source, tmp_path / "package")
    source.paths["events"].rename(source.paths["events"].with_name("unavailable.jsonl"))
    relocated = tmp_path / "moved"
    (tmp_path / "package").rename(relocated)
    imported = verify(source, relocated, receipt["manifest_sha256"])
    imported.revalidate()


@pytest.mark.asyncio
async def test_legacy_original36_package_is_never_an_additional_source(
    tmp_path, monkeypatch
):
    from evals.tests.test_analysis_package import export as export_legacy

    source = await additional_source(tmp_path / "run", monkeypatch)
    receipt = export_legacy(tmp_path / "legacy", tmp_path / "legacy-package")
    with pytest.raises(ValueError):
        verify(source, tmp_path / "legacy-package", receipt["manifest_sha256"])


@pytest.mark.asyncio
async def test_symlink_to_identical_bytes_is_not_a_regular_package_artifact(
    tmp_path, monkeypatch
):
    source = await additional_source(tmp_path / "run", monkeypatch)
    package = tmp_path / "package"
    receipt = export(source, package)
    target = package / "artifacts/agent/events.jsonl"
    copied = tmp_path / "same-events.jsonl"
    copied.write_bytes(target.read_bytes())
    target.unlink()
    try:
        target.symlink_to(copied)
    except OSError as error:
        if getattr(error, "winerror", None) != 1314:
            raise
        pytest.skip("native symlink creation requires unavailable Windows privilege")
    with pytest.raises(ValueError, match="link|reparse"):
        verify(source, package, receipt["manifest_sha256"])


@pytest.mark.asyncio
@pytest.mark.parametrize("successor", ["source", "model"])
async def test_revalidation_requires_the_latest_registered_source_and_model(
    tmp_path, monkeypatch, successor
):
    host_pid = os.getpid()
    source = await additional_source(tmp_path / "run", monkeypatch)
    package = tmp_path / "package"
    receipt = export(source, package)
    imported = verify(source, package, receipt["manifest_sha256"])
    monkeypatch.delenv("TASK13_WORKER_NONCE", raising=False)
    monkeypatch.setattr(os, "getpid", lambda: host_pid)
    if successor == "source":
        from evals.tests.test_source_epochs import register

        register(
            source.budget,
            {
                **source.epoch,
                "epoch_id": "synthetic-epoch-2",
                "epoch_number": 2,
                "predecessor_epoch_id": source.epoch["epoch_id"],
                "source_sha256": "f" * 64,
            },
        )
    else:
        from evals.adapters.model_identities import require_registered_model_identity
        from evals.tests.test_model_identities import adopt

        request = source.request
        previous = require_registered_model_identity(
            source.budget,
            request.model_identity_binding.model_epoch_id,
            epoch_id=request.epoch_id,
            source_sha256=request.source_sha256,
            config_sha256=request.config_sha256,
            purpose="development",
        )
        adopt(
            source.budget,
            {
                **previous,
                "model_epoch_id": "model-1",
                "model_epoch_number": 1,
                "predecessor_model_epoch_id": "model-0",
                "expected_model": {
                    "id": "model-1",
                    "response_model": "new-approved",
                    "fingerprint": "new-approved-fp",
                },
            },
        )
    before = source.budget.read_bytes()
    with pytest.raises(ValueError, match="retired"):
        imported.revalidate()
    assert source.budget.read_bytes() == before
