"""Free E2 controller boundary checks; synthetic inputs never dispatch a model."""

from copy import deepcopy
from hashlib import sha256

import pytest

from evals.contracts import canonical_hash
from evals.e_planning import planning_requests
from evals.tests.test_e_planning_contracts import registration_fixture
from evals.tests.test_e_planning_journal import register_fixture
from scripts import task13_worker_runtime as runtime


def host_fixture(tmp_path, monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace

    from evals.e_planning import build_e_planning_registration
    from evals.runners.manifest import file_hash
    from evals.tests.test_source_epochs import (
        historical_account,
        manifest_for,
        register,
    )

    budget, identity, controller = historical_account(tmp_path)
    register(budget, manifest_for(identity, controller))
    frozen = registration_fixture()
    controller_file = tmp_path / "controller.json"
    controller_file.write_text('{"synthetic":true}', encoding="utf-8")
    options = {
        "phase": "development",
        "budget_identity": identity,
        "source_dir": str(tmp_path / "source"),
        "source_commit": "f" * 40,
        "budget_dir": str(tmp_path),
        "image_id": "sha256:" + "1" * 64,
        "dependencies_lock_sha256": "2" * 64,
        "knowledge_sha256": "4" * 64,
        "controller_manifest_path": str(controller_file),
        "import_source_dir": str(tmp_path / "package"),
    }
    dependencies = {"lock_sha256": "2" * 64, "tree_sha256": "3" * 64}
    entrypoints = [
        "scripts/task13_worker_runtime.py",
        "evals/remediation.py",
        "evals/adapters/budget_v2.py",
        "evals/adapters/e_planning_worker.py",
        "evals/adapters/e_planning_contracts.py",
        "evals/adapters/e_planning_journal.py",
        "evals/adapters/analysis_package.py",
        "evals/adapters/analysis_import.py",
        "evals/e_planning.py",
        "evals/adapters/e_planning_review.py",
        "evals/adapters/verification_worker.py",
    ]
    repository = Path(runtime.__file__).resolve().parents[1]
    entries = {name: file_hash(repository / name) for name in entrypoints}
    epoch = manifest_for(
        identity,
        controller,
        1,
        source_commit="f" * 40,
        source_sha256="1" * 64,
        config_sha256=frozen["core_config_sha256"],
        entrypoints=entries,
        entrypoints_sha256=canonical_hash(entries),
        runtime_binding=runtime.e_planning_runtime_binding(options, dependencies),
    )
    register(budget, epoch)
    registration = build_e_planning_registration(
        frozen["source_selection_receipt"],
        registration_id=frozen["registration_id"],
        source_package_manifest_sha256="d" * 64,
        epoch_binding={
            "epoch_id": epoch["epoch_id"],
            "epoch_manifest_sha256": canonical_hash(epoch),
            "source_commit": epoch["source_commit"],
            "source_sha256": epoch["source_sha256"],
            "budget_identity": identity,
        },
        budget_source_receipt_sha256=epoch["source_sha256"],
        core_config=frozen["core_config"],
        synthetic=True,
    )
    dispatch = tmp_path / "dispatch"
    dispatch.mkdir()
    _, authority, _ = register_fixture(dispatch / "e-planning.sqlite", registration)
    options.update(
        import_dispatch_path=str(dispatch / "e-planning.sqlite"),
        planning_authority_sha256=canonical_hash(authority),
    )
    request = planning_requests(registration)[0]
    provenance = request.source.model_dump(mode="json")
    provenance.pop("source_identity")
    source = SimpleNamespace(
        source_identity=request.source_identity, provenance=provenance
    )
    monkeypatch.setattr(
        "evals.adapters.analysis_package.verify_portable_analysis_package",
        lambda *args: source,
    )
    monkeypatch.setattr(
        "evals.adapters.remediation_worker.validate_exported_source",
        lambda *args, **kwargs: None,
    )
    return request, options, dependencies, source


@pytest.mark.parametrize(
    "tamper",
    [
        None,
        "phase",
        "identity",
        "image",
        "dependencies",
        "controller",
        "epoch",
        "source_commit",
        "source_sha256",
        "config_sha256",
        "provenance",
        "extra_journal_file",
    ],
)
def test_host_epoch_runtime_and_metadata_checks_are_readonly(
    tmp_path, monkeypatch, tamper
):
    import sqlite3
    from pathlib import Path

    request, options, dependencies, source = host_fixture(tmp_path, monkeypatch)
    if tamper == "phase":
        options["phase"] = "formal"
    elif tamper == "identity":
        options["budget_identity"] = {}
    elif tamper == "image":
        options["image_id"] = "sha256:" + "f" * 64
    elif tamper == "dependencies":
        dependencies["tree_sha256"] = "f" * 64
    elif tamper == "controller":
        Path(options["controller_manifest_path"]).write_text("changed")
    elif tamper == "epoch":
        request = request.model_copy(update={"epoch_id": "missing-epoch"})
    elif tamper in {"source_commit", "source_sha256", "config_sha256"}:
        request = request.model_copy(
            update={tamper: "e" * (40 if tamper == "source_commit" else 64)}
        )
    elif tamper == "provenance":
        source.provenance["analysis_output_sha256"] = "e" * 64
    elif tamper == "extra_journal_file":
        (Path(options["import_dispatch_path"]).parent / "private.txt").write_text(
            "unregistered"
        )
    budget = Path(options["budget_dir"]) / "campaign.sqlite"
    with sqlite3.connect(budget.resolve().as_uri() + "?mode=ro", uri=True) as db:
        before = db.iterdump()
        before = list(before)
    if tamper:
        with pytest.raises((ValueError, PermissionError)):
            runtime.validate_e_planning_host(
                request, tmp_path / "agent", options, dependencies
            )
    else:
        assert runtime.validate_e_planning_host(
            request, tmp_path / "agent", options, dependencies
        ) == runtime.e_planning_runtime_binding(options, dependencies)
    with sqlite3.connect(budget.resolve().as_uri() + "?mode=ro", uri=True) as db:
        assert list(db.iterdump()) == before


def test_dedicated_request_is_parsed_and_unknown_fields_are_rejected():
    request = planning_requests(registration_fixture())[0]
    assert runtime._worker_request(request.model_dump(mode="json")) == request
    with pytest.raises(ValueError):
        runtime._worker_request(
            {**request.model_dump(mode="json"), "auto_approve": True}
        )


def test_planning_mounts_are_exact_and_legacy_cannot_request_them():
    mounts = {target: "/synthetic" + target for target in runtime.READ_ONLY_MOUNTS}
    mounts.update(
        {"/app/budget": "/synthetic/budget", "/app/output": "/synthetic/output"}
    )
    added = {
        "/app/import-source": "/synthetic/package",
        "/app/import-dispatch": "/synthetic/journal",
    }
    options = {
        "name": "task13-worker-abc",
        "image_id": "sha256:" + "a" * 64,
        "network": "synthetic",
        "environment": {},
    }
    with pytest.raises(ValueError):
        runtime.docker_run_arguments(mounts={**mounts, **added}, **options)
    arguments = runtime.docker_run_arguments(
        mounts={**mounts, **added},
        schema_version="task13-e-planning-worker-v1",
        **options,
    )
    bindings = [arguments[i + 1] for i, arg in enumerate(arguments) if arg == "--mount"]
    assert any("target=/app/import-source,readonly" in row for row in bindings)
    assert any(row.endswith("target=/app/import-dispatch") for row in bindings)
    for missing in added:
        with pytest.raises(ValueError):
            runtime.docker_run_arguments(
                mounts={k: v for k, v in {**mounts, **added}.items() if k != missing},
                schema_version="task13-e-planning-worker-v1",
                **options,
            )


def test_readonly_request_validation_does_not_claim_or_create_files(tmp_path):
    from evals.adapters.e_planning_journal import EPlanningDispatchJournal

    path = tmp_path / "e-planning.sqlite"
    registration, authority, _ = register_fixture(path)
    request = planning_requests(registration)[0]
    journal = EPlanningDispatchJournal.open_existing(
        path,
        expected_registration_sha256=canonical_hash(registration),
        expected_authority_sha256=canonical_hash(authority),
    )
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}
    result = journal.validate_request(request)
    assert result["status"] == "unclaimed"
    assert result["request_sha256"] == canonical_hash(request)
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}
    journal.claim_planning_slot(request)
    assert journal.validate_request(request)["status"] == "started"
    wrong = request.model_copy(update={"epoch_id": "another-epoch"})
    with pytest.raises(PermissionError):
        journal.validate_request(wrong)


def test_runtime_binding_is_calculated_from_actual_receipts(tmp_path):
    assert callable(getattr(runtime, "e_planning_runtime_binding", None))
    controller = tmp_path / "controller.json"
    controller.write_bytes(b'{"synthetic":true}')
    options = {
        "image_id": "sha256:" + "1" * 64,
        "dependencies_lock_sha256": "2" * 64,
        "knowledge_sha256": "4" * 64,
        "controller_manifest_path": str(controller),
    }
    receipt = {"tree_sha256": "3" * 64, "lock_sha256": "2" * 64}
    expected = {
        "image_id": options["image_id"],
        "dependencies_lock_sha256": "2" * 64,
        "dependencies_tree_sha256": "3" * 64,
        "knowledge_sha256": "4" * 64,
        "controller_manifest_sha256": sha256(controller.read_bytes()).hexdigest(),
    }
    assert runtime.e_planning_runtime_binding(options, receipt) == expected
    with pytest.raises(ValueError):
        runtime.e_planning_runtime_binding(
            options, {**receipt, "lock_sha256": "f" * 64}
        )


@pytest.mark.parametrize(
    "field",
    [
        "source_package_manifest_sha256",
        "registration_sha256",
        "request_sha256",
        "authority_sha256",
        "readonly_source",
        "writable_dispatch",
    ],
)
def test_pre_go_requires_actual_planning_probe_matches_every_binding(field):
    assert callable(getattr(runtime, "validate_e_planning_probe", None))
    request = planning_requests(registration_fixture())[0]
    probe = {
        "source_package_manifest_sha256": request.source_package_manifest_sha256,
        "registration_sha256": request.registration_sha256,
        "request_sha256": canonical_hash(request),
        "authority_sha256": "f" * 64,
        "readonly_source": True,
        "writable_dispatch": True,
    }
    runtime.validate_e_planning_probe(probe, request, authority_sha256="f" * 64)
    changed = deepcopy(probe)
    changed[field] = False if isinstance(changed[field], bool) else "0" * 64
    with pytest.raises(ValueError):
        runtime.validate_e_planning_probe(changed, request, authority_sha256="f" * 64)
