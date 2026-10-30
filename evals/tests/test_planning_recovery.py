"""Explicit recovery reuses settled analysis bytes; never dispatches a model."""

import json
import os
import sqlite3
from copy import deepcopy
from pathlib import Path

import pytest

from evals.contracts import canonical_hash
from evals.tests.test_additional_analysis import additional_source, export, verify


def test_recovery_contract_rejects_changed_analysis_identity_class():
    from evals.adapters.planning_recovery import validate_identity_contract_equivalence

    current = (
        Path(__file__).resolve().parents[1] / "adapters/e_planning_contracts.py"
    ).read_bytes()
    validate_identity_contract_equivalence(current)
    changed = current.replace(
        b"class ModelIdentityBinding(Contract):", b"class ModelIdentityBinding(object):"
    )
    with pytest.raises(ValueError, match="identity contract"):
        validate_identity_contract_equivalence(changed)


async def recovery_inputs(tmp_path, monkeypatch):
    from evals.adapters.planning_recovery import build_recovery_lineage
    from evals.additional_source_selection import build_additional_source_selection
    from evals.tests import test_epoch_development as epoch_tests
    from evals.tests.test_source_epochs import register

    host_pid = os.getpid
    original_inputs = epoch_tests.development_inputs

    def inputs(*args, extra_source_entries=(), **kwargs):
        return original_inputs(
            *args,
            extra_source_entries=set(extra_source_entries)
            | {
                "evals/adapters/additional_analysis.py",
            },
            **kwargs,
        )

    monkeypatch.setattr(epoch_tests, "development_inputs", inputs)
    source = await additional_source(tmp_path / "run", monkeypatch)
    package = tmp_path / "package"
    exported = export(source, package)
    imported = verify(source, package, exported["manifest_sha256"])
    selection = build_additional_source_selection(source.registration, imported)
    execution_config = {
        "model": source.registration["request"]["model"],
        "model_identity": {
            "id": "new-recovery-model",
            "response_model": "approved",
            "fingerprint": "approved-fp",
        },
    }
    successor = deepcopy(source.epoch)
    successor.update(
        epoch_id="recovery-successor",
        epoch_number=source.epoch["epoch_number"] + 1,
        predecessor_epoch_id=source.epoch["epoch_id"],
        source_commit="e" * 40,
        source_sha256="d" * 64,
        config_sha256=canonical_hash(execution_config),
    )
    monkeypatch.setattr(os, "getpid", host_pid)
    monkeypatch.delenv("TASK13_WORKER_NONCE", raising=False)
    register(source.budget, successor)
    from evals.tests.test_model_identities import adopt

    with sqlite3.connect(source.budget) as db:
        original_model = json.loads(
            db.execute(
                "SELECT manifest_json FROM supplement_model_epochs ORDER BY model_epoch_number DESC LIMIT 1"
            ).fetchone()[0]
        )
    successor_model = deepcopy(original_model)
    successor_model.update(
        model_epoch_id="new-recovery-model",
        model_epoch_number=original_model["model_epoch_number"] + 1,
        predecessor_model_epoch_id=original_model["model_epoch_id"],
        epoch_id=successor["epoch_id"],
        source_manifest_sha256=canonical_hash(successor),
        source_sha256=successor["source_sha256"],
        config_sha256=successor["config_sha256"],
    )
    successor_model["expected_model"]["id"] = "new-recovery-model"
    adopt(source.budget, successor_model)
    execution = {
        "epoch_id": successor["epoch_id"],
        "source_commit": successor["source_commit"],
        "source_sha256": successor["source_sha256"],
        "budget_identity": source.request.budget_identity,
        "model_epoch_id": "new-recovery-model",
    }
    lineage = build_recovery_lineage(
        original_registration=source.registration,
        source=selection["source"],
        execution_epoch_binding=execution,
        execution_core_config_sha256=canonical_hash(execution_config),
        authorization_record_sha256="a" * 64,
        predecessor_terminal_sha256="b" * 64,
        recovery_id="explicit-startup-recovery",
    )
    return source, package, exported, selection, lineage


@pytest.mark.asyncio
async def test_explicit_recovery_reads_retired_settled_analysis_without_dispatch(
    tmp_path, monkeypatch
):
    from evals.adapters.additional_analysis import verify_additional_analysis_package

    source, package, exported, _, lineage = await recovery_inputs(tmp_path, monkeypatch)
    before = source.budget.read_bytes()
    with pytest.raises(ValueError, match="retired"):
        verify(source, package, exported["manifest_sha256"])
    recovered = verify_additional_analysis_package(
        package,
        exported["manifest_sha256"],
        source.registration_sha,
        canonical_hash(source.request),
        source.budget,
        recovery_lineage=lineage,
    )
    recovered.revalidate()
    from evals.adapters.model_identity_runtime import require_dispatch_identity

    with pytest.raises(ValueError, match="retired"):
        require_dispatch_identity(source.budget, source.request)
    assert recovered.provenance["source_epoch_id"] == source.request.epoch_id
    assert recovered.provenance["request_sha256"] == canonical_hash(source.request)
    assert source.budget.read_bytes() == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "original_request_sha256",
        "original_package_manifest_sha256",
        "original_analysis_output_sha256",
        "original_core_config_sha256",
    ],
)
async def test_recovery_rejects_substituted_original_analysis(
    tmp_path, monkeypatch, field
):
    from evals.adapters.additional_analysis import verify_additional_analysis_package

    source, package, exported, _, lineage = await recovery_inputs(tmp_path, monkeypatch)
    lineage[field] = "0" * 64
    with pytest.raises(ValueError):
        verify_additional_analysis_package(
            package,
            exported["manifest_sha256"],
            source.registration_sha,
            canonical_hash(source.request),
            source.budget,
            recovery_lineage=lineage,
        )


@pytest.mark.asyncio
async def test_recovery_registration_keeps_original_analysis_and_new_execution(
    tmp_path, monkeypatch
):
    from evals.e_planning import build_e_planning_registration, planning_requests

    source, package, exported, selection, lineage = await recovery_inputs(
        tmp_path, monkeypatch
    )
    core = deepcopy(source.registration["request"]["model"])
    config = {
        "model": core,
        "model_identity": {
            "id": "new-recovery-model",
            "response_model": "approved",
            "fingerprint": "approved-fp",
        },
    }
    lineage["execution_core_config_sha256"] = canonical_hash(config)
    with sqlite3.connect(source.budget) as db:
        epoch_pin = db.execute(
            "SELECT manifest_sha256 FROM supplement_source_epochs ORDER BY epoch_number DESC LIMIT 1"
        ).fetchone()[0]
        model_pin = db.execute(
            "SELECT manifest_sha256 FROM supplement_model_epochs ORDER BY model_epoch_number DESC LIMIT 1"
        ).fetchone()[0]
    registration = build_e_planning_registration(
        selection,
        registration_id="3" * 32,
        source_package_manifest_sha256=exported["manifest_sha256"],
        epoch_binding={
            key: value
            for key, value in lineage["execution_epoch_binding"].items()
            if key != "model_epoch_id"
        }
        | {
            "epoch_manifest_sha256": epoch_pin,
            "model_identity_binding": {
                "model_epoch_id": "new-recovery-model",
                "model_identity_sha256": model_pin,
            },
        },
        budget_source_receipt_sha256="d" * 64,
        core_config=config,
        synthetic=True,
        mode="additional-development-replicates-v1",
        recovery_lineage=lineage,
    )
    for request in planning_requests(registration):
        assert request.original_request_sha256 == canonical_hash(source.request)
        assert request.epoch_id == "recovery-successor"
        assert request.recovery_lineage == lineage
        from evals.adapters.planning_analysis import verify_planning_analysis

        before = source.budget.read_bytes()
        imported = verify_planning_analysis(request, package, source.budget)
        imported.revalidate()
        assert imported.provenance["source_epoch_id"] == source.request.epoch_id
        assert source.budget.read_bytes() == before
