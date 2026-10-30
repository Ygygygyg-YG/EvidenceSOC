"""Dispatch analysis verification only from an independently validated E request."""

import json
from pathlib import Path

from evals.adapters.e_planning_contracts import EPlanningRequest

ADDITIONAL_ENTRYPOINTS = frozenset(
    {
        "evals/adapters/planning_analysis.py",
        "evals/adapters/additional_analysis.py",
        "evals/additional_source_selection.py",
        "evals/adapters/epoch_development.py",
        "evals/adapters/epoch_remediation.py",
        "evals/adapters/remediation_worker.py",
        "evals/adapters/remediation_contracts.py",
    }
)


def validate_additional_export(epoch, source_root):
    """Require the new verifier chain in both the epoch and actual worker export."""
    receipt = json.loads((Path(source_root) / "source_receipt.json").read_bytes())
    entries, files = epoch["entrypoints"], receipt["files"]
    if (
        not ADDITIONAL_ENTRYPOINTS <= entries.keys()
        or not ADDITIONAL_ENTRYPOINTS <= files.keys()
        or any(files[name] != entries[name] for name in ADDITIONAL_ENTRYPOINTS)
    ):
        raise ValueError("additional planning entrypoint differs from worker export")


def verify_planning_analysis(
    request, root, budget_path, *, mounted_host_budget_path=None
):
    """The package cannot choose a verifier, supply independent pins or host paths."""
    request = EPlanningRequest.model_validate(request.model_dump(mode="json"))
    if request.source.source_kind == "additional-development-v1":
        from evals.adapters.additional_analysis import (
            verify_additional_analysis_package,
        )

        imported = verify_additional_analysis_package(
            root,
            request.source_package_manifest_sha256,
            request.source.source_registration_sha256,
            request.original_request_sha256,
            budget_path,
            mounted_host_budget_path=mounted_host_budget_path,
            recovery_lineage=request.recovery_lineage,
        )
        recovery = request.recovery_lineage
        if recovery is not None:
            from evals.adapters.planning_recovery import validate_recovery_execution

            validate_recovery_execution(
                recovery,
                {
                    key: getattr(request, key)
                    for key in (
                        "epoch_id",
                        "source_commit",
                        "source_sha256",
                        "budget_identity",
                    )
                }
                | {
                    "model_identity_binding": request.model_identity_binding.model_dump(
                        mode="json"
                    )
                },
                request.core_config_sha256,
            )
        original = recovery["original_epoch_binding"] if recovery else None
        expected = {
            **request.source.model_dump(mode="json", exclude={"source_identity"}),
            "source_package_schema_version": "task13-additional-analysis-package-v1",
            "source_core_sha256": recovery["original_core_config_sha256"]
            if recovery
            else request.core_config_sha256,
            "source_epoch_id": original["epoch_id"] if recovery else request.epoch_id,
            "source_epoch_manifest_sha256": original["epoch_manifest_sha256"]
            if recovery
            else request.epoch_manifest_sha256,
            "source_model_identity_binding": original["model_identity_binding"]
            if recovery
            else request.model_identity_binding.model_dump(mode="json"),
            "source_commit": original["source_commit"]
            if recovery
            else request.source_commit,
            "source_sha256": original["source_sha256"]
            if recovery
            else request.source_sha256,
        }
        if imported.source_identity != request.source_identity or any(
            imported.provenance.get(key) != value for key, value in expected.items()
        ):
            raise ValueError(
                "additional planning source/registration/epoch/core/model differs"
            )
        return imported
    from evals.adapters.analysis_package import verify_portable_analysis_package

    imported = verify_portable_analysis_package(
        root, request.source_package_manifest_sha256
    )
    if imported.provenance.get("source_kind") is not None:
        raise ValueError("original planning source cannot accept additional provenance")
    return imported
