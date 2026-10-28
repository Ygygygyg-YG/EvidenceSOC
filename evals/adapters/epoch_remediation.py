"""Explicit latest-epoch regression requests on the original supplement account."""

from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import Field

from evals.adapters.e_planning_contracts import ModelIdentityBinding
from evals.adapters.remediation_contracts import RemediationRequest
from evals.contracts import SHA256

WORKER_ENTRYPOINTS = frozenset(
    {
        "scripts/task13_worker_runtime.py",
        "evals/adapters/epoch_remediation.py",
        "evals/adapters/remediation_worker.py",
        "evals/adapters/remediation_contracts.py",
        "evals/adapters/budget_v2.py",
        "evals/adapters/source_epochs.py",
    }
)


class EpochRemediationRequest(RemediationRequest):
    schema_version: Literal["task13-remediation-worker-v3"] = (
        "task13-remediation-worker-v3"
    )
    purpose: Literal["regression"] = "regression"
    epoch_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,256}$")
    epoch_manifest_sha256: str = Field(pattern=SHA256)
    model_identity_binding: ModelIdentityBinding | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    def budget_binding(self) -> dict:
        binding = {**super().budget_binding(), "epoch_id": self.epoch_id}
        if self.model_identity_binding is not None:
            binding.update(self.model_identity_binding.model_dump(mode="json"))
        return binding


def validate_epoch_runtime(
    request,
    agent_dir,
    source,
    budget_path,
    runtime_binding,
    source_commit,
    worker=False,
) -> dict:
    request = EpochRemediationRequest.model_validate(request.model_dump(mode="json"))
    return _validate_registered_epoch_runtime(
        request, agent_dir, source, budget_path, runtime_binding, source_commit, worker
    )


def _validate_registered_epoch_runtime(
    request,
    agent_dir,
    source,
    budget_path,
    runtime_binding,
    source_commit,
    worker=False,
) -> dict:
    """SELECT-only admission; caller supplies independently observed runtime identity.

    The host also verifies the Git archive via its existing runtime validator.
    Workers retain the minimal source mount: host controller-only entries are
    checked on the host, and every mounted entry is checked again in-worker.
    """
    from evals.adapters.remediation_worker import (
        require_existing_budget,
        validate_exported_source,
    )
    from evals.adapters.source_epochs import require_registered_epoch

    # Authority comes from the exact validated contract, never caller phase/schema
    # parameters. Public v3 and v4 entrypoints each revalidate their own contract.
    if type(request) is EpochRemediationRequest:
        request = EpochRemediationRequest.model_validate(
            request.model_dump(mode="json")
        )
        phase, scope = "formal", "regression"
        required = WORKER_ENTRYPOINTS
    else:
        from evals.adapters.epoch_development import EpochDevelopmentRequest

        if type(request) is not EpochDevelopmentRequest:
            raise ValueError("exact registered epoch worker request required")
        request = EpochDevelopmentRequest.model_validate(
            request.model_dump(mode="json")
        )
        phase, scope = "development", "development"
        required = WORKER_ENTRYPOINTS | {"evals/adapters/epoch_development.py"}
    if worker:
        if os.getpid() != 1 or not os.environ.get("TASK13_WORKER_NONCE"):
            raise PermissionError(f"epoch {scope} requires inspected worker PID1")
        if os.environ.get("TASK13_PHASE") != phase:
            raise ValueError(f"epoch {scope} worker phase must be {phase}")
    source, budget_path = Path(source), Path(budget_path)
    validate_exported_source(request, agent_dir, source, source_commit=source_commit)
    require_existing_budget(budget_path, request.budget_identity)
    epoch = require_registered_epoch(
        budget_path,
        request.epoch_id,
        source_sha256=request.source_sha256,
        config_sha256=request.config_sha256,
        budget_identity=request.budget_identity,
        manifest_sha256=request.epoch_manifest_sha256,
        latest=True,
    )
    if request.model_identity_binding is not None:
        from evals.adapters.model_identity_runtime import require_dispatch_identity

        require_dispatch_identity(budget_path, request)
    # The worker's Linux path differs from the original Windows host path.
    # The inspected host wrapper passes the exact independently checked pin.
    if (
        worker
        and os.environ.get("TASK13_EPOCH_HOST_BUDGET_PATH") != epoch["budget_path"]
    ) or (not worker and Path(epoch["budget_path"]).resolve() != budget_path.resolve()):
        raise ValueError("epoch regression requires its original host budget path")
    if (
        epoch["source_commit"] != request.source_commit
        or epoch["runtime_binding"] != runtime_binding
    ):
        raise ValueError("registered regression epoch runtime binding differs")
    receipt = json.loads((source / "source_receipt.json").read_text(encoding="utf-8"))
    files, entries = receipt["files"], epoch["entrypoints"]
    required = required | (
        {
            "evals/adapters/model_identity_runtime.py",
            "evals/adapters/model_identities.py",
            "evals/adapters/model_client.py",
            "evals/contracts.py",
            "evals/adapters/e_planning_contracts.py",
        }
        if request.model_identity_binding is not None
        else set()
    )
    if (
        not required <= entries.keys()
        or not required <= files.keys()
        or any(files[name] != entries[name] for name in entries.keys() & files.keys())
    ):
        raise ValueError("registered regression epoch worker entrypoint differs")
    if not worker:
        root = Path(__file__).resolve().parents[2]
        for relative, digest in entries.items():
            target = root / relative
            if (
                not target.is_file()
                or any(
                    part.is_symlink() or part.is_junction()
                    for part in (target, *target.parents)
                )
                or sha256(target.read_bytes()).hexdigest() != digest
            ):
                raise ValueError(
                    "actual regression controller entrypoint differs from epoch"
                )
    return epoch


def validate_epoch_worker(request, agent_dir):
    """No key, model, budget construction or service access before this returns."""
    request = EpochRemediationRequest.model_validate(request.model_dump(mode="json"))
    try:
        source = Path(os.environ["TASK13_SOURCE_DIR"])
        budget = Path(os.environ["TASK13_BUDGET_DB"])
        runtime = json.loads(os.environ["TASK13_RUNTIME_BINDING"])
        commit = os.environ["TASK13_SOURCE_COMMIT"]
    except (KeyError, json.JSONDecodeError) as exc:
        raise ValueError(
            "complete epoch regression worker runtime binding is required"
        ) from exc
    validate_epoch_runtime(
        request, agent_dir, source, budget, runtime, commit, worker=True
    )
    return request


async def run_epoch_remediation(request, agent_dir):
    """Dedicated regression path; reuse the existing runner only after admission."""
    from evals.adapters.remediation_worker import run_remediation

    request = validate_epoch_worker(request, agent_dir)
    return await run_remediation(request, agent_dir)
