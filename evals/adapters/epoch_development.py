"""Explicit adopted-identity development analysis on the latest source epoch."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from evals.adapters.e_planning_contracts import ModelIdentityBinding
from evals.adapters.remediation_contracts import RemediationRequest
from evals.contracts import SHA256, CallBudget, ModelConfig, SeedPolicy


class EpochDevelopmentRequest(RemediationRequest):
    schema_version: Literal["task13-remediation-worker-v4"] = (
        "task13-remediation-worker-v4"
    )
    purpose: Literal["development"] = "development"
    group: Literal["B3"] = "B3"
    repeat: Literal[1] = 1
    budget: CallBudget = Field(default_factory=lambda: CallBudget(max_model_calls=1))
    epoch_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,256}$")
    epoch_manifest_sha256: str = Field(pattern=SHA256)
    model_identity_binding: ModelIdentityBinding

    @model_validator(mode="after")
    def frozen_scientific_settings(self) -> Self:
        if (
            self.model != ModelConfig()
            or self.seed != SeedPolicy()
            or self.budget != CallBudget(max_model_calls=1)
        ):
            raise ValueError(
                "epoch development requires frozen model/seed/analysis budget"
            )
        return self

    def budget_binding(self) -> dict:
        return {
            **super().budget_binding(),
            "epoch_id": self.epoch_id,
            **self.model_identity_binding.model_dump(mode="json"),
        }


def validate_epoch_development_runtime(
    request,
    agent_dir,
    source,
    budget_path,
    runtime_binding,
    source_commit,
    worker=False,
) -> dict:
    """SELECT-only source/model/account admission before model or service access."""
    from evals.adapters.epoch_remediation import _validate_registered_epoch_runtime

    request = EpochDevelopmentRequest.model_validate(request.model_dump(mode="json"))
    return _validate_registered_epoch_runtime(
        request, agent_dir, source, budget_path, runtime_binding, source_commit, worker
    )


def validate_epoch_development_worker(request, agent_dir):
    request = EpochDevelopmentRequest.model_validate(request.model_dump(mode="json"))
    try:
        source = Path(os.environ["TASK13_SOURCE_DIR"])
        budget = Path(os.environ["TASK13_BUDGET_DB"])
        runtime = json.loads(os.environ["TASK13_RUNTIME_BINDING"])
        commit = os.environ["TASK13_SOURCE_COMMIT"]
    except (KeyError, json.JSONDecodeError) as exc:
        raise ValueError(
            "complete epoch development worker runtime binding is required"
        ) from exc
    validate_epoch_development_runtime(
        request, agent_dir, source, budget, runtime, commit, worker=True
    )
    return request


async def run_epoch_development(request, agent_dir):
    """One existing development analysis; never response planning or regression."""
    from evals.adapters.remediation_worker import run_remediation

    request = validate_epoch_development_worker(request, agent_dir)
    return await run_remediation(request, agent_dir)
