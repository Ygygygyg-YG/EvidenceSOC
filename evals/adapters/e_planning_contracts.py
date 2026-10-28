"""Answer-free E2 planning contracts; validation never grants dispatch authority."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from evals.adapters.remediation_contracts import CAMPAIGN, ENTRY_PROMPT
from evals.contracts import (
    SHA256,
    CallBudget,
    Contract,
    ModelConfig,
    SeedPolicy,
    WorkerRunSpec,
    canonical_hash,
)

HEX32 = r"^[0-9a-f]{32}$"
CASE = r"^(?:ait-[0-9a-f]{24}|dedale-[0-9a-f]{16})$"


def slot_identity(registration_id: str, ordinal: int, case_id: str) -> dict:
    slot = (
        "development-eplan-"
        + canonical_hash([registration_id, ordinal, "planning"])[:24]
    )
    run = CAMPAIGN + "-" + canonical_hash([slot, 1])[:16]
    return {
        "planning_slot_id": slot,
        "slot_id": slot,
        "run_id": run,
        "request_id": canonical_hash([registration_id, ordinal, "respond-request"])[
            :32
        ],
        "namespace": canonical_hash([registration_id, ordinal, "planning-namespace"])[
            :32
        ],
        "incident_id": "IN-" + canonical_hash([run, case_id, "B3"])[:26],
        "trial_id": canonical_hash([registration_id, ordinal, "six-branch-trial"])[:32],
    }


class OriginalBudgetIdentity(Contract):
    schema_version: Literal["task13-original-budget-identity-v1"]
    baseline_count: int = Field(ge=1, strict=True)
    baseline_max_rowid: int = Field(ge=1, strict=True)
    baseline_sha256: str = Field(pattern=SHA256)

    @model_validator(mode="after")
    def nonempty_prefix(self) -> Self:
        if self.baseline_max_rowid < self.baseline_count:
            raise ValueError("original budget prefix identity differs")
        return self


class EPlanningSource(Contract):
    source_row_id: str = Field(pattern=r"^development-[0-9a-f]{24}$")
    order_index: int = Field(ge=0, le=35, strict=True)
    case_id: str = Field(pattern=CASE)
    dataset: Literal["ait", "dedale"]
    agent_sha256: str = Field(pattern=SHA256)
    request_sha256: str = Field(pattern=SHA256)
    manifest_sha256: str = Field(pattern=SHA256)
    analysis_output_sha256: str = Field(pattern=SHA256)
    imported_values_sha256: str = Field(pattern=SHA256)
    source_identity: str = Field(pattern=SHA256)
    source_package_manifest_sha256: str = Field(pattern=SHA256)
    source_kind: Literal["additional-development-v1"] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    source_registration_sha256: str | None = Field(
        default=None, pattern=SHA256, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def original_identity(self) -> Self:
        if (self.source_kind is None) != (self.source_registration_sha256 is None):
            raise ValueError("additional source kind and registration must be paired")
        if self.source_kind is not None and self.order_index != 0:
            raise ValueError("additional source requires its single registered row")
        if not self.case_id.startswith(self.dataset + "-") or self.source_identity != (
            canonical_hash([self.case_id, self.source_row_id, self.request_sha256])
        ):
            raise ValueError("original source identity or dataset differs")
        return self


class ESelectedSourceLineageEntry(Contract):
    """Immutable original source identity; no planning/package alias can replace it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_row_id: str = Field(pattern=r"^development-[0-9a-f]{24}$")
    order_index: int = Field(ge=0, le=35, strict=True)
    case_id: str = Field(pattern=CASE)
    dataset: Literal["ait", "dedale"]
    agent_sha256: str = Field(pattern=SHA256)
    source_identity: str = Field(pattern=SHA256)
    original_request_sha256: str = Field(pattern=SHA256)
    original_artifact_manifest_sha256: str = Field(pattern=SHA256)
    source_package_manifest_sha256: str = Field(pattern=SHA256)
    source_analysis_output_sha256: str = Field(pattern=SHA256)
    imported_values_sha256: str = Field(pattern=SHA256)
    source_kind: Literal["additional-development-v1"] | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    source_registration_sha256: str | None = Field(
        default=None, pattern=SHA256, exclude_if=lambda value: value is None
    )


class ESelectedSourceLineage(Contract):
    """Versioned receipt, separate from the complete registration's hash."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["task13-e-selected-source-lineage-v1"]
    source_selection_receipt_sha256: str = Field(pattern=SHA256)
    selected_sources: tuple[ESelectedSourceLineageEntry, ...] = Field(
        min_length=1, max_length=1
    )


def build_selected_source_lineage(
    source: EPlanningSource, source_selection_receipt_sha256: str
) -> ESelectedSourceLineage:
    """Mechanically project the chosen original source, never caller receipt JSON."""
    return ESelectedSourceLineage(
        schema_version="task13-e-selected-source-lineage-v1",
        source_selection_receipt_sha256=source_selection_receipt_sha256,
        selected_sources=(
            ESelectedSourceLineageEntry(
                source_row_id=source.source_row_id,
                order_index=source.order_index,
                case_id=source.case_id,
                dataset=source.dataset,
                agent_sha256=source.agent_sha256,
                source_identity=source.source_identity,
                original_request_sha256=source.request_sha256,
                original_artifact_manifest_sha256=source.manifest_sha256,
                source_package_manifest_sha256=source.source_package_manifest_sha256,
                source_analysis_output_sha256=source.analysis_output_sha256,
                imported_values_sha256=source.imported_values_sha256,
                **(
                    {
                        "source_kind": source.source_kind,
                        "source_registration_sha256": source.source_registration_sha256,
                    }
                    if source.source_kind is not None
                    else {}
                ),
            ),
        ),
    )


class ResponseCallLimit(Contract):
    logical: Literal[1] = 1
    physical: Literal[3] = 3


class ModelIdentityBinding(Contract):
    model_epoch_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,256}$")
    model_identity_sha256: str = Field(pattern=SHA256)


class EPlanningRequest(Contract):
    schema_version: Literal["task13-e-planning-worker-v1"] = (
        "task13-e-planning-worker-v1"
    )
    campaign_id: Literal["task13-repair-202610-v2"] = CAMPAIGN
    mode: Literal[
        "same-source-replicates-v1", "additional-development-replicates-v1"
    ] = "same-source-replicates-v1"
    registration_id: str = Field(pattern=HEX32)
    registration_sha256: str = Field(pattern=SHA256)
    ordinal: int = Field(ge=1, le=3, strict=True)
    planning_slot_id: str
    slot_id: str
    run_id: str
    request_id: str = Field(pattern=HEX32)
    namespace: str = Field(pattern=HEX32)
    incident_id: str
    trial_id: str = Field(pattern=HEX32)
    attempt: Literal[1] = 1
    purpose: Literal["development"] = "development"
    group: Literal["B3"] = "B3"
    case_id: str = Field(pattern=CASE)
    dataset: Literal["ait", "dedale"]
    agent_sha256: str = Field(pattern=SHA256)
    source: EPlanningSource
    source_identity: str = Field(pattern=SHA256)
    source_row_id: str
    original_request_sha256: str = Field(pattern=SHA256)
    original_manifest_sha256: str = Field(pattern=SHA256)
    analysis_output_sha256: str = Field(pattern=SHA256)
    imported_values_sha256: str = Field(pattern=SHA256)
    source_package_manifest_sha256: str = Field(pattern=SHA256)
    source_selection_receipt_sha256: str = Field(pattern=SHA256)
    selected_source_lineage: ESelectedSourceLineage
    selected_source_lineage_sha256: str = Field(pattern=SHA256)
    epoch_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,120}$")
    epoch_manifest_sha256: str = Field(pattern=SHA256)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=SHA256)
    budget_source_receipt_sha256: str = Field(pattern=SHA256)
    config_sha256: str = Field(pattern=SHA256)
    core_config_sha256: str = Field(pattern=SHA256)
    budget_identity: dict
    model_identity_binding: ModelIdentityBinding | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    model: ModelConfig = Field(default_factory=ModelConfig)
    seed: SeedPolicy = Field(default_factory=SeedPolicy)
    budget: CallBudget = Field(default_factory=lambda: CallBudget(max_model_calls=1))
    entry_prompt: Literal[ENTRY_PROMPT] = ENTRY_PROMPT
    response_call_limit: ResponseCallLimit = Field(default_factory=ResponseCallLimit)
    plan_ttl_seconds: Literal[1800] = 1800
    auto_renew: Literal[False] = False
    execution_policy: Literal["import-analysis-respond-only-v1"] = (
        "import-analysis-respond-only-v1"
    )

    @model_validator(mode="after")
    def frozen_bindings(self) -> Self:
        OriginalBudgetIdentity.model_validate(self.budget_identity)
        additional = self.source.source_kind is not None
        if (self.mode == "additional-development-replicates-v1") != additional:
            raise ValueError("planning mode differs from its explicit source kind")
        if additional and self.model_identity_binding is None:
            raise ValueError("additional source requires an adopted model identity")
        identities = slot_identity(self.registration_id, self.ordinal, self.case_id)
        if any(getattr(self, key) != value for key, value in identities.items()):
            raise ValueError("planning slot/request/incident/trial identity differs")
        expected_source = {
            "case_id": self.source.case_id,
            "dataset": self.source.dataset,
            "agent_sha256": self.source.agent_sha256,
            "source_identity": self.source.source_identity,
            "source_row_id": self.source.source_row_id,
            "original_request_sha256": self.source.request_sha256,
            "original_manifest_sha256": self.source.manifest_sha256,
            "analysis_output_sha256": self.source.analysis_output_sha256,
            "imported_values_sha256": self.source.imported_values_sha256,
            "source_package_manifest_sha256": self.source.source_package_manifest_sha256,
        }
        if any(getattr(self, key) != value for key, value in expected_source.items()):
            raise ValueError("original analysis lineage differs from planning input")
        if (
            self.selected_source_lineage
            != build_selected_source_lineage(
                self.source, self.source_selection_receipt_sha256
            )
            or canonical_hash(self.selected_source_lineage)
            != self.selected_source_lineage_sha256
        ):
            raise ValueError("selected source lineage receipt or hash differs")
        if self.budget_source_receipt_sha256 != self.source_sha256:
            raise ValueError(
                "budget source receipt differs from epoch execution source"
            )
        if (
            self.config_sha256 != self.core_config_sha256
            or self.model != ModelConfig()
            or self.seed != SeedPolicy()
            or self.budget != CallBudget(max_model_calls=1)
        ):
            raise ValueError("frozen model/seed/response-only budget differs")
        return self

    def worker_spec(self) -> WorkerRunSpec:
        return WorkerRunSpec(
            run_id=self.run_id,
            case_id=self.case_id,
            group=self.group,
            config_sha256=self.config_sha256,
            model=self.model,
            seed=self.seed,
            budget=self.budget,
        )

    def budget_binding(self) -> dict:
        binding = {
            key: getattr(self, key)
            for key in (
                "campaign_id",
                "case_id",
                "group",
                "attempt",
                "purpose",
                "source_sha256",
                "config_sha256",
                "epoch_id",
            )
        }
        if self.model_identity_binding is not None:
            binding.update(self.model_identity_binding.model_dump(mode="json"))
        return binding
