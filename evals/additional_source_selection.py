"""Single registered development analysis selection; metadata grants no authority."""

from __future__ import annotations

from typing import Literal, Self

from evidencesoc.agents.analysis_import import ImportedAnalysis
from pydantic import Field, model_validator

from evals.adapters.additional_analysis import AdditionalDevelopmentRegistration
from evals.adapters.e_planning_contracts import EPlanningSource
from evals.contracts import SHA256, Contract, canonical_hash

RULE = "single-registered-development-analysis-v1"


class AdditionalSourceSelection(Contract):
    schema_version: Literal["task13-additional-analysis-source-selection-v1"]
    rule: Literal["single-registered-development-analysis-v1"]
    rule_sha256: str = Field(pattern=SHA256)
    status: Literal["selected"]
    additional_registration: AdditionalDevelopmentRegistration
    additional_registration_sha256: str = Field(pattern=SHA256)
    source: EPlanningSource
    result_artifact_sha256: str = Field(pattern=SHA256)

    @model_validator(mode="after")
    def same_registered_analysis(self) -> Self:
        registration, source = self.additional_registration, self.source
        request = registration.request
        expected = {
            "source_kind": "additional-development-v1",
            "source_registration_sha256": canonical_hash(registration),
            "source_row_id": request.slot_id,
            "order_index": 0,
            "case_id": request.case_id,
            "dataset": request.case_id.split("-", 1)[0],
            "agent_sha256": request.agent_sha256,
            "request_sha256": registration.request_sha256,
            "manifest_sha256": source.source_package_manifest_sha256,
        }
        if (
            self.rule_sha256 != canonical_hash(RULE)
            or self.additional_registration_sha256 != canonical_hash(registration)
            or any(getattr(source, key) != value for key, value in expected.items())
        ):
            raise ValueError(
                "additional selection differs from its registered analysis"
            )
        return self


def validate_additional_source_selection(value) -> dict:
    return AdditionalSourceSelection.model_validate(value).model_dump(mode="json")


def build_additional_source_selection(registration, imported: ImportedAnalysis) -> dict:
    """Derive from a typed, revalidated package; no caller-authored analysis values."""
    if not isinstance(imported, ImportedAnalysis):
        raise TypeError("additional selection requires verified ImportedAnalysis")
    registration = AdditionalDevelopmentRegistration.model_validate(registration)
    imported.revalidate()
    provenance = imported.provenance
    request = registration.request
    expected = {
        "source_kind": "additional-development-v1",
        "source_registration_sha256": canonical_hash(registration),
        "source_package_schema_version": "task13-additional-analysis-package-v1",
        "source_core_sha256": registration.core_sha256,
        "source_epoch_id": registration.epoch_id,
        "source_epoch_manifest_sha256": registration.epoch_manifest_sha256,
        "source_model_identity_binding": registration.model_identity_binding.model_dump(
            mode="json"
        ),
        "source_synthetic": registration.synthetic,
        "source_commit": request.source_commit,
        "source_sha256": request.source_sha256,
    }
    if any(provenance.get(key) != value for key, value in expected.items()):
        raise ValueError(
            "verified additional source registration/core/epoch/model differs"
        )
    source = {
        key: provenance.get(key)
        for key in EPlanningSource.model_fields
        if key != "source_identity"
    }
    source["source_identity"] = imported.source_identity
    try:
        result_sha256 = provenance["artifacts"]["result"]["sha256"]
    except (KeyError, TypeError) as error:
        raise ValueError("verified result artifact digest is missing") from error
    return validate_additional_source_selection(
        {
            "schema_version": "task13-additional-analysis-source-selection-v1",
            "rule": RULE,
            "rule_sha256": canonical_hash(RULE),
            "status": "selected",
            "additional_registration": registration.model_dump(mode="json"),
            "additional_registration_sha256": canonical_hash(registration),
            "source": source,
            "result_artifact_sha256": result_sha256,
        }
    )
