"""Pure E2 preregistration construction; no registration, dispatch or consent."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Literal, Self

from pydantic import Field, model_validator

from evals.adapters.e_participation import EParticipationPolicy
from evals.adapters.e_planning_contracts import (
    HEX32,
    EPlanningRequest,
    EPlanningSource,
    ESelectedSourceLineage,
    ModelIdentityBinding,
    OriginalBudgetIdentity,
    build_selected_source_lineage,
    slot_identity,
)
from evals.adapters.remediation_contracts import CAMPAIGN
from evals.contracts import SHA256, Contract, ModelConfig, canonical_hash

SOURCE_KEYS = (
    "source_row_id",
    "order_index",
    "case_id",
    "dataset",
    "agent_sha256",
    "request_sha256",
    "manifest_sha256",
    "analysis_output_sha256",
    "imported_values_sha256",
)
BRANCH_ORDER = [
    (condition, enabled)
    for condition in ("success", "failure", "no_change")
    for enabled in (True, False)
]


class EpochBinding(Contract):
    epoch_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,120}$")
    epoch_manifest_sha256: str = Field(pattern=SHA256)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=SHA256)
    budget_identity: OriginalBudgetIdentity
    model_identity_binding: ModelIdentityBinding | None = Field(
        default=None, exclude_if=lambda value: value is None
    )


def _selected_source(selection, mode="same-source-replicates-v1"):
    if mode == "additional-development-replicates-v1":
        from evals.additional_source_selection import (
            validate_additional_source_selection,
        )

        selection = validate_additional_source_selection(selection)
        return selection["source"], 1
    if mode != "same-source-replicates-v1":
        raise ValueError("unknown planning source mode")
    if not isinstance(selection, dict):
        raise ValueError("original source selection receipt is required")  # noqa: TRY004 - invalid external receipt.
    rule = "first-three-qualified-original-36-v1"
    if (
        selection.get("schema_version") != "task13-analysis-source-selection-v1"
        or selection.get("rule") != rule
        or selection.get("rule_sha256") != canonical_hash(rule)
        or selection.get("status") != "insufficient_qualified_sources"
        or re.fullmatch(SHA256, selection.get("original_bundle_sha256", "")) is None
    ):
        raise ValueError("preserved insufficient first-three selection is required")
    rows, selected = selection.get("rows", []), selection.get("selected_sources", [])
    if (
        not isinstance(rows, list)
        or not isinstance(selected, list)
        or any(not isinstance(r, dict) for r in rows + selected)
        or len(rows) != 36
        or [r.get("order_index") for r in rows] != list(range(36))
        or len({r.get("source_row_id") for r in rows}) != 36
        or any(
            r.get("source_status") not in {"completed", "failed", "unknown"}
            or r.get("status") not in {"selected", "rejected"}
            for r in rows
        )
    ):
        raise ValueError("all original 36 ordered terminal rows are required")
    qualified = [r for r in rows if r["status"] == "selected"]
    if not 1 <= len(qualified) <= 2 or len(selected) != len(qualified):
        raise ValueError("same-source mode requires one or two qualified sources")
    try:
        if [{key: r[key] for key in SOURCE_KEYS} for r in qualified] != [
            {key: r[key] for key in SOURCE_KEYS} for r in selected
        ] or any(r["source_status"] != "completed" for r in qualified):
            raise ValueError("selected source differs from original qualified rows")
        first = {key: selected[0][key] for key in SOURCE_KEYS}
    except (KeyError, TypeError) as error:
        raise ValueError("complete original analysis lineage is required") from error
    return first, len(qualified)


def _slots(registration_id, case_id):
    slots = []
    for ordinal in (1, 2, 3):
        identity = slot_identity(registration_id, ordinal, case_id)
        branches = [
            {
                "condition": condition,
                "verification_enabled": enabled,
                "request_id": canonical_hash(
                    [registration_id, ordinal, "branch-request", number]
                )[:32],
                "namespace": canonical_hash(
                    [registration_id, ordinal, "branch-namespace", number]
                )[:32],
            }
            for number, (condition, enabled) in enumerate(BRANCH_ORDER, 1)
        ]
        slots.append({"ordinal": ordinal, **identity, "branches": branches})
    return slots


class EPlanningRegistration(Contract):
    schema_version: Literal["task13-e-planning-registration-v1"]
    campaign_id: Literal["task13-repair-202610-v2"]
    registration_id: str = Field(pattern=HEX32)
    synthetic: bool = Field(strict=True)
    mode: Literal["same-source-replicates-v1", "additional-development-replicates-v1"]
    source_selection_receipt: dict
    source_selection_receipt_sha256: str = Field(pattern=SHA256)
    source: EPlanningSource
    selected_source_lineage: ESelectedSourceLineage
    selected_source_lineage_sha256: str = Field(pattern=SHA256)
    qualified_source_count: int = Field(ge=1, le=2, strict=True)
    distinct_source_count: Literal[1]
    distinct_case_count: Literal[1]
    replicate_count: Literal[3]
    f8_approval_credit: Literal[0]
    approval_policy: Literal["three-independent-new-plans-and-user-decisions-v1"]
    epoch_binding: EpochBinding
    budget_source_receipt_sha256: str = Field(pattern=SHA256)
    core_config: dict
    core_config_sha256: str = Field(pattern=SHA256)
    recovery_lineage: dict | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    slots: list[dict] = Field(min_length=3, max_length=3)

    @model_validator(mode="after")
    def fixed_registration(self) -> Self:
        if "participation_policy" in self.core_config:
            EParticipationPolicy.model_validate(
                self.core_config["participation_policy"]
            )
        descriptor = self.core_config.get("model_identity")
        reference = self.epoch_binding.model_identity_binding
        if (descriptor is None) != (reference is None):
            raise ValueError(
                "model identity descriptor and reference must both be present"
            )
        if reference is not None and (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"id", "response_model", "fingerprint"}
            or any(not isinstance(v, str) or not v.strip() for v in descriptor.values())
            or descriptor["id"] != reference.model_epoch_id
        ):
            raise ValueError("model identity descriptor differs from reference")
        first, count = _selected_source(self.source_selection_receipt, self.mode)
        if (self.mode == "additional-development-replicates-v1") != (
            self.source.source_kind == "additional-development-v1"
        ):
            raise ValueError("planning mode differs from selected source kind")
        if self.recovery_lineage is not None:
            from evals.adapters.planning_recovery import (
                validate_recovery_execution,
                validate_recovery_original,
            )

            if self.mode != "additional-development-replicates-v1":
                raise ValueError("explicit recovery requires additional analysis")
            validate_recovery_original(
                self.recovery_lineage,
                self.source_selection_receipt["additional_registration"],
                self.source.source_package_manifest_sha256,
                self.source.request_sha256,
            )
            validate_recovery_execution(
                self.recovery_lineage,
                self.epoch_binding.model_dump(mode="json"),
                self.core_config_sha256,
            )
            if self.synthetic is not self.recovery_lineage["synthetic"]:
                raise ValueError("recovery synthetic flag differs")
        elif self.mode == "additional-development-replicates-v1":
            additional = self.source_selection_receipt["additional_registration"]
            original = additional["request"]
            if (
                self.synthetic is not additional["synthetic"]
                or self.core_config_sha256 != additional["core_sha256"]
                or any(
                    self.epoch_binding.model_dump(mode="json").get(key) != original[key]
                    for key in (
                        "epoch_id",
                        "epoch_manifest_sha256",
                        "source_commit",
                        "source_sha256",
                        "budget_identity",
                        "model_identity_binding",
                    )
                )
            ):
                raise ValueError(
                    "planning additional analysis epoch/core/model/synthetic differs"
                )
        if (
            canonical_hash(self.source_selection_receipt)
            != self.source_selection_receipt_sha256
            or count != self.qualified_source_count
            or any(getattr(self.source, key) != value for key, value in first.items())
            or canonical_hash(self.core_config) != self.core_config_sha256
            or self.core_config.get("model") != ModelConfig().model_dump(mode="json")
            or self.slots != _slots(self.registration_id, self.source.case_id)
        ):
            raise ValueError("frozen source/selection/core config/slots differ")
        if (
            self.selected_source_lineage
            != build_selected_source_lineage(
                self.source, canonical_hash(self.source_selection_receipt)
            )
            or canonical_hash(self.selected_source_lineage)
            != self.selected_source_lineage_sha256
        ):
            raise ValueError("selected source lineage differs from original selection")
        if self.budget_source_receipt_sha256 != self.epoch_binding.source_sha256:
            raise ValueError(
                "budget source receipt differs from epoch execution source"
            )
        return self


def build_e_planning_registration(
    selection_receipt,
    *,
    registration_id,
    source_package_manifest_sha256,
    epoch_binding,
    budget_source_receipt_sha256,
    core_config,
    synthetic,
    mode="same-source-replicates-v1",
    recovery_lineage=None,
) -> dict:
    """Build a proposal, preserving shortage; this does not approve/register it."""
    first, count = _selected_source(selection_receipt, mode)
    if mode == "additional-development-replicates-v1" and (
        first["source_package_manifest_sha256"] != source_package_manifest_sha256
    ):
        raise ValueError("additional selected package manifest pin differs")
    source = {
        **first,
        "source_identity": canonical_hash(
            [first["case_id"], first["source_row_id"], first["request_sha256"]]
        ),
        "source_package_manifest_sha256": source_package_manifest_sha256,
    }
    lineage = build_selected_source_lineage(
        EPlanningSource.model_validate(source), canonical_hash(selection_receipt)
    ).model_dump(mode="json")
    value = {
        "schema_version": "task13-e-planning-registration-v1",
        "campaign_id": CAMPAIGN,
        "registration_id": registration_id,
        "synthetic": synthetic,
        "mode": mode,
        "source_selection_receipt": deepcopy(selection_receipt),
        "source_selection_receipt_sha256": canonical_hash(selection_receipt),
        "source": source,
        "selected_source_lineage": lineage,
        "selected_source_lineage_sha256": canonical_hash(lineage),
        "qualified_source_count": count,
        "distinct_source_count": 1,
        "distinct_case_count": 1,
        "replicate_count": 3,
        "f8_approval_credit": 0,
        "approval_policy": "three-independent-new-plans-and-user-decisions-v1",
        "epoch_binding": deepcopy(epoch_binding),
        "budget_source_receipt_sha256": budget_source_receipt_sha256,
        "core_config": deepcopy(core_config),
        "core_config_sha256": canonical_hash(core_config),
        "slots": _slots(registration_id, first["case_id"]),
        **(
            {"recovery_lineage": deepcopy(recovery_lineage)}
            if recovery_lineage is not None
            else {}
        ),
    }
    return EPlanningRegistration.model_validate(value).model_dump(mode="json")


def validate_e_planning_registration(registration: dict) -> dict:
    """Return a detached validated value; never upgrade a v1 selection's status."""
    return EPlanningRegistration.model_validate(registration).model_dump(mode="json")


def planning_requests(registration: dict) -> tuple[EPlanningRequest, ...]:
    r = validate_e_planning_registration(registration)
    source = r["source"]
    requests = []
    for slot in r["slots"]:
        request = {
            **{key: value for key, value in slot.items() if key != "branches"},
            **r["epoch_binding"],
            "registration_id": r["registration_id"],
            "mode": r["mode"],
            "registration_sha256": canonical_hash(r),
            "source": source,
            **{
                key: source[key]
                for key in (
                    "case_id",
                    "dataset",
                    "agent_sha256",
                    "source_identity",
                    "source_row_id",
                    "analysis_output_sha256",
                    "imported_values_sha256",
                    "source_package_manifest_sha256",
                )
            },
            "original_request_sha256": source["request_sha256"],
            "original_manifest_sha256": source["manifest_sha256"],
            "source_selection_receipt_sha256": r["source_selection_receipt_sha256"],
            "selected_source_lineage": r["selected_source_lineage"],
            "selected_source_lineage_sha256": r["selected_source_lineage_sha256"],
            "budget_source_receipt_sha256": r["budget_source_receipt_sha256"],
            "config_sha256": r["core_config_sha256"],
            "core_config_sha256": r["core_config_sha256"],
            "model": r["core_config"]["model"],
            **(
                {"participation_policy": r["core_config"]["participation_policy"]}
                if "participation_policy" in r["core_config"]
                else {}
            ),
            **(
                {"recovery_lineage": r["recovery_lineage"]}
                if r.get("recovery_lineage") is not None
                else {}
            ),
        }
        requests.append(EPlanningRequest.model_validate(request))
    return tuple(requests)
