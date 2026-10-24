"""Bound supplement review/renewal; delegates actual decisions to the product."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from evals.adapters.artifacts import write_immutable_json
from evals.adapters.budget_v2 import PURPOSE_PHASES, SupplementBudgetAccount
from evals.adapters.model_client import TrackedModel
from evals.adapters.remediation_contracts import CAMPAIGN
from evals.adapters.remediation_worker import (
    PayloadRecorder,
    StableCallModel,
    require_existing_budget,
    validate_exported_source,
)
from evals.adapters.verification_worker import SourceReviewRequest, run_source_review
from evals.contracts import SHA256, canonical_hash


class RemediationReviewRequest(SourceReviewRequest):
    """A registered review operation is not an approval or a renewal authorization."""

    schema_version: Literal["task13-remediation-review-worker-v2"] = (
        "task13-remediation-review-worker-v2"
    )
    campaign_id: Literal["task13-repair-202610-v2"] = CAMPAIGN
    run_id: str
    case_id: str = Field(pattern=r"^(?:ait-[0-9a-f]{24}|dedale-[0-9a-f]{16})$")
    group: Literal["B3"] = "B3"
    slot_id: str = Field(pattern=r"^(?:f8|development)-review-[0-9a-f]{24}$")
    attempt: int = Field(ge=1, strict=True)
    purpose: Literal["f8", "development"]
    source_sha256: str = Field(pattern=SHA256)
    config_sha256: str = Field(pattern=SHA256)
    budget_identity: dict

    @model_validator(mode="after")
    def stable_bound_operation(self) -> Self:
        if self.run_id != CAMPAIGN + "-" + canonical_hash([self.slot_id, self.attempt])[
            :16
        ] or not self.slot_id.startswith(self.purpose + "-review-"):
            raise ValueError("review identity differs from its registered slot/attempt")
        identity = self.budget_identity
        if (
            set(identity)
            != {
                "schema_version",
                "baseline_count",
                "baseline_max_rowid",
                "baseline_sha256",
            }
            or identity.get("schema_version") != "task13-original-budget-identity-v1"
            or type(identity.get("baseline_count")) is not int
            or type(identity.get("baseline_max_rowid")) is not int
            or not 0 < identity["baseline_count"] <= identity["baseline_max_rowid"]
            or not isinstance(identity.get("baseline_sha256"), str)
            or re.fullmatch(SHA256, identity["baseline_sha256"]) is None
        ):
            raise ValueError("frozen original budget identity is required")
        return self

    def source_review_request(self) -> SourceReviewRequest:
        values = self.model_dump(mode="json")
        return SourceReviewRequest(
            **{
                key: values[key]
                for key in SourceReviewRequest.model_fields
                if key != "schema_version"
            }
        )

    def budget_binding(self) -> dict:
        return {
            key: getattr(self, key)
            for key in (
                "campaign_id",
                "case_id",
                "group",
                "attempt",
                "purpose",
                "source_sha256",
                "config_sha256",
            )
        }


def validate_review_binding(
    request: RemediationReviewRequest, agent_dir: Path, source: Path
) -> None:
    """Verify mounted frozen bytes before opening any retained product workflow."""
    request = RemediationReviewRequest.model_validate(request.model_dump(mode="json"))
    source = Path(source)
    if (
        source.is_symlink()
        or source.is_junction()
        or (source / "source_receipt.json").is_symlink()
    ):
        raise ValueError("review source contains a filesystem link")
    validate_exported_source(request, agent_dir, source)


def make_review_model(
    request: RemediationReviewRequest,
    budget_path: Path,
    *,
    transport=None,
    payload_sink=None,
) -> StableCallModel:
    request = RemediationReviewRequest.model_validate(request.model_dump(mode="json"))
    if request.operation != "renew_plan":
        raise PermissionError("read/decision operations must not construct a model")
    require_existing_budget(budget_path, request.budget_identity)
    account = SupplementBudgetAccount(budget_path, **request.budget_binding())
    tracked = TrackedModel(
        request.model,
        api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
        account=account,
        phase=PURPOSE_PHASES[request.purpose],
        max_calls=3,
        max_logical_calls=1,
        transport=transport,
        payload_sink=payload_sink,
    )
    return StableCallModel(tracked, request.slot_id, request.run_id)


async def run_remediation_review(
    request: RemediationReviewRequest, agent_dir: Path
) -> dict:
    if (
        os.getpid() != 1
        or not os.environ.get("TASK13_WORKER_NONCE")
        or os.environ.get("TASK13_PHASE") != "verification"
    ):
        raise PermissionError(
            "supplement review requires its inspected verification worker"
        )
    request = RemediationReviewRequest.model_validate(request.model_dump(mode="json"))
    validate_review_binding(request, agent_dir, Path(os.environ["TASK13_SOURCE_DIR"]))
    budget_path = Path(os.environ["TASK13_BUDGET_DB"])
    require_existing_budget(budget_path, request.budget_identity)
    recorder = PayloadRecorder(Path(os.environ["TASK13_OUTPUT_DIR"]))
    original = request.source_review_request()

    def factory(original_request):
        if original_request != original:
            raise ValueError("original review operation differs from the bound request")
        return make_review_model(request, budget_path, payload_sink=recorder)

    result = await run_source_review(original, agent_dir, model_factory=factory)
    if request.operation == "renew_plan":
        write_immutable_json(
            Path(os.environ["TASK13_OUTPUT_DIR"]) / "review-payloads.json",
            recorder.records,
        )
    return {
        **result,
        "source_review_input_sha256": result.get("input_sha256"),
        "input_sha256": canonical_hash(request),
        "campaign_id": request.campaign_id,
        "run_id": request.run_id,
        "slot_id": request.slot_id,
        "attempt": request.attempt,
        "purpose": request.purpose,
        "source_sha256": request.source_sha256,
        "config_sha256": request.config_sha256,
        "budget_identity": request.budget_identity,
        "payloads": recorder.records,
    }
