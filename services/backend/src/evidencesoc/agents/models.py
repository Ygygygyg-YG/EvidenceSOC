from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidencesoc.domain.models import (
    AttackClassification,
    AttackOrigin,
    PlanRollbackStep,
    PlanValidationCheck,
    ResponsePlan,
)
from evidencesoc.domain.response_action import SimulatedAction


class AttackStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_step_id: str = Field(min_length=1, max_length=64)
    sequence: int = Field(ge=1)
    phase: str | None = Field(max_length=64)
    technique_id: str | None = Field(default=None, pattern=r"^T\d{4}(?:\.\d{3})?$")
    description: str = Field(min_length=1)
    occurred_at: datetime | None
    evidence_ids: list[str] = Field(min_length=1)


class AnalysisOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    origin: AttackOrigin | None
    classification: AttackClassification | None

    @model_validator(mode="after")
    def no_evaluation_labels(self) -> Self:
        if self.classification is not None and self.classification.dataset_labels:
            raise ValueError("evaluation labels are unavailable to the investigation")
        return self


class ReconstructionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attack_steps: list[AttackStep]

    @model_validator(mode="after")
    def ordered_unique_steps(self) -> Self:
        sequences = [step.sequence for step in self.attack_steps]
        if sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("attack step sequences must be contiguous and increasing")
        if len({step.attack_step_id for step in self.attack_steps}) != len(
            self.attack_steps
        ):
            raise ValueError("attack step identifiers must be unique")
        return self


class ResponseOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    response_plan: ResponsePlan | None

    @model_validator(mode="after")
    def simulated_actions_only(self) -> Self:
        if self.response_plan is not None:
            plan = self.response_plan
            actions = [SimulatedAction.model_validate(item) for item in plan.actions]
            now = datetime.now(UTC)
            targets = {action.target for action in actions}
            if (
                plan.risk_level is None
                or not plan.risk_reason
                or not plan.risk_reason.strip()
                or not plan.business_impact
                or not plan.business_impact.strip()
                or plan.expires_at is None
                or plan.expires_at <= now
                or plan.created_at < now - timedelta(minutes=5)
                or plan.created_at > now + timedelta(minutes=1)
                or plan.expires_at > plan.created_at + timedelta(minutes=30)
                or not plan.rollback_steps
                or not plan.validation_checks
                or set(plan.affected_assets) != targets
                or {step.target for step in plan.rollback_steps} != targets
                or {check.target for check in plan.validation_checks} != targets
            ):
                raise ValueError("response plan review details must be complete")
            citations = set(plan.evidence_ids)
            action_ids = [action.action_id for action in actions]
            if any(not action.traceable for action in actions) or len(
                set(action_ids)
            ) != len(action_ids):
                raise ValueError(
                    "response actions require unique traceable identifiers"
                )
            rollbacks = {step.step_id: step for step in plan.rollback_steps}
            for action in actions:
                if (
                    not set(action.evidence_ids or []) <= citations
                    or action.rollback_ref not in rollbacks
                    or rollbacks[action.rollback_ref].target != action.target
                ):
                    raise ValueError("response action must cite its plan and rollback")
            review_steps: list[PlanRollbackStep | PlanValidationCheck] = [
                *plan.rollback_steps,
                *plan.validation_checks,
            ]
            for step in review_steps:
                if (
                    step.target not in targets
                    or not set(step.evidence_ids) <= citations
                ):
                    raise ValueError("response plan step must cite a planned target")
            for check in plan.validation_checks:
                if not any(
                    check.target == action.target
                    and check.query == action.verification_query
                    for action in actions
                ):
                    raise ValueError("validation check must use the approved query")
        return self
