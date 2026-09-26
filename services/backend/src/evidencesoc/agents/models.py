from __future__ import annotations

import re
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from evidencesoc.domain.event_search_policy import (
    ALLOWED_EVENT_FILTERS,
    MAX_EVENT_RESULTS,
    validate_event_search,
)
from evidencesoc.domain.models import AttackClassification, AttackOrigin, ResponsePlan

SIMULATED_ACTIONS = frozenset(
    {"block_ip_simulated", "isolate_host_simulated", "disable_account_simulated"}
)


class SimulatedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal[
        "block_ip_simulated", "isolate_host_simulated", "disable_account_simulated"
    ]
    target: str = Field(min_length=1, max_length=255)
    risk: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    preview: str = Field(min_length=1)
    rollback: str = Field(min_length=1)
    verification_query: dict[str, Any]

    @field_validator("target", "risk", "impact", "preview", "rollback")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("action details must not be blank")
        return value.strip()

    @model_validator(mode="after")
    def bounded_action(self) -> Self:
        if self.action == "block_ip_simulated":
            ip_address(self.target)
        elif re.fullmatch(r"[A-Za-z0-9_.@:-]+", self.target) is None:
            raise ValueError("target must be a host or account identifier")
        query = self.verification_query
        if set(query) - {"filters", "time_from", "time_to", "limit"}:
            raise ValueError("verification must use bounded read-only event search")
        filters = query.get("filters")
        if not isinstance(filters, dict) or not filters:
            raise ValueError("verification filters are required")
        if any(
            key not in ALLOWED_EVENT_FILTERS
            or not isinstance(value, str)
            or not value.strip()
            for key, value in filters.items()
        ):
            raise ValueError("verification filter is not allowed")
        target_filter = {
            "block_ip_simulated": "source_ip",
            "isolate_host_simulated": "host",
        }.get(self.action)
        if target_filter is not None and filters.get(target_filter) != self.target:
            raise ValueError("verification query must refer to the simulated target")
        limit = query.get("limit", 100)
        if type(limit) is not int or not 1 <= limit <= MAX_EVENT_RESULTS:
            raise ValueError("verification result limit is invalid")
        if ("time_from" in query) != ("time_to" in query):
            raise ValueError("verification requires both time boundaries")
        if "time_from" in query:
            start = datetime.fromisoformat(query["time_from"])
            end = datetime.fromisoformat(query["time_to"])
            validate_event_search(start, end, filters, limit)
        return self


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
            for action in self.response_plan.actions:
                SimulatedAction.model_validate(action)
        return self
