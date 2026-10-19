"""Deterministic simulation-effect rules over typed, separately cited observations."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    field_validator,
)


class EffectObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    target: str = Field(min_length=1)
    observed_at: datetime
    evidence_ids: list[str] = Field(default_factory=list)
    network_blocked: StrictBool | None = None
    host_isolated: StrictBool | None = None
    account_enabled: StrictBool | None = None
    error_code: str | None = None

    @field_validator("observed_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("effect observations require timezone-aware times")
        return value


def evaluate_simulated_effect(
    action_type: str,
    before: EffectObservation | dict | None,
    after: EffectObservation | dict | None,
) -> Literal["success", "failure", "insufficient_evidence"]:
    try:
        earlier = EffectObservation.model_validate(before)
        later = EffectObservation.model_validate(after)
    except (ValidationError, TypeError, ValueError):
        return "insufficient_evidence"
    if (
        (earlier.namespace, earlier.action_id, earlier.target)
        != (later.namespace, later.action_id, later.target)
        or later.observed_at <= earlier.observed_at
        or not earlier.evidence_ids
        or not later.evidence_ids
    ):
        return "insufficient_evidence"
    if later.error_code:
        return "failure"
    fields = {
        "block_ip_simulated": ("network_blocked", False, True),
        "isolate_host_simulated": ("host_isolated", False, True),
        "disable_account_simulated": ("account_enabled", True, False),
    }
    if action_type not in fields:
        return "insufficient_evidence"
    name, initial, expected = fields[action_type]
    return (
        "success"
        if getattr(earlier, name) is initial and getattr(later, name) is expected
        else "insufficient_evidence"
    )
