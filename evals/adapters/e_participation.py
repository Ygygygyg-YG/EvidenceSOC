"""Explicit successor participation policy; absent policy preserves old limits."""

from datetime import UTC, datetime, timedelta, timezone
from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from evals.contracts import SHA256, Contract


class EParticipationPolicy(Contract):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["task13-e-participation-policy-v1"]
    dispatch_window: Literal["anytime"]
    user_presence_required: bool = Field(strict=True)
    plan_approval: Literal["individual-user-decision-v1"]
    authorization_record_sha256: str = Field(pattern=SHA256)

    @model_validator(mode="after")
    def no_presence_requirement(self) -> Self:
        if self.user_presence_required is not False:
            raise ValueError("anytime policy must explicitly remove user presence")
        return self


def require_participation_window(now=None, participation_policy=None):
    """Admit the registered window only; this never records a plan decision."""
    current = now or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise PermissionError("review requires an actual zoned timestamp")
    if participation_policy is not None:
        EParticipationPolicy.model_validate(participation_policy)
    elif current.astimezone(timezone(timedelta(hours=8))).hour < 19:
        raise PermissionError("review window is 19:00-00:00 Asia/Shanghai")
