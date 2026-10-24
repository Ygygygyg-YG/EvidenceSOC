"""The approved, simulation-only response action contract."""

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

SIMULATED_ACTIONS = frozenset(
    {"block_ip_simulated", "isolate_host_simulated", "disable_account_simulated"}
)


def canonical_host_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 255
        and re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*",
            value,
        )
        is not None
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
    # Older persisted plans have only the original action fields. New workflow
    # output must fill all of these before a plan can be approved.
    action_id: str | None = Field(default=None, pattern=r"^ACT-[A-Za-z0-9-]{1,60}$")
    type: (
        Literal[
            "block_ip_simulated", "isolate_host_simulated", "disable_account_simulated"
        ]
        | None
    ) = None
    parameters: dict[str, str] | None = None
    expected_effect: str | None = None
    rollback_ref: str | None = None
    evidence_ids: list[str] | None = None

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
        elif self.action == "isolate_host_simulated":
            if not canonical_host_identifier(self.target):
                raise ValueError("target must be a canonical host identifier")
        elif (
            re.fullmatch(
                r"[A-Za-z][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z0-9_-]+)*", self.target
            )
            is None
        ):
            raise ValueError("target must be a conservative account identifier")
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
            "disable_account_simulated": "account",
        }.get(self.action)
        if target_filter not in ALLOWED_EVENT_FILTERS:
            raise ValueError(
                "account verification is unavailable under the event search policy"
            )
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
        if self.type is not None and self.type != self.action:
            raise ValueError("action type must match the simulated allowlist action")
        if self.parameters is not None:
            key = {
                "block_ip_simulated": "source_ip",
                "isolate_host_simulated": "host",
                "disable_account_simulated": "account",
            }[self.action]
            if self.parameters != {key: self.target}:
                raise ValueError("action parameters must refer only to its target")
        if self.expected_effect is not None and not self.expected_effect.strip():
            raise ValueError("expected effect must not be blank")
        if self.rollback_ref is not None and not self.rollback_ref.strip():
            raise ValueError("rollback reference must not be blank")
        if self.evidence_ids is not None and (
            not self.evidence_ids
            or any(not isinstance(item, str) or not item for item in self.evidence_ids)
        ):
            raise ValueError("action evidence citations are required")
        return self

    @property
    def traceable(self) -> bool:
        return all(
            value is not None
            for value in (
                self.action_id,
                self.type,
                self.parameters,
                self.expected_effect,
                self.rollback_ref,
                self.evidence_ids,
            )
        )


class SimulationActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=1)
    outcome: Literal["success", "failure", "skipped"]
    description: str = Field(min_length=1)
    started_at: datetime
    finished_at: datetime

    @model_validator(mode="after")
    def valid_time_order(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("simulation action finished before it started")
        return self


class SimulationExecution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    simulation_id: str = Field(min_length=1)
    response_plan_id: str = Field(min_length=1)
    plan_version: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["pending", "running", "completed", "failed"]
    started_at: datetime | None
    finished_at: datetime | None
    action_results: list[SimulationActionResult]
    error: str | None

    @model_validator(mode="after")
    def valid_progress(self) -> Self:
        if self.started_at is None and self.status != "pending":
            raise ValueError("started_at is required once simulation starts")
        if self.status in {"completed", "failed"} and self.finished_at is None:
            raise ValueError("finished_at is required once simulation ends")
        if self.status in {"pending", "running"} and self.finished_at is not None:
            raise ValueError("unfinished simulation cannot have finished_at")
        if self.status == "pending" and (
            self.started_at is not None or self.action_results
        ):
            raise ValueError("pending simulation cannot contain executed actions")
        if self.status == "completed" and not self.action_results:
            raise ValueError("completed simulation requires action results")
        if (
            self.started_at is not None
            and self.finished_at is not None
            and self.finished_at < self.started_at
        ):
            raise ValueError("simulation finished before it started")
        if len({item.action_id for item in self.action_results}) != len(
            self.action_results
        ):
            raise ValueError("simulation action results must be unique")
        return self
