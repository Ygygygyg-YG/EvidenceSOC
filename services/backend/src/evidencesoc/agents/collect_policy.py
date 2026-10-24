"""Validate model proposed collection calls against the current incident."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidencesoc.tools.policy import (
    PolicyDeniedError,
    validate_alert_context,
    validate_attack_lookup,
    validate_event_search,
    validate_tool_name,
)

SEARCH_ARGUMENTS = ("time_from", "time_to", "filters", "limit")


class CollectionPolicyDenied(PolicyDeniedError):
    """A stable denial code without exposing argument values or raw exceptions."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CollectionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["call", "stop"]
    tool_name: str | None = Field(default=None, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def valid_action(self) -> CollectionDecision:
        if self.action == "call" and not self.tool_name:
            raise ValueError("call must name a tool")
        if self.action == "stop" and (self.tool_name or self.arguments):
            raise ValueError("stop must not include a tool call")
        try:
            json.dumps(self.arguments, ensure_ascii=False, allow_nan=False).encode(
                "utf-8"
            )
            if self.tool_name is not None:
                self.tool_name.encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError("tool decision must contain valid JSON values") from exc
        return self


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise CollectionPolicyDenied(
            "POLICY_ARGUMENTS_INVALID", "time bound must be a string"
        )
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise CollectionPolicyDenied(
            "POLICY_ARGUMENTS_INVALID", "invalid time bound"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CollectionPolicyDenied(
            "POLICY_ARGUMENTS_INVALID", "time bound must have a timezone"
        )
    return parsed.astimezone(UTC)


def _integer(value: object, name: str) -> int:
    if type(value) is not int:
        raise CollectionPolicyDenied(
            "POLICY_ARGUMENTS_INVALID", f"{name} must be an integer"
        )
    return value


def validate_collection_call(
    tool_name: str, arguments: dict[str, Any], scope: dict[str, Any]
) -> dict[str, Any]:
    """Return canonical arguments, rejecting cross incident or broader queries."""
    try:
        validate_tool_name(tool_name)
    except PolicyDeniedError as exc:
        raise CollectionPolicyDenied(
            "POLICY_TOOL_DENIED", "tool is not allowed"
        ) from exc
    if not isinstance(arguments, dict):
        raise CollectionPolicyDenied(
            "POLICY_ARGUMENTS_INVALID", "arguments must be an object"
        )
    if tool_name == "get_alert_context":
        if set(arguments) - {"alert_id", "before_seconds", "after_seconds"}:
            raise CollectionPolicyDenied(
                "POLICY_ARGUMENTS_INVALID", "unexpected alert context argument"
            )
        alert_id = arguments.get("alert_id")
        if alert_id != scope["alert_id"]:
            raise CollectionPolicyDenied(
                "POLICY_INCIDENT_DENIED", "alert belongs to another incident"
            )
        before = _integer(arguments.get("before_seconds", 900), "before_seconds")
        after = _integer(arguments.get("after_seconds", 900), "after_seconds")
        try:
            validate_alert_context(alert_id, before, after)
        except PolicyDeniedError as exc:
            raise CollectionPolicyDenied("POLICY_LIMIT_DENIED", str(exc)) from exc
        return {"alert_id": alert_id, "before_seconds": before, "after_seconds": after}

    if tool_name == "lookup_attack_technique":
        if set(arguments) - {"query", "limit"}:
            raise CollectionPolicyDenied(
                "POLICY_ARGUMENTS_INVALID", "unexpected knowledge lookup argument"
            )
        query = arguments.get("query")
        limit = _integer(arguments.get("limit", 10), "limit")
        if not isinstance(query, str):
            raise CollectionPolicyDenied(
                "POLICY_ARGUMENTS_INVALID", "query must be a string"
            )
        query = " ".join(query.split())
        if not query:
            raise CollectionPolicyDenied(
                "POLICY_ARGUMENTS_INVALID", "query must not be blank"
            )
        try:
            validate_attack_lookup(query, limit)
        except PolicyDeniedError as exc:
            raise CollectionPolicyDenied("POLICY_LIMIT_DENIED", str(exc)) from exc
        return {"query": query, "limit": limit}

    if set(arguments) != set(SEARCH_ARGUMENTS):
        raise CollectionPolicyDenied(
            "POLICY_ARGUMENTS_INVALID", "event search requires scoped arguments"
        )
    start = _timestamp(arguments["time_from"])
    end = _timestamp(arguments["time_to"])
    lower = _timestamp(scope["time_from"])
    upper = _timestamp(scope["time_to"])
    if start < lower or end > upper:
        raise CollectionPolicyDenied(
            "POLICY_TIME_SCOPE_DENIED", "event search exceeds incident time window"
        )
    filters = arguments["filters"]
    if not isinstance(filters, dict):
        raise CollectionPolicyDenied(
            "POLICY_ARGUMENTS_INVALID", "filters must be an object"
        )
    if "dataset_id" in filters and "dataset_id" not in scope["filters"]:
        raise CollectionPolicyDenied(
            "POLICY_TARGET_SCOPE_DENIED", "dataset filter is not anchored to incident"
        )
    if not scope["filters"]:
        raise CollectionPolicyDenied(
            "POLICY_TARGET_SCOPE_DENIED", "incident has no safe event search anchor"
        )
    if any(filters.get(key) != value for key, value in scope["filters"].items()):
        raise CollectionPolicyDenied(
            "POLICY_TARGET_SCOPE_DENIED", "event search must retain incident filters"
        )
    limit = _integer(arguments["limit"], "limit")
    if not 1 <= limit <= scope["limit"]:
        raise CollectionPolicyDenied(
            "POLICY_LIMIT_DENIED", "event search limit exceeds incident scope"
        )
    try:
        validate_event_search(start, end, filters, limit)
    except PolicyDeniedError as exc:
        raise CollectionPolicyDenied("POLICY_ARGUMENTS_INVALID", str(exc)) from exc
    return {
        "time_from": start.isoformat(),
        "time_to": end.isoformat(),
        "filters": dict(sorted(filters.items())),
        "limit": limit,
    }
