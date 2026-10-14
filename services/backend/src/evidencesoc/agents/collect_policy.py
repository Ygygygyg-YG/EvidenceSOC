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
        raise PolicyDeniedError("time bound must be a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PolicyDeniedError("invalid time bound") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PolicyDeniedError("time bound must have a timezone")
    return parsed.astimezone(UTC)


def _integer(value: object, name: str) -> int:
    if type(value) is not int:
        raise PolicyDeniedError(f"{name} must be an integer")
    return value


def validate_collection_call(
    tool_name: str, arguments: dict[str, Any], scope: dict[str, Any]
) -> dict[str, Any]:
    """Return canonical arguments, rejecting cross incident or broader queries."""
    validate_tool_name(tool_name)
    if not isinstance(arguments, dict):
        raise PolicyDeniedError("arguments must be an object")
    if tool_name == "get_alert_context":
        if set(arguments) - {"alert_id", "before_seconds", "after_seconds"}:
            raise PolicyDeniedError("unexpected alert context argument")
        alert_id = arguments.get("alert_id")
        if alert_id != scope["alert_id"]:
            raise PolicyDeniedError("alert belongs to another incident")
        before = _integer(arguments.get("before_seconds", 900), "before_seconds")
        after = _integer(arguments.get("after_seconds", 900), "after_seconds")
        validate_alert_context(alert_id, before, after)
        return {"alert_id": alert_id, "before_seconds": before, "after_seconds": after}

    if tool_name == "lookup_attack_technique":
        if set(arguments) - {"query", "limit"}:
            raise PolicyDeniedError("unexpected knowledge lookup argument")
        query = arguments.get("query")
        limit = _integer(arguments.get("limit", 10), "limit")
        if not isinstance(query, str):
            raise PolicyDeniedError("query must be a string")
        query = " ".join(query.split())
        validate_attack_lookup(query, limit)
        return {"query": query, "limit": limit}

    if set(arguments) != {"time_from", "time_to", "filters", "limit"}:
        raise PolicyDeniedError("event search requires scoped arguments")
    start = _timestamp(arguments["time_from"])
    end = _timestamp(arguments["time_to"])
    lower = _timestamp(scope["time_from"])
    upper = _timestamp(scope["time_to"])
    if start < lower or end > upper:
        raise PolicyDeniedError("event search exceeds incident time window")
    filters = arguments["filters"]
    if not isinstance(filters, dict):
        raise PolicyDeniedError("filters must be an object")
    if "dataset_id" in filters and "dataset_id" not in scope["filters"]:
        raise PolicyDeniedError("dataset filter is not anchored to incident")
    if not scope["filters"]:
        raise PolicyDeniedError("incident has no safe event search anchor")
    if any(filters.get(key) != value for key, value in scope["filters"].items()):
        raise PolicyDeniedError("event search must retain incident filters")
    limit = _integer(arguments["limit"], "limit")
    if limit > scope["limit"]:
        raise PolicyDeniedError("event search limit exceeds incident scope")
    validate_event_search(start, end, filters, limit)
    return {
        "time_from": start.isoformat(),
        "time_to": end.isoformat(),
        "filters": dict(sorted(filters.items())),
        "limit": limit,
    }
