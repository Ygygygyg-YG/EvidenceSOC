from __future__ import annotations

from datetime import UTC, datetime

import pytest
from evidencesoc.agents.collect_policy import (
    CollectionDecision,
    validate_collection_call,
)
from pydantic import ValidationError

SCOPE = {
    "alert_id": "AL-1",
    "time_from": "2026-09-21T10:05:00+00:00",
    "time_to": "2026-09-21T10:35:00+00:00",
    "filters": {"source_ip": "203.0.113.42", "host": "shop.example.test"},
    "limit": 100,
}


def test_search_stays_within_incident_scope_and_canonicalizes_time() -> None:
    arguments = validate_collection_call(
        "search_security_events",
        {
            "time_from": "2026-09-21T18:10:00+08:00",
            "time_to": "2026-09-21T18:30:00+08:00",
            "filters": {**SCOPE["filters"], "severity": "high"},
            "limit": 50,
        },
        SCOPE,
    )
    assert datetime.fromisoformat(arguments["time_from"]) == datetime(
        2026, 9, 21, 10, 10, tzinfo=UTC
    )
    assert arguments["time_from"].endswith("+00:00")


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("shell", {"command": "whoami"}),
        ("get_alert_context", {"alert_id": "AL-other"}),
        (
            "search_security_events",
            {
                "time_from": SCOPE["time_from"],
                "time_to": SCOPE["time_to"],
                "filters": {"source_ip": "203.0.113.99"},
                "limit": 100,
            },
        ),
        (
            "search_security_events",
            {
                "time_from": "2026-09-21T09:00:00Z",
                "time_to": SCOPE["time_to"],
                "filters": SCOPE["filters"],
                "limit": 100,
            },
        ),
        ("lookup_attack_technique", {"query": "SQL injection", "limit": 11}),
        ("lookup_attack_technique", {"query": "SQL injection", "limit": True}),
    ],
)
def test_rejects_unknown_tools_and_scope_expansion(
    tool: str, arguments: dict[str, object]
) -> None:
    with pytest.raises((ValueError, PermissionError, TypeError)):
        validate_collection_call(tool, arguments, SCOPE)


def test_context_window_can_narrow_but_not_change_alert() -> None:
    assert validate_collection_call(
        "get_alert_context",
        {"alert_id": "AL-1", "before_seconds": 300, "after_seconds": 0},
        SCOPE,
    ) == {"alert_id": "AL-1", "before_seconds": 300, "after_seconds": 0}


def test_search_without_an_incident_entity_is_denied() -> None:
    with pytest.raises(ValueError):
        validate_collection_call(
            "search_security_events",
            {
                "time_from": SCOPE["time_from"],
                "time_to": SCOPE["time_to"],
                "filters": {"severity": "high"},
                "limit": 10,
            },
            {**SCOPE, "filters": {}},
        )


def test_search_cannot_drop_or_change_ait_scenario_filter() -> None:
    scoped = {**SCOPE, "filters": {**SCOPE["filters"], "dataset_id": "ait-v2.1:shaw"}}
    arguments = {
        "time_from": SCOPE["time_from"],
        "time_to": SCOPE["time_to"],
        "filters": dict(scoped["filters"]),
        "limit": 20,
    }
    assert (
        validate_collection_call("search_security_events", arguments, scoped)[
            "filters"
        ]["dataset_id"]
        == "ait-v2.1:shaw"
    )
    for filters in (
        SCOPE["filters"],
        {**SCOPE["filters"], "dataset_id": "ait-v2.1:wilson"},
    ):
        with pytest.raises(ValueError):
            validate_collection_call(
                "search_security_events", {**arguments, "filters": filters}, scoped
            )


def test_search_cannot_invent_scenario_filter_when_incident_has_none() -> None:
    with pytest.raises(ValueError, match="dataset"):
        validate_collection_call(
            "search_security_events",
            {
                "time_from": SCOPE["time_from"],
                "time_to": SCOPE["time_to"],
                "filters": {**SCOPE["filters"], "dataset_id": "other-scenario"},
                "limit": 20,
            },
            SCOPE,
        )


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("x" * 129, {}),
        ("search_security_events", {"limit": float("nan")}),
        ("search_security_events", {"opaque": object()}),
    ],
)
def test_model_decision_rejects_unpersistable_values(
    tool_name: str, arguments: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        CollectionDecision(
            action="call",
            tool_name=tool_name,
            arguments=arguments,
            rationale="inspect the incident",
        )


@pytest.mark.parametrize(
    ("tool", "arguments", "code"),
    [
        ("shell", {}, "POLICY_TOOL_DENIED"),
        ("get_alert_context", {"alert_id": "AL-other"}, "POLICY_INCIDENT_DENIED"),
        (
            "search_security_events",
            dict(SCOPE),
            "POLICY_ARGUMENTS_INVALID",
        ),
        (
            "search_security_events",
            {
                **{key: value for key, value in SCOPE.items() if key != "alert_id"},
                "time_from": "2026-09-21T09:00:00Z",
            },
            "POLICY_TIME_SCOPE_DENIED",
        ),
        (
            "search_security_events",
            {
                **{key: value for key, value in SCOPE.items() if key != "alert_id"},
                "filters": {"host": "another.example.test"},
            },
            "POLICY_TARGET_SCOPE_DENIED",
        ),
        (
            "search_security_events",
            {
                **{key: value for key, value in SCOPE.items() if key != "alert_id"},
                "limit": 101,
            },
            "POLICY_LIMIT_DENIED",
        ),
    ],
)
def test_policy_denials_preserve_the_rejected_boundary(
    tool: str, arguments: dict[str, object], code: str
) -> None:
    with pytest.raises(ValueError) as caught:
        validate_collection_call(tool, arguments, SCOPE)
    assert getattr(caught.value, "code", None) == code
