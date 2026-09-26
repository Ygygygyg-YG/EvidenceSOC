from datetime import UTC, datetime, timedelta

import pytest

from evidencesoc.tools import policy

START = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
END = START + timedelta(minutes=5)


@pytest.mark.parametrize("limit", [0, -1, 201])
def test_event_search_rejects_invalid_limit(limit: int) -> None:
    with pytest.raises(policy.PolicyDeniedError, match="limit") as error:
        policy.validate_event_search(START, END, {}, limit)

    assert error.value.code == "POLICY_DENIED"


@pytest.mark.parametrize(
    ("time_from", "time_to"),
    [
        (START, START),
        (END, START),
        (START.replace(tzinfo=None), END),
        (START, END.replace(tzinfo=None)),
    ],
)
def test_event_search_rejects_invalid_time(
    time_from: datetime,
    time_to: datetime,
) -> None:
    with pytest.raises(policy.PolicyDeniedError, match="time"):
        policy.validate_event_search(time_from, time_to, {}, 100)


@pytest.mark.parametrize(
    "filters",
    [{"query_string": "*"}, {"source": "  "}],
)
def test_event_search_rejects_invalid_filters(
    filters: dict[str, str],
) -> None:
    with pytest.raises(policy.PolicyDeniedError, match="filter"):
        policy.validate_event_search(START, END, filters, 100)


def test_event_search_accepts_limit_200() -> None:
    assert policy.validate_event_search(
        START, END, {"source": "web"}, 200
    ) is None


@pytest.mark.parametrize(
    ("alert_id", "before_seconds", "after_seconds"),
    [
        ("", 900, 900),
        ("   ", 900, 900),
        ("AL-1", -1, 0),
        ("AL-1", 901, 0),
        ("AL-1", 0, -1),
        ("AL-1", 0, 901),
    ],
)
def test_alert_context_rejects_invalid_arguments(
    alert_id: str,
    before_seconds: int,
    after_seconds: int,
) -> None:
    with pytest.raises(policy.PolicyDeniedError):
        policy.validate_alert_context(
            alert_id, before_seconds, after_seconds
        )


def test_alert_context_accepts_900_seconds() -> None:
    assert policy.validate_alert_context("AL-1", 900, 900) is None


@pytest.mark.parametrize(
    ("query", "limit"),
    [("", 10), ("   ", 10), ("T1059", 0), ("T1059", 11)],
)
def test_attack_lookup_rejects_invalid_arguments(
    query: str,
    limit: int,
) -> None:
    with pytest.raises(policy.PolicyDeniedError):
        policy.validate_attack_lookup(query, limit)


def test_attack_lookup_accepts_10_results() -> None:
    assert policy.validate_attack_lookup("T1059", 10) is None


def test_unknown_tool_is_denied() -> None:
    with pytest.raises(policy.PolicyDeniedError, match="tool"):
        policy.validate_tool_name("run_shell")


@pytest.mark.parametrize(
    "name",
    [
        "search_security_events",
        "get_alert_context",
        "lookup_attack_technique",
    ],
)
def test_three_known_tools_are_allowed(name: str) -> None:
    assert policy.validate_tool_name(name) is None
