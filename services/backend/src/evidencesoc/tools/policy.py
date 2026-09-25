from evidencesoc.domain.event_search_policy import (
    ALLOWED_EVENT_FILTERS,
    MAX_EVENT_RESULTS,
    PolicyDeniedError,
    validate_event_search,
)

MAX_CONTEXT_SECONDS = 900
MAX_ATTACK_RESULTS = 10

ALLOWED_TOOLS = frozenset(
    {
        "search_security_events",
        "get_alert_context",
        "lookup_attack_technique",
    }
)


def validate_alert_context(
    alert_id: str,
    before_seconds: int = 900,
    after_seconds: int = 900,
) -> None:
    if not alert_id.strip():
        raise PolicyDeniedError("alert_id must not be blank")

    if not 0 <= before_seconds <= MAX_CONTEXT_SECONDS:
        raise PolicyDeniedError("before_seconds must be between 0 and 900")

    if not 0 <= after_seconds <= MAX_CONTEXT_SECONDS:
        raise PolicyDeniedError("after_seconds must be between 0 and 900")


def validate_attack_lookup(
    query: str,
    limit: int = 10,
) -> None:
    if not query.strip():
        raise PolicyDeniedError("query must not be blank")

    if not 1 <= limit <= MAX_ATTACK_RESULTS:
        raise PolicyDeniedError("limit must be between 1 and 10")


def validate_tool_name(name: str) -> None:
    if name not in ALLOWED_TOOLS:
        raise PolicyDeniedError(f"tool is not allowed: {name}")


__all__ = (
    "ALLOWED_EVENT_FILTERS",
    "ALLOWED_TOOLS",
    "MAX_ATTACK_RESULTS",
    "MAX_CONTEXT_SECONDS",
    "MAX_EVENT_RESULTS",
    "PolicyDeniedError",
    "validate_alert_context",
    "validate_attack_lookup",
    "validate_event_search",
    "validate_tool_name",
)
