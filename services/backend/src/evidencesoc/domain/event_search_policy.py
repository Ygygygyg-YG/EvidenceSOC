from datetime import datetime

MAX_EVENT_RESULTS = 200

ALLOWED_EVENT_FILTERS = frozenset(
    {
        "source",
        "event_type",
        "severity",
        "source_ip",
        "destination_ip",
        "host",
        "service",
    }
)


class PolicyDeniedError(ValueError):
    code = "POLICY_DENIED"


def validate_event_search(
    time_from: datetime,
    time_to: datetime,
    filters: dict[str, str],
    limit: int = 100,
) -> None:
    if not 1 <= limit <= MAX_EVENT_RESULTS:
        raise PolicyDeniedError("limit must be between 1 and 200")

    if (
        time_from.tzinfo is None
        or time_to.tzinfo is None
        or time_from.utcoffset() is None
        or time_to.utcoffset() is None
        or time_from >= time_to
    ):
        raise PolicyDeniedError("time range must have a timezone and be increasing")

    for field, value in filters.items():
        if field not in ALLOWED_EVENT_FILTERS:
            raise PolicyDeniedError(f"filter field is not allowed: {field}")
        if not isinstance(value, str) or not value.strip():
            raise PolicyDeniedError(f"filter value is empty: {field}")
