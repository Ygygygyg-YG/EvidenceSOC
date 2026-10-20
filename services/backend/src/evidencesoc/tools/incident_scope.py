"""Database-derived incident boundaries shared by collection and MCP search."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import UTC, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.persistence.tables import AlertTable, IncidentTable, SecurityEventTable

OBSERVATION_FIELDS = frozenset(
    {
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "host",
        "service",
        "message",
        "event_type",
        "source",
        "observed_at",
        "severity",
        "user",
        "username",
        "account",
    }
)


def observations(raw: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        key: deepcopy(value) for key, value in raw.items() if key in OBSERVATION_FIELDS
    }
    http = raw.get("http")
    if isinstance(http, dict):
        result["http"] = {
            key: deepcopy(value)
            for key, value in http.items()
            if key in {"method", "path", "status_code"}
        }
    return result


def load_incident_scope(
    sessions: Callable[[], Session], incident_id: str
) -> dict[str, Any]:
    """Read trusted alert ownership, event digests, sources and time bounds."""
    with sessions() as session:
        alert = session.scalar(
            select(AlertTable)
            .join(IncidentTable, IncidentTable.alert_id == AlertTable.alert_id)
            .where(IncidentTable.incident_id == incident_id)
        )
        if alert is None:
            raise LookupError("incident or its alert does not exist")
        at = alert.created_at
        at = at.replace(tzinfo=UTC) if at.tzinfo is None else at.astimezone(UTC)
        events = session.scalars(
            select(SecurityEventTable)
            .where(SecurityEventTable.event_id.in_(alert.event_ids))
            .order_by(SecurityEventTable.observed_at, SecurityEventTable.event_id)
        ).all()
        filters: dict[str, str] = {}
        sources = []
        dataset_ids = []
        for event in events:
            if calculate_content_sha256(event.raw) != event.content_sha256:
                raise ValueError("alert source event integrity check failed")
            dataset_ids.append(event.raw.get("dataset_id"))
            raw = observations(event.raw)
            anchor = {
                key: raw[key]
                for key in ("source_ip", "host", "service")
                if isinstance(raw.get(key), str) and raw[key].strip()
            }
            sources.append({"filters": anchor, "raw": raw})
            if not filters and anchor:
                filters = dict(anchor)
        if any(value is not None for value in dataset_ids):
            dataset = dataset_ids[0]
            if (
                not isinstance(dataset, str)
                or not dataset.strip()
                or any(value != dataset for value in dataset_ids)
            ):
                raise PermissionError("alert mixes dataset scenarios")
            if filters:
                filters["dataset_id"] = dataset
            for source in sources:
                if source["filters"]:
                    source["filters"]["dataset_id"] = dataset
        return {
            "alert_id": alert.alert_id,
            "time_from": (at - timedelta(seconds=900)).isoformat(),
            "time_to": (at + timedelta(seconds=900)).isoformat(),
            "filters": filters,
            "source_scopes": sources,
            "limit": 100,
        }


def validate_incident_search(arguments: dict[str, Any], scope: dict[str, Any]) -> None:
    """Allow any observed source, retaining its complete anchor and window."""
    from evidencesoc.agents.collect_policy import validate_collection_call
    from evidencesoc.tools.policy import PolicyDeniedError

    for source in scope["source_scopes"]:
        if not source["filters"]:
            continue
        try:
            validate_collection_call(
                "search_security_events",
                arguments,
                {**scope, "filters": source["filters"]},
            )
        except PolicyDeniedError:
            continue
        return
    raise PolicyDeniedError("event search exceeds database-bound incident scope")
