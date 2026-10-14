from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime, timedelta
from time import monotonic

from opensearchpy import OpenSearch
from opensearchpy.exceptions import ConnectionError as OpenSearchConnectionError
from opensearchpy.exceptions import ConnectionTimeout as OpenSearchConnectionTimeout
from opensearchpy.exceptions import TransportError as OpenSearchTransportError
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from evidencesoc.domain.models import EvidenceItem
from evidencesoc.evidence.service import (
    EvidenceIntegrityError,
    EvidenceService,
    EvidenceSourceNotFoundError,
)
from evidencesoc.execution import check_execution
from evidencesoc.persistence.event_repository import (
    EventRepository,
    EvidenceRepository,
    IncidentNotFoundError,
)
from evidencesoc.persistence.event_search import OpenSearchEventStore
from evidencesoc.persistence.tables import (
    AlertTable,
    IncidentTable,
    SecurityEventTable,
)
from evidencesoc.tools.errors import (
    ToolDependencyError,
    ToolDependencyTimeout,
    ToolNotFoundError,
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _set_statement_timeout(session: Session, timeout_seconds: float) -> None:
    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return
    milliseconds = max(1, int(timeout_seconds * 1000))
    session.execute(
        text("SELECT set_config('statement_timeout', :timeout, true)"),
        {"timeout": f"{milliseconds}ms"},
    )


class AlertContextRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def list_event_ids(
        self,
        *,
        incident_id: str,
        alert_id: str,
        before_seconds: int,
        after_seconds: int,
        limit: int,
        timeout_seconds: float | None = None,
    ) -> list[str]:
        if timeout_seconds is not None:
            _set_statement_timeout(self._session, timeout_seconds)

        row = self._session.execute(
            select(AlertTable.created_at, AlertTable.event_ids)
            .join(IncidentTable, IncidentTable.alert_id == AlertTable.alert_id)
            .where(
                IncidentTable.incident_id == incident_id,
                AlertTable.alert_id == alert_id,
            )
        ).one_or_none()
        if row is None:
            raise ToolNotFoundError("alert context not found")

        created_at, raw_event_ids = row
        if isinstance(raw_event_ids, str):
            try:
                raw_event_ids = json.loads(raw_event_ids)
            except json.JSONDecodeError as exc:
                raise ToolDependencyError("alert event allowlist is invalid") from exc
        if not isinstance(raw_event_ids, list) or any(
            not isinstance(event_id, str) or not event_id.strip()
            for event_id in raw_event_ids
        ):
            raise ToolDependencyError("alert event allowlist is invalid")

        created_at = _utc(created_at)
        lower = created_at - timedelta(seconds=before_seconds)
        upper = created_at + timedelta(seconds=after_seconds)
        rows = self._session.execute(
            select(SecurityEventTable.event_id)
            .where(
                SecurityEventTable.event_id.in_(raw_event_ids),
                SecurityEventTable.observed_at >= lower,
                SecurityEventTable.observed_at <= upper,
            )
            .order_by(
                SecurityEventTable.observed_at,
                SecurityEventTable.event_id,
            )
            .limit(limit)
        ).scalars()
        return list(rows)


class AlertContextWork:
    def __init__(
        self,
        *,
        repository_factory: Callable[
            [], AbstractContextManager[AlertContextRepository]
        ],
        evidence_factory: Callable[[], AbstractContextManager[EvidenceService]],
        clock: Callable[[], float] = monotonic,
        max_attempts: int = 3,
    ) -> None:
        if not 1 <= max_attempts <= 3:
            raise ValueError("max_attempts must be between 1 and 3")
        self._repository_factory = repository_factory
        self._evidence_factory = evidence_factory
        self._clock = clock
        self._max_attempts = max_attempts

    def __call__(
        self,
        *,
        alert_id: str,
        before_seconds: int,
        after_seconds: int,
        incident_id: str,
    ) -> list[EvidenceItem]:
        deadline = self._clock() + 10.0
        for attempt in range(self._max_attempts):
            remaining = min(deadline - self._clock(), check_execution() or 10.0)
            if remaining <= 0:
                raise ToolDependencyTimeout("alert context deadline exceeded")
            try:
                with self._repository_factory() as repository:
                    event_ids = repository.list_event_ids(
                        incident_id=incident_id,
                        alert_id=alert_id,
                        before_seconds=before_seconds,
                        after_seconds=after_seconds,
                        limit=200,
                        timeout_seconds=remaining,
                    )
                break
            except OperationalError as exc:
                if self._clock() >= deadline:
                    raise ToolDependencyTimeout("alert context timed out") from exc
                if attempt == self._max_attempts - 1:
                    raise ToolDependencyError("alert context unavailable") from exc
        else:
            raise AssertionError("unreachable retry state")

        if self._clock() >= deadline:
            raise ToolDependencyTimeout("deadline exceeded before evidence creation")
        if not event_ids:
            return []

        query = {
            "alert_id": alert_id,
            "before_seconds": before_seconds,
            "after_seconds": after_seconds,
            "limit": 200,
        }
        try:
            check_execution()
            with self._evidence_factory() as service:
                return service.create_for_events(
                    incident_id=incident_id,
                    event_ids=event_ids,
                    query=query,
                )
        except (EvidenceSourceNotFoundError, IncidentNotFoundError) as exc:
            raise ToolNotFoundError(str(exc)) from exc
        except OpenSearchConnectionTimeout as exc:
            raise ToolDependencyTimeout("evidence source timed out") from exc
        except OpenSearchConnectionError as exc:
            raise ToolDependencyError("evidence source unavailable") from exc
        except (
            EvidenceIntegrityError,
            OpenSearchTransportError,
            SQLAlchemyError,
        ) as exc:
            raise ToolDependencyError("evidence creation unavailable") from exc


def build_alert_context_work(
    *,
    opensearch_url: str,
    index_name: str,
    session_factory: sessionmaker[Session],
    max_attempts: int = 3,
) -> AlertContextWork:
    if not opensearch_url.strip():
        raise ValueError("OpenSearch URL must not be blank")

    client = OpenSearch(
        hosts=[opensearch_url],
        timeout=10,
        max_retries=0,
        retry_on_status=(),
        retry_on_timeout=False,
    )

    @contextmanager
    def repository_factory() -> Iterator[AlertContextRepository]:
        with session_factory() as session:
            yield AlertContextRepository(session)

    @contextmanager
    def evidence_factory() -> Iterator[EvidenceService]:
        with session_factory() as session:
            yield EvidenceService(
                EventRepository(session),
                EvidenceRepository(session),
                OpenSearchEventStore(client, index_name=index_name),
            )

    return AlertContextWork(
        repository_factory=repository_factory,
        evidence_factory=evidence_factory,
        max_attempts=max_attempts,
    )
