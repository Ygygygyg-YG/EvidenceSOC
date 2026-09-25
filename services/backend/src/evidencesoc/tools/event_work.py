from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import datetime
from time import monotonic

from opensearchpy import OpenSearch
from opensearchpy.exceptions import ConnectionError as OpenSearchConnectionError
from opensearchpy.exceptions import ConnectionTimeout as OpenSearchConnectionTimeout
from opensearchpy.exceptions import TransportError as OpenSearchTransportError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from evidencesoc.domain.models import EvidenceItem
from evidencesoc.evidence.service import (
    EvidenceIntegrityError,
    EvidenceService,
    EvidenceSourceNotFoundError,
)
from evidencesoc.persistence.event_repository import (
    EventRepository,
    EvidenceRepository,
    IncidentNotFoundError,
)
from evidencesoc.persistence.event_search import (
    EventSearchResponseError,
    OpenSearchEventQuery,
    OpenSearchEventStore,
)
from evidencesoc.tools.security_events import ToolDependencyError


class ToolDependencyTimeout(ToolDependencyError):
    code = "DEPENDENCY_TIMEOUT"


class ToolNotFoundError(ToolDependencyError):
    code = "NOT_FOUND"


class EventSearchWork:
    """只重试只读 ID 查询；证据创建不重试。"""

    def __init__(
        self,
        *,
        query: OpenSearchEventQuery,
        evidence_factory: Callable[[], AbstractContextManager[EvidenceService]],
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._query = query
        self._evidence_factory = evidence_factory
        self._clock = clock

    def __call__(
        self,
        *,
        time_from: datetime,
        time_to: datetime,
        filters: dict[str, str],
        limit: int,
        incident_id: str,
    ) -> list[EvidenceItem]:
        deadline = self._clock() + 10.0
        search_filters = dict(filters)

        for attempt in range(3):
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise ToolDependencyTimeout("event search deadline exceeded")

            try:
                event_ids = self._query.search_event_ids(
                    time_from=time_from,
                    time_to=time_to,
                    filters=search_filters,
                    limit=limit,
                    request_timeout=remaining,
                )
                break
            except OpenSearchConnectionTimeout as exc:
                if attempt == 2 or self._clock() >= deadline:
                    raise ToolDependencyTimeout("event search timed out") from exc
            except OpenSearchConnectionError as exc:
                if self._clock() >= deadline:
                    raise ToolDependencyTimeout("event search timed out") from exc
                if attempt == 2:
                    raise ToolDependencyError("event search unavailable") from exc
            except EventSearchResponseError as exc:
                raise ToolDependencyError("invalid event search response") from exc
            except OpenSearchTransportError as exc:
                if self._clock() >= deadline:
                    raise ToolDependencyTimeout("event search timed out") from exc
                if exc.status_code not in {502, 503, 504} or attempt == 2:
                    raise ToolDependencyError("event search unavailable") from exc
        else:
            raise AssertionError("unreachable retry state")

        if self._clock() >= deadline:
            raise ToolDependencyTimeout("deadline exceeded before evidence creation")
        if len(event_ids) > limit:
            raise ToolDependencyError("event search exceeded result limit")
        if not event_ids:
            return []

        query_metadata = {
            "time_from": time_from,
            "time_to": time_to,
            "filters": dict(search_filters),
            "limit": limit,
        }

        # 不能重试：数据库提交失败时，提交结果可能不明确。
        try:
            with self._evidence_factory() as service:
                return service.create_for_events(
                    incident_id=incident_id,
                    event_ids=event_ids,
                    query=query_metadata,
                )
        except (EvidenceSourceNotFoundError, IncidentNotFoundError) as exc:
            raise ToolNotFoundError(str(exc)) from exc
        except OpenSearchConnectionTimeout as exc:
            raise ToolDependencyTimeout("evidence source timed out") from exc
        except (
            EvidenceIntegrityError,
            OpenSearchTransportError,
            SQLAlchemyError,
        ) as exc:
            raise ToolDependencyError("evidence creation unavailable") from exc


def build_event_search_work(
    *,
    opensearch_url: str,
    index_name: str,
    session_factory: sessionmaker[Session],
) -> EventSearchWork:
    if not opensearch_url.strip():
        raise ValueError("OpenSearch URL must not be blank")

    client = OpenSearch(
        hosts=[opensearch_url],
        max_retries=0,
        retry_on_status=(),
        retry_on_timeout=False,
    )
    query = OpenSearchEventQuery(client, index_name=index_name)

    @contextmanager
    def evidence_factory() -> Iterator[EvidenceService]:
        # Session 在执行 work 的线程中创建、使用、关闭。
        with session_factory() as session:
            yield EvidenceService(
                EventRepository(session),
                EvidenceRepository(session),
                OpenSearchEventStore(client, index_name=index_name),
            )

    return EventSearchWork(query=query, evidence_factory=evidence_factory)
