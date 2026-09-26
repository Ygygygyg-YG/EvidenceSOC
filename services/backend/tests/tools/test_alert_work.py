from __future__ import annotations

import json
from contextlib import nullcontext
from datetime import UTC, datetime
from typing import Any, Self

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from evidencesoc.evidence.service import EvidenceIntegrityError
from evidencesoc.tools.alert_work import AlertContextRepository, AlertContextWork
from evidencesoc.tools.errors import (
    ToolDependencyError,
    ToolDependencyTimeout,
    ToolNotFoundError,
)


def _database() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE alerts ("
            "alert_id VARCHAR(64) PRIMARY KEY, "
            "created_at DATETIME NOT NULL, "
            "event_ids JSON NOT NULL)"
        )
        connection.exec_driver_sql(
            "CREATE TABLE incidents ("
            "incident_id VARCHAR(64) PRIMARY KEY, "
            "alert_id VARCHAR(64) NOT NULL)"
        )
        connection.exec_driver_sql(
            "CREATE TABLE security_events ("
            "event_id VARCHAR(64) PRIMARY KEY, "
            "observed_at DATETIME NOT NULL)"
        )
        connection.exec_driver_sql(
            "INSERT INTO alerts VALUES (?, ?, ?)",
            (
                "AL-1",
                "2026-09-21 12:00:00.000000",
                json.dumps(["EVT-in-window-1", "EVT-in-window-2", "EVT-outside"]),
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO incidents VALUES (?, ?)",
            ("IN-1", "AL-1"),
        )
        for event_id, observed_at in (
            ("EVT-in-window-1", "2026-09-21 11:55:00.000000"),
            ("EVT-in-window-2", "2026-09-21 12:05:00.000000"),
            ("EVT-outside", "2026-09-21 12:06:00.000000"),
            ("EVT-unallowlisted", "2026-09-21 12:01:00.000000"),
        ):
            connection.exec_driver_sql(
                "INSERT INTO security_events VALUES (?, ?)",
                (event_id, observed_at),
            )
    return sessionmaker(bind=engine, class_=Session)


def test_repository_enforces_incident_allowlist_and_inclusive_window() -> None:
    sessions = _database()
    with sessions() as session:
        repository = AlertContextRepository(session)
        assert repository.list_event_ids(
            incident_id="IN-1",
            alert_id="AL-1",
            before_seconds=300,
            after_seconds=300,
            limit=200,
        ) == ["EVT-in-window-1", "EVT-in-window-2"]

        with pytest.raises(ToolNotFoundError):
            repository.list_event_ids(
                incident_id="IN-other",
                alert_id="AL-1",
                before_seconds=300,
                after_seconds=300,
                limit=200,
            )


class FakeRepository:
    def __init__(self, event_ids: list[str]) -> None:
        self.event_ids = event_ids
        self.calls = 0

    def list_event_ids(self, **_kwargs: object) -> list[str]:
        self.calls += 1
        return self.event_ids


class FlakyRepository(FakeRepository):
    def __init__(self) -> None:
        super().__init__([])
        self.failures = 2

    def list_event_ids(self, **kwargs: object) -> list[str]:
        self.calls += 1
        if self.failures:
            self.failures -= 1
            raise OperationalError("SELECT", {}, RuntimeError("temporary"))
        return self.event_ids


class EvidenceSpy:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls = 0
        self.error = error

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def create_for_events(self, **_kwargs: object) -> list[Any]:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return []


def _work(
    repository: object,
    evidence: EvidenceSpy,
    *,
    clock=lambda: 0.0,
) -> AlertContextWork:
    return AlertContextWork(
        repository_factory=lambda: nullcontext(repository),
        evidence_factory=lambda: evidence,
        clock=clock,
    )


def test_work_retries_read_only_lookup_at_most_twice() -> None:
    repository = FlakyRepository()
    evidence = EvidenceSpy()

    assert _work(repository, evidence)(
        alert_id="AL-1",
        before_seconds=300,
        after_seconds=300,
        incident_id="IN-1",
    ) == []
    assert repository.calls == 3
    assert evidence.calls == 0


def test_work_stops_before_evidence_when_deadline_is_exhausted() -> None:
    repository = FakeRepository(["EVT-1"])
    evidence = EvidenceSpy()
    times = iter([0.0, 11.0])

    with pytest.raises(ToolDependencyTimeout, match="deadline"):
        _work(repository, evidence, clock=lambda: next(times))(
            alert_id="AL-1",
            before_seconds=300,
            after_seconds=300,
            incident_id="IN-1",
        )

    assert evidence.calls == 0


def test_evidence_persistence_is_not_retried() -> None:
    repository = FakeRepository(["EVT-1"])
    evidence = EvidenceSpy(EvidenceIntegrityError("EVT-1", "mismatch"))

    with pytest.raises(ToolDependencyError, match="evidence creation"):
        _work(repository, evidence)(
            alert_id="AL-1",
            before_seconds=300,
            after_seconds=300,
            incident_id="IN-1",
        )

    assert evidence.calls == 1


def test_repository_window_uses_aware_utc_bounds() -> None:
    assert datetime.now(UTC).tzinfo is UTC
