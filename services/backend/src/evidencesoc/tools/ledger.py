"""Durable logical-call budget and recovery ledger for investigation tools."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from evidencesoc.ids import new_ulid
from evidencesoc.persistence.tables import (
    AgentRunTable,
    IncidentTable,
    InvestigationToolCallTable,
)


class BudgetExceeded(RuntimeError):
    """The collection round or investigation has no logical calls left."""


class AttemptLimitExceeded(RuntimeError):
    """A logical call has used all three physical attempts."""


class InvalidLedgerTransition(RuntimeError):
    """A terminal call cannot be executed or changed again."""


@dataclass(frozen=True)
class LedgerReservation:
    call_id: str
    incident_id: str
    run_id: str
    round_no: int
    purpose: str
    fingerprint: str
    tool_name: str
    arguments: dict[str, Any]
    rationale: str
    status: str
    attempts: int
    charged: bool
    source_call_id: str | None
    result: Any | None
    error_code: str | None
    reused: bool
    budget_used: int
    round_used: int


@dataclass(frozen=True)
class LedgerSummary:
    incident_id: str
    round_no: int
    round_used: int
    total_used: int
    round_remaining: int
    total_remaining: int
    verification_calls: int
    verification_attempts: int


def query_fingerprint(tool_name: str, arguments: dict[str, Any]) -> str:
    """Fingerprint a normalized logical query, independent of model rationale."""
    canonical = json.dumps(
        [tool_name, arguments],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


class Ledger:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._sessions = session_factory

    @contextmanager
    def _write(self) -> Iterator[Session]:
        with self._sessions() as session, session.begin():
            if session.get_bind().dialect.name == "sqlite":
                # SQLite ignores SELECT FOR UPDATE. Reserve the writer slot before
                # reading counts so independent processes cannot overspend.
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            yield session

    @staticmethod
    def _lock_incident(session: Session, incident_id: str) -> None:
        query = select(IncidentTable.incident_id).where(
            IncidentTable.incident_id == incident_id
        )
        if session.get_bind().dialect.name == "postgresql":
            query = query.with_for_update()
        if session.scalar(query) is None:
            raise LookupError("incident does not exist")

    @staticmethod
    def _count(
        session: Session, incident_id: str, purpose: str, round_no: int | None = None
    ) -> int:
        query = (
            select(func.count())
            .select_from(InvestigationToolCallTable)
            .where(
                InvestigationToolCallTable.incident_id == incident_id,
                InvestigationToolCallTable.purpose == purpose,
                InvestigationToolCallTable.charged.is_(True),
            )
        )
        if round_no is not None:
            query = query.where(InvestigationToolCallTable.round_no == round_no)
        return int(session.scalar(query) or 0)

    @classmethod
    def _snapshot(
        cls, session: Session, row: InvestigationToolCallTable, *, reused: bool = False
    ) -> LedgerReservation:
        return LedgerReservation(
            call_id=row.call_id,
            incident_id=row.incident_id,
            run_id=row.run_id,
            round_no=row.round_no,
            purpose=row.purpose,
            fingerprint=row.fingerprint,
            tool_name=row.tool_name,
            arguments=deepcopy(row.arguments),
            rationale=row.rationale,
            status=row.status,
            attempts=row.attempts,
            charged=row.charged,
            source_call_id=row.source_call_id,
            result=deepcopy(row.result),
            error_code=row.error_code,
            reused=reused,
            budget_used=cls._count(session, row.incident_id, row.purpose),
            round_used=cls._count(session, row.incident_id, row.purpose, row.round_no),
        )

    def reserve(
        self,
        incident_id: str,
        run_id: str,
        round_no: int,
        tool_name: str,
        arguments: dict[str, Any],
        rationale: str,
        purpose: str = "collection",
    ) -> LedgerReservation:
        if not isinstance(round_no, int) or isinstance(round_no, bool) or round_no < 1:
            raise ValueError("round_no must be a positive integer")
        if purpose not in {"collection", "verification"}:
            raise ValueError("unsupported ledger purpose")
        if not isinstance(arguments, dict):
            raise TypeError("tool arguments must be a JSON object")
        normalized = json.loads(
            json.dumps(arguments, ensure_ascii=False, sort_keys=True, allow_nan=False)
        )
        fingerprint = query_fingerprint(tool_name, normalized)
        with self._write() as session:
            self._lock_incident(session, incident_id)
            run_incident_id = session.scalar(
                select(AgentRunTable.incident_id).where(AgentRunTable.run_id == run_id)
            )
            if run_incident_id != incident_id:
                raise PermissionError("run does not belong to incident")
            query = select(InvestigationToolCallTable).where(
                InvestigationToolCallTable.incident_id == incident_id,
                InvestigationToolCallTable.purpose == purpose,
                InvestigationToolCallTable.fingerprint == fingerprint,
            )
            if purpose == "verification":
                # Post-approval checks may only reuse calls from their own run.
                query = query.where(InvestigationToolCallTable.run_id == run_id)
            prior = session.scalars(
                query.order_by(
                    InvestigationToolCallTable.created_at.desc(),
                    InvestigationToolCallTable.call_id.desc(),
                )
            ).all()
            reusable_statuses = {"reserved", "running"}
            if purpose == "verification":
                # A failed validation remains terminal through recovery.
                reusable_statuses.add("failed")
            same_round = [row for row in prior if row.round_no == round_no]
            existing = next(
                (row for row in same_round if row.status == "completed"), None
            )
            if existing is None:
                existing = next(
                    (
                        row
                        for row in same_round
                        if row.status in reusable_statuses
                    ),
                    None,
                )
            if existing is not None:
                return self._snapshot(session, existing, reused=True)
            completed = next((row for row in prior if row.status == "completed"), None)
            if completed is not None:
                now = datetime.now(UTC)
                alias = InvestigationToolCallTable(
                    call_id="LC-" + new_ulid(),
                    incident_id=incident_id,
                    run_id=run_id,
                    round_no=round_no,
                    purpose=purpose,
                    fingerprint=fingerprint,
                    tool_name=tool_name,
                    arguments=normalized,
                    rationale=rationale,
                    status="completed",
                    attempts=0,
                    charged=False,
                    source_call_id=completed.call_id,
                    result=deepcopy(completed.result),
                    error_code=None,
                    created_at=now,
                    updated_at=now,
                )
                session.add(alias)
                session.flush()
                return self._snapshot(session, alias, reused=True)
            unfinished = next(
                (row for row in prior if row.status in reusable_statuses), None
            )
            if unfinished is not None:
                return self._snapshot(session, unfinished, reused=True)
            if purpose == "collection":
                if self._count(session, incident_id, purpose, round_no) >= 3:
                    raise BudgetExceeded(
                        "collection round has used three logical calls"
                    )
                if self._count(session, incident_id, purpose) >= 6:
                    raise BudgetExceeded("investigation has used six logical calls")
            now = datetime.now(UTC)
            row = InvestigationToolCallTable(
                call_id="LC-" + new_ulid(),
                incident_id=incident_id,
                run_id=run_id,
                round_no=round_no,
                purpose=purpose,
                fingerprint=fingerprint,
                tool_name=tool_name,
                arguments=normalized,
                rationale=rationale,
                status="reserved",
                attempts=0,
                charged=True,
                source_call_id=None,
                result=None,
                error_code=None,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            return self._snapshot(session, row)

    @staticmethod
    def _locked_call(session: Session, call_id: str) -> InvestigationToolCallTable:
        query = select(InvestigationToolCallTable).where(
            InvestigationToolCallTable.call_id == call_id
        )
        if session.get_bind().dialect.name == "postgresql":
            query = query.with_for_update()
        row = session.scalar(query)
        if row is None:
            raise LookupError("ledger call does not exist")
        return row

    def begin_attempt(self, call_id: str) -> LedgerReservation:
        with self._write() as session:
            row = self._locked_call(session, call_id)
            if row.status in {"completed", "failed"}:
                raise InvalidLedgerTransition("terminal call cannot be attempted")
            if row.attempts >= 3:
                raise AttemptLimitExceeded(
                    "logical call has used three physical attempts"
                )
            row.attempts += 1
            row.status = "running"
            row.updated_at = datetime.now(UTC)
            session.flush()
            return self._snapshot(session, row)

    def complete(self, call_id: str, result: Any) -> LedgerReservation:
        normalized = json.loads(json.dumps(result, ensure_ascii=False, allow_nan=False))
        with self._write() as session:
            row = self._locked_call(session, call_id)
            if row.status == "completed" and row.result == normalized:
                return self._snapshot(session, row, reused=True)
            if row.status != "running":
                raise InvalidLedgerTransition("only a running call can complete")
            row.status = "completed"
            row.result = normalized
            row.error_code = None
            row.updated_at = datetime.now(UTC)
            session.flush()
            return self._snapshot(session, row)

    def fail(self, call_id: str, error_code: str) -> LedgerReservation:
        if not error_code or len(error_code) > 64:
            raise ValueError("error_code must be between 1 and 64 characters")
        with self._write() as session:
            row = self._locked_call(session, call_id)
            if row.status == "failed" and row.error_code == error_code:
                return self._snapshot(session, row, reused=True)
            if row.status not in {"reserved", "running"}:
                raise InvalidLedgerTransition("terminal call cannot be failed again")
            row.status = "failed"
            row.error_code = error_code
            row.updated_at = datetime.now(UTC)
            session.flush()
            return self._snapshot(session, row)

    def calls(
        self, incident_id: str, round_no: int, purpose: str = "collection"
    ) -> list[LedgerReservation]:
        with self._sessions() as session:
            rows = session.scalars(
                select(InvestigationToolCallTable)
                .where(
                    InvestigationToolCallTable.incident_id == incident_id,
                    InvestigationToolCallTable.round_no == round_no,
                    InvestigationToolCallTable.purpose == purpose,
                )
                .order_by(
                    InvestigationToolCallTable.created_at,
                    InvestigationToolCallTable.call_id,
                )
            ).all()
            return [self._snapshot(session, row) for row in rows]

    def summary(self, incident_id: str, round_no: int) -> LedgerSummary:
        with self._sessions() as session:
            round_used = self._count(session, incident_id, "collection", round_no)
            total_used = self._count(session, incident_id, "collection")
            verification_calls = self._count(session, incident_id, "verification")
            verification_attempts = int(
                session.scalar(
                    select(
                        func.coalesce(func.sum(InvestigationToolCallTable.attempts), 0)
                    ).where(
                        InvestigationToolCallTable.incident_id == incident_id,
                        InvestigationToolCallTable.purpose == "verification",
                    )
                )
                or 0
            )
            return LedgerSummary(
                incident_id=incident_id,
                round_no=round_no,
                round_used=round_used,
                total_used=total_used,
                round_remaining=max(0, 3 - round_used),
                total_remaining=max(0, 6 - total_used),
                verification_calls=verification_calls,
                verification_attempts=verification_attempts,
            )
