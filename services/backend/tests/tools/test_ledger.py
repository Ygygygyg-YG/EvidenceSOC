from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
from evidencesoc.persistence.tables import InvestigationToolCallTable
from evidencesoc.tools.ledger import (
    AttemptLimitExceeded,
    BudgetExceeded,
    InvalidLedgerTransition,
    Ledger,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def ledger():
    db_path = Path.cwd() / f".ledger-test-{uuid4().hex}.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_path}",
        connect_args={"timeout": 30},
    )
    with engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE incidents (incident_id VARCHAR(64) PRIMARY KEY)")
        )
        connection.execute(
            text(
                "CREATE TABLE agent_runs (run_id VARCHAR(64) PRIMARY KEY, incident_id VARCHAR(64))"
            )
        )
        connection.execute(text("INSERT INTO incidents VALUES ('IN-1'), ('IN-2')"))
        connection.execute(
            text(
                "INSERT INTO agent_runs VALUES ('AR-1', 'IN-1'), ('AR-2', 'IN-1'), ('AR-OTHER', 'IN-2')"
            )
        )
    InvestigationToolCallTable.__table__.create(engine)
    yield Ledger(sessionmaker(engine, expire_on_commit=False))
    engine.dispose()
    db_path.unlink(missing_ok=True)


def reserve(ledger, number, *, round_no=1, purpose="collection", run_id="AR-1"):
    return ledger.reserve(
        "IN-1",
        run_id,
        round_no,
        "search_security_events",
        {"filters": {"source_ip": f"203.0.113.{number}"}, "limit": 10},
        "check related events",
        purpose=purpose,
    )


def test_completed_query_is_reused_across_rounds_without_spending_budget(ledger):
    first = reserve(ledger, 1)
    assert first.status == "reserved"
    assert first.reused is False
    attempted = ledger.begin_attempt(first.call_id)
    assert attempted.attempts == 1
    completed = ledger.complete(first.call_id, [{"evidence_id": "EV-1"}])
    assert completed.status == "completed"

    repeated = reserve(ledger, 1, round_no=2, run_id="AR-2")
    assert repeated.call_id != first.call_id
    assert repeated.reused is True
    assert repeated.charged is False
    assert repeated.source_call_id == first.call_id
    assert repeated.result == [{"evidence_id": "EV-1"}]
    assert [call.call_id for call in ledger.calls("IN-1", 1)] == [first.call_id]
    assert [call.call_id for call in ledger.calls("IN-1", 2)] == [repeated.call_id]
    assert ledger.summary("IN-1", 2).total_used == 1
    assert ledger.summary("IN-1", 2).round_used == 0


def test_failed_and_empty_calls_spend_budget_but_verification_is_separate(ledger):
    first = reserve(ledger, 1)
    ledger.fail(first.call_id, "DEPENDENCY_TIMEOUT")
    second = reserve(ledger, 2)
    ledger.begin_attempt(second.call_id)
    ledger.complete(second.call_id, [])
    reserve(ledger, 3)
    with pytest.raises(BudgetExceeded):
        reserve(ledger, 4)
    for number in (4, 5, 6):
        reserve(ledger, number, round_no=2, run_id="AR-2")
    with pytest.raises(BudgetExceeded):
        reserve(ledger, 7, round_no=3, run_id="AR-2")

    verification = reserve(ledger, 1, purpose="verification", run_id="AR-2")
    assert verification.purpose == "verification"
    summary = ledger.summary("IN-1", 2)
    assert (summary.round_used, summary.total_used) == (3, 6)
    assert (summary.round_remaining, summary.total_remaining) == (0, 0)
    assert summary.verification_calls == 1


def test_incomplete_query_resumes_same_record_and_attempt_limit_survives_restart(
    ledger,
):
    first = reserve(ledger, 1)
    ledger.begin_attempt(first.call_id)
    recovered = reserve(ledger, 1, run_id="AR-2")
    assert recovered.call_id == first.call_id
    assert recovered.reused is True
    assert recovered.attempts == 1
    ledger.begin_attempt(first.call_id)
    ledger.begin_attempt(first.call_id)
    with pytest.raises(AttemptLimitExceeded):
        ledger.begin_attempt(first.call_id)
    failed = ledger.fail(first.call_id, "RETRY_EXHAUSTED")
    assert failed.status == "failed"
    second = reserve(ledger, 1)
    assert second.call_id != first.call_id
    assert ledger.summary("IN-1", 1).round_used == 2


def test_concurrent_reservations_are_serialized_and_cannot_overspend(ledger):
    with ThreadPoolExecutor(max_workers=8) as pool:
        duplicates = list(pool.map(lambda _: reserve(ledger, 1), range(8)))
    assert len({item.call_id for item in duplicates}) == 1
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(reserve, ledger, number) for number in range(2, 10)]
        outcomes = [
            future.result() if future.exception() is None else future.exception()
            for future in futures
        ]
    assert sum(not isinstance(item, Exception) for item in outcomes) == 2
    assert all(
        isinstance(item, BudgetExceeded)
        for item in outcomes
        if isinstance(item, Exception)
    )
    assert ledger.summary("IN-1", 1).round_used == 3


def test_concurrent_a1_reservations_preserve_both_nontransferable_slots(ledger):
    protected = ledger.with_reservations(
        first_round_reserved_calls=1,
        total_reserved_calls=1,
    )
    for round_no, expected in ((1, 2), (2, 3)):
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [
                pool.submit(
                    reserve, protected, round_no * 10 + number, round_no=round_no
                )
                for number in range(8)
            ]
            outcomes = [
                future.result() if future.exception() is None else future.exception()
                for future in futures
            ]
        assert sum(not isinstance(item, Exception) for item in outcomes) == expected
        assert all(
            isinstance(item, BudgetExceeded)
            for item in outcomes
            if isinstance(item, Exception)
        )
    summary = protected.summary("IN-1", 2)
    assert summary.total_used == 5
    assert summary.total_remaining == 0


@pytest.mark.parametrize("recovery_round", [1, 2])
def test_failed_verification_stays_terminal_after_restart(ledger, recovery_round):
    first = reserve(ledger, 1, purpose="verification")
    for _ in range(3):
        ledger.begin_attempt(first.call_id)
    ledger.fail(first.call_id, "DEPENDENCY_TIMEOUT")

    restarted = Ledger(ledger._sessions)
    recovered = reserve(restarted, 1, round_no=recovery_round, purpose="verification")
    assert recovered.call_id == first.call_id
    assert recovered.status == "failed"
    assert recovered.attempts == 3
    assert recovered.error_code == "DEPENDENCY_TIMEOUT"
    assert recovered.reused is True
    with pytest.raises(InvalidLedgerTransition):
        restarted.begin_attempt(recovered.call_id)
    summary = restarted.summary("IN-1", recovery_round)
    assert summary.verification_calls == 1
    assert summary.verification_attempts == 3


def test_failed_verification_allows_a_fresh_validation_run(ledger):
    first = reserve(ledger, 1, purpose="verification")
    for _ in range(3):
        ledger.begin_attempt(first.call_id)
    ledger.fail(first.call_id, "DEPENDENCY_TIMEOUT")

    restarted = Ledger(ledger._sessions)
    fresh = reserve(restarted, 1, purpose="verification", run_id="AR-2")
    assert fresh.call_id != first.call_id
    assert fresh.run_id == "AR-2"
    assert fresh.status == "reserved"
    assert fresh.attempts == 0
    assert fresh.reused is False
    assert restarted.begin_attempt(fresh.call_id).attempts == 1


def test_run_must_belong_to_incident(ledger):
    with pytest.raises(PermissionError):
        reserve(ledger, 1, run_id="AR-OTHER")
