from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from evidencesoc.domain.models import EvidenceItem
from evidencesoc.tools import security_events
from evidencesoc.tools.policy import PolicyDeniedError


class WorkSpy:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, **_kwargs: object) -> list[object]:
        self.calls += 1
        return []


class AuditSpy:
    def __init__(self) -> None:
        self.records: list[object] = []

    def record(self, record: object) -> None:
        self.records.append(record)


@pytest.mark.asyncio
async def test_limit_201_is_rejected_before_storage_and_audited() -> None:
    work = WorkSpy()
    audit = AuditSpy()
    context = SimpleNamespace(
        run_id="AR-unit-test",
        incident_id="IN-unit-test",
        trace_id="TRACE-unit-test",
    )
    tool = security_events.SecurityEventTools(
        context=context,
        work=work,
        audit=audit,
    )
    start = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)

    with pytest.raises(PolicyDeniedError):
        await tool.search_security_events(
            time_from=start,
            time_to=start + timedelta(minutes=5),
            filters={},
            limit=201,
        )

    assert work.calls == 0
    assert len(audit.records) == 1
    record = audit.records[0]
    assert record.error_code == "POLICY_DENIED"
    result = record.result
    assert result["trace_id"] == "TRACE-unit-test"
    assert "limit" in result["reason"]


class RecordingWork:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> list[object]:
        self.calls.append(kwargs)
        return []


@pytest.mark.asyncio
async def test_valid_search_calls_work_and_audits() -> None:
    work = RecordingWork()
    audit = AuditSpy()
    context = SimpleNamespace(
        run_id="AR-unit-test",
        incident_id="IN-unit-test",
        trace_id="TRACE-unit-test",
    )
    tool = security_events.SecurityEventTools(
        context=context,
        work=work,
        audit=audit,
    )
    start = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
    end = start + timedelta(minutes=5)

    result = await tool.search_security_events(
        time_from=start,
        time_to=end,
        filters={"source": "web"},
        limit=2,
    )

    assert result == []
    assert work.calls == [
        {
            "time_from": start,
            "time_to": end,
            "filters": {"source": "web"},
            "limit": 2,
            "incident_id": "IN-unit-test",
        }
    ]
    assert len(audit.records) == 1
    record = audit.records[0]
    assert record.run_id == "AR-unit-test"
    assert record.success is True
    assert record.error_code is None
    assert record.result["trace_id"] == "TRACE-unit-test"


class TooManyWork:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, **_kwargs: object) -> list[object]:
        self.calls += 1
        return [object(), object(), object()]


@pytest.mark.asyncio
async def test_backend_result_over_limit_is_rejected() -> None:
    work = TooManyWork()
    audit = AuditSpy()
    context = SimpleNamespace(
        run_id="AR-unit-test",
        incident_id="IN-unit-test",
        trace_id="TRACE-unit-test",
    )
    tool = security_events.SecurityEventTools(
        context=context,
        work=work,
        audit=audit,
    )
    start = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)

    with pytest.raises(RuntimeError, match="too many results") as error:
        await tool.search_security_events(
            time_from=start,
            time_to=start + timedelta(minutes=5),
            filters={},
            limit=2,
        )

    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    assert work.calls == 1
    assert len(audit.records) == 1
    record = audit.records[0]
    assert record.success is False
    assert record.error_code == "DEPENDENCY_UNAVAILABLE"
    assert record.result["trace_id"] == "TRACE-unit-test"
    assert record.result["result_count"] == 3


class WrongTypeWork:
    def __call__(self, **_kwargs: object) -> list[object]:
        return [object()]


@pytest.mark.asyncio
async def test_wrong_result_type_is_rejected() -> None:
    audit = AuditSpy()
    tool = security_events.SecurityEventTools(
        context=SimpleNamespace(
            run_id="AR-unit-test",
            incident_id="IN-unit-test",
            trace_id="TRACE-unit-test",
        ),
        work=WrongTypeWork(),
        audit=audit,
    )
    start = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)

    with pytest.raises(RuntimeError, match="invalid evidence item") as error:
        await tool.search_security_events(
            start, start + timedelta(minutes=5), {}, limit=2
        )

    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    assert len(audit.records) == 1
    record = audit.records[0]
    assert record.success is False
    assert record.error_code == "DEPENDENCY_UNAVAILABLE"
    assert record.result["trace_id"] == "TRACE-unit-test"
    assert record.result["result_count"] == 1


class EvidenceWork:
    def __init__(self, item: EvidenceItem) -> None:
        self.item = item

    def __call__(self, **_kwargs: object) -> list[object]:
        return [self.item]


@pytest.mark.asyncio
async def test_valid_evidence_item_is_returned() -> None:
    start = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
    item = EvidenceItem(
        evidence_id="EV-" + "0" * 26,
        event_id="evt-1",
        source="web",
        observed_at=start,
        query={},
        summary="verified event",
        content_sha256="a" * 64,
    )
    audit = AuditSpy()
    tool = security_events.SecurityEventTools(
        context=SimpleNamespace(
            run_id="AR-unit-test",
            incident_id="IN-unit-test",
            trace_id="TRACE-unit-test",
        ),
        work=EvidenceWork(item),
        audit=audit,
    )

    result = await tool.search_security_events(
        start, start + timedelta(minutes=5), {}, limit=2
    )

    assert result == [item]
    assert len(audit.records) == 1
    assert audit.records[0].success is True

class UnavailableWork:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, **_kwargs: object) -> list[object]:
        self.calls += 1
        raise security_events.ToolDependencyError(
            "event search dependency unavailable"
        )


@pytest.mark.asyncio
async def test_work_dependency_error_is_audited() -> None:
    work = UnavailableWork()
    audit = AuditSpy()
    tool = security_events.SecurityEventTools(
        context=SimpleNamespace(
            run_id="AR-unit-test",
            incident_id="IN-unit-test",
            trace_id="TRACE-unit-test",
        ),
        work=work,
        audit=audit,
    )
    start = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)

    with pytest.raises(
        security_events.ToolDependencyError, match="unavailable"
    ) as error:
        await tool.search_security_events(
            start, start + timedelta(minutes=5), {}, limit=2
        )

    assert error.value.code == "DEPENDENCY_UNAVAILABLE"
    assert work.calls == 1
    assert len(audit.records) == 1
    record = audit.records[0]
    assert record.success is False
    assert record.error_code == "DEPENDENCY_UNAVAILABLE"
    assert record.result["trace_id"] == "TRACE-unit-test"


@pytest.mark.asyncio
async def test_unexpected_work_failure_is_coded_and_audited_once() -> None:
    def broken_work(**_kwargs: object) -> list[object]:
        raise RuntimeError("private database connection string")

    audit = AuditSpy()
    tool = security_events.SecurityEventTools(
        context=SimpleNamespace(
            run_id="AR-unit-test",
            incident_id="IN-unit-test",
            trace_id="TRACE-unit-test",
        ),
        work=broken_work,
        audit=audit,
    )
    start = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)

    with pytest.raises(security_events.ToolDependencyError, match="dependency unavailable"):
        await tool.search_security_events(
            start, start + timedelta(minutes=5), {}, limit=2
        )

    assert len(audit.records) == 1
    assert audit.records[0].error_code == "DEPENDENCY_UNAVAILABLE"
    assert "private database connection string" not in audit.records[0].result["reason"]
