from __future__ import annotations

from types import SimpleNamespace

import pytest
from evidencesoc.domain.models import EvidenceItem
from evidencesoc.tools.alert_context import AlertContextTools
from evidencesoc.tools.errors import ToolDependencyError
from evidencesoc.tools.policy import PolicyDeniedError

CONTEXT = SimpleNamespace(
    run_id="AR-alert-test",
    incident_id="IN-alert-test",
    trace_id="TRACE-alert-test",
)


class WorkSpy:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return self.result


class AuditSpy:
    def __init__(self) -> None:
        self.records: list[object] = []

    def record(self, record: object) -> None:
        self.records.append(record)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alert_id", "before", "after"),
    [
        ("", 900, 900),
        ("AL-1", -1, 0),
        ("AL-1", 901, 0),
        ("AL-1", 0, -1),
        ("AL-1", 0, 901),
    ],
)
async def test_alert_policy_denial_precedes_work(
    alert_id: str,
    before: int,
    after: int,
) -> None:
    work = WorkSpy([])
    audit = AuditSpy()
    tool = AlertContextTools(context=CONTEXT, work=work, audit=audit)

    with pytest.raises(PolicyDeniedError):
        await tool.get_alert_context(alert_id, before, after)

    assert work.calls == []
    assert [record.error_code for record in audit.records] == ["POLICY_DENIED"]


@pytest.mark.asyncio
async def test_alert_context_delegates_incident_scope_and_audits() -> None:
    work = WorkSpy([])
    audit = AuditSpy()
    tool = AlertContextTools(context=CONTEXT, work=work, audit=audit)

    assert await tool.get_alert_context("AL-1", 300, 600) == []
    assert work.calls == [
        {
            "alert_id": "AL-1",
            "before_seconds": 300,
            "after_seconds": 600,
            "incident_id": "IN-alert-test",
        }
    ]
    assert audit.records[0].result == {
        "trace_id": "TRACE-alert-test",
        "result_count": 0,
    }


@pytest.mark.asyncio
async def test_alert_context_rejects_invalid_dependency_result() -> None:
    audit = AuditSpy()
    tool = AlertContextTools(
        context=CONTEXT,
        work=WorkSpy([object()]),
        audit=audit,
    )

    with pytest.raises(ToolDependencyError, match="invalid evidence"):
        await tool.get_alert_context("AL-1")

    assert len(audit.records) == 1
    assert audit.records[0].error_code == "DEPENDENCY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_alert_context_rejects_more_than_200_results() -> None:
    audit = AuditSpy()
    tool = AlertContextTools(
        context=CONTEXT,
        work=WorkSpy([object()] * 201),
        audit=audit,
    )

    with pytest.raises(ToolDependencyError, match="too many results"):
        await tool.get_alert_context("AL-1")

    assert len(audit.records) == 1
    assert audit.records[0].error_code == "DEPENDENCY_UNAVAILABLE"
    assert audit.records[0].result["result_count"] == 201


def test_alert_context_type_contract_is_importable() -> None:
    assert EvidenceItem.model_fields["event_id"].is_required()
