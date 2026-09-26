from __future__ import annotations

from types import SimpleNamespace

import pytest

from evidencesoc.tools.attack import AttackTools
from evidencesoc.tools.errors import ToolDependencyError
from evidencesoc.tools.policy import PolicyDeniedError

CONTEXT = SimpleNamespace(
    run_id="AR-attack-test",
    incident_id="IN-attack-test",
    trace_id="TRACE-attack-test",
)

ATTACK_RESULT = {
    "knowledge_chunk_id": "KC-T1190",
    "technique_id": "T1190",
    "title": "Exploit Public-Facing Application",
    "summary": "Adversaries may exploit an internet-facing application.",
    "source_uri": "https://attack.mitre.org/techniques/T1190/",
    "version": "19.2",
}


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
async def test_attack_lookup_returns_stable_records_and_audits() -> None:
    work = WorkSpy([ATTACK_RESULT])
    audit = AuditSpy()
    tool = AttackTools(context=CONTEXT, work=work, audit=audit)

    assert await tool.lookup_attack_technique("T1190", limit=10) == [ATTACK_RESULT]
    assert work.calls == [{"query": "T1190", "limit": 10}]
    assert audit.records[0].result == {
        "trace_id": CONTEXT.trace_id,
        "result_count": 1,
    }


@pytest.mark.asyncio
async def test_unknown_technique_returns_empty_without_fabrication() -> None:
    tool = AttackTools(context=CONTEXT, work=WorkSpy([]), audit=AuditSpy())
    assert await tool.lookup_attack_technique("T9999", 10) == []


@pytest.mark.asyncio
async def test_attack_policy_denial_precedes_work() -> None:
    work = WorkSpy([])
    audit = AuditSpy()
    tool = AttackTools(context=CONTEXT, work=work, audit=audit)

    with pytest.raises(PolicyDeniedError):
        await tool.lookup_attack_technique(" ", 10)

    assert work.calls == []
    assert audit.records[0].error_code == "POLICY_DENIED"


@pytest.mark.asyncio
async def test_attack_lookup_rejects_malformed_dependency_results() -> None:
    tool = AttackTools(
        context=CONTEXT,
        work=WorkSpy([{"technique_id": "T1190"}]),
        audit=AuditSpy(),
    )

    with pytest.raises(ToolDependencyError, match="invalid results"):
        await tool.lookup_attack_technique("T1190")
