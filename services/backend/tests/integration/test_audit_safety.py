from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select

from evidencesoc.config import Settings
from evidencesoc.ids import new_ulid
from evidencesoc.mcp_server.context import RunContext
from evidencesoc.mcp_server.restricted import RestrictedFastMCP
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.json_encoding import restore_json
from evidencesoc.persistence.tables import (
    AgentRunTable,
    AlertTable,
    IncidentTable,
    ToolCallTable,
)
from evidencesoc.tools.attack import AttackTools
from evidencesoc.tools.audit_sql import SqlAuditWriter


@pytest.mark.asyncio
async def test_denials_and_business_calls_audit_untrusted_text_in_postgresql() -> None:
    suffix = new_ulid()
    alert_id = f"AL-{suffix}"
    incident_id = f"IN-{suffix}"
    run_id = f"AR-{suffix}"
    context = RunContext(run_id, incident_id, f"TRACE-{suffix}")
    engine = create_database_engine(Settings().database_url)
    sessions = create_session_factory(engine)
    now = datetime.now(UTC)

    try:
        with sessions() as session:
            session.add(
                AlertTable(
                    alert_id=alert_id,
                    title="Task 6 audit test",
                    severity="info",
                    created_at=now,
                    event_ids=[],
                )
            )
            session.flush()
            session.add(
                IncidentTable(
                    incident_id=incident_id,
                    alert_id=alert_id,
                    status="received",
                    created_at=now,
                )
            )
            session.flush()
            session.add(
                AgentRunTable(
                    run_id=run_id,
                    incident_id=incident_id,
                    agent_name="task6-audit-test",
                    status="running",
                    started_at=now,
                    evidence_ids=[],
                )
            )
            session.commit()

        try:
            audit = SqlAuditWriter(session_factory=sessions)
            server = RestrictedFastMCP(context=context, boundary_audit=audit)
            long_name = "run_shell_" + "x" * 140
            nul_name = "run\x00shell"
            nul_argument = "part\x00two"

            for name, arguments in (
                (long_name, {}),
                (nul_name, {"query": nul_argument}),
            ):
                denied = await server.call_tool(name, arguments)
                assert denied.isError is True
                assert denied.structuredContent["error"]["code"] == "POLICY_DENIED"

            attack = AttackTools(
                context=context,
                work=lambda **_kwargs: [],
                audit=audit,
            )
            assert await attack.lookup_attack_technique(nul_argument) == []

            with sessions() as session:
                records = session.execute(
                    select(ToolCallTable).where(ToolCallTable.run_id == run_id)
                ).scalars().all()

            assert len(records) == 3
            long_record = next(
                row
                for row in records
                if restore_json(row.result)["reason"] == "request denied"
                and restore_json(row.result).get("requested_tool_name") == long_name
            )
            assert len(long_record.tool_name) <= 128

            nul_record = next(
                row
                for row in records
                if restore_json(row.result).get("requested_tool_name") == nul_name
            )
            assert len(nul_record.tool_name) <= 128
            assert "\x00" not in nul_record.tool_name
            assert restore_json(nul_record.arguments) == {"query": nul_argument}

            business_record = next(
                row for row in records if row.tool_name == "lookup_attack_technique"
            )
            assert business_record.success is True
            assert restore_json(business_record.arguments) == {
                "query": nul_argument,
                "limit": 10,
            }
        finally:
            with sessions() as session:
                session.execute(
                    delete(ToolCallTable).where(ToolCallTable.run_id == run_id)
                )
                session.execute(
                    delete(AgentRunTable).where(AgentRunTable.run_id == run_id)
                )
                session.execute(
                    delete(IncidentTable).where(IncidentTable.incident_id == incident_id)
                )
                session.execute(
                    delete(AlertTable).where(AlertTable.alert_id == alert_id)
                )
                session.commit()
    finally:
        engine.dispose()
