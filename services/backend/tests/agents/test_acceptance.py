from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import delete, select

from evidencesoc.agents.checkpoint import open_checkpointer
from evidencesoc.agents.graph import InvestigationWorkflow, open_workflow
from evidencesoc.agents.nodes import NodeHandlers
from evidencesoc.agents.services import PostgresWorkflowServices
from evidencesoc.config import Settings
from evidencesoc.ids import new_event_id, new_ulid
from evidencesoc.ingestion.jsonl import ParsedLogRecord
from evidencesoc.ingestion.normalize import normalize_record
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.event_repository import EventRepository
from evidencesoc.persistence.event_search import (
    OpenSearchEventStore,
    create_opensearch_client,
)
from evidencesoc.persistence.tables import (
    AgentRunTable,
    AlertTable,
    ApprovalTable,
    IncidentTable,
    ResponsePlanTable,
    SecurityEventTable,
    ToolCallTable,
    ValidationResultTable,
)

ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture
def live_incident():
    suffix = new_ulid()
    incident_id, alert_id = f"IN-{suffix}", f"AL-{suffix}"
    index = f"security-events-task8-{suffix.lower()}"
    settings = Settings(llm_mode="fixture", opensearch_index=index)
    engine = create_database_engine(settings.database_url)
    sessions = create_session_factory(engine)
    client = create_opensearch_client(settings.opensearch_url)
    event_ids = []
    try:
        template = json.loads(
            (ROOT / "infra/opensearch/security-events-template.json").read_text(
                encoding="utf-8"
            )
        )
        client.indices.create(index=index, body=template["template"])
        store = OpenSearchEventStore(client, index_name=index)
        for offset, line in enumerate(
            (ROOT / "data/samples/sql-injection.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ):
            raw = json.loads(line)
            raw["external_id"] = f"task8-{suffix}-{offset}"
            raw["host"] = f"task8-{suffix.lower()}.example.test"
            raw["username"] = "task8-demo-user"
            raw["labels"] = ["forbidden-truth"]
            event = normalize_record(
                ParsedLogRecord(raw, "task8-acceptance", offset + 1),
                event_id=new_event_id(),
                ingested_at=datetime.now(UTC),
            )
            with sessions() as session:
                EventRepository(session).register(event)
                session.commit()
            event_ids.append(event.event_id)
            store.index_event(event)
        client.indices.refresh(index=index)
        with sessions() as session:
            session.add(
                AlertTable(
                    alert_id=alert_id,
                    title="SQL injection demonstration",
                    severity="high",
                    created_at=datetime(2026, 9, 21, 10, 20, 17, tzinfo=UTC),
                    event_ids=event_ids,
                )
            )
            session.flush()
            session.add(
                IncidentTable(
                    incident_id=incident_id,
                    alert_id=alert_id,
                    status="received",
                    created_at=datetime.now(UTC),
                )
            )
            session.commit()
        yield settings, incident_id, sessions
    finally:
        with sessions() as session:
            session.execute(
                delete(IncidentTable).where(IncidentTable.incident_id == incident_id)
            )
            session.execute(delete(AlertTable).where(AlertTable.alert_id == alert_id))
            session.execute(
                delete(SecurityEventTable).where(
                    SecurityEventTable.event_id.in_(event_ids)
                )
            )
            session.commit()
        if client.indices.exists(index=index):
            client.indices.delete(index=index)
        client.close()
        engine.dispose()


CHILD_CODE = """
import asyncio, json, sys
from evidencesoc.agents.graph import open_workflow
from evidencesoc.config import Settings
async def main():
    settings = Settings(llm_mode='fixture', opensearch_index=sys.argv[2])
    async with open_workflow(settings) as workflow:
        state = await workflow.run_investigation(sys.argv[1])
        if sys.argv[3] == 'approve':
            state = await workflow.approve(sys.argv[1], response_plan_id=state['response_plan']['response_plan_id'],
                decision='approved', reason='Task8 reviewed simulation', decided_by='acceptance-reviewer')
        print(json.dumps(state, ensure_ascii=True))
asyncio.run(main())
"""


async def child(incident_id, index, action):
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-B",
        "-c",
        CHILD_CODE,
        incident_id,
        index,
        action,
        cwd=ROOT / "services/backend",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=90)
    except BaseException:
        process.kill()
        await process.wait()
        raise
    assert process.returncode == 0, (
        f"workflow process failed: {stderr.decode(errors='replace')[-1500:]}"
    )
    return json.loads(stdout)


@pytest.mark.asyncio
async def test_real_mcp_six_roles_and_postgres_resume_in_fresh_process(live_incident):
    settings, incident_id, sessions = live_incident
    try:
        before = await child(incident_id, settings.opensearch_index, "run")
        assert before["status"] == "awaiting_approval", before.get("errors")
        assert before["fallback_used"] is True
        assert not before["simulation"] and before["approval"] is None
        assert before["origin"]["observed_source_ip"] == "203.0.113.42"
        assert before["classification"]["primary_type"] == "sql_injection"
        assert before["classification"]["technique_ids"] == ["T1190"]
        assert before["attack_steps"] and all(
            step["evidence_ids"] for step in before["attack_steps"]
        )
        assert "forbidden-truth" not in json.dumps(before)
        after = await child(incident_id, settings.opensearch_index, "approve")
        assert after["status"] == "completed", after.get("errors")
        assert after["trace_id"] == before["trace_id"]
        assert after["response_plan"] == before["response_plan"]
        assert after["validation_result"]["outcome"] == "success"
        assert "simulation only" in after["validation_result"]["summary"]
        async with open_workflow(settings) as recovered:
            replay = await recovered.run_investigation(incident_id)
            assert replay["simulation"] == after["simulation"]
            with pytest.raises(ValueError):
                await recovered.approve(
                    incident_id,
                    response_plan_id=after["response_plan"]["response_plan_id"],
                    decision="approved",
                    reason="duplicate",
                    decided_by="reviewer",
                )
        with sessions() as session:
            runs = session.scalars(
                select(AgentRunTable).where(AgentRunTable.incident_id == incident_id)
            ).all()
            assert len(runs) == 6 and all(run.status == "completed" for run in runs)
            calls = session.scalars(
                select(ToolCallTable).where(
                    ToolCallTable.run_id.in_([run.run_id for run in runs])
                )
            ).all()
            assert {call.tool_name for call in calls} == {
                "search_security_events",
                "get_alert_context",
                "lookup_attack_technique",
            }
            assert all(call.success for call in calls)
            plan_id = after["response_plan"]["response_plan_id"]
            assert session.get(IncidentTable, incident_id).status == "completed"
            assert session.get(ResponsePlanTable, plan_id) is not None
            assert (
                len(
                    session.scalars(
                        select(ApprovalTable).where(
                            ApprovalTable.response_plan_id == plan_id
                        )
                    ).all()
                )
                == 1
            )
            assert (
                len(
                    session.scalars(
                        select(ValidationResultTable).where(
                            ValidationResultTable.response_plan_id == plan_id
                        )
                    ).all()
                )
                == 1
            )
    finally:
        async with open_checkpointer(settings.database_url) as saver:
            await saver.adelete_thread(incident_id)


@pytest.mark.asyncio
async def test_all_three_simulated_actions_validate_with_real_scoped_queries(
    live_incident,
):
    settings, incident_id, _sessions = live_incident

    class ThreeActions(NodeHandlers):
        async def respond(self, state):
            delta = await super().respond(state)
            plan = delta["response_plan"]
            template = plan["actions"][0]
            host = state["origin"]["entry_host"]
            plan["actions"].extend(
                [
                    {
                        **template,
                        "action": "isolate_host_simulated",
                        "target": host,
                        "verification_query": {"filters": {"host": host}, "limit": 10},
                    },
                    {
                        **template,
                        "action": "disable_account_simulated",
                        "target": "task8-demo-user",
                        "verification_query": {"filters": {"host": host}, "limit": 5},
                    },
                ]
            )
            return delta

    services = PostgresWorkflowServices(settings)
    try:
        async with open_checkpointer(settings.database_url) as saver:
            workflow = InvestigationWorkflow(
                services=services,
                settings=settings,
                checkpointer=saver,
                nodes=ThreeActions(services, settings),
                database_url=settings.database_url,
            )
            try:
                before = await workflow.run_investigation(incident_id)
                assert before["status"] == "awaiting_approval"
                after = await workflow.approve(
                    incident_id,
                    response_plan_id=before["response_plan"]["response_plan_id"],
                    decision="approved",
                    reason="reviewed all three previews",
                    decided_by="reviewer",
                )
                assert after["status"] == "completed", after.get("errors")
                assert after["validation_result"]["outcome"] == "success"
                assert len(after["simulation"]) == 3
                assert all(action["simulated"] for action in after["simulation"])
            finally:
                await saver.adelete_thread(incident_id)
    finally:
        services.close()
