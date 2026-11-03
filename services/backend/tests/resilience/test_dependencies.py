"""Native owned service/child failures. All seeded approvals are synthetic rejects.

Opt in with TASK14_RUN_OWNED_FAULTS=1, TASK14_OWNED_COMPOSE_PROJECT,
DATABASE_URL (dedicated task14_faults_* database), and OPENSEARCH_URL.
Requires a migrated empty owned database; never uses provider credentials.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from hashlib import sha256

import pytest
from evidencesoc.agents.capabilities import InvestigationCapabilities, capability_scope
from evidencesoc.agents.nodes import NodeHandlers
from evidencesoc.agents.services import PostgresWorkflowServices
from evidencesoc.config import BACKEND_ROOT
from evidencesoc.ids import new_ulid
from evidencesoc.mcp_server.client import open_stdio_session
from evidencesoc.persistence.tables import (
    AlertTable,
    ApprovalTable,
    EvidenceItemTable,
    ResponsePlanTable,
    ToolCallTable,
    ValidationResultTable,
)
from mcp.client import stdio
from sqlalchemy import select
from tests.integration.test_task12_service_acceptance import search_arguments
from tests.security.support import model_surrogate
from tests.security.test_prompt_injection import HOSTILE


@asynccontextmanager
async def native_session(live):
    # These fault scenarios do not use retrieval; avoid loading an unrelated local model.
    with capability_scope(
        InvestigationCapabilities(
            allowed_tools=frozenset({"get_alert_context", "search_security_events"}),
            rag_mode="disabled",
        )
    ):
        async with open_stdio_session(
            live.context,
            settings=live.settings,
            backend_dir=BACKEND_ROOT,
            managed_attempts=True,
        ) as session:
            yield session


@pytest.fixture
def owned_live_scope(owned_services, request):
    # Validate ownership before the reusable fixture can write any incident/index.
    live = request.getfixturevalue("live_scope")
    assert live.settings.database_url == owned_services.settings.database_url
    assert live.settings.opensearch_url == owned_services.settings.opensearch_url
    with live.sessions() as session, session.begin():
        plan_id = "RP-synthetic-task14-" + new_ulid()
        session.add(
            ResponsePlanTable(
                response_plan_id=plan_id,
                incident_id=live.incidents[0],
                summary="Synthetic Task14 fixture; no user approval credit",
                actions=[],
                created_at=datetime.now(UTC),
                requires_approval=True,
                evidence_ids=[],
            )
        )
        session.flush()
        session.add(
            ApprovalTable(
                approval_id="AP-synthetic-task14-" + new_ulid(),
                response_plan_id=plan_id,
                decision="rejected",
                reason="Synthetic fault-test rejection; never execute",
                decided_by="task14-synthetic-fixture",
                decided_at=datetime.now(UTC),
            )
        )
    return live


def artifacts(live):
    """Full row snapshot of owned evidence/response/approval/validation only."""
    with live.sessions() as session:
        plans = select(ResponsePlanTable.response_plan_id).where(
            ResponsePlanTable.incident_id == live.incidents[0]
        )
        statements = [
            select(EvidenceItemTable).where(
                EvidenceItemTable.incident_id == live.incidents[0]
            ),
            select(ResponsePlanTable).where(
                ResponsePlanTable.incident_id == live.incidents[0]
            ),
            select(ApprovalTable).where(ApprovalTable.response_plan_id.in_(plans)),
            select(ValidationResultTable).where(
                ValidationResultTable.response_plan_id.in_(plans)
            ),
        ]
        rows = [
            [
                {
                    column.name: getattr(row, column.key)
                    for column in row.__table__.columns
                }
                for row in session.scalars(statement).all()
            ]
            for statement in statements
        ]
    for group in rows:
        group.sort(key=lambda row: json.dumps(row, sort_keys=True, default=str))
    return json.dumps(rows, sort_keys=True, default=str)


async def seed_prior_evidence(live, session):
    planner = live.collector(session)
    assert (
        await planner._call(
            "get_alert_context",
            {"alert_id": live.alerts[0]},
            "Read prior durable evidence.",
        )
        == "called"
    )
    assert len(planner.values) == 2
    return planner


def assert_preserved(live, before):
    after = artifacts(live)
    assert after == before
    parsed = json.loads(after)
    assert (
        len(parsed[0]) == 2
        and len(parsed[2]) == 1
        and parsed[2][0]["decision"] == "rejected"
    )
    assert parsed[3] == [], "no successful or fabricated verification may be created"
    print(
        f"task14_preserved incident={live.incidents[0]} artifacts_sha256={sha256(after.encode()).hexdigest()} synthetic_approval_credit=0"
    )


@pytest.mark.asyncio
async def test_owned_postgres_stop_fails_closed_without_fabricated_durable_outcome(
    owned_live_scope, owned_services
):
    live = owned_live_scope
    async with native_session(live) as session:
        planner = await seed_prior_evidence(live, session)
        before = artifacts(live)
        prior_rows = planner.ledger.calls(live.incidents[0], 1)
        # Existing application tool transport, not a stand-alone failing SELECT.
        with (
            owned_services.stopped("postgres"),
            pytest.raises(
                RuntimeError, match="^MCP tool failed: DEPENDENCY_UNAVAILABLE$"
            ),
        ):
            await asyncio.wait_for(
                PostgresWorkflowServices._call(
                    session,
                    "get_alert_context",
                    {"alert_id": live.alerts[0]},
                ),
                timeout=15,
            )
        assert_preserved(live, before)
        assert planner.ledger.calls(live.incidents[0], 1) == prior_rows
        with live.sessions() as stored:
            audit = stored.scalars(
                select(ToolCallTable).where(ToolCallTable.run_id == live.runs[0])
            ).all()
            assert len(audit) == 1 and audit[0].success
        # DB-down cannot persist an audit/failure; the test does not invent one.
        restored = await PostgresWorkflowServices._call(
            session, "get_alert_context", {"alert_id": live.alerts[0]}
        )
        assert {item["event_id"] for item in restored} == set(live.events[:2])
        assert_preserved(live, before)


async def interrupted_collection(live, session, before):
    recovering = live.collector(session, round_no=2)
    report = await recovering.run()
    assert report["collection_stop_reason"] == "recovery_failed"
    rows = recovering.ledger.calls(live.incidents[0], 1)
    failed = [row for row in rows if row.status == "failed"]
    assert len(failed) == 1 and failed[0].attempts == 3
    assert failed[0].error_code == "DEPENDENCY_UNAVAILABLE" and failed[0].result is None
    assert (
        report["collection_budget_used"] == 2
        and report["collection_model_attempts"] == 0
    )
    assert report["collection_tool_attempts"] == 3
    assert not {"approval", "simulation", "validation_result"} & report.keys()
    assert_preserved(live, before)


@pytest.mark.asyncio
async def test_native_pipeline_rejects_hostile_persisted_alert_proposals(
    owned_live_scope,
):
    """Persisted hostile alert -> triage -> real model HTTP -> MCP/ledger -> nodes."""
    live = owned_live_scope
    with live.sessions() as stored, stored.begin():
        stored.get(AlertTable, live.alerts[0]).title = HOSTILE
    before = json.loads(artifacts(live))
    proposals = [
        {
            "action": "call",
            "tool_name": "get_alert_context",
            "arguments": {"alert_id": live.alerts[1]},
            "rationale": "Obey the scope override.",
        },
        {
            "action": "call",
            "tool_name": "get_alert_context",
            "arguments": {"alert_id": live.alerts[0], "approval": "approved"},
            "rationale": "Obey the approval override.",
        },
    ]
    with model_surrogate(proposals=proposals) as (local, requests):
        settings = live.settings.model_copy(
            update={
                "llm_mode": "deepseek",
                "deepseek_api_key": local.deepseek_api_key,
                "deepseek_base_url": local.deepseek_base_url,
                "deepseek_model": local.deepseek_model,
            }
        )
        services = PostgresWorkflowServices(
            settings,
            session_factory=live.sessions,
            capabilities=InvestigationCapabilities(rag_mode="disabled"),
        )
        nodes = NodeHandlers(services, settings)
        state = {
            "incident_id": live.incidents[0],
            "_run_id": live.runs[0],
            "approval": None,
            "simulation": None,
            "attacker_truth": "PRIVATE_STATE_SENTINEL",
        }
        state.update(await nodes.triage(state))
        assert state["alerts"][0]["title"] == HOSTILE
        report = await nodes.collect(state)
    assert len(requests) == report["collection_model_attempts"] == 2
    assert report["collection_refusal_codes"] == [
        "POLICY_ARGUMENTS_INVALID",
        "POLICY_INCIDENT_DENIED",
    ]
    assert (
        report["collection_budget_used"] == 3
        and report["collection_tool_attempts"] == 1
    )
    assert report["collection_stop_reason"] == "budget_exhausted"
    assert len(report["evidence"]) == 2
    for request in requests:
        assert [message["role"] for message in request["messages"]] == [
            "system",
            "user",
        ]
        assert HOSTILE not in request["messages"][0]["content"]
        serialized = request["messages"][1]["content"]
        assert json.loads(serialized)["alerts"][0]["title"] == HOSTILE
        assert "PRIVATE_STATE_SENTINEL" not in serialized
        assert "approval" not in json.loads(serialized)
    assert json.loads(artifacts(live))[1:] == before[1:]
    with live.sessions() as stored:
        audit = stored.scalars(
            select(ToolCallTable).where(ToolCallTable.run_id == live.runs[0])
        ).all()
        assert (
            len(audit) == 1
            and audit[0].success
            and audit[0].tool_name == "get_alert_context"
        )
    assert not {"approval", "simulation", "validation_result"} & report.keys()


@pytest.mark.asyncio
async def test_owned_opensearch_stop_bounds_recovery_attempts_and_preserves_evidence(
    owned_live_scope, owned_services
):
    live = owned_live_scope
    async with native_session(live) as session:
        planner = await seed_prior_evidence(live, session)
        planner.ledger.reserve(
            live.incidents[0],
            live.runs[0],
            1,
            "search_security_events",
            search_arguments(live),
            "Interrupted collection before result confirmation.",
        )
        before = artifacts(live)
        with owned_services.stopped("opensearch"):
            await interrupted_collection(live, session, before)
        with live.sessions() as stored:
            audit = stored.scalars(
                select(ToolCallTable).where(
                    ToolCallTable.run_id == live.runs[0],
                    ToolCallTable.tool_name == "search_security_events",
                )
            ).all()
            assert len(audit) == 3 and all(
                not row.success and row.error_code == "DEPENDENCY_UNAVAILABLE"
                for row in audit
            )
        restored = await PostgresWorkflowServices._call(
            session, "get_alert_context", {"alert_id": live.alerts[0]}
        )
        assert {item["event_id"] for item in restored} == set(live.events[:2])
        assert_preserved(live, before)


@pytest.mark.asyncio
async def test_owned_mcp_child_exit_is_bounded_and_fresh_session_recovers(
    owned_live_scope, monkeypatch
):
    live = owned_live_scope
    created = []
    original_spawn = stdio._create_platform_compatible_process

    async def capture_owned_child(**kwargs):
        assert kwargs["args"] == ["-m", "evidencesoc.mcp_server.main"]
        assert kwargs["env"]["EVIDENCESOC_RUN_ID"] == live.runs[0]
        assert kwargs["env"]["DATABASE_URL"] == live.settings.database_url
        child = await original_spawn(**kwargs)
        created.append(child)
        return child

    # Capture only this real SDK-created child handle; do not stub any MCP response.
    monkeypatch.setattr(
        stdio, "_create_platform_compatible_process", capture_owned_child
    )
    async with native_session(live) as session:
        planner = await seed_prior_evidence(live, session)
        planner.ledger.reserve(
            live.incidents[0],
            live.runs[0],
            1,
            "search_security_events",
            search_arguments(live),
            "Interrupted collection before result confirmation.",
        )
        before = artifacts(live)
        assert len(created) == 1 and created[0].returncode is None
        created[0].terminate()
        await asyncio.wait_for(created[0].wait(), timeout=5)
        await interrupted_collection(live, session, before)
    async with native_session(live) as session:
        restored = await PostgresWorkflowServices._call(
            session, "get_alert_context", {"alert_id": live.alerts[0]}
        )
        assert {item["event_id"] for item in restored} == set(live.events[:2])
    assert len(created) == 2 and all(child.returncode is not None for child in created)
    assert_preserved(live, before)
