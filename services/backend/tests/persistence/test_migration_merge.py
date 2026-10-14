"""Keep the Task 10 schema history and the investigation ledger on one graph."""

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from evidencesoc.api.tables import ApiBase
from evidencesoc.persistence.tables import Base
from sqlalchemy import JSON, Column, MetaData, String, Table, create_engine
from sqlalchemy.dialects.postgresql import JSONB

BACKEND = Path(__file__).resolve().parents[2]
MERGE_REVISION = "e902c4b7a1d6"


def test_task10_and_ledger_revisions_merge_without_rewriting_history() -> None:
    script = ScriptDirectory.from_config(Config(str(BACKEND / "alembic.ini")))

    assert script.get_heads() == [MERGE_REVISION]
    assert script.get_revision("c0e8c2a18a7d").down_revision == "b6d091c3e217"
    assert script.get_revision("d7b7d8cb8b42").down_revision == "c0e8c2a18a7d"
    assert script.get_revision("f3f8c2a59010").down_revision == "d7b7d8cb8b42"
    assert script.get_revision("c74a62f911ab").down_revision == "b6d091c3e217"
    assert set(script.get_revision(MERGE_REVISION).down_revision) == {
        "f3f8c2a59010",
        "c74a62f911ab",
    }


def test_metadata_covers_both_branches_of_the_migration_graph() -> None:
    response_plan = Base.metadata.tables["response_plans"]
    assert {
        "execution_mode",
        "risk_level",
        "risk_reason",
        "affected_assets",
        "business_impact",
        "expires_at",
        "rollback_steps",
        "validation_checks",
    } <= set(response_plan.columns.keys())
    assert response_plan.c.execution_mode.server_default is not None
    for name in ("affected_assets", "rollback_steps", "validation_checks"):
        assert response_plan.c[name].server_default is not None

    validation = Base.metadata.tables["validation_results"]
    assert {"time_from", "time_to", "checks"} <= set(validation.columns.keys())
    assert validation.c.checks.server_default is not None

    assert {
        "key",
        "plan_id",
        "payload_sha256",
        "accepted_response",
    } <= set(ApiBase.metadata.tables["api_decision_receipts"].columns.keys())
    assert "investigation_tool_calls" in Base.metadata.tables
    assert "query_fingerprint" in Base.metadata.tables["evidence_items"].columns
    assert "output_summary" in Base.metadata.tables["agent_runs"].columns


def test_task10_metadata_can_be_cloned_for_sqlite_tests() -> None:
    metadata = MetaData()
    Table("incidents", metadata, Column("incident_id", String(64), primary_key=True))
    for name in ("response_plans", "validation_results"):
        table = Base.metadata.tables[name].to_metadata(metadata)
        for column in table.columns:
            if isinstance(column.type, JSONB):
                column.type = JSON()
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        metadata.create_all(engine)
    finally:
        engine.dispose()
