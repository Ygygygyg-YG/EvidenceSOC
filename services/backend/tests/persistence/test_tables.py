from importlib import import_module
from types import ModuleType

import pytest

MODULE_NAME = "evidencesoc.persistence.tables"

EXPECTED_TABLES = {
    "security_events",
    "alerts",
    "incidents",
    "evidence_items",
    "attack_steps",
    "agent_runs",
    "tool_calls",
    "investigation_tool_calls",
    "response_plans",
    "approvals",
    "validation_results",
    "knowledge_chunks",
    "evaluation_runs",
}


def tables_module() -> ModuleType:
    try:
        return import_module(MODULE_NAME)
    except ModuleNotFoundError as exc:
        if exc.name != MODULE_NAME:
            raise
        pytest.fail(f"{MODULE_NAME} 尚未创建")


def test_metadata_contains_all_required_tables() -> None:
    module = tables_module()

    assert hasattr(module, "Base"), "SQLAlchemy Base 尚未实现"
    assert set(module.Base.metadata.tables) == EXPECTED_TABLES


CORE_REQUIRED_COLUMNS = {
    "security_events": {
        "event_id",
        "source",
        "external_id",
        "deduplication_key",
        "observed_at",
        "ingested_at",
        "severity",
        "event_type",
        "raw",
        "content_sha256",
        "index_status",
        "indexed_at",
        "index_error",
    },
    "alerts": {
        "alert_id",
        "title",
        "severity",
        "created_at",
        "event_ids",
    },
    "incidents": {
        "incident_id",
        "alert_id",
        "status",
        "created_at",
    },
    "evidence_items": {
        "evidence_id",
        "incident_id",
        "source",
        "observed_at",
        "query",
        "query_fingerprint",
        "summary",
        "content_sha256",
        "event_id",
    },
    "response_plans": {
        "response_plan_id",
        "incident_id",
        "summary",
        "actions",
        "created_at",
        "requires_approval",
        "evidence_ids",
    },
    "approvals": {
        "approval_id",
        "response_plan_id",
        "decision",
        "reason",
        "decided_by",
        "decided_at",
    },
    "validation_results": {
        "validation_id",
        "response_plan_id",
        "outcome",
        "summary",
        "checked_at",
        "evidence_ids",
    },
}


EXPECTED_CORE_FOREIGN_KEYS = {
    ("incidents", "alert_id", "alerts.alert_id"),
    ("evidence_items", "incident_id", "incidents.incident_id"),
    (
        "evidence_items",
        "event_id",
        "security_events.event_id",
    ),
    (
        "response_plans",
        "incident_id",
        "incidents.incident_id",
    ),
    (
        "approvals",
        "response_plan_id",
        "response_plans.response_plan_id",
    ),
    (
        "validation_results",
        "response_plan_id",
        "response_plans.response_plan_id",
    ),
}


def test_core_tables_have_required_columns() -> None:
    module = tables_module()

    for table_name, required_columns in CORE_REQUIRED_COLUMNS.items():
        table = module.Base.metadata.tables[table_name]
        actual_columns = set(table.columns.keys())
        missing_columns = required_columns - actual_columns

        assert not missing_columns, f"{table_name} 缺少字段：{sorted(missing_columns)}"


def test_core_tables_have_required_foreign_keys() -> None:
    module = tables_module()
    actual_foreign_keys: set[tuple[str, str, str]] = set()

    for table in module.Base.metadata.tables.values():
        for foreign_key in table.foreign_keys:
            actual_foreign_keys.add(
                (
                    table.name,
                    foreign_key.parent.name,
                    foreign_key.target_fullname,
                )
            )

    assert EXPECTED_CORE_FOREIGN_KEYS <= actual_foreign_keys


SUPPORT_REQUIRED_COLUMNS = {
    "attack_steps": {
        "attack_step_id",
        "incident_id",
        "sequence",
        "phase",
        "technique_id",
        "description",
        "occurred_at",
        "evidence_ids",
    },
    "agent_runs": {
        "run_id",
        "incident_id",
        "agent_name",
        "status",
        "started_at",
        "finished_at",
        "evidence_ids",
        "output_summary",
    },
    "tool_calls": {
        "tool_call_id",
        "run_id",
        "tool_name",
        "arguments",
        "result",
        "started_at",
        "finished_at",
        "success",
        "error_code",
    },
    "investigation_tool_calls": {
        "call_id",
        "incident_id",
        "run_id",
        "round_no",
        "purpose",
        "fingerprint",
        "tool_name",
        "arguments",
        "rationale",
        "status",
        "attempts",
        "charged",
        "source_call_id",
        "result",
        "error_code",
        "created_at",
        "updated_at",
    },
    "knowledge_chunks": {
        "knowledge_chunk_id",
        "source",
        "content",
        "metadata",
        "embedding",
    },
    "evaluation_runs": {
        "evaluation_run_id",
        "dataset_name",
        "configuration",
        "metrics",
        "status",
        "started_at",
        "finished_at",
    },
}


EXPECTED_SUPPORT_FOREIGN_KEYS = {
    (
        "attack_steps",
        "incident_id",
        "incidents.incident_id",
    ),
    (
        "agent_runs",
        "incident_id",
        "incidents.incident_id",
    ),
    (
        "tool_calls",
        "run_id",
        "agent_runs.run_id",
    ),
    (
        "investigation_tool_calls",
        "incident_id",
        "incidents.incident_id",
    ),
    (
        "investigation_tool_calls",
        "run_id",
        "agent_runs.run_id",
    ),
    (
        "investigation_tool_calls",
        "source_call_id",
        "investigation_tool_calls.call_id",
    ),
}


def test_support_tables_have_required_columns() -> None:
    module = tables_module()

    for table_name, required_columns in SUPPORT_REQUIRED_COLUMNS.items():
        table = module.Base.metadata.tables[table_name]
        actual_columns = set(table.columns.keys())
        missing_columns = required_columns - actual_columns

        assert not missing_columns, f"{table_name} 缺少字段：{sorted(missing_columns)}"


def test_support_tables_have_required_foreign_keys() -> None:
    module = tables_module()
    actual_foreign_keys: set[tuple[str, str, str]] = set()

    for table in module.Base.metadata.tables.values():
        for foreign_key in table.foreign_keys:
            actual_foreign_keys.add(
                (
                    table.name,
                    foreign_key.parent.name,
                    foreign_key.target_fullname,
                )
            )

    assert EXPECTED_SUPPORT_FOREIGN_KEYS <= actual_foreign_keys


EXPECTED_CONSTRAINT_NAMES = {
    "security_events": {
        "ck_security_events_severity",
        "ck_security_events_content_sha256",
        "uq_security_events_source_deduplication_key",
        "ck_security_events_index_status",
    },
    "alerts": {
        "ck_alerts_severity",
    },
    "incidents": {
        "ck_incidents_status",
    },
    "evidence_items": {
        "ck_evidence_items_content_sha256",
        "uq_evidence_items_incident_event_query",
    },
    "attack_steps": {
        "uq_attack_steps_incident_sequence",
    },
    "agent_runs": {
        "ck_agent_runs_status",
        "ck_agent_runs_time_order",
    },
    "tool_calls": {
        "ck_tool_calls_time_order",
    },
    "investigation_tool_calls": {
        "ck_investigation_tool_calls_round",
        "ck_investigation_tool_calls_purpose",
        "ck_investigation_tool_calls_status",
        "ck_investigation_tool_calls_attempts",
    },
    "response_plans": {
        "ck_response_plans_requires_approval",
    },
    "approvals": {
        "ck_approvals_decision",
        "ck_approvals_reason_nonblank",
    },
    "validation_results": {
        "ck_validation_results_outcome",
    },
    "evaluation_runs": {
        "ck_evaluation_runs_status",
        "ck_evaluation_runs_time_order",
    },
}


def test_tables_define_required_database_constraints() -> None:
    module = tables_module()

    for table_name, expected_names in EXPECTED_CONSTRAINT_NAMES.items():
        table = module.Base.metadata.tables[table_name]
        actual_names = {
            constraint.name
            for constraint in table.constraints
            if constraint.name is not None
        }
        missing_names = expected_names - actual_names

        assert not missing_names, f"{table_name} 缺少约束：{sorted(missing_names)}"
