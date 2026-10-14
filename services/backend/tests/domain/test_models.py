from datetime import UTC, datetime, timedelta
from importlib import import_module
from typing import Any

import pytest
from pydantic import ValidationError

MODULE_NAME = "evidencesoc.domain.models"
NOW = datetime(2026, 9, 20, 10, 0, tzinfo=UTC)
EVIDENCE_ID = "EV-01ARZ3NDEKTSV4RRFFQ69G5FAV"


def model_class(name: str) -> type[Any]:
    """动态加载模型，让缺少模型表现为测试失败而不是收集错误。"""
    try:
        module = import_module(MODULE_NAME)
    except ModuleNotFoundError as exc:
        if exc.name != MODULE_NAME:
            raise
        pytest.fail(f"{MODULE_NAME} 尚未创建")

    assert hasattr(module, name), f"{name} 尚未实现"
    return getattr(module, name)


def test_security_event_rejects_invalid_severity() -> None:
    SecurityEvent = model_class("SecurityEvent")

    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="EVENT-001",
            source="nginx",
            external_id="request-001",
            observed_at=NOW,
            ingested_at=NOW,
            severity="urgent",
            event_type="http_request",
            raw={"method": "GET", "path": "/login"},
            content_sha256="a" * 64,
        )


def test_attack_origin_rejects_confidence_above_one() -> None:
    AttackOrigin = model_class("AttackOrigin")

    with pytest.raises(ValidationError):
        AttackOrigin(
            observed_source_ip="203.0.113.10",
            entry_host="web-01",
            entry_service="https",
            first_seen_at=NOW,
            source_scope="external",
            confidence=1.1,
            evidence_ids=[EVIDENCE_ID],
        )


def test_attack_origin_rejects_missing_evidence_ids() -> None:
    AttackOrigin = model_class("AttackOrigin")

    with pytest.raises(ValidationError):
        AttackOrigin(
            observed_source_ip="203.0.113.10",
            entry_host="web-01",
            entry_service="https",
            first_seen_at=NOW,
            source_scope="external",
            confidence=0.8,
            evidence_ids=[],
        )


def test_agent_run_rejects_invalid_time_order() -> None:
    AgentRun = model_class("AgentRun")

    with pytest.raises(ValidationError):
        AgentRun(
            run_id="RUN-001",
            incident_id="INC-001",
            agent_name="triage-agent",
            status="completed",
            started_at=NOW,
            finished_at=NOW - timedelta(minutes=1),
            evidence_ids=[EVIDENCE_ID],
        )


def test_approval_record_rejects_blank_reason() -> None:
    ApprovalRecord = model_class("ApprovalRecord")

    with pytest.raises(ValidationError):
        ApprovalRecord(
            approval_id="APPROVAL-001",
            response_plan_id="PLAN-001",
            decision="approved",
            reason="   ",
            decided_by="analyst-01",
            decided_at=NOW,
        )


def test_attack_origin_accepts_unknown_source_scope() -> None:
    AttackOrigin = model_class("AttackOrigin")

    origin = AttackOrigin(
        observed_source_ip=None,
        entry_host=None,
        entry_service=None,
        first_seen_at=None,
        source_scope="unknown",
        confidence=0.0,
        evidence_ids=[EVIDENCE_ID],
    )

    assert origin.source_scope == "unknown"


def test_attack_classification_supports_multiple_attack_types() -> None:
    AttackClassification = model_class("AttackClassification")

    classification = AttackClassification(
        primary_type="web_attack",
        attack_types=["sql_injection", "credential_access"],
        dataset_labels=[],
        attack_phase="initial_access",
        technique_ids=["T1190"],
        confidence=0.9,
        evidence_ids=[EVIDENCE_ID],
    )

    assert classification.attack_types == [
        "sql_injection",
        "credential_access",
    ]


def test_incident_status_defines_all_workflow_states() -> None:
    IncidentStatus = model_class("IncidentStatus")

    assert {status.value for status in IncidentStatus} == {
        "received",
        "triaged",
        "collecting",
        "analyzing",
        "reconstructing",
        "awaiting_approval",
        "simulating",
        "validating",
        "completed",
        "failed",
        "manual_review",
        "rejected",
    }


def test_incident_defaults_to_received() -> None:
    Incident = model_class("Incident")
    IncidentStatus = model_class("IncidentStatus")

    incident = Incident(
        incident_id="INC-001",
        alert_id="ALERT-001",
        created_at=NOW,
    )

    assert incident.status is IncidentStatus.RECEIVED


def test_incident_accepts_analyzing_status() -> None:
    Incident = model_class("Incident")
    IncidentStatus = model_class("IncidentStatus")

    incident = Incident(
        incident_id="INC-001",
        alert_id="ALERT-001",
        status="analyzing",
        created_at=NOW,
    )

    assert incident.status is IncidentStatus.ANALYZING


def test_incident_rejects_invalid_status() -> None:
    Incident = model_class("Incident")

    with pytest.raises(ValidationError) as exc_info:
        Incident(
            incident_id="INC-001",
            alert_id="ALERT-001",
            status="invalid-status",
            created_at=NOW,
        )

    assert any(error["loc"] == ("status",) for error in exc_info.value.errors())


def test_evidence_item_contains_audit_information() -> None:
    EvidenceItem = model_class("EvidenceItem")

    evidence = EvidenceItem(
        evidence_id=EVIDENCE_ID,
        event_id="EVENT-001",
        source="nginx",
        observed_at=NOW,
        query={"event_id": "EVENT-001"},
        summary="发现异常登录请求",
        content_sha256="a" * 64,
    )

    assert evidence.evidence_id == EVIDENCE_ID

    assert evidence.event_id == "EVENT-001"
    assert evidence.query == {"event_id": "EVENT-001"}
    assert evidence.content_sha256 == "a" * 64


def test_evidence_item_rejects_missing_evidence_id() -> None:
    EvidenceItem = model_class("EvidenceItem")

    with pytest.raises(ValidationError) as exc_info:
        EvidenceItem(
            event_id="EVENT-001",
            source="nginx",
            observed_at=NOW,
            query={"event_id": "EVENT-001"},
            summary="发现异常登录请求",
            content_sha256="a" * 64,
        )

    assert any(error["loc"] == ("evidence_id",) for error in exc_info.value.errors())


def test_evidence_item_rejects_invalid_sha256() -> None:
    EvidenceItem = model_class("EvidenceItem")

    with pytest.raises(ValidationError) as exc_info:
        EvidenceItem(
            evidence_id=EVIDENCE_ID,
            event_id="EVENT-001",
            source="nginx",
            observed_at=NOW,
            query={"event_id": "EVENT-001"},
            summary="发现异常登录请求",
            content_sha256="not-a-sha256",
        )

    assert any(error["loc"] == ("content_sha256",) for error in exc_info.value.errors())


def test_alert_accepts_valid_data() -> None:
    Alert = model_class("Alert")
    Severity = model_class("Severity")

    alert = Alert(
        alert_id="ALERT-001",
        title="检测到疑似 SQL 注入",
        severity="high",
        created_at=NOW,
        event_ids=["EVENT-001", "EVENT-002"],
    )

    assert alert.severity is Severity.HIGH
    assert alert.event_ids == ["EVENT-001", "EVENT-002"]


def test_alert_rejects_empty_event_ids() -> None:
    Alert = model_class("Alert")

    with pytest.raises(ValidationError) as exc_info:
        Alert(
            alert_id="ALERT-001",
            title="检测到疑似 SQL 注入",
            severity="high",
            created_at=NOW,
            event_ids=[],
        )

    assert any(error["loc"] == ("event_ids",) for error in exc_info.value.errors())


def test_response_plan_requires_approval_by_default() -> None:
    ResponsePlan = model_class("ResponsePlan")

    plan = ResponsePlan(
        response_plan_id="PLAN-001",
        incident_id="INC-001",
        summary="阻断恶意来源并验证服务可用性",
        actions=[
            {
                "action": "block_ip_simulated",
                "target": "203.0.113.10",
                "risk": "Shared source address",
                "impact": "Simulation only",
                "preview": "Simulate a block",
                "rollback": "Remove the simulated block",
                "verification_query": {"filters": {"source_ip": "203.0.113.10"}},
            }
        ],
        created_at=NOW,
        evidence_ids=[EVIDENCE_ID],
    )

    assert plan.requires_approval is True
    assert plan.actions[0].action == "block_ip_simulated"
    assert plan.model_dump(mode="json")["actions"][0]["target"] == "203.0.113.10"


@pytest.mark.parametrize(
    "action",
    [
        {"action": "block_ip", "target": "203.0.113.10"},
        {"action": "block_ip_simulated", "target": "203.0.113.10"},
        {
            "action": "block_ip_simulated",
            "target": "203.0.113.10",
            "risk": "Shared source address",
            "impact": "Simulation only",
            "preview": "Simulate a block",
            "rollback": "Remove the simulated block",
            "verification_query": {"filters": {"source_ip": "203.0.113.11"}},
        },
    ],
)
def test_response_plan_rejects_invalid_simulated_actions(
    action: dict[str, Any],
) -> None:
    ResponsePlan = model_class("ResponsePlan")

    with pytest.raises(ValidationError) as exc_info:
        ResponsePlan(
            response_plan_id="PLAN-001",
            incident_id="INC-001",
            summary="Simulation only",
            actions=[action],
            created_at=NOW,
            evidence_ids=[EVIDENCE_ID],
        )

    assert any(error["loc"][:2] == ("actions", 0) for error in exc_info.value.errors())


def test_response_plan_rejects_empty_actions() -> None:
    ResponsePlan = model_class("ResponsePlan")

    with pytest.raises(ValidationError) as exc_info:
        ResponsePlan(
            response_plan_id="PLAN-001",
            incident_id="INC-001",
            summary="没有处置动作",
            actions=[],
            created_at=NOW,
            evidence_ids=[EVIDENCE_ID],
        )

    assert any(error["loc"] == ("actions",) for error in exc_info.value.errors())


def test_response_plan_rejects_missing_evidence_ids() -> None:
    ResponsePlan = model_class("ResponsePlan")

    with pytest.raises(ValidationError) as exc_info:
        ResponsePlan(
            response_plan_id="PLAN-001",
            incident_id="INC-001",
            summary="阻断恶意来源",
            actions=[
                {
                    "type": "block_ip",
                    "target": "203.0.113.10",
                }
            ],
            created_at=NOW,
            evidence_ids=[],
        )

    assert any(error["loc"] == ("evidence_ids",) for error in exc_info.value.errors())


def test_response_plan_cannot_disable_approval() -> None:
    ResponsePlan = model_class("ResponsePlan")

    with pytest.raises(ValidationError) as exc_info:
        ResponsePlan(
            response_plan_id="PLAN-001",
            incident_id="INC-001",
            summary="阻断恶意来源",
            actions=[
                {
                    "type": "block_ip",
                    "target": "203.0.113.10",
                }
            ],
            created_at=NOW,
            requires_approval=False,
            evidence_ids=[EVIDENCE_ID],
        )

    assert any(
        error["loc"] == ("requires_approval",) for error in exc_info.value.errors()
    )


def test_validation_outcome_defines_all_results() -> None:
    ValidationOutcome = model_class("ValidationOutcome")

    assert {outcome.value for outcome in ValidationOutcome} == {
        "success",
        "failure",
        "insufficient_evidence",
    }


def test_validation_result_accepts_success() -> None:
    ValidationOutcome = model_class("ValidationOutcome")
    ValidationResult = model_class("ValidationResult")

    result = ValidationResult(
        validation_id="VALIDATION-001",
        response_plan_id="PLAN-001",
        outcome="success",
        summary="恶意请求已被阻断，正常服务仍然可用",
        checked_at=NOW,
        evidence_ids=[EVIDENCE_ID],
    )

    assert result.outcome is ValidationOutcome.SUCCESS
    assert result.evidence_ids == [EVIDENCE_ID]
    assert result.time_from is None and result.time_to is None
    assert result.checks == []


def test_validation_result_records_actual_query_window_and_check_outcome() -> None:
    ValidationResult = model_class("ValidationResult")
    result = ValidationResult(
        validation_id="VALIDATION-002",
        response_plan_id="PLAN-001",
        outcome="insufficient_evidence",
        summary="No matching event returned.",
        checked_at=NOW,
        evidence_ids=[EVIDENCE_ID],
        time_from=NOW - timedelta(minutes=5),
        time_to=NOW,
        checks=[
            {
                "check_id": "VC-1",
                "condition": {
                    "time_from": (NOW - timedelta(minutes=5)).isoformat(),
                    "time_to": NOW.isoformat(),
                    "filters": {"source_ip": "203.0.113.42"},
                    "limit": 10,
                },
                "outcome": "insufficient_evidence",
                "evidence_ids": [],
                "explanation": "The executed query returned no matching evidence.",
            }
        ],
    )

    assert result.checks[0].evidence_ids == []
    assert result.checks[0].condition["limit"] == 10


def test_validation_result_requires_a_complete_query_window() -> None:
    ValidationResult = model_class("ValidationResult")
    with pytest.raises(ValidationError):
        ValidationResult(
            validation_id="VALIDATION-003",
            response_plan_id="PLAN-001",
            outcome="success",
            summary="Query completed.",
            checked_at=NOW,
            evidence_ids=[EVIDENCE_ID],
            time_from=NOW - timedelta(minutes=5),
        )


def test_validation_check_cannot_cite_evidence_outside_result() -> None:
    ValidationResult = model_class("ValidationResult")
    with pytest.raises(ValidationError):
        ValidationResult(
            validation_id="VALIDATION-004",
            response_plan_id="PLAN-001",
            outcome="success",
            summary="Query completed.",
            checked_at=NOW,
            evidence_ids=[EVIDENCE_ID],
            checks=[
                {
                    "check_id": "VC-1",
                    "condition": {"filters": {"source_ip": "203.0.113.42"}},
                    "outcome": "success",
                    "evidence_ids": ["EV-01ARZ3NDEKTSV4RRFFQ69G5FAA"],
                    "explanation": "Other event.",
                }
            ],
        )


def test_validation_result_rejects_invalid_outcome() -> None:
    ValidationResult = model_class("ValidationResult")

    with pytest.raises(ValidationError) as exc_info:
        ValidationResult(
            validation_id="VALIDATION-001",
            response_plan_id="PLAN-001",
            outcome="maybe",
            summary="验证结果未知",
            checked_at=NOW,
            evidence_ids=[EVIDENCE_ID],
        )

    assert any(error["loc"] == ("outcome",) for error in exc_info.value.errors())


def test_validation_result_rejects_missing_evidence_ids() -> None:
    ValidationResult = model_class("ValidationResult")

    with pytest.raises(ValidationError) as exc_info:
        ValidationResult(
            validation_id="VALIDATION-001",
            response_plan_id="PLAN-001",
            outcome="insufficient_evidence",
            summary="没有足够证据判断处置效果",
            checked_at=NOW,
            evidence_ids=[],
        )

    assert any(error["loc"] == ("evidence_ids",) for error in exc_info.value.errors())
