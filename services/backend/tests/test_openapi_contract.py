from evidencesoc.main import app

CORE_SCHEMA_NAMES = {
    "SecurityEvent",
    "Alert",
    "Incident",
    "EvidenceItem",
    "AttackOrigin",
    "AttackClassification",
    "AgentRun",
    "ResponsePlan",
    "ApprovalRecord",
    "ValidationResult",
}


def test_openapi_contains_core_domain_schemas() -> None:
    openapi_schema = app.openapi()
    schemas = (
        openapi_schema
        .get("components", {})
        .get("schemas", {})
    )

    missing_schemas = CORE_SCHEMA_NAMES - set(schemas)

    assert not missing_schemas, (
        "OpenAPI 缺少核心 DTO: "
        + ", ".join(sorted(missing_schemas))
    )
