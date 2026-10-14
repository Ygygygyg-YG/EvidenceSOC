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
    schemas = openapi_schema.get("components", {}).get("schemas", {})

    missing_schemas = CORE_SCHEMA_NAMES - set(schemas)

    assert not missing_schemas, "OpenAPI 缺少核心 DTO: " + ", ".join(
        sorted(missing_schemas)
    )


def test_task9_routes_have_typed_results_errors_and_sse_content():
    schema = app.openapi()
    paths = schema["paths"]
    for path, method in (
        ("/api/v1/alerts", "get"),
        ("/api/v1/incidents/{incident_id}", "get"),
        ("/api/v1/evaluations/{evaluation_id}", "get"),
        ("/api/v1/response-plans/{plan_id}/approve", "post"),
        ("/api/v1/response-plans/{plan_id}/reject", "post"),
    ):
        responses = paths[path][method]["responses"]
        success = responses.get("200", responses.get("202"))
        assert success["content"]["application/json"]["schema"].get("$ref"), path
        assert responses["422"]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("ErrorEnvelope")
    responses = paths["/api/v1/investigations/{investigation_id}/stream"]["get"][
        "responses"
    ]
    assert "text/event-stream" in responses["200"]["content"]


def test_response_plan_read_routes_have_typed_openapi_results():
    schema = app.openapi()
    for path in ("/api/v1/response-plans", "/api/v1/response-plans/{plan_id}"):
        responses = schema["paths"][path]["get"]["responses"]
        assert responses["200"]["content"]["application/json"]["schema"][
            "$ref"
        ].startswith("#/components/schemas/ResponsePlan")
        assert responses["404"]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("ErrorEnvelope")


def test_response_plan_actions_have_a_typed_openapi_schema():
    schemas = app.openapi()["components"]["schemas"]
    action = schemas["ResponsePlan"]["properties"]["actions"]["items"]

    assert action["$ref"] == "#/components/schemas/SimulatedAction"
    assert schemas["SimulatedAction"]["additionalProperties"] is False
    assert schemas["SimulatedAction"]["properties"]["action"]["enum"] == [
        "block_ip_simulated",
        "isolate_host_simulated",
        "disable_account_simulated",
    ]


def test_evidence_detail_route_has_typed_openapi_result():
    responses = app.openapi()["paths"][
        "/api/v1/incidents/{incident_id}/evidence/{evidence_id}"
    ]["get"]["responses"]
    assert responses["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "EvidenceDetail"
    )
    assert responses["404"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "ErrorEnvelope"
    )
