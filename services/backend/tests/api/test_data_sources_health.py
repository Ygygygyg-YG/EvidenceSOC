from evidencesoc.config import Settings
from evidencesoc.main import create_app
from fastapi.testclient import TestClient


def test_data_sources_health_route_returns_typed_store_snapshot():
    checked_at = "2026-10-01T00:00:00Z"
    snapshot = {
        "checked_at": checked_at,
        "postgresql_status": "ok",
        "opensearch_status": None,
        "is_stale": False,
        "sources": [
            {
                "source": "nginx",
                "last_ingested_at": checked_at,
                "ingestion_lag_seconds": 0,
                "status": None,
                "is_stale": None,
            }
        ],
    }

    class Store:
        def __init__(self):
            self.calls = 0

        def list_recoverable(self):
            return []

        def source_health(self):
            self.calls += 1
            return snapshot

    store = Store()
    app = create_app(
        settings=Settings(_env_file=None, llm_mode="fixture"),
        store=store,
        workflow=object(),
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/data-sources/health")

    assert response.status_code == 200, response.text
    assert response.json() == snapshot
    assert store.calls == 1
    responses = app.openapi()["paths"]["/api/v1/data-sources/health"]["get"][
        "responses"
    ]
    assert responses["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "SourceHealthSummary"
    )
