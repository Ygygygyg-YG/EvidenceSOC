"""Optional live OpenSearch check for AIT scenario query isolation."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from evidencesoc.config import Settings
from evidencesoc.ids import new_event_id, new_ulid
from evidencesoc.ingestion.jsonl import ParsedLogRecord
from evidencesoc.ingestion.normalize import normalize_record
from evidencesoc.persistence.event_search import (
    OpenSearchEventQuery,
    OpenSearchEventStore,
    create_opensearch_client,
)


@pytest.mark.skipif(
    os.getenv("EVIDENCESOC_TEST_OPENSEARCH") != "1",
    reason="requires opt-in local OpenSearch connectivity",
)
def test_shared_index_does_not_return_another_ait_scenario() -> None:
    root = Path(__file__).resolve().parents[4]
    template = json.loads(
        (root / "infra/opensearch/security-events-template.json").read_text(
            encoding="utf-8"
        )
    )
    client = create_opensearch_client(Settings().opensearch_url)
    index = f"security-events-scope-{new_ulid().lower()}"
    observed_at = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
    try:
        client.indices.create(index=index, body=template["template"])
        store = OpenSearchEventStore(client, index_name=index)
        owned: dict[str, str] = {}
        for scenario in ("shaw", "wilson"):
            raw = {
                "source": "dnsmasq",
                "event_type": "dns.log",
                "severity": "info",
                "observed_at": observed_at.isoformat(),
                "source_ip": "203.0.113.7",
                "host": "shared-host.example.test",
                "dataset_id": f"ait-v2.1:{scenario}",
                "message": "same entity and timestamp",
            }
            event = normalize_record(
                ParsedLogRecord(raw, "scenario-isolation", 1),
                event_id=new_event_id(),
                ingested_at=datetime.now(UTC),
            )
            owned[scenario] = event.event_id
            store.index_event(event)
        client.indices.refresh(index=index)
        query = OpenSearchEventQuery(client, index_name=index)
        for scenario in ("shaw", "wilson"):
            assert query.search_event_ids(
                time_from=observed_at - timedelta(seconds=1),
                time_to=observed_at + timedelta(seconds=1),
                filters={
                    "source_ip": "203.0.113.7",
                    "dataset_id": f"ait-v2.1:{scenario}",
                },
                limit=10,
            ) == [owned[scenario]]
    finally:
        try:
            if client.indices.exists(index=index):
                client.indices.delete(index=index)
        finally:
            client.close()
