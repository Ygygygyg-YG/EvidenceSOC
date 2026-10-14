"""Persist the repository's SQL injection sample for the Task10 UI demo.

Run from the repository with ``uv run --project services/backend python
scripts/seed-task10.py`` while the local API and its dependencies are ready.
The event source and alert identity are stable, so rerunning is safe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from evidencesoc.config import Settings
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.ingestion.service import IngestionService
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.event_repository import EventRepository
from evidencesoc.persistence.event_search import (
    OpenSearchEventStore,
    create_opensearch_client,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data/samples/sql-injection.jsonl"
API_URL = "http://127.0.0.1:8000"
TITLE = "Task10 SQL 注入演示告警"


def sample_identity(sample_bytes: bytes) -> tuple[int, str, str]:
    """Choose an evidence-window timestamp and an input-format-independent ID."""
    records = [
        json.loads(line)
        for line in sample_bytes.decode("utf-8").splitlines()
        if line.strip()
    ]
    if len(records) != 5:
        raise RuntimeError(
            "Expected the repository's five SQL injection sample events."
        )
    observed = sorted(
        datetime.fromisoformat(record["observed_at"].replace("Z", "+00:00"))
        for record in records
    )
    if any(value.tzinfo is None for value in observed):
        raise RuntimeError("Sample timestamps must contain a timezone.")
    chosen = observed[len(observed) // 2]
    if any(abs(value - chosen) >= timedelta(minutes=15) for value in observed):
        raise RuntimeError(
            "Sample events exceed the investigation's 15-minute evidence window."
        )
    canonical = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return (
        len(records),
        chosen.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        digest,
    )


def verify_alert_in_list(
    client: httpx.Client, expected_id: str, event_ids: list[str]
) -> int:
    """Find the persisted alert even if newer user data fills the first page."""
    page = 1
    last_page = 1
    while page <= last_page:
        response = client.get("/api/v1/alerts", params={"page": page, "page_size": 200})
        response.raise_for_status()
        listing = response.json()
        total = listing["total"]
        last_page = max(1, (total + 199) // 200)
        for item in listing["items"]:
            if item["alert_id"] == expected_id:
                if item["event_ids"] != event_ids or item["title"] != TITLE:
                    raise RuntimeError(
                        "Persisted alert does not match the imported sample."
                    )
                return total
        page += 1
    raise RuntimeError("The created alert was not found in the list API.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--api-url",
        default=API_URL,
        help="Backend API origin (default: %(default)s); DB and index use Settings env.",
    )
    arguments = parser.parse_args()
    sample_bytes = SAMPLE.read_bytes()
    expected_count, created_at, digest = sample_identity(sample_bytes)
    alert_id = "AL-TASK10-" + digest[:24].upper()
    key = "task10-sql-demo-v1-" + digest

    with httpx.Client(base_url=arguments.api_url, timeout=15, trust_env=False) as client:
        ready = client.get("/health/ready")
        ready.raise_for_status()
        if ready.json() != {"status": "ok"}:
            raise RuntimeError("The local backend is not ready.")

        settings = Settings()
        engine = create_database_engine(settings.database_url)
        search = create_opensearch_client(settings.opensearch_url)
        try:
            index = settings.opensearch_index
            if not search.indices.exists(index=index):
                template = json.loads(
                    (ROOT / "infra/opensearch/security-events-template.json").read_text(
                        encoding="utf-8"
                    )
                )
                search.indices.create(index=index, body=template["template"])
            store = OpenSearchEventStore(search, index_name=index)
            sessions = create_session_factory(engine)
            with sessions() as session:
                repository = EventRepository(session)
                report = IngestionService(repository, store).import_file(SAMPLE)
                event_ids = report.event_ids
                if (
                    report.failed
                    or report.total != expected_count
                    or len(event_ids) != expected_count
                    or len(set(event_ids)) != expected_count
                ):
                    raise RuntimeError(
                        "Sample import or indexing was incomplete; no alert was created."
                    )
                events = [repository.get(event_id) for event_id in event_ids]
                for event in events:
                    if calculate_content_sha256(event.raw) != event.content_sha256:
                        raise RuntimeError(
                            "A persisted sample event failed integrity verification."
                        )
                    store.index_event(event)
                search.indices.refresh(index=index)
                for event in events:
                    document = store.get_document(event.event_id)
                    raw_document = document.get("raw_event") if document else None
                    if (
                        not document
                        or document.get("event_id") != event.event_id
                        or document.get("content_sha256") != event.content_sha256
                        or not isinstance(raw_document, dict)
                        or calculate_content_sha256(raw_document)
                        != event.content_sha256
                    ):
                        raise RuntimeError(
                            "A sample event is missing or changed in the search index."
                        )

            payload = {
                "alert_id": alert_id,
                "title": TITLE,
                "severity": "high",
                "created_at": created_at,
                "event_ids": event_ids,
            }
            response = client.post(
                "/api/v1/alerts", headers={"Idempotency-Key": key}, json=payload
            )
            response.raise_for_status()
            alert = response.json()
            if (
                response.status_code not in (200, 201)
                or alert.get("alert_id") != alert_id
                or alert.get("event_ids") != event_ids
            ):
                raise RuntimeError(
                    "The alert API returned a result inconsistent with the sample."
                )
            total = verify_alert_in_list(client, alert_id, event_ids)
            print(
                json.dumps(
                    {
                        "alert_id": alert_id,
                        "event_count": len(event_ids),
                        "created_at": created_at,
                        "events_inserted": report.inserted,
                        "events_reused": report.duplicated,
                        "alert_created": response.status_code == 201,
                        "list_total": total,
                    },
                    ensure_ascii=False,
                )
            )
        finally:
            search.close()
            engine.dispose()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 -- keep connection details out of CLI output
        detail = (
            str(error)
            if isinstance(error, RuntimeError)
            else "Check local dependencies."
        )
        print(f"Task10 seed failed ({type(error).__name__}): {detail}", file=sys.stderr)
        raise SystemExit(1) from None
