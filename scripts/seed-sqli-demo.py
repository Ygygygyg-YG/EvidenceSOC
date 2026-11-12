"""Import five synthetic nginx records and create the SQL injection demo alerts.

Run with uv run --project services/backend python scripts/seed-sqli-demo.py.
Use the same local database, OpenSearch index and demo directory as the API.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal, TypedDict
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from evidencesoc.config import Settings
from evidencesoc.ingestion.jsonl import parse_log_file
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.ingestion.service import ImportReport, IngestionService
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.event_repository import EventRepository
from evidencesoc.persistence.event_search import (
    OpenSearchEventQuery,
    OpenSearchEventStore,
    build_event_document,
    create_opensearch_client,
)
from opensearchpy.exceptions import RequestError

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data/samples/sql-injection-demo.jsonl"
INDEX_TEMPLATE = ROOT / "infra/opensearch/security-events-template.json"
EVENT_COUNT = 5
Mode = Literal["fixture", "deepseek"]
CASES: dict[str, tuple[Mode, str]] = {
    "FIXTURE": ("fixture", "SQL 注入演示 · 规则调查"),
    "DEEPSEEK": ("deepseek", "SQL 注入演示 · DeepSeek 调查"),
    "REJECT": ("fixture", "SQL 注入演示 · 拒绝审批"),
}


class SeedError(RuntimeError):
    pass


class SeedManifest(TypedDict):
    run_id: str
    anchor: str
    event_ids: list[str]
    event_hashes: dict[str, str]
    alerts: dict[str, Mode]
    records: list[dict[str, Any]]
    include_reject: bool


def run_identifier(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise argparse.ArgumentTypeError("use a 32-character lowercase UUID hex value")
    return value


def loopback_origin(value: str) -> str:
    value = value.rstrip("/")
    try:
        origin = urlsplit(value)
        port = origin.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "use a loopback HTTP(S) origin with a port"
        ) from exc
    if (
        origin.scheme not in {"http", "https"}
        or origin.hostname not in {"127.0.0.1", "::1", "localhost"}
        or port is None
        or origin.username is not None
        or origin.password is not None
        or value != f"{origin.scheme}://{origin.netloc}"
    ):
        raise argparse.ArgumentTypeError("use a loopback HTTP(S) origin with a port")
    return value


def utc_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def render_records(run_id: str, anchor: datetime) -> list[dict[str, Any]]:
    records = [record.raw for record in parse_log_file(SAMPLE)]
    times = [datetime.fromisoformat(record["observed_at"]) for record in records]
    if (
        len(records) != EVENT_COUNT
        or any(time.utcoffset() is None for time in times)
        or times != sorted(set(times))
        or times[-1] - times[0] >= timedelta(minutes=15)
    ):
        raise SeedError("Expected five ordered sample events within 15 minutes.")
    dataset = f"sqli-{run_id}"
    return [
        {
            **record,
            "external_id": f"nginx-sqli-demo-{run_id}-{number:03d}",
            "observed_at": utc_timestamp(anchor + (observed - times[-1])),
            "host": f"{dataset}.example.test",
            "dataset_id": dataset,
        }
        for number, (record, observed) in enumerate(zip(records, times, strict=True), 1)
    ]


@contextmanager
def run_lock(path: Path) -> Iterator[None]:
    """Serialize same-ID runs and release the lock if a process exits mid-import."""
    with path.open("a+b") as lock:
        lock.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise SeedError("A seed process already holds this run lock.") from exc
        yield


def write_manifest(path: Path, manifest: SeedManifest) -> None:
    with TemporaryDirectory(dir=path.parent) as staging:
        staged = Path(staging) / path.name
        with staged.open("w", encoding="utf-8") as output:
            json.dump(manifest, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        staged.replace(path)


def prepare_manifest(path: Path, run_id: str, include_reject: bool) -> SeedManifest:
    if path.exists():
        manifest: SeedManifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest["run_id"] != run_id or len(manifest["records"]) != EVENT_COUNT:
            raise SeedError("The seed manifest does not match this run.")
        if include_reject and not manifest["include_reject"]:
            manifest["include_reject"] = True
            write_manifest(path, manifest)
        return manifest

    anchor = utc_timestamp(datetime.now(UTC))
    manifest = {
        "run_id": run_id,
        "anchor": anchor,
        "event_ids": [],
        "event_hashes": {},
        "alerts": {},
        "records": render_records(run_id, datetime.fromisoformat(anchor)),
        "include_reject": include_reject,
    }
    write_manifest(path, manifest)
    return manifest


def import_events(
    settings: Settings, records: list[dict[str, Any]]
) -> tuple[ImportReport, dict[str, str]]:
    engine = create_database_engine(settings.database_url)
    try:
        with closing(create_opensearch_client(settings.opensearch_url)) as search:
            index = settings.opensearch_index
            if not search.indices.exists(index=index):
                template = json.loads(INDEX_TEMPLATE.read_text(encoding="utf-8"))
                try:
                    search.indices.create(index=index, body=template["template"])
                except RequestError as exc:
                    if exc.error != "resource_already_exists_exception":
                        raise
            store = OpenSearchEventStore(search, index_name=index)
            sessions = create_session_factory(engine)
            with (
                sessions() as session,
                TemporaryDirectory(dir=settings.demo_sqli_directory) as staging,
            ):
                sample = Path(staging) / SAMPLE.name
                sample.write_text(
                    "".join(json.dumps(record) + "\n" for record in records),
                    encoding="utf-8",
                )
                repository = EventRepository(session)
                report = IngestionService(repository, store).import_file(sample)
                if (
                    report.failed
                    or report.total != EVENT_COUNT
                    or len(report.event_ids) != EVENT_COUNT
                    or len(set(report.event_ids)) != EVENT_COUNT
                ):
                    raise SeedError("The sample import or indexing was incomplete.")
                hashes: dict[str, str] = {}
                events = [repository.get(event_id) for event_id in report.event_ids]
                for record, event in zip(records, events, strict=True):
                    expected_hash = calculate_content_sha256(record)
                    if (
                        event.content_sha256 != expected_hash
                        or calculate_content_sha256(event.raw) != expected_hash
                    ):
                        raise SeedError(
                            "An imported event failed integrity verification."
                        )
                    hashes[event.event_id] = expected_hash
                    store.index_event(event)
                search.indices.refresh(index=index)
                for event in events:
                    if store.get_document(event.event_id) != build_event_document(
                        event
                    ):
                        raise SeedError(
                            "An imported event is missing or changed in OpenSearch."
                        )
                anchor = events[-1].observed_at
                found = OpenSearchEventQuery(search, index_name=index).search_event_ids(
                    time_from=anchor - timedelta(minutes=15),
                    time_to=anchor + timedelta(minutes=15),
                    filters={
                        field: records[-1][field]
                        for field in ("dataset_id", "source_ip", "host", "service")
                    },
                )
                if found != report.event_ids:
                    raise SeedError(
                        "The OpenSearch evidence window differs from the sample."
                    )
                return report, hashes
    finally:
        engine.dispose()


def register_alerts(
    client: httpx.Client,
    manifest: SeedManifest,
    event_ids: list[str],
    web_url: str,
) -> dict[str, dict[str, Any]]:
    registered: dict[str, dict[str, Any]] = {}
    run_id = manifest["run_id"]
    for suffix, (mode, title) in CASES.items():
        if suffix == "REJECT" and not manifest["include_reject"]:
            continue
        alert_id = f"AL-SQLI-DEMO-{run_id}-{suffix}"
        response = client.post(
            "/api/v1/alerts",
            headers={"Idempotency-Key": f"sqli-demo-v1-{run_id}-{suffix.lower()}"},
            json={
                "alert_id": alert_id,
                "title": title,
                "severity": "high",
                "created_at": manifest["anchor"],
                "event_ids": event_ids,
            },
        )
        response.raise_for_status()
        detail = client.get(f"/api/v1/alerts/{alert_id}")
        detail.raise_for_status()
        alert = detail.json()
        if (
            response.status_code not in (200, 201)
            or alert.get("alert_id") != alert_id
            or alert.get("title") != title
            or alert.get("severity") != "high"
            or datetime.fromisoformat(alert["created_at"])
            != datetime.fromisoformat(manifest["anchor"])
            or alert.get("event_ids") != event_ids
            or [event["event_id"] for event in alert["events"]] != event_ids
        ):
            raise SeedError("The API alert does not match the imported sample.")
        registered[suffix.lower()] = {
            "alert_id": alert_id,
            "mode": mode,
            "url": f"{web_url}/alerts/{alert_id}",
            "created": response.status_code == 201,
        }
    return registered


def seed_run(
    client: httpx.Client,
    settings: Settings,
    run_id: str,
    web_url: str,
    *,
    include_reject: bool,
) -> dict[str, Any]:
    ready = client.get("/health/ready")
    ready.raise_for_status()
    if ready.json() != {"status": "ok"}:
        raise SeedError("The local backend is not ready.")

    directory = settings.demo_sqli_directory
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{run_id}.json"
    with run_lock(path.with_suffix(".lock")):
        manifest = prepare_manifest(path, run_id, include_reject)
        report, hashes = import_events(settings, manifest["records"])
        if manifest["event_ids"] and (
            manifest["event_ids"] != report.event_ids
            or manifest["event_hashes"] != hashes
        ):
            raise SeedError(
                "The imported events differ from this run's verified evidence."
            )
        alerts = register_alerts(client, manifest, report.event_ids, web_url)
        manifest["event_ids"] = report.event_ids
        manifest["event_hashes"] = hashes
        manifest["alerts"] = {
            alert["alert_id"]: alert["mode"] for alert in alerts.values()
        }
        write_manifest(path, manifest)

    return {
        "run_id": run_id,
        "anchor": manifest["anchor"],
        "event_ids": report.event_ids,
        "events_inserted": report.inserted,
        "events_reused": report.duplicated,
        "alerts": alerts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--api-url", type=loopback_origin, default="http://127.0.0.1:8000"
    )
    parser.add_argument(
        "--web-url", type=loopback_origin, default="http://127.0.0.1:3000"
    )
    parser.add_argument(
        "--run-id", type=run_identifier, help="Resume a run with this ID."
    )
    parser.add_argument(
        "--include-reject",
        action="store_true",
        help="Add a fixture alert for the rejection flow.",
    )
    args = parser.parse_args()
    run_id = args.run_id or uuid4().hex
    print(f"SQLi demo run ID: {run_id}", file=sys.stderr, flush=True)
    with httpx.Client(base_url=args.api_url, timeout=15, trust_env=False) as client:
        result = seed_run(
            client, Settings(), run_id, args.web_url, include_reject=args.include_reject
        )
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 -- keep connection settings out of CLI output
        if isinstance(error, SeedError):
            detail = str(error)
        elif isinstance(error, httpx.HTTPStatusError):
            detail = (
                f"Local API returned HTTP {error.response.status_code} for "
                f"{error.request.method} {error.request.url.path}."
            )
        else:
            detail = "Check the local API, database, and search configuration."
        print(
            f"SQLi demo seed failed ({type(error).__name__}): {detail}", file=sys.stderr
        )
        raise SystemExit(1) from None
