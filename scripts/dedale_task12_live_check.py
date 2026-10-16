"""DEDALE calibration against real PostgreSQL, OpenSearch and MCP stdio.

Run with services/backend/.venv/Scripts/python.exe. This never starts the graph,
an LLM or retrieval. A real service-chain pass is distinct from freeze approval:
without an independently verified OS filesystem boundary, exit status stays 1.
No .env file is loaded and neither connection URLs nor event text are reported.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from hashlib import file_digest, sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
FORBIDDEN_KEYS = frozenset(
    {
        "gold",
        "ground_truth",
        "is_attack",
        "attack_types",
        "attack_steps",
        "technique_id",
        "labels",
        "label",
        "scoring",
        "expected_answer",
    }
)


def utc(value: str | datetime) -> datetime:
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)


def reject_answers(value: Any) -> None:
    if isinstance(value, dict):
        if FORBIDDEN_KEYS.intersection(value):
            raise ValueError("answer-bearing fields are forbidden")
        for child in value.values():
            reject_answers(child)
    elif isinstance(value, list):
        for child in value:
            reject_answers(child)


@dataclass(frozen=True)
class CaseScope:
    case_id: str
    dataset_id: str
    host: str
    time_from: datetime
    time_to: datetime
    created_at: datetime
    index_name: str

    def validate_request(
        self,
        *,
        case_id: str,
        dataset_id: str,
        index_name: str,
        time_from: str | datetime,
        time_to: str | datetime,
    ) -> None:
        lower, upper = utc(time_from), utc(time_to)
        if (
            case_id != self.case_id
            or dataset_id != self.dataset_id
            or index_name != self.index_name
            or not self.time_from <= lower < upper <= self.time_to
        ):
            raise ValueError("request escapes calibration scope")


def select_calibration_events(
    rows: list[dict[str, Any]],
    *,
    case_id: str,
) -> tuple[list[dict[str, Any]], CaseScope]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", case_id):
        raise ValueError("case_id must be a neutral lowercase identifier")
    if not rows:
        raise ValueError("events input is empty")
    for row in rows:
        reject_answers(row)
        if row.get("dataset_id") != "dedale-v2.1":
            raise ValueError("input dataset must be dedale-v2.1")
        if not isinstance(row.get("host"), str) or not row["host"]:
            raise ValueError("event host is missing")
        if not isinstance(row.get("message"), str) or not row["message"]:
            raise ValueError("event message is missing")
        utc(row["observed_at"])
    first = min(rows, key=lambda row: utc(row["observed_at"]))
    when = utc(first["observed_at"])
    lower = when.replace(minute=when.minute // 30 * 30, second=0, microsecond=0)
    scope = CaseScope(
        case_id,
        f"dedale-v2.1:{case_id}",
        first["host"],
        lower,
        lower + timedelta(minutes=30),
        lower + timedelta(minutes=15),
        "security-events-dedale-task12-" + uuid4().hex,
    )
    selected = []
    for row in rows:
        if (
            row["host"] == scope.host
            and scope.time_from <= utc(row["observed_at"]) < scope.time_to
        ):
            projected = deepcopy(row)
            projected["dataset_id"] = scope.dataset_id
            selected.append(projected)
    if len(selected) > 199:
        raise ValueError(
            "calibration input exceeds the 199-event explicit acceptance limit"
        )
    return selected, scope


def fixture_settings(**overrides):
    from evidencesoc.config import Settings

    values = {
        "database_url": os.environ.get(
            "DATABASE_URL", Settings.model_fields["database_url"].default
        ),
        "opensearch_url": os.environ.get("OPENSEARCH_URL", "http://127.0.0.1:9200"),
        "rag_data_directory": ROOT / ".pytest_cache/dedale-no-model",
        **overrides,
        "llm_mode": "fixture",
        "deepseek_api_key": None,
    }
    return Settings(_env_file=None, **values)


def new_report() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "pending",
        "freeze_eligible": False,
        "model_invocations": 0,
        "checks": {
            "scoring_filesystem_isolation": {
                "status": "pending",
                "reason": "A working directory is not an OS filesystem boundary; no independent scoring filesystem isolation was established by this harness.",
            },
        },
    }


def finalize_report(report: dict[str, Any], output: Path) -> None:
    statuses = [check["status"] for check in report["checks"].values()]
    report["status"] = (
        "failed"
        if "failed" in statuses
        else ("pending" if "pending" in statuses else "passed")
    )
    report["live_acceptance_passed"] = report["status"] == "passed"
    # A calibration chain cannot approve the independent full-dataset freeze.
    report["freeze_eligible"] = False
    report["acceptance_scope"] = (
        "calibration service chain and MCP filesystem boundary only"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def read_events(path: Path) -> list[dict[str, Any]]:
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("events must be JSON objects")
    return rows


def upper_boundary_probe(scope: CaseScope) -> dict[str, Any]:
    """An explicit instrument, never an observed dataset sample or scored row."""
    return {
        "source": "acceptance-probe",
        "external_id": "dedale-task12-end-boundary",
        "dataset_id": scope.dataset_id,
        "host": scope.host,
        "observed_at": scope.time_to.isoformat(),
        "event_type": "acceptance_probe",
        "probe_kind": "synthetic_end_boundary",
        "message": "Synthetic acceptance boundary instrument",
        "severity": "info",
    }


def source_tokens(raw: dict[str, Any]) -> list[str]:
    process = raw.get("process", {})
    if not isinstance(process, dict):
        return []
    return [
        value
        for key in ("executable", "command_line", "title")
        if isinstance((value := process.get(key)), str) and len(value) >= 3
    ]


def verify_source_projection(selected, raw_lines: list[bytes]) -> int:
    """Recompute the complete allowed projection from exact original line bytes."""
    from evals.datasets.dedale.parse import parse_event

    checked = 0
    for event in selected:
        provenance = event.get("provenance", event)
        line_number = provenance.get("line_number")
        if not isinstance(line_number, int) or not 1 <= line_number <= len(raw_lines):
            raise ValueError("original source line is unavailable")
        raw_line = raw_lines[line_number - 1]
        projected = parse_event(
            raw_line,
            archive=provenance["archive"],
            relative_log_path=provenance["relative_log_path"],
            line_number=line_number,
        )
        projected["dataset_id"] = event["dataset_id"]
        if projected != event:
            raise ValueError("original bytes/hash or allowed projection differs")
        original = json.loads(raw_line)
        original = original.get("_source", original)
        tokens = source_tokens(original)
        if tokens:
            if not any(token in event["message"] for token in tokens):
                raise ValueError("message omitted original process/command content")
            checked += 1
    if not checked:
        raise ValueError("no original process/command text verified")
    return checked


# Production build_server and transport, with explicit fixture settings and no .env.
# Keep model execution impossible even if an unexpected attack lookup is introduced.
CHILD_CODE = r"""
import os
from evidencesoc.config import Settings
from evidencesoc.mcp_server.context import load_run_context
from evidencesoc.mcp_server.main import build_server
from evidencesoc.persistence.database import create_database_engine, create_session_factory
from evidencesoc.rag.embeddings import LocalEmbeddingProvider
def deny_model(*args, **kwargs):
    raise RuntimeError("model execution forbidden in DEDALE acceptance")
LocalEmbeddingProvider.embed_query = deny_model
LocalEmbeddingProvider.embed_documents = deny_model
settings = Settings(_env_file=None, llm_mode="fixture", deepseek_api_key=None)
engine = create_database_engine(settings.database_url, bounded_tool_connections=True)
try:
    server = build_server(context=load_run_context(os.environ), settings=settings,
                          session_factory=create_session_factory(engine), max_attempts=1)
    server.run(transport="stdio")
finally:
    engine.dispose()
"""


def docker_json(arguments: list[str]):
    result = subprocess.run(
        ["docker", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError("Docker inspection failed")
    return json.loads(result.stdout)


def dependency_tree_sha256(root: Path) -> str:
    digest = sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or path.is_junction():
            raise ValueError("runtime dependency tree contains a filesystem link")
        if path.is_file() and path.suffix != ".pyc":
            relative = path.relative_to(root).as_posix()
            digest.update(relative.encode("utf-8") + b"\0")
            with path.open("rb") as stream:
                digest.update(file_digest(stream, "sha256").digest())
    return digest.hexdigest()


def isolated_stdio_parameters(parameters, options, report):
    from mcp import StdioServerParameters
    from sqlalchemy.engine import make_url

    from scripts.dedale_task12_runtime import docker_run_arguments

    dependencies = ROOT / "data/dedale/runtime/linux-packages"
    if not (dependencies / "mcp").is_dir():
        raise ValueError("minimal Linux MCP dependencies are unavailable")
    image = docker_json(["image", "inspect", options["image"]])[0]["Id"]
    mounts = {
        "/opt/dedale-deps": str(dependencies.resolve()),
        "/app/backend/src": str((ROOT / "services/backend/src").resolve()),
        "/app/runtime.py": str((ROOT / "scripts/dedale_task12_runtime.py").resolve()),
        "/app/agent": str(options["agent_dir"].resolve()),
    }
    environment = dict(parameters.env)
    database = make_url(environment["DATABASE_URL"])
    if database.host in {"localhost", "127.0.0.1"}:
        database = database.set(host="postgres", port=5432)
    environment["DATABASE_URL"] = database.render_as_string(hide_password=False)
    environment["OPENSEARCH_URL"] = "http://opensearch:9200"
    environment.update(
        {
            "PYTHONPATH": "/app/backend/src:/opt/dedale-deps",
            "PYTHONDONTWRITEBYTECODE": "1",
            "RAG_DATA_DIRECTORY": "/no-model-artifacts",
            "OPENBLAS_NUM_THREADS": "1",
            "DEDALE_ISOLATION_NONCE": options["nonce"],
            "DEDALE_FORBIDDEN_PATHS": json.dumps(
                [
                    str(options["scoring_canary"].resolve()),
                    "/scoring/canary.json",
                    "/app/scoring/canary.json",
                    "/app/agent/../scoring/canary.json",
                    "/workspace/scoring/canary.json",
                ]
            ),
        }
    )
    arguments = docker_run_arguments(
        name=options["name"],
        image_id=image,
        network=options["network"],
        mounts=mounts,
        environment=environment,
    )
    report["runtime_artifacts"] = {
        "harness_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "bootstrap_sha256": sha256(
            (ROOT / "scripts/dedale_task12_runtime.py").read_bytes()
        ).hexdigest(),
        "backend_source_sha256": dependency_tree_sha256(ROOT / "services/backend/src"),
        "linux_dependencies_sha256": dependency_tree_sha256(dependencies),
        "agent_events_sha256": sha256(
            (options["agent_dir"] / "events.jsonl").read_bytes()
        ).hexdigest(),
        "host_scoring_canary_sha256": sha256(
            options["scoring_canary"].read_bytes()
        ).hexdigest(),
    }
    options["expected_mounts"] = mounts
    options["image_id"] = image
    return StdioServerParameters(
        command="docker", args=arguments, env=environment, cwd=ROOT
    )


async def exercise_mcp(settings, scope, sessions, event_ids, report, runtime_options):
    from evidencesoc.agents.services import PostgresWorkflowServices
    from evidencesoc.mcp_server.client import build_stdio_parameters
    from evidencesoc.mcp_server.context import RunContext
    from evidencesoc.persistence.tables import SecurityEventTable, ToolCallTable
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client
    from sqlalchemy import func, select

    context = RunContext("AR-dedale-check", "IN-dedale-check", "TRACE-dedale-check")
    parameters = build_stdio_parameters(
        context,
        settings=settings,
        backend_dir=ROOT / "services/backend",
        managed_attempts=True,
    )
    parameters.args = ["-B", "-c", CHILD_CODE]
    parameters.env.update(
        {"LLM_MODE": "fixture", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}
    )
    if runtime_options["mode"] == "docker":
        parameters = isolated_stdio_parameters(parameters, runtime_options, report)
    workflow = PostgresWorkflowServices(settings, session_factory=sessions)
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as log:
        async with (
            stdio_client(parameters, errlog=log) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            if runtime_options["mode"] == "docker":
                from scripts.dedale_task12_runtime import (
                    PROBE_PREFIX,
                    validate_container_inspection,
                    validate_probe_binding,
                )

                inspected = await asyncio.to_thread(
                    docker_json, ["inspect", runtime_options["name"]]
                )
                info = inspected[0]
                container = validate_container_inspection(
                    info,
                    runtime_options["expected_mounts"],
                    runtime_options["network"],
                )
                if container["image_id"] != runtime_options["image_id"]:
                    raise ValueError(
                        "MCP runtime image differs from inspected local image"
                    )
                log.seek(0)
                probes = [
                    json.loads(line.removeprefix(PROBE_PREFIX))
                    for line in log.read().splitlines()
                    if line.startswith(PROBE_PREFIX)
                ]
                if len(probes) != 1:
                    raise ValueError(
                        "same-process MCP filesystem probe missing or ambiguous"
                    )
                probe = probes[0]
                validate_probe_binding(
                    probe,
                    info,
                    nonce=runtime_options["nonce"],
                    agent_sha256=report["runtime_artifacts"]["agent_events_sha256"],
                )
                report["checks"]["scoring_filesystem_isolation"] = {
                    "status": "passed",
                    "boundary": "actual MCP stdio runtime container",
                    "same_process_probe": probe,
                    "container_inspection": container,
                    "host_scoring_canary_exists": runtime_options[
                        "scoring_canary"
                    ].is_file(),
                }
            tools = await session.list_tools()
            if {tool.name for tool in tools.tools} != {
                "get_alert_context",
                "search_security_events",
                "lookup_attack_technique",
            }:
                raise ValueError("unexpected MCP tools")
            arguments = {
                "case_id": scope.case_id,
                "dataset_id": scope.dataset_id,
                "index_name": scope.index_name,
                "time_from": scope.time_from.isoformat(),
                "time_to": scope.time_to.isoformat(),
            }
            rejected = 0
            for field, changed in (
                ("case_id", "another"),
                ("dataset_id", "dedale-v2.1:another"),
                ("index_name", "security-events-v1"),
                ("time_from", (scope.time_from - timedelta(seconds=1)).isoformat()),
                ("time_to", (scope.time_to + timedelta(seconds=1)).isoformat()),
            ):
                try:
                    scope.validate_request(**{**arguments, field: changed})
                except ValueError:
                    rejected += 1
            if rejected != 5:
                raise ValueError("scope negative probes did not reject all escapes")
            report["checks"]["harness_request_scope"] = {
                "status": "passed",
                "rejected_probes": rejected,
                "boundary": "harness before MCP dispatch; not an OS or backend authorization claim",
            }
            scope.validate_request(**arguments)
            values = []
            for name, args in (
                (
                    "get_alert_context",
                    {
                        "alert_id": "AL-dedale-check",
                        "before_seconds": 900,
                        "after_seconds": 900,
                    },
                ),
                (
                    "search_security_events",
                    {
                        "time_from": arguments["time_from"],
                        "time_to": arguments["time_to"],
                        "filters": {"dataset_id": scope.dataset_id, "host": scope.host},
                        "limit": 200,
                    },
                ),
            ):
                response = await session.call_tool(name, args)
                if response.isError:
                    code = (
                        (response.structuredContent or {})
                        .get("error", {})
                        .get("code", "UNKNOWN")
                    )
                    raise RuntimeError(f"MCP {name} failed ({code})")
                items = (response.structuredContent or {}).get("result")
                if not isinstance(items, list) or {
                    item["event_id"] for item in items
                } != set(event_ids):
                    raise ValueError(f"MCP {name} returned unexpected scoped event ids")
                hydrated = await workflow.hydrate_evidence(context.incident_id, items)
                if len(hydrated) != len(event_ids):
                    raise ValueError("hydration lost evidence")
                with sessions() as database:
                    for item in hydrated:
                        raw = database.get(SecurityEventTable, item["event_id"]).raw
                        if item["raw"].get("message") != raw["message"]:
                            raise ValueError(
                                "hydration omitted process/command message"
                            )
                values.extend(items)
                report["checks"][name] = {
                    "status": "passed",
                    "returned": len(items),
                    "hydrated": len(hydrated),
                }
            # Real MCP boundary denies unexpected index/case arguments and wrong alert ownership.
            for name, args, code in (
                ("get_alert_context", {"alert_id": "AL-other-case"}, "NOT_FOUND"),
                (
                    "search_security_events",
                    {
                        "time_from": arguments["time_from"],
                        "time_to": arguments["time_to"],
                        "filters": {"case_id": "other"},
                    },
                    "POLICY_DENIED",
                ),
                (
                    "search_security_events",
                    {
                        "time_from": arguments["time_from"],
                        "time_to": arguments["time_to"],
                        "filters": {},
                        "index": "security-events-v1",
                    },
                    "POLICY_DENIED",
                ),
            ):
                response = await session.call_tool(name, args)
                if (
                    not response.isError
                    or (response.structuredContent or {}).get("error", {}).get("code")
                    != code
                ):
                    raise ValueError("MCP negative probe was not denied")
            report["checks"]["mcp_negative_probes"] = {
                "status": "passed",
                "rejected": 3,
            }
    with sessions() as database:
        audit_count = database.scalar(select(func.count()).select_from(ToolCallTable))
    if audit_count != 5:
        raise ValueError("MCP calls were not all audited")
    report["counts"]["tool_calls"] = audit_count
    report["counts"]["evidence_results"] = len(values)


def run_live(events, scope, settings, report, runtime_options):
    from evidencesoc.ingestion.jsonl import ParsedLogRecord
    from evidencesoc.ingestion.normalize import canonical_json, normalize_record
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
    from evidencesoc.persistence.tables import (
        AgentRunTable,
        AlertTable,
        Base,
        EvidenceItemTable,
        IncidentTable,
        SecurityEventTable,
        ToolCallTable,
    )
    from sqlalchemy import create_engine, func, select
    from sqlalchemy.engine import make_url

    database_name = "dedale_task12_" + uuid4().hex
    base_url = make_url(settings.database_url)
    if base_url.get_backend_name() != "postgresql":
        raise ValueError("real PostgreSQL is required")
    admin = create_engine(
        base_url.set(database="postgres"),
        isolation_level="AUTOCOMMIT",
        connect_args={"connect_timeout": 5},
    )
    search = create_opensearch_client(settings.opensearch_url)
    engine = None
    database_created = index_created = False
    report["isolation"] = {
        "database_name": database_name,
        "index_name": scope.index_name,
    }
    try:
        with admin.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
        database_created = True
        isolated_url = base_url.set(database=database_name).render_as_string(
            hide_password=False
        )
        settings = fixture_settings(
            database_url=isolated_url,
            opensearch_url=settings.opensearch_url,
            opensearch_index=scope.index_name,
        )
        engine = create_database_engine(isolated_url)
        Base.metadata.create_all(
            engine,
            tables=[
                table.__table__
                for table in (
                    SecurityEventTable,
                    AlertTable,
                    IncidentTable,
                    EvidenceItemTable,
                    AgentRunTable,
                    ToolCallTable,
                )
            ],
        )
        sessions = create_session_factory(engine)
        template = json.loads(
            (ROOT / "infra/opensearch/security-events-template.json").read_text(
                encoding="utf-8"
            )
        )
        search.indices.create(index=scope.index_name, body=template["template"])
        index_created = True
        store = OpenSearchEventStore(search, index_name=scope.index_name)
        # A separate file is an import artifact only. It does not provide filesystem isolation.
        with tempfile.TemporaryDirectory(
            prefix="dedale-task12-", dir=ROOT / ".pytest_cache"
        ) as temporary:
            path = Path(temporary) / "events.jsonl"
            path.write_text(
                "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in events),
                encoding="utf-8",
            )
            imports = []
            for _ in range(2):
                with sessions() as session:
                    imports.append(
                        IngestionService(EventRepository(session), store).import_file(
                            path
                        )
                    )
        first, second = imports
        count = len(events)
        if (
            first.inserted,
            first.indexed,
            first.failed,
            second.inserted,
            second.duplicated,
            second.failed,
        ) != (count, count, 0, 0, count, 0) or first.event_ids != second.event_ids:
            raise ValueError("duplicate ingestion was not idempotent")
        search.indices.refresh(index=scope.index_name)
        with sessions() as session:
            persisted = session.scalar(
                select(func.count()).select_from(SecurityEventTable)
            )
        indexed = search.count(index=scope.index_name)["count"]
        if persisted != count or indexed != count:
            raise ValueError("database/index counts differ")
        report["counts"] = {
            "selected": count,
            "postgres_events": persisted,
            "opensearch_events": indexed,
        }
        search.indices.flush(index=scope.index_name)
        statistics = search.indices.stats(index=scope.index_name, metric="store,docs")[
            "_all"
        ]["primaries"]
        report["resource_probe"] = {
            "selected_events": count,
            "canonical_input_bytes": sum(
                len(canonical_json(row)) + 1 for row in events
            ),
            "canonical_bytes_include_newline": True,
            "opensearch_primary_store_bytes": statistics["store"]["size_in_bytes"],
            "opensearch_document_count": statistics["docs"]["count"],
            "boundary": "sample index before synthetic boundary instrument; no full-dataset extrapolation",
        }
        report["checks"]["duplicate_import"] = {
            "status": "passed",
            "first_inserted": first.inserted,
            "second_inserted": second.inserted,
            "second_duplicated": second.duplicated,
        }
        with sessions() as session:
            rows = session.scalars(select(SecurityEventTable)).all()
            report["content_hashes"] = [
                {
                    "event_id": row.event_id,
                    "content_sha256": row.content_sha256,
                    "raw_line_sha256": row.raw["raw_line_sha256"],
                    "event_fingerprint": row.raw["event_fingerprint"],
                }
                for row in sorted(rows, key=lambda row: row.event_id)
            ]
        # Include a clearly marked synthetic end-boundary instrument in the alert
        # allowlist and index. Both real tools must exclude it from evidence.
        probe = normalize_record(
            ParsedLogRecord(
                upper_boundary_probe(scope), "acceptance-boundary-probe", 1
            ),
            event_id="EVT-dedale-end-boundary",
            ingested_at=datetime.now(UTC),
        )
        with sessions() as session:
            repository = EventRepository(session)
            repository.register(probe)
            store.index_event(probe)
            repository.mark_indexed(probe.event_id)
        search.indices.refresh(index=scope.index_name)
        report["counts"]["synthetic_boundary_instruments"] = 1
        with sessions() as session, session.begin():
            session.add(
                AlertTable(
                    alert_id="AL-dedale-check",
                    title="Calibration context",
                    severity="info",
                    created_at=scope.created_at,
                    event_ids=[*first.event_ids, probe.event_id],
                )
            )
            session.flush()
            session.add(
                IncidentTable(
                    incident_id="IN-dedale-check",
                    alert_id="AL-dedale-check",
                    status="collecting",
                    created_at=scope.created_at,
                )
            )
            session.flush()
            session.add(
                AgentRunTable(
                    run_id="AR-dedale-check",
                    incident_id="IN-dedale-check",
                    agent_name="log_collector",
                    status="running",
                    started_at=datetime.now(UTC),
                    evidence_ids=[],
                )
            )
        with tempfile.TemporaryDirectory(
            prefix="dedale-runtime-", dir=ROOT / ".pytest_cache"
        ) as temporary:
            runtime_root = Path(temporary)
            agent_dir = runtime_root / "agent"
            agent_dir.mkdir()
            (agent_dir / "events.jsonl").write_text(
                "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in events),
                encoding="utf-8",
            )
            scoring_dir = runtime_root / "scoring"
            scoring_dir.mkdir()
            scoring_canary = scoring_dir / "canary.json"
            scoring_canary.write_text(
                json.dumps({"canary": uuid4().hex}), encoding="utf-8"
            )
            options = {
                **runtime_options,
                "agent_dir": agent_dir,
                "scoring_canary": scoring_canary,
                "nonce": uuid4().hex,
                "name": "dedale-mcp-" + uuid4().hex,
            }
            try:
                asyncio.run(
                    exercise_mcp(
                        settings, scope, sessions, first.event_ids, report, options
                    )
                )
            finally:
                if options["mode"] == "docker":
                    subprocess.run(
                        ["docker", "rm", "--force", options["name"]],
                        capture_output=True,
                        check=False,
                        timeout=15,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    # --rm normally already removed it. Inspect must confirm absence.
                    result = subprocess.run(
                        ["docker", "inspect", options["name"]],
                        capture_output=True,
                        check=False,
                        timeout=15,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    report["checks"]["container_cleanup"] = {
                        "status": "passed" if result.returncode else "failed"
                    }
        report["checks"]["half_open_window"] = {
            "status": "passed",
            "synthetic_end_boundary_excluded_by_both_tools": True,
        }
        report["checks"]["real_service_chain"] = {
            "status": "passed",
            "transport": "MCP stdio",
            "historical_alert_time": scope.created_at.isoformat(),
        }
    finally:
        cleanup_errors = []
        if engine is not None:
            engine.dispose()
        if index_created:
            try:
                search.indices.delete(index=scope.index_name)
            except Exception:  # noqa: BLE001 - always attempt the remaining owned cleanup.
                cleanup_errors.append("isolated_index")
        if database_created:
            try:
                with admin.connect() as connection:
                    connection.exec_driver_sql(
                        f'DROP DATABASE "{database_name}" WITH (FORCE)'
                    )
            except Exception:  # noqa: BLE001 - retain a safe cleanup failure record.
                cleanup_errors.append("isolated_database")
        search.close()
        admin.dispose()
        report["checks"]["isolated_resource_cleanup"] = {
            "status": "failed" if cleanup_errors else "passed",
            "remaining_resources": cleanup_errors,
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--raw-events", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data/dedale/research/task12-live-report.json",
    )
    parser.add_argument("--case-id", default="calibration-001")
    parser.add_argument("--runtime", choices=["docker", "host"], default="docker")
    parser.add_argument("--docker-image", default="strix:latest")
    parser.add_argument("--docker-network", default="evidencesoc_default")
    args = parser.parse_args(argv)
    report = new_report()
    try:
        rows = read_events(args.events)
        events, scope = select_calibration_events(rows, case_id=args.case_id)
        raw_path = args.raw_events or args.events.with_name("benign-raw.jsonl")
        checked = verify_source_projection(
            events, raw_path.read_bytes().splitlines(keepends=True)
        )
        report["checks"]["source_projection"] = {
            "status": "passed",
            "process_command_rows_verified": checked,
        }
        report["input_sha256"] = sha256(args.events.read_bytes()).hexdigest()
        report["original_input_sha256"] = sha256(raw_path.read_bytes()).hexdigest()
        report["scope"] = {
            key: value.isoformat() if isinstance(value, datetime) else value
            for key, value in asdict(scope).items()
        }
        run_live(
            events,
            scope,
            fixture_settings(),
            report,
            {
                "mode": args.runtime,
                "image": args.docker_image,
                "network": args.docker_network,
            },
        )
    except Exception as error:  # noqa: BLE001 - fail closed without leaking dependency URLs.
        # Dependency errors can contain URLs or raw rows; emit only the safe type.
        report["checks"]["execution"] = {
            "status": "failed",
            "error_type": type(error).__name__,
        }
    finalize_report(report, args.output)
    print(
        json.dumps(
            {
                "status": report["status"],
                "freeze_eligible": report["freeze_eligible"],
                "report": str(args.output.resolve()),
            }
        )
    )
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
