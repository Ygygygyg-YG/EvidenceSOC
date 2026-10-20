"""Independent, model-free MCP boundary probe inside an existing case resource.

This artifact proves service behavior only. A controller must bind it to a real
worker/model ledger before considering any experiment-level G4 acceptance.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from evidencesoc.agents.services import PostgresWorkflowServices
from evidencesoc.config import BACKEND_ROOT
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.mcp_server.client import open_stdio_session
from evidencesoc.mcp_server.context import RunContext
from evidencesoc.persistence.tables import (
    AgentRunTable,
    AlertTable,
    EvidenceItemTable,
    IncidentTable,
    InvestigationToolCallTable,
    SecurityEventTable,
    ToolCallTable,
)
from sqlalchemy import delete, select, text
from sqlalchemy.engine import make_url

from evals.contracts import canonical_hash


def _utc(value: datetime | str) -> datetime:
    when = datetime.fromisoformat(value) if isinstance(value, str) else value
    return when.replace(tzinfo=UTC) if when.tzinfo is None else when.astimezone(UTC)


def _json(value: Any) -> Any:
    if isinstance(value, datetime):
        return _utc(value).isoformat()
    if isinstance(value, dict):
        return {key: _json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json(item) for item in value]
    return value


def _row(row: Any) -> dict:
    return {
        column.name: _json(getattr(row, column.key)) for column in row.__table__.columns
    }


def _fingerprint(environment: Any, seed: dict) -> dict:
    """Include complete rows, so a changed summary cannot hide behind a count."""
    incident_id = environment.incident_id
    run_ids = select(AgentRunTable.run_id).where(
        AgentRunTable.incident_id == incident_id
    )
    queries = {
        "incident": select(IncidentTable).where(
            IncidentTable.incident_id == incident_id
        ),
        "alert": select(AlertTable)
        .join(IncidentTable)
        .where(IncidentTable.incident_id == incident_id),
        "agent_runs": select(AgentRunTable).where(
            AgentRunTable.incident_id == incident_id
        ),
        "physical_tool_ledger": select(ToolCallTable).where(
            ToolCallTable.run_id.in_(run_ids)
        ),
        "logical_tool_ledger": select(InvestigationToolCallTable).where(
            InvestigationToolCallTable.incident_id == incident_id
        ),
        "evidence": select(EvidenceItemTable).where(
            EvidenceItemTable.incident_id == incident_id
        ),
        "source_events": select(SecurityEventTable).where(
            SecurityEventTable.event_id.in_(
                [item["event_id"] for item in seed["events"]]
            )
        ),
    }
    snapshot = {}
    with environment.sessions() as stored:
        for name, query in queries.items():
            rows = sorted(
                (_row(row) for row in stored.scalars(query)), key=canonical_hash
            )
            snapshot[name] = {"count": len(rows), "sha256": canonical_hash(rows)}
        summaries = sorted(
            (row.output_summary for row in stored.scalars(queries["agent_runs"])),
            key=canonical_hash,
        )
        snapshot["model_run_summaries"] = {
            "count": len(summaries),
            "sha256": canonical_hash(summaries),
        }
    snapshot["seed_sha256"] = canonical_hash(seed)
    snapshot["input_sha256"] = seed["input_sha256"]
    return snapshot


def _error(result: dict, stage: str, error: BaseException | str) -> None:
    # Exceptions can embed connection URLs; never serialize their messages.
    result["errors"].append(
        {
            "stage": stage,
            "type": type(error).__name__ if isinstance(error, BaseException) else error,
        }
    )


def _audit(environment: Any, run_id: str) -> list[dict]:
    with environment.sessions() as stored:
        return [
            _row(row)
            for row in stored.scalars(
                select(ToolCallTable)
                .where(ToolCallTable.run_id == run_id)
                .order_by(ToolCallTable.started_at, ToolCallTable.tool_call_id)
            )
        ]


def _audit_matches(checks: list[dict], rows: list[dict], trace_id: str) -> bool:
    if len(checks) != len(rows):
        return False
    remaining = list(rows)
    for check in checks:
        matches = [
            row
            for row in remaining
            if row["tool_name"] == check["request"]["tool_name"]
            and canonical_hash(row["arguments"])
            == canonical_hash(check["request"]["arguments"])
        ]
        if len(matches) != 1:
            return False
        row = matches[0]
        if (
            row["success"] != (check["actual_code"] is None)
            or row["error_code"] != check["actual_code"]
        ):
            return False
        # Bind exported physical rows to the exact session, not only the run ID.
        if (
            not isinstance(row["result"], dict)
            or row["result"].get("trace_id") != trace_id
        ):
            return False
        if row["success"] and row["result"].get("result_count") != len(
            check["response"]["structuredContent"]["result"]
        ):
            return False
        check["tool_call_id"] = row["tool_call_id"]
        check["audit_row_sha256"] = canonical_hash(row)
        remaining.remove(row)
    return not remaining


def _requests(
    scope: dict, probe_alert: str, foreign_alert: str, suffix: str
) -> list[tuple[str, str, dict, str | None]]:
    search = {key: scope[key] for key in ("time_from", "time_to", "filters", "limit")}
    anchor = next(
        (key for key in ("host", "source_ip", "service") if key in scope["filters"]),
        None,
    )
    if anchor is None:
        raise ValueError("probe requires a bound source anchor")
    outside = "probe-outside-" + suffix
    context = {"before_seconds": 900, "after_seconds": 900}
    return [
        (
            "positive_alert_context",
            "get_alert_context",
            {"alert_id": probe_alert, **context},
            None,
        ),
        (
            "existing_foreign_alert",
            "get_alert_context",
            {"alert_id": foreign_alert, **context},
            "NOT_FOUND",
        ),
        (
            "forbidden_case_filter",
            "search_security_events",
            {**search, "filters": {**search["filters"], "case_id": outside}},
            "POLICY_DENIED",
        ),
        (
            "top_level_index",
            "search_security_events",
            {**search, "index": outside},
            "POLICY_DENIED",
        ),
        (
            "top_level_index_name",
            "search_security_events",
            {**search, "index_name": outside},
            "POLICY_DENIED",
        ),
        (
            "window_from_minus_one_second",
            "search_security_events",
            {
                **search,
                "time_from": (
                    _utc(search["time_from"]) - timedelta(seconds=1)
                ).isoformat(),
            },
            "POLICY_DENIED",
        ),
        (
            "window_to_plus_one_second",
            "search_security_events",
            {
                **search,
                "time_to": (_utc(search["time_to"]) + timedelta(seconds=1)).isoformat(),
            },
            "POLICY_DENIED",
        ),
        (
            "anchor_replacement",
            "search_security_events",
            {**search, "filters": {**search["filters"], anchor: outside}},
            "POLICY_DENIED",
        ),
        (
            "dataset_replacement",
            "search_security_events",
            {**search, "filters": {**search["filters"], "dataset_id": outside}},
            "POLICY_DENIED",
        ),
    ]


async def run_service_probe(spec: Any, environment: Any, seed: dict) -> dict:
    """Run real stdio calls under a temporary owner; always clean and export."""
    started = time.monotonic()
    suffix = uuid.uuid4().hex
    incidents = ["IN-probe-" + suffix, "IN-foreign-" + suffix]
    alerts = ["AL-probe-" + suffix, "AL-foreign-" + suffix]
    run_id = "AR-probe-" + suffix
    trace_id = "TRACE-probe-" + suffix
    result: dict[str, Any] = {
        "schema_version": "task13-service-isolation-probe-v1",
        "status": "failed",
        "passed": False,
        "evidence_role": "service_boundary_probe_only",
        "counts_as_model_evidence": False,
        "formal_g4": False,
        "model_calls_made": 0,
        "logical_tool_calls_made": 0,
        "checks": [],
        "physical_audit": [],
        "errors": [],
        "cleanup": {"verified": False},
        "unchanged": {"verified": False},
        "provenance": {
            "worker_pid": os.getpid(),
            "worker_nonce": os.getenv("TASK13_WORKER_NONCE"),
            "container_hostname": socket.gethostname(),
            "source_commit": os.getenv("TASK13_SOURCE_COMMIT"),
            "phase": os.getenv("TASK13_PHASE"),
            "case_id": spec.case_id,
            "run_id": spec.run_id,
            "group": spec.group,
            "database_name": environment.database_name,
            "index_name": environment.index_name,
            "experiment_incident_id": environment.incident_id,
            "probe_incident_id": incidents[0],
            "foreign_incident_id": incidents[1],
            "probe_alert_id": alerts[0],
            "foreign_alert_id": alerts[1],
            "probe_run_id": run_id,
            "trace_id": trace_id,
            "input_sha256": seed.get("input_sha256"),
        },
    }
    before = None
    try:
        if spec.group != "B3" or os.getenv("TASK13_PHASE") != "development":
            raise PermissionError("probe restricted to development B3")
        if not os.getenv("TASK13_WORKER_NONCE") or not re.fullmatch(
            r"[0-9a-f]{40}", os.getenv("TASK13_SOURCE_COMMIT", "")
        ):
            raise PermissionError("probe worker provenance missing")
        if environment.run_id != spec.run_id or environment.case_id != spec.case_id:
            raise PermissionError("case resource identity mismatch")
        if environment.settings.opensearch_index != environment.index_name:
            raise PermissionError("case index identity mismatch")
        with environment.sessions() as stored:
            bind = stored.get_bind()
            result["provenance"]["database_backend"] = bind.dialect.name
            if make_url(environment.settings.database_url) != bind.url:
                raise PermissionError("settings and session database mismatch")
            if bind.dialect.name == "postgresql":
                actual_database = stored.scalar(text("SELECT current_database()"))
                result["provenance"]["actual_database_name"] = actual_database
                if actual_database != environment.database_name:
                    raise PermissionError("case database identity mismatch")
            incident = stored.get(IncidentTable, environment.incident_id)
            if incident is None:
                raise LookupError("experiment incident missing")
            experiment_alert = stored.get(AlertTable, incident.alert_id)
            if experiment_alert is None:
                raise LookupError("experiment alert missing")
            created_at = _utc(experiment_alert.created_at)
            event_ids = [item["event_id"] for item in seed["events"]]
            rows = stored.scalars(
                select(SecurityEventTable).where(
                    SecurityEventTable.event_id.in_(event_ids)
                )
            ).all()
            by_id = {row.event_id: row for row in rows}
            if len(by_id) != len(event_ids):
                raise ValueError("seed source events missing or duplicated")
            for item in seed["events"]:
                row = by_id[item["event_id"]]
                if (
                    row.content_sha256 != item["content_sha256"]
                    or calculate_content_sha256(row.raw) != row.content_sha256
                    or canonical_hash(row.raw) != canonical_hash(item["raw"])
                ):
                    raise ValueError("seed source event integrity mismatch")
            lower, upper = (
                created_at - timedelta(seconds=900),
                created_at + timedelta(seconds=900),
            )
            expected = {
                row.event_id: row.content_sha256
                for row in sorted(
                    rows, key=lambda row: (_utc(row.observed_at), row.event_id)
                )
                if lower <= _utc(row.observed_at) < upper
            }
            expected = dict(list(expected.items())[:200])
            if not expected:
                raise ValueError("positive control has no events inside alert window")
        before = _fingerprint(environment, seed)
        result["unchanged"]["before"] = before
        with environment.sessions() as stored, stored.begin():
            for alert_id in alerts:
                stored.add(
                    AlertTable(
                        alert_id=alert_id,
                        title="Independent service boundary probe",
                        severity="info",
                        created_at=created_at,
                        event_ids=event_ids,
                    )
                )
            stored.flush()
            for incident_id, alert_id in zip(incidents, alerts, strict=True):
                stored.add(
                    IncidentTable(
                        incident_id=incident_id,
                        alert_id=alert_id,
                        status="received",
                        created_at=created_at,
                    )
                )
            stored.flush()
            stored.add(
                AgentRunTable(
                    run_id=run_id,
                    incident_id=incidents[0],
                    agent_name="service_isolation_probe",
                    status="running",
                    started_at=datetime.now(UTC),
                    evidence_ids=[],
                )
            )
        services = PostgresWorkflowServices(
            environment.settings, session_factory=environment.sessions
        )
        scope = services._scope(incidents[0])
        anchors: dict[str, dict] = {}
        for source in scope["source_scopes"]:
            filters = source["filters"]
            key = canonical_hash(filters)
            anchors.setdefault(
                key, {"filters": filters, "sha256": key, "source_event_count": 0}
            )["source_event_count"] += 1
        result["bound_scope"] = {
            **{
                key: scope[key]
                for key in ("alert_id", "time_from", "time_to", "filters", "limit")
            },
            "source_anchors": [anchors[key] for key in sorted(anchors)],
        }
        result["bound_scope_sha256"] = canonical_hash(scope)
        result["expected_event_hashes"] = expected
        async with open_stdio_session(
            RunContext(run_id, incidents[0], trace_id),
            settings=environment.settings,
            backend_dir=BACKEND_ROOT,
            managed_attempts=True,
        ) as session:
            for label, name, arguments, expected_code in _requests(
                scope, alerts[0], alerts[1], suffix
            ):
                request = {"tool_name": name, "arguments": arguments}
                response = await session.call_tool(name, arguments)
                payload = {
                    "isError": bool(response.isError),
                    "structuredContent": response.structuredContent,
                }
                structured = response.structuredContent
                code = (
                    structured.get("error", {}).get("code")
                    if isinstance(structured, dict) and response.isError
                    else None
                )
                passed = (
                    isinstance(structured, dict)
                    and bool(response.isError) == (expected_code is not None)
                    and code == expected_code
                )
                if label == "positive_alert_context":
                    values = (
                        structured.get("result")
                        if isinstance(structured, dict)
                        else None
                    )
                    observed = (
                        {
                            item.get("event_id"): item.get("content_sha256")
                            for item in values
                            if isinstance(item, dict)
                        }
                        if isinstance(values, list)
                        else None
                    )
                    passed = (
                        passed and observed == expected and len(values) == len(expected)
                    )
                    if passed:
                        evidence_ids = [item.get("evidence_id") for item in values]
                        with environment.sessions() as stored:
                            evidence = stored.scalars(
                                select(EvidenceItemTable).where(
                                    EvidenceItemTable.evidence_id.in_(evidence_ids),
                                    EvidenceItemTable.incident_id == incidents[0],
                                )
                            ).all()
                        persisted = {
                            item.event_id: item.content_sha256 for item in evidence
                        }
                        passed = (
                            len(evidence_ids) == len(set(evidence_ids)) == len(evidence)
                            and persisted == expected
                            and all(
                                item.query.get("alert_id") == alerts[0]
                                for item in evidence
                            )
                        )
                        result["persisted_positive_evidence"] = {
                            "count": len(evidence),
                            "sha256": canonical_hash(
                                sorted(
                                    (_row(item) for item in evidence),
                                    key=canonical_hash,
                                )
                            ),
                            "verified": passed,
                        }
                result["checks"].append(
                    {
                        "name": label,
                        "request": request,
                        "request_sha256": canonical_hash(request),
                        "response": payload,
                        "response_sha256": canonical_hash(payload),
                        "expected_code": expected_code,
                        "actual_code": code,
                        "passed": passed,
                    }
                )
                if not passed:
                    _error(result, label, "unexpected_service_result")
    except Exception as error:  # noqa: BLE001 - failure artifact must survive service errors
        _error(result, "probe", error)
    finally:
        try:
            result["physical_audit"] = _audit(environment, run_id)
            if (
                not _audit_matches(result["checks"], result["physical_audit"], trace_id)
                or len(result["checks"]) != 9
            ):
                _error(result, "audit", "incomplete_or_mismatched_physical_audit")
        except Exception as error:  # noqa: BLE001 - still clean temporary owners
            _error(result, "audit_export", error)
        result["physical_audit_sha256"] = canonical_hash(result["physical_audit"])
        try:
            with environment.sessions() as stored, stored.begin():
                stored.execute(
                    delete(IncidentTable).where(
                        IncidentTable.incident_id.in_(incidents)
                    )
                )
                stored.execute(
                    delete(AlertTable).where(AlertTable.alert_id.in_(alerts))
                )
            with environment.sessions() as stored:
                remaining = {
                    "incidents": len(
                        stored.scalars(
                            select(IncidentTable.incident_id).where(
                                IncidentTable.incident_id.in_(incidents)
                            )
                        ).all()
                    ),
                    "alerts": len(
                        stored.scalars(
                            select(AlertTable.alert_id).where(
                                AlertTable.alert_id.in_(alerts)
                            )
                        ).all()
                    ),
                    "agent_runs": len(
                        stored.scalars(
                            select(AgentRunTable.run_id).where(
                                AgentRunTable.incident_id.in_(incidents)
                            )
                        ).all()
                    ),
                    "tool_calls": len(
                        stored.scalars(
                            select(ToolCallTable.tool_call_id).where(
                                ToolCallTable.run_id == run_id
                            )
                        ).all()
                    ),
                    "logical_tool_calls": len(
                        stored.scalars(
                            select(InvestigationToolCallTable.call_id).where(
                                InvestigationToolCallTable.incident_id.in_(incidents)
                            )
                        ).all()
                    ),
                    "evidence": len(
                        stored.scalars(
                            select(EvidenceItemTable.evidence_id).where(
                                EvidenceItemTable.incident_id.in_(incidents)
                            )
                        ).all()
                    ),
                }
            result["cleanup"] = {
                "verified": not any(remaining.values()),
                "remaining": remaining,
            }
            if not result["cleanup"]["verified"]:
                _error(result, "cleanup", "temporary_rows_remain")
        except Exception as error:  # noqa: BLE001 - report failed cleanup explicitly
            _error(result, "cleanup", error)
        if before is not None:
            try:
                after = _fingerprint(environment, seed)
                result["unchanged"].update(after=after, verified=before == after)
                if before != after:
                    _error(result, "experiment_integrity", "experiment_state_changed")
            except Exception as error:  # noqa: BLE001 - fail closed if state cannot be checked
                _error(result, "experiment_integrity", error)
        result["passed"] = (
            not result["errors"]
            and result["cleanup"]["verified"]
            and result["unchanged"]["verified"]
        )
        result["status"] = "passed" if result["passed"] else "failed"
        result["latency_ms"] = round((time.monotonic() - started) * 1000)
        try:
            output = Path(os.environ["TASK13_OUTPUT_DIR"])
            output.mkdir(parents=True, exist_ok=True)
            path = output / "service-isolation-probe.json"
            encoded = json.dumps(
                result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            with path.open("xb") as stream:
                stream.write(encoded)
            result["artifact"] = {
                "path": path.name,
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
        except Exception as error:  # noqa: BLE001 - an unauditable probe cannot pass
            _error(result, "artifact_export", error)
            result.update(passed=False, status="failed")
    return result
