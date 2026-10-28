"""Dedicated, answer-free supplement worker; never infers paid scope from v1 IDs."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import time
from copy import deepcopy
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from evidencesoc.agents.capabilities import InvestigationCapabilities, capability_scope
from evidencesoc.agents.models import AnalysisOutput
from evidencesoc.agents.nodes import validate_output_citations
from evidencesoc.config import BACKEND_ROOT
from evidencesoc.mcp_server.client import open_stdio_session
from evidencesoc.mcp_server.context import RunContext
from evidencesoc.persistence.tables import AgentRunTable, ToolCallTable
from sqlalchemy import select

from evals.adapters.budget_v2 import SupplementBudgetAccount
from evals.adapters.diagnosis import validate_diagnosis
from evals.adapters.environment import case_environment
from evals.adapters.evidencesoc import _complete_usage, run_case
from evals.adapters.isolation_probe import run_service_probe
from evals.adapters.model_client import BudgetLimit, TrackedModel
from evals.adapters.remediation_contracts import CAMPAIGN, RemediationRequest
from evals.adapters.seed import load_seed
from evals.adapters.worker_errors import exception_category
from evals.contracts import AdapterResult, canonical_hash

DEVELOPMENT_ANALYSIS_SCHEMA = AnalysisOutput


def _write_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, allow_nan=False)
        stream.write("\n")


def _original_budget_rows(db, cutoff: int) -> list:
    return db.execute(
        "SELECT rowid,id,request_key,phase,upper,actual,settled FROM reservations "
        "WHERE rowid<=? ORDER BY rowid",
        (cutoff,),
    ).fetchall()


def _budget_snapshot(path: Path, cutoff: int | None = None) -> tuple[dict, list]:
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("v2 requires the existing original campaign.sqlite account")
    try:
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
            db.execute("BEGIN")
            values = dict(db.execute("SELECT key,value FROM config"))
            if cutoff is None:
                cutoff = db.execute(
                    "SELECT COALESCE(MAX(rowid),0) FROM reservations"
                ).fetchone()[0]
            rows = _original_budget_rows(db, cutoff)
    except sqlite3.Error as exc:
        raise ValueError("existing original budget schema is unavailable") from exc
    if values.get("total") not in {"100", "100.0"} or values.get("development") not in {
        "15",
        "15.0",
    }:
        raise ValueError("existing original budget limits differ from frozen 100/15")
    return values, rows


def read_budget_identity(path: Path) -> dict:
    """Read-only controller registration of historical rows before v2 dispatch.

    Freeze the returned identity into the config and request. Never regenerate it
    while dispatching or derive it from an untrusted replacement account.
    """
    _, rows = _budget_snapshot(path)
    if not rows:
        raise ValueError(
            "original budget identity requires nonempty historical reservations"
        )
    return {
        "schema_version": "task13-original-budget-identity-v1",
        "baseline_count": len(rows),
        "baseline_max_rowid": rows[-1][0],
        "baseline_sha256": canonical_hash(rows),
    }


def require_existing_budget(path: Path, identity: dict | None = None) -> None:
    """Require the frozen historical prefix, not merely compatible empty tables."""
    if (
        not isinstance(identity, dict)
        or set(identity)
        != {"schema_version", "baseline_count", "baseline_max_rowid", "baseline_sha256"}
        or identity["schema_version"] != "task13-original-budget-identity-v1"
        or type(identity["baseline_count"]) is not int
        or type(identity["baseline_max_rowid"]) is not int
        or not 0 < identity["baseline_count"] <= identity["baseline_max_rowid"]
        or not isinstance(identity["baseline_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", identity["baseline_sha256"]) is None
    ):
        raise ValueError("frozen original budget identity is required")
    _, rows = _budget_snapshot(path, identity["baseline_max_rowid"])
    if (
        len(rows) != identity["baseline_count"]
        or not rows
        or rows[-1][0] != identity["baseline_max_rowid"]
        or canonical_hash(rows) != identity["baseline_sha256"]
    ):
        raise ValueError(
            "existing original budget identity differs from frozen historical ledger"
        )


def validate_binding(
    request: RemediationRequest,
    agent_dir: Path,
    source: Path,
    *,
    source_commit: str | None = None,
) -> None:
    """Recheck mounted bytes in-worker; the controller also validates the Git archive."""
    if getattr(request, "schema_version", None) == "task13-remediation-worker-v4":
        from evals.adapters.epoch_development import EpochDevelopmentRequest

        request = EpochDevelopmentRequest.model_validate(
            request.model_dump(mode="json")
        )
    elif getattr(request, "schema_version", None) == "task13-remediation-worker-v3":
        from evals.adapters.epoch_remediation import EpochRemediationRequest

        request = EpochRemediationRequest.model_validate(
            request.model_dump(mode="json")
        )
    else:
        request = RemediationRequest.model_validate(request.model_dump(mode="json"))
    validate_exported_source(request, agent_dir, source, source_commit=source_commit)


def validate_exported_source(request, agent_dir, source, *, source_commit=None) -> None:
    """Shared mounted-byte check after the caller validates its dedicated schema."""
    if request.source_commit != (
        source_commit
        if source_commit is not None
        else os.environ.get("TASK13_SOURCE_COMMIT")
    ):
        raise ValueError("worker implementation commit differs from v2 request")
    events = Path(agent_dir) / "events.jsonl"
    if (
        events.is_symlink()
        or sha256(events.read_bytes()).hexdigest() != request.agent_sha256
    ):
        raise ValueError("worker case input hash differs from v2 request")
    source = Path(source).resolve()
    receipt_path = source / "source_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if (
        canonical_hash(receipt) != request.source_sha256
        or receipt.get("source_commit") != request.source_commit
    ):
        raise ValueError("worker source receipt hash differs from v2 request")
    files = receipt.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("worker source receipt is incomplete")
    expected = set(files) | {"source_receipt.json"}
    observed = set()
    for path in source.rglob("*"):
        if path.is_symlink() or path.is_junction():
            raise ValueError("worker source contains a filesystem link")
        if path.is_file():
            observed.add(path.relative_to(source).as_posix())
    if observed != expected:
        raise ValueError("worker source export contains unregistered files")
    for relative, digest in files.items():
        target = (source / relative).resolve()
        if (
            not target.is_relative_to(source)
            or sha256(target.read_bytes()).hexdigest() != digest
        ):
            raise ValueError("worker source export content differs from receipt")


class StableCallModel:
    """Map random product hints to slot/role/first-seen ordinal before accounting.

    Repeated hints retain the same logical key for <=3 physical attempts. A new
    worker maps its first hint to the same key, so an old reservation blocks replay.
    """

    def __init__(self, model: TrackedModel, slot_id: str, run_id: str):
        self.model = model
        self.slot_id = slot_id
        self.run_id = run_id
        self._calls: dict[tuple[str, str], str] = {}

    @property
    def ledger(self):
        return self.model.ledger

    @property
    def account(self):
        return self.model.account

    @property
    def config(self):
        return self.model.config

    @property
    def phase(self):
        return self.model.phase

    async def structured(self, role, schema, state):
        hint = state.get("_model_call_id")
        if not isinstance(hint, str) or not hint:
            raise ValueError("v2 product caller must supply a logical model call hint")
        key = (role, hint)
        if key not in self._calls:
            self._calls[key] = "v2-" + canonical_hash(
                [self.slot_id, role, len(self._calls) + 1]
            )
        before = len(self.model.ledger)
        try:
            return await self.model.structured(
                role, schema, {**state, "_model_call_id": self._calls[key]}
            )
        finally:
            for record in self.model.ledger[before:]:
                record.update(
                    slot_id=self.slot_id,
                    run_id=self.run_id,
                    stable_logical_call_id=self._calls[key],
                )


class PayloadRecorder:
    """Persist exact post-serialization HTTP bodies; never accept or record headers."""

    def __init__(self, output: Path):
        self.output = Path(output)
        self.records: list[dict] = []

    def __call__(self, record: dict) -> None:
        ordinal = len(self.records) + 1
        payload_path = f"model-http-{ordinal:02d}.json"
        body_path = f"model-http-{ordinal:02d}.body.json"
        with (self.output / body_path).open("xb") as stream:
            stream.write(record["http_body"])
        _write_json(self.output / payload_path, record["payload"])
        context = json.loads(record["payload"]["messages"][-1]["content"])
        self.records.append(
            {
                "physical_request_id": record["physical_request_id"],
                "payload_path": payload_path,
                "http_body_path": body_path,
                "http_body_sha256": record["http_body_sha256"],
                "request_sha256": canonical_hash(record["payload"]),
                "messages_sha256": canonical_hash(record["payload"]["messages"]),
                "knowledge_ids": [
                    item["knowledge_chunk_id"] for item in context.get("knowledge", [])
                ],
                "context_bytes": len(
                    record["payload"]["messages"][-1]["content"].encode()
                ),
            }
        )


def make_model(
    request, budget_path: Path, phase: str, *, transport=None, payload_sink=None
):
    expected_phase = "development" if request.purpose == "development" else "formal"
    if phase != expected_phase:
        raise ValueError("worker phase differs from bound supplement purpose")
    require_existing_budget(budget_path, request.budget_identity)
    account = SupplementBudgetAccount(budget_path, **request.budget_binding())
    model = TrackedModel(
        request.model,
        api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
        account=account,
        phase=phase,
        transport=transport,
        max_calls=3
        if request.purpose == "development"
        else request.budget.max_model_calls * request.budget.max_model_attempts,
        max_logical_calls=1
        if request.purpose == "development"
        else request.budget.max_model_calls,
        entry_prompt=request.entry_prompt if request.purpose == "development" else None,
        payload_sink=payload_sink,
    )
    return StableCallModel(model, request.slot_id, request.run_id)


async def lookup_knowledge(environment, request) -> list[dict]:
    """Exactly one actual scoped MCP lookup; disabled conditions never call here."""
    if request.rag_mode == "disabled":
        raise PermissionError("empty knowledge condition prohibits lookup")
    run_id = "AR-" + canonical_hash([request.slot_id, "initial-lookup"])[:26]
    with environment.sessions() as session:
        session.add(
            AgentRunTable(
                run_id=run_id,
                incident_id=environment.incident_id,
                agent_name="remediation_analysis",
                status="running",
                started_at=datetime.now(UTC),
                evidence_ids=[],
            )
        )
        session.commit()
    async with open_stdio_session(
        RunContext(
            run_id,
            environment.incident_id,
            "TRACE-" + canonical_hash(request.slot_id)[:26],
        ),
        settings=environment.settings,
        backend_dir=BACKEND_ROOT,
        managed_attempts=True,
    ) as client:
        response = await client.call_tool(
            "lookup_attack_technique",
            {"query": request.initial_query, "limit": request.seed.knowledge_top_k},
        )
    if response.isError:
        raise ValueError("scoped development MCP lookup failed")
    results = response.structuredContent
    if results is None:
        results = json.loads(response.content[0].text)
    if isinstance(results, dict):
        results = results.get("result")
    if not isinstance(results, list) or any(
        not isinstance(item, dict) for item in results
    ):
        raise ValueError("development MCP lookup returned invalid knowledge")
    return results


def export_tool_ledger(environment) -> list[dict]:
    with environment.sessions() as session:
        calls = session.scalars(
            select(ToolCallTable)
            .join(AgentRunTable, ToolCallTable.run_id == AgentRunTable.run_id)
            .where(AgentRunTable.incident_id == environment.incident_id)
        ).all()
        return [
            {
                "tool_call_id": call.tool_call_id,
                "tool_name": call.tool_name,
                "arguments": call.arguments,
                "result": call.result,
                "success": call.success,
                "error_code": call.error_code,
            }
            for call in calls
        ]


def development_seed(request, agent_dir) -> dict:
    # Keep the mechanical seed (including alert IDs) identical across conditions.
    # The case resource still uses the real slot's unique run_id and incident ID.
    spec = request.worker_spec().model_copy(
        update={"run_id": CAMPAIGN + "-development-seed"}
    )
    return load_seed(spec, agent_dir)


async def one_development_analysis(model, state, registry, *, timeout_seconds=120):
    """One product-schema analysis, up to three physical attempts, no rule fallback."""
    errors = []
    for _ in range(3):
        try:
            # raw seed keys can originate in sets. Normalize only this analysis
            # copy so separate workers send identical bytes for fixed inputs.
            model_state = json.loads(
                json.dumps(state, ensure_ascii=False, sort_keys=True, allow_nan=False)
            )
            model_state["_model_call_id"] = "development-analysis"
            value = await asyncio.wait_for(
                model.structured(
                    "analyze",
                    DEVELOPMENT_ANALYSIS_SCHEMA,
                    model_state,
                ),
                timeout=timeout_seconds,
            )
            output = DEVELOPMENT_ANALYSIS_SCHEMA.model_validate(value)
            if output.diagnosis is None:
                raise ValueError("evaluation analysis requires an explicit diagnosis")
            validate_output_citations(output, state)
            validate_diagnosis(output.diagnosis, registry)
            return output.model_dump(mode="json"), errors
        except BudgetLimit:
            raise
        except Exception as error:  # noqa: BLE001 - retain sanitized physical failures without provider exception text
            errors.append(
                {
                    "stage": "analysis",
                    "type": type(error).__name__,
                    "category": exception_category(error),
                }
            )
    return None, errors


async def _run_development(request, agent_dir) -> AdapterResult:
    started = time.monotonic()
    output = Path(os.environ["TASK13_OUTPUT_DIR"])
    recorder = PayloadRecorder(output)
    result = AdapterResult(product_status="analysis_only")
    model = None
    probe = None
    seed = None
    knowledge: list[dict] = []
    try:
        spec = request.worker_spec()
        seed = development_seed(request, agent_dir)
        result.evidence_registry = seed["registry"]
        model = make_model(
            request,
            Path(os.environ["TASK13_BUDGET_DB"]),
            "development",
            payload_sink=recorder,
        )
        with case_environment(spec, seed) as environment:
            try:
                before = canonical_hash(model.ledger)
                probe = await run_service_probe(spec, environment, seed)
                after = canonical_hash(model.ledger)
                probe.update(
                    model_ledger_before_sha256=before, model_ledger_after_sha256=after
                )
                if before != after or probe.get("status") != "passed":
                    raise ValueError("independent service isolation probe failed")
                state = {
                    "alerts": deepcopy(seed["alerts"]),
                    "evidence": deepcopy(seed["evidence"]),
                    "knowledge": [],
                }
                policy = InvestigationCapabilities(
                    allowed_tools=frozenset()
                    if request.rag_mode == "disabled"
                    else frozenset({"lookup_attack_technique"}),
                    rag_mode=request.rag_mode,
                    verification_enabled=False,
                )
                with capability_scope(policy):
                    if request.rag_mode != "disabled":
                        knowledge = await lookup_knowledge(environment, request)
                        state["knowledge"] = deepcopy(knowledge)
                    analysis, errors = await one_development_analysis(
                        model,
                        state,
                        seed["registry"],
                        timeout_seconds=request.model.timeout_seconds,
                    )
                result.errors.extend(errors)
                if analysis is not None:
                    result.diagnostic_snapshot = {
                        **analysis,
                        "sealed_after": "analyze",
                        "sealed_at": datetime.now(UTC).isoformat(),
                    }
                    result.diagnosis_status = "succeeded"
                else:
                    result.execution_status = result.diagnosis_status = "failed"
            finally:
                result.tool_ledger = export_tool_ledger(environment)
    except Exception as error:  # noqa: BLE001 - retain a sanitized failed attempt and all physical ledger rows
        result.execution_status = result.diagnosis_status = "failed"
        result.errors.append(
            {
                "stage": "remediation_analysis",
                "type": type(error).__name__,
                "category": exception_category(error),
            }
        )
    finally:
        result.model_ledger = model.ledger if model else []
        if probe is not None:
            result.isolation_evidence = {"service_probe": probe}
        ledger = result.model_ledger
        usage_complete = _complete_usage(ledger)
        cost_complete = bool(ledger) and all(
            item.get("cost_cny") is not None for item in ledger
        )
        total_latency = round((time.monotonic() - started) * 1000)
        probe_latency = probe.get("latency_ms", 0) if probe is not None else 0
        diagnosis = (
            result.diagnostic_snapshot["diagnosis"]
            if result.diagnostic_snapshot
            else None
        )
        detail = {
            "slot_id": request.slot_id,
            "run_id": request.run_id,
            "repeat": request.repeat,
            "mode": request.rag_mode,
            "initial_query": request.initial_query,
            "initial_query_sha256": request.initial_query_sha256,
            "entry_prompt_sha256": sha256(request.entry_prompt.encode()).hexdigest(),
            "entry_schema": DEVELOPMENT_ANALYSIS_SCHEMA.__name__,
            "entry_schema_sha256": canonical_hash(
                DEVELOPMENT_ANALYSIS_SCHEMA.model_json_schema()
            ),
            "fixed_seed_sha256": canonical_hash(seed) if seed is not None else None,
            "model_config_sha256": canonical_hash(request.model),
            "knowledge_returned": len(knowledge),
            "knowledge_returned_ids": [
                item["knowledge_chunk_id"] for item in knowledge
            ],
            "knowledge_in_context": len(recorder.records[-1]["knowledge_ids"])
            if recorder.records
            else 0,
            "citations": diagnosis.get("evidence_ids", []) if diagnosis else [],
            "payloads": recorder.records,
            "retrieval_requests": 0
            if request.rag_mode == "disabled"
            else len(
                [
                    item
                    for item in result.tool_ledger
                    if item["tool_name"] == "lookup_attack_technique"
                ]
            ),
        }
        _write_json(output / "returned-knowledge.json", knowledge)
        _write_json(output / "development-condition.json", detail)
        result.artifact_hashes.update(
            {
                "returned_knowledge": sha256(
                    (output / "returned-knowledge.json").read_bytes()
                ).hexdigest(),
                "development_condition": sha256(
                    (output / "development-condition.json").read_bytes()
                ).hexdigest(),
            }
        )
        result.resources = {
            "latency_ms": max(0, total_latency - probe_latency),
            "worker_total_latency_ms": total_latency,
            "isolation_probe_latency_ms": probe_latency,
            "input_tokens": sum(item["usage"]["prompt_tokens"] for item in ledger)
            if usage_complete
            else None,
            "output_tokens": sum(item["usage"]["completion_tokens"] for item in ledger)
            if usage_complete
            else None,
            "cost": sum(item["cost_cny"] for item in ledger) if cost_complete else None,
            "model_logical_calls": len({item["logical_call_id"] for item in ledger}),
            "model_physical_attempts": len(ledger),
            "missing_reason": None
            if usage_complete and cost_complete
            else "usage_or_cost_unavailable",
            "development": detail,
        }
    return result


async def run_remediation(
    request: RemediationRequest, agent_dir: Path
) -> AdapterResult:
    if os.getpid() != 1 or not os.environ.get("TASK13_WORKER_NONCE"):
        raise PermissionError("v2 adapter requires inspected container worker PID1")
    if getattr(request, "schema_version", None) == "task13-remediation-worker-v4":
        from evals.adapters.epoch_development import validate_epoch_development_worker

        request = validate_epoch_development_worker(request, agent_dir)
    elif getattr(request, "schema_version", None) == "task13-remediation-worker-v3":
        from evals.adapters.epoch_remediation import validate_epoch_worker

        request = validate_epoch_worker(request, agent_dir)
    else:
        request = RemediationRequest.model_validate(request.model_dump(mode="json"))
    validate_binding(request, agent_dir, Path(os.environ["TASK13_SOURCE_DIR"]))
    budget_path = Path(os.environ["TASK13_BUDGET_DB"])
    require_existing_budget(budget_path, request.budget_identity)
    expected = "development" if request.purpose == "development" else "formal"
    if os.environ.get("TASK13_PHASE") != expected:
        raise ValueError("v2 worker phase differs from registered purpose")
    if request.purpose == "development":
        return await _run_development(request, agent_dir)
    return await run_case(
        request.worker_spec(),
        agent_dir,
        model_factory=lambda spec, phase: make_model(request, budget_path, phase),
    )
