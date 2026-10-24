"""Zero-paid-call R1/R2 gates against the frozen KB and real isolated services.

Run ``python -m evals.rag_gates --project-root ...``. Each attempt is append-only.
The child installs passive method observers, then runs the original MCP server.
Only model HTTP is replaced, at httpx.MockTransport, after payload serialization.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import socket
import subprocess
import sys
import uuid
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel

from evals.adapters.model_client import BudgetAccount, TrackedModel
from evals.contracts import ModelConfig, WorkerRunSpec, canonical_hash

QUERY = "password guessing"
EXACT_QUERY = "T1110.001"
EXPECTED_TECHNIQUE = "T1110.001"
RECORDED_RESPONSE = {
    "id": "local-recorded-rag-gate-response",
    "model": "local-recording-only-v1",
    "choices": [{"message": {"content": '{"observed":true}'}, "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 0, "completion_tokens": 0},
}
CHANNELS = ("exact", "keyword", "semantic", "embedding", "rrf", "legacy_keyword")


def write_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, default=str)


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fresh_condition_state(seed: dict, incident_id: str) -> dict:
    return {
        "incident_id": incident_id,
        "alerts": deepcopy(seed.get("alerts", [])),
        "evidence": deepcopy(seed.get("evidence", [])),
        "knowledge": [],
    }


def assert_channels(mode: str, events: list[dict], *, exact_query: bool) -> dict:
    counts = {channel: 0 for channel in CHANNELS}
    counts.update(
        Counter(
            event["channel"] for event in events if event.get("channel") in CHANNELS
        )
    )
    forbidden = (
        {*CHANNELS}
        if mode == "disabled"
        else {"exact", "keyword", "legacy_keyword"}
        if mode == "semantic_only"
        else {"keyword", "semantic", "embedding", "rrf", "legacy_keyword"}
        if exact_query
        else {"exact", "legacy_keyword"}
    )
    for channel in forbidden:
        assert counts[channel] == 0, f"forbidden channel {channel}: {counts[channel]}"
    required = (
        []
        if mode == "disabled"
        else ["exact"]
        if exact_query
        else ["semantic", "embedding", "rrf"]
        if mode == "semantic_only"
        else ["keyword", "embedding", "semantic", "rrf"]
    )
    for channel in required:
        assert counts[channel] == 1, f"required channel {channel}: {counts[channel]}"
    return counts


def assert_public_results(results: list[dict], official: dict) -> None:
    for item in results:
        row = official.get(item["knowledge_chunk_id"])
        assert row is not None, "result must be a frozen official chunk"
        assert item["summary"] == row["content"], "official content differs"
        assert item["source_uri"] == row["source"], "official source differs"
        for key in ("technique_id", "title", "version"):
            assert item[key] == row["chunk_metadata"][key], f"official {key} differs"


def assert_condition_isolation(records: list[dict]) -> None:
    assert {record["mode"] for record in records} == {
        "disabled",
        "semantic_only",
        "hybrid",
    }
    for key in ("state_id", "result_cache_id", "mcp_pid"):
        assert len({record[key] for record in records}) == 3, f"shared {key}"
    for key in ("fixed_input_sha256", "query", "model_config_sha256"):
        assert len({record[key] for record in records}) == 1, f"changed {key}"


class _RecordedAnswer(BaseModel):
    observed: bool


async def capture_model_input(
    state: dict, config: ModelConfig, destination: Path, name: str
) -> dict:
    """Capture exact final request bytes; a mandatory transport prevents network IO."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    captures = []

    def intercept(request: httpx.Request) -> httpx.Response:
        assert request.url == config.base_url + "/chat/completions"
        assert (
            request.headers["authorization"]
            == "Bearer LOCAL-RECORDED-RESPONSE-NO-API-KEY"
        )
        body = request.content
        payload = json.loads(body)
        body_name, payload_name = name + "-http-body.json", name + "-payload.json"
        with (destination / body_name).open("xb") as stream:
            stream.write(body)
        write_json(destination / payload_name, payload)
        context_text = payload["messages"][-1]["content"]
        context = json.loads(context_text)
        captures.append(
            {
                "payload_path": payload_name,
                "http_body_path": body_name,
                "http_body_sha256": hashlib.sha256(body).hexdigest(),
                "request_sha256": canonical_hash(payload),
                "messages_sha256": canonical_hash(payload["messages"]),
                "context_sha256": hashlib.sha256(context_text.encode()).hexdigest(),
                "context_bytes": len(context_text.encode()),
                "knowledge_ids": [
                    item["knowledge_chunk_id"] for item in context["knowledge"]
                ],
                "knowledge": context["knowledge"],
            }
        )
        return httpx.Response(200, json=deepcopy(RECORDED_RESPONSE))

    model = TrackedModel(
        config,
        api_key="LOCAL-RECORDED-RESPONSE-NO-API-KEY",
        account=BudgetAccount(destination / (name + "-mock-budget.sqlite")),
        phase="development",
        transport=httpx.MockTransport(intercept),
    )
    result = await model.structured("analyze", _RecordedAnswer, state)
    assert result.observed is True
    assert len(captures) == len(model.ledger) == 1
    record = captures[0]
    assert model.ledger[0]["request_sha256"] == record["request_sha256"]
    assert model.ledger[0]["cost_cny"] == 0
    record.update(
        mock_transport_requests=1,
        paid_model_requests=0,
        response_kind="fixed_recording_no_provider_call",
        recorded_response=deepcopy(RECORDED_RESPONSE),
        ledger=model.ledger,
    )
    write_json(destination / (name + "-input-receipt.json"), record)
    return record


@contextmanager
def local_network_only():
    """Fail closed if service/model code ever tries a non-loopback TCP connection."""
    original = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_getaddrinfo = socket.getaddrinfo
    blocked = []

    def require_local(host):
        if isinstance(host, bytes):
            host = host.decode("ascii")
        if host not in {None, "127.0.0.1", "localhost", "::1"}:
            blocked.append(str(host))
            raise PermissionError("RAG gate permits loopback services only")

    def connect(sock, address):
        if isinstance(address, tuple):
            require_local(address[0])
        return original(sock, address)

    def connect_ex(sock, address):
        if isinstance(address, tuple):
            require_local(address[0])
        return original_connect_ex(sock, address)

    def getaddrinfo(host, *args, **kwargs):
        require_local(host)
        return original_getaddrinfo(host, *args, **kwargs)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.getaddrinfo = getaddrinfo
    try:
        yield blocked
    finally:
        socket.socket.connect = original
        socket.socket.connect_ex = original_connect_ex
        socket.getaddrinfo = original_getaddrinfo


def observed_mcp_main(trace_path: Path) -> None:
    """Passive wrappers forward to the real repository, embedder, RRF and server."""
    from evidencesoc.mcp_server.main import main
    from evidencesoc.rag import embeddings, retriever
    from evidencesoc.tools.attack_work import AttackKnowledgeRepository

    def emit(event):
        with trace_path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps({"pid": os.getpid(), **event}, ensure_ascii=False) + "\n"
            )

    emit({"event": "child_started", "cache_policy": "fresh_process_no_result_cache"})

    def observe(owner, method, channel):
        original = getattr(owner, method)

        def wrapped(*args, **kwargs):
            emit({"event": "channel_invoked", "channel": channel})
            result = original(*args, **kwargs)
            emit(
                {
                    "event": "channel_returned",
                    "channel_result": channel,
                    "result": result
                    if channel != "embedding"
                    else {"dimensions": len(result)},
                }
            )
            return result

        setattr(owner, method, wrapped)

    for channel in ("exact", "keyword", "semantic"):
        observe(retriever.PostgresKnowledgeRepository, channel, channel)
    observe(embeddings.LocalEmbeddingProvider, "embed_query", "embedding")
    observe(AttackKnowledgeRepository, "lookup", "legacy_keyword")
    observe(retriever, "reciprocal_rank_fusion", "rrf")
    with local_network_only() as blocked:
        try:
            main()
        finally:
            emit({"event": "child_finished", "nonlocal_connect_attempts": len(blocked)})


def load_frozen_corpus(directory: Path) -> tuple[dict, dict]:
    from evidencesoc.rag.embeddings import MODEL_ID, validate_vectors
    from evidencesoc.rag.ingest_attack import parse_attack
    from evidencesoc.rag.models import SourceManifest

    snapshot = directory / "knowledge_chunks.jsonl"
    receipt = json.loads(
        (directory / "preparation-receipt.json").read_text(encoding="utf-8")
    )
    assert file_hash(snapshot) == receipt["sha256"], "frozen snapshot hash mismatch"
    source = directory / "enterprise-attack-19.2.json"
    manifest = SourceManifest.model_validate_json(
        (directory / "enterprise-attack-19.2.manifest.json").read_text(encoding="utf-8")
    )
    assert file_hash(source) == manifest.sha256 == receipt["source_sha256"]
    expected = {
        chunk.knowledge_chunk_id: chunk
        for chunk in parse_attack(
            source.read_bytes(), manifest=manifest, embedding_model=MODEL_ID
        )
    }
    rows = [
        json.loads(line) for line in snapshot.read_text(encoding="utf-8").splitlines()
    ]
    official = {row["knowledge_chunk_id"]: row for row in rows}
    assert len(rows) == len(official) == len(expected) == receipt["rows"] == 997
    for identity, row in official.items():
        pinned = expected[identity]
        assert row["content"] == pinned.content and row["source"] == pinned.source_uri
        assert row["chunk_metadata"] == pinned.metadata
        validate_vectors([row["embedding"]], expected_count=1)
    return official, {
        **receipt,
        "model_manifest_sha256": file_hash(directory / "model" / "manifest.json"),
    }


def local_service_environment(project: Path, knowledge: Path) -> dict:
    """Only service settings are selected from .env; model credentials are unused."""
    from evidencesoc.config import Settings
    from sqlalchemy.engine import make_url

    selected = {}
    with (project / ".env").open(encoding="utf-8-sig") as stream:
        for line in stream:
            key = line.partition("=")[0].strip()
            if key in {"DATABASE_URL", "OPENSEARCH_URL"}:
                selected[key] = line.partition("=")[2].strip().strip("\"'")
    settings = Settings(
        _env_file=None, **{key.lower(): value for key, value in selected.items()}
    )
    assert make_url(settings.database_url).host in {"127.0.0.1", "localhost", "::1"}
    assert urlsplit(settings.opensearch_url).hostname in {
        "127.0.0.1",
        "localhost",
        "::1",
    }
    return {
        "DATABASE_URL": settings.database_url,
        "OPENSEARCH_URL": settings.opensearch_url,
        "RAG_DATA_DIRECTORY": str(knowledge),
    }


@contextmanager
def scoped_environment(values: dict):
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


async def real_condition(
    environment,
    seed: dict,
    mode: str,
    query: str,
    attempt: Path,
    name: str,
    official: dict,
    config: ModelConfig,
) -> dict:
    from evidencesoc.agents.capabilities import (
        InvestigationCapabilities,
        capability_scope,
    )
    from evidencesoc.mcp_server.client import build_stdio_parameters
    from evidencesoc.mcp_server.context import RunContext
    from evidencesoc.persistence.tables import AgentRunTable, ToolCallTable
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client
    from sqlalchemy import select

    directory = attempt / name
    directory.mkdir()
    run_id, state_id, cache_id = (
        "AR-" + uuid.uuid4().hex,
        uuid.uuid4().hex,
        uuid.uuid4().hex,
    )
    state = fresh_condition_state(seed, environment.incident_id)
    # This cache exists only for this condition and cannot be populated by a prior condition.
    result_cache = {}
    with environment.sessions() as session:
        session.add(
            AgentRunTable(
                run_id=run_id,
                incident_id=environment.incident_id,
                agent_name="rag_gate",
                status="running",
                started_at=datetime.now(UTC),
                evidence_ids=[],
            )
        )
        session.commit()
    policy = InvestigationCapabilities(rag_mode=mode)
    trace = directory / "channels.jsonl"
    with capability_scope(policy):
        allowed = True
        try:
            policy.require_tool("lookup_attack_technique")
        except PermissionError:
            allowed = False
        parameters = build_stdio_parameters(
            RunContext(run_id, environment.incident_id, "TRACE-" + state_id),
            settings=environment.settings,
            backend_dir=Path(__file__).resolve().parents[1] / "services" / "backend",
            python_executable=sys.executable,
            managed_attempts=True,
        )
        parameters.args = ["-m", "evals.rag_gates", "--mcp-child", str(trace)]
        # Only the original three local service env settings and scope are passed by the MCP client.
        with (directory / "mcp-stderr.txt").open("x", encoding="utf-8") as errlog:
            async with (
                stdio_client(parameters, errlog=errlog) as (read, write),
                ClientSession(read, write) as mcp,
            ):
                await mcp.initialize()
                response = await mcp.call_tool(
                    "lookup_attack_technique", {"query": query, "limit": 10}
                )
                write_json(
                    directory / "mcp-response.json", response.model_dump(mode="json")
                )
                if mode == "disabled":
                    assert not allowed and response.isError, (
                        "empty condition must deny real tool request"
                    )
                    assert (
                        response.structuredContent["error"]["code"] == "POLICY_DENIED"
                    )
                    results = []
                else:
                    assert allowed and not response.isError, (
                        "allowed real MCP lookup failed"
                    )
                    structured = response.structuredContent
                    results = (
                        structured["result"]
                        if isinstance(structured, dict) and "result" in structured
                        else structured
                    )
                    if not isinstance(results, list):
                        # FastMCP encodes list returns under its generated result wrapper.
                        results = json.loads(response.content[0].text)
                    if isinstance(results, dict):
                        results = results["result"]
                    assert isinstance(results, list) and results, (
                        "known query returned no knowledge"
                    )
                    result_cache[query] = deepcopy(results)
                    state["knowledge"] = deepcopy(result_cache[query])
    events = [
        json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()
    ]
    write_json(directory / "returned-knowledge.json", results)
    counts = assert_channels(mode, events, exact_query=query == EXACT_QUERY)
    assert_public_results(results, official)
    assert (
        events[-1]["event"] == "child_finished"
        and events[-1]["nonlocal_connect_attempts"] == 0
    )
    with environment.sessions() as session:
        calls = session.scalars(
            select(ToolCallTable).where(ToolCallTable.run_id == run_id)
        ).all()
        audit = [
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
    write_json(directory / "backend-tool-audit.json", audit)
    assert len(audit) == 1 and audit[0]["success"] == allowed
    model_input = await capture_model_input(state, config, directory, "final")
    if mode == "disabled":
        assert model_input["knowledge_ids"] == []
        payload_text = (directory / model_input["payload_path"]).read_text(
            encoding="utf-8"
        )
        assert all(identity not in payload_text for identity in official), (
            "empty condition leaked frozen knowledge"
        )
    else:
        assert EXPECTED_TECHNIQUE in {item["technique_id"] for item in results}, (
            "expected official technique missing"
        )
        assert EXPECTED_TECHNIQUE in {
            item["technique_id"] for item in model_input["knowledge"]
        }, "expected technique lost during packing"
        assert model_input["knowledge_ids"] == [
            item["knowledge_chunk_id"] for item in results[:5]
        ]
    record = {
        "mode": mode,
        "query": query,
        "retrieval_allowed": allowed,
        "state_id": state_id,
        "result_cache_id": cache_id,
        "mcp_pid": events[0]["pid"],
        "cache_policy": "fresh_process_and_fresh_result_dictionary",
        "channel_counts": counts,
        "fixed_input_sha256": canonical_hash(
            fresh_condition_state(seed, environment.incident_id)
        ),
        "model_config_sha256": canonical_hash(config.model_dump(mode="json")),
        "knowledge_returned_ids": [item["knowledge_chunk_id"] for item in results],
        "backend_tool_calls": len(audit),
        "mcp_tool_requests": 1,
        "model_input": model_input,
        "evidence_directory": name,
    }
    write_json(directory / "condition.json", record)
    return record


def source_binding(root: Path) -> dict:
    paths = [
        "evals/rag_gates.py",
        "evals/adapters/model_client.py",
        "evals/adapters/environment.py",
        "services/backend/src/evidencesoc/rag/retriever.py",
        "services/backend/src/evidencesoc/rag/embeddings.py",
        "services/backend/src/evidencesoc/mcp_server/main.py",
        "services/backend/src/evidencesoc/mcp_server/client.py",
        "services/backend/src/evidencesoc/agents/capabilities.py",
    ]
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    return {
        "git_head": commit,
        "files_sha256": {path: file_hash(root / path) for path in paths},
    }


def write_engineering_seed(attempt: Path) -> Path:
    agent = attempt / "fixed-agent-input"
    agent.mkdir()
    event = {
        "source": "gate-observation",
        "severity": "info",
        "event_type": "observation",
        "host": "gate-local-host",
        "observed_at": "2026-10-22T00:00:00Z",
        "message": "password guessing",
    }
    with (agent / "events.jsonl").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")
    return agent


async def run_gates(project: Path) -> Path:
    from evals.adapters.environment import case_environment
    from evals.adapters.seed import load_seed

    project = project.resolve()
    root = Path(__file__).resolve().parents[1]
    output = project / "data/task13/supplements/task13-repair-202610-v2/gates"
    output.mkdir(parents=True, exist_ok=True)
    attempt = output / (
        "attempt-"
        + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-")
        + uuid.uuid4().hex[:10]
    )
    attempt.mkdir()
    frozen = project / "data/task13/knowledge/v1"
    stage = "frozen_corpus"
    try:
        official, snapshot = load_frozen_corpus(frozen)
        config = ModelConfig()
        binding = {
            "source": source_binding(root),
            "knowledge_snapshot": snapshot,
            "model_config": config.model_dump(mode="json"),
            "paid_model_requests": 0,
            "model_credential_source": "none_fixed_nonsecret_literal",
            "scope": "deterministic_engineering_smoke_only_not_formal_effectiveness",
            "fixed_queries": [
                {
                    "kind": "ordinary",
                    "query": QUERY,
                    "expected_technique": EXPECTED_TECHNIQUE,
                },
                {
                    "kind": "exact",
                    "query": EXACT_QUERY,
                    "expected_technique": EXPECTED_TECHNIQUE,
                },
            ],
        }
        write_json(attempt / "preregistered-inputs.json", binding)
        # A fixed harmless local observation anchors identical evidence in every condition.
        # It is engineering input only; knowledge always comes from the 997 official chunks.
        agent = write_engineering_seed(attempt)
        spec = WorkerRunSpec(
            run_id="rag-gates-v2",
            case_id="fixed-engineering-query",
            group="B3",
            config_sha256=canonical_hash(binding),
        )
        seed = load_seed(spec, agent)
        stage = "isolated_local_services"
        with (
            scoped_environment(local_service_environment(project, frozen)),
            local_network_only() as blocked,
        ):
            with case_environment(spec, seed) as environment:
                resources = {
                    "database_name": environment.database_name,
                    "index_name": environment.index_name,
                    "incident_id": environment.incident_id,
                    "cleanup": "context_manager_drop_fresh_resources",
                }
                write_json(attempt / "isolated-resources.json", resources)
                records = []
                for name, mode, query in [
                    ("empty", "disabled", QUERY),
                    ("semantic", "semantic_only", QUERY),
                    ("hybrid", "hybrid", QUERY),
                    ("exact", "hybrid", EXACT_QUERY),
                ]:
                    stage = name
                    records.append(
                        await real_condition(
                            environment,
                            seed,
                            mode,
                            query,
                            attempt,
                            name,
                            official,
                            config,
                        )
                    )
                assert_condition_isolation(records[:3])
                stage = "final_http_truncation"
                results = json.loads(
                    (attempt / "hybrid/returned-knowledge.json").read_text(
                        encoding="utf-8"
                    )
                )
                assert len(results) > 5, "real query must exercise the first-five bound"
                bounded = await capture_model_input(
                    {"knowledge": results},
                    ModelConfig(max_context_bytes=4096),
                    attempt,
                    "byte-bound",
                )
                assert (
                    0 < len(bounded["knowledge_ids"]) < 5
                    and bounded["context_bytes"] <= 4096
                )
                assert all(
                    len(item["summary"].encode()) <= 2048
                    for item in bounded["knowledge"]
                )
            assert not blocked
        complete = {
            **binding,
            "status": "passed",
            "created_at": datetime.now(UTC).isoformat(),
            "resources": resources,
            "nonlocal_connect_attempts": len(blocked),
            "attempt_directory": str(attempt),
            "cleanup_completed": True,
        }
        r1 = {
            **complete,
            "gate": "R1",
            "records": [record for record in records if record["mode"] != "disabled"],
            "byte_bound": bounded,
        }
        r2 = {
            **complete,
            "gate": "R2",
            "records": records[:3],
            "same_results_allowed": True,
            "semantic_hybrid_same_returned_ids": records[1]["knowledge_returned_ids"]
            == records[2]["knowledge_returned_ids"],
        }
        write_json(attempt / "r1-channel.json", r1)
        write_json(attempt / "r2-isolation.json", r2)
        write_json(
            attempt / "gate-summary.json",
            {
                "status": "passed",
                "R1": file_hash(attempt / "r1-channel.json"),
                "R2": file_hash(attempt / "r2-isolation.json"),
                "paid_model_requests": 0,
            },
        )
        # Canonical receipts are created once; attempts always preserve failures and reruns.
        for name in ("r1-channel.json", "r2-isolation.json"):
            if not (output / name).exists():
                with (output / name).open("xb") as stream:
                    stream.write((attempt / name).read_bytes())
        return attempt
    except BaseException as error:
        write_json(
            attempt / "failed-attempt.json",
            {
                "status": "failed",
                "stage": stage,
                "error_type": type(error).__name__,
                "assertion": str(error) if isinstance(error, AssertionError) else None,
                "paid_model_requests": 0,
                "not_passed": ["R1", "R2"],
            },
        )
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--mcp-child", type=Path)
    args = parser.parse_args()
    if args.mcp_child:
        observed_mcp_main(args.mcp_child)
    elif args.project_root:
        print(asyncio.run(run_gates(args.project_root)))
    else:
        parser.error("--project-root is required")


if __name__ == "__main__":
    main()
