"""Only synthetic exported sources, existing synthetic accounts and MockTransport."""

import json
import os
import sqlite3
import subprocess
import sys
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from types import ModuleType, SimpleNamespace

import httpx
import pytest
from pydantic import BaseModel

from evals.adapters.model_client import BudgetAccount, BudgetLimit
from evals.adapters.remediation_contracts import (
    CAMPAIGN,
    ENTRY_PROMPT,
    RemediationRequest,
)
from evals.contracts import AdapterResult, canonical_hash


def request_for(tmp_path, *, purpose="development", mode="hybrid", index=0):
    from evals.adapters.remediation_worker import read_budget_identity

    budget = BudgetAccount(tmp_path / "budget" / "campaign.sqlite")
    with sqlite3.connect(budget.path) as db:
        empty = db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 0
    if empty:
        historic = budget.reserve("synthetic-original-history", 0.01, "formal")
        budget.settle(historic, 0.001)
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    (source / "worker.py").write_text("# synthetic frozen source\n", encoding="utf-8")
    receipt = {
        "source_commit": "a" * 40,
        "archive_sha256": "b" * 64,
        "files": {"worker.py": sha256((source / "worker.py").read_bytes()).hexdigest()},
    }
    (source / "source_receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
    agent = tmp_path / "agent"
    agent.mkdir(exist_ok=True)
    (agent / "events.jsonl").write_text(
        json.dumps(
            {
                "source": "synthetic",
                "event_type": "observation",
                "severity": "info",
                "observed_at": "2026-10-22T00:00:00Z",
                "host": "synthetic-host",
                "message": "password guessing",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    slot = purpose + "-" + canonical_hash([mode, index])[:24]
    values = {
        "run_id": CAMPAIGN + "-" + canonical_hash([slot, 1])[:16],
        "case_id": "ait-" + "0" * 24,
        "group": "B3",
        "slot_id": slot,
        "purpose": purpose,
        "source_commit": "a" * 40,
        "source_sha256": canonical_hash(receipt),
        "config_sha256": "c" * 64,
        "agent_sha256": sha256((agent / "events.jsonl").read_bytes()).hexdigest(),
        "budget_identity": read_budget_identity(budget.path),
    }
    if purpose == "development":
        values.update(
            rag_mode=mode,
            initial_query="password guessing",
            initial_query_sha256=sha256(b"password guessing").hexdigest(),
        )
    return RemediationRequest(**values), agent, source


def worker_environment(monkeypatch, tmp_path, request, source):
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-nonce")
    monkeypatch.setenv("TASK13_SOURCE_DIR", str(source))
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", request.source_commit)
    monkeypatch.setenv(
        "TASK13_PHASE", "development" if request.purpose == "development" else "formal"
    )
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-secret-must-not-be-recorded")
    budget = tmp_path / "budget" / "campaign.sqlite"
    BudgetAccount(budget)
    monkeypatch.setenv("TASK13_BUDGET_DB", str(budget))
    output = tmp_path / request.slot_id
    output.mkdir()
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(output))
    return budget, output


def test_runtime_recognizes_v2_request_without_changing_v1_route(tmp_path):
    from scripts.task13_worker_runtime import _worker_request

    request, _, _ = request_for(tmp_path)
    parsed = _worker_request(request.model_dump(mode="json"))
    assert isinstance(parsed, RemediationRequest)
    assert parsed.budget_binding()["purpose"] == "development"
    assert _worker_request(request.worker_spec().model_dump(mode="json")).group == "B3"


@pytest.mark.asyncio
async def test_runtime_invokes_the_dedicated_v2_adapter(tmp_path, monkeypatch):
    from evals.adapters import remediation_worker
    from scripts.task13_worker_runtime import _invoke_adapter

    request, agent, _ = request_for(tmp_path)
    calls = []

    async def run(request, agent):
        calls.append((request, agent))
        return AdapterResult()

    monkeypatch.setattr(remediation_worker, "run_remediation", run)
    await _invoke_adapter(request, agent)
    assert calls == [(request, agent)]


@pytest.mark.parametrize("tamper", ["agent", "source", "receipt", "commit"])
def test_worker_rejects_input_or_export_drift(tmp_path, monkeypatch, tamper):
    from evals.adapters.remediation_worker import validate_binding

    request, agent, source = request_for(tmp_path)
    worker_environment(monkeypatch, tmp_path, request, source)
    if tamper == "agent":
        (agent / "events.jsonl").write_text("{}\n", encoding="utf-8")
    elif tamper == "source":
        (source / "worker.py").write_text("changed", encoding="utf-8")
    elif tamper == "receipt":
        (source / "source_receipt.json").write_text("{}", encoding="utf-8")
    else:
        monkeypatch.setenv("TASK13_SOURCE_COMMIT", "d" * 40)
    with pytest.raises(ValueError):
        validate_binding(request, agent, source)


def test_v2_factory_refuses_missing_original_account_and_wrong_phase(
    tmp_path, monkeypatch
):
    from evals.adapters.remediation_worker import make_model

    request, _, _ = request_for(tmp_path)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic")
    missing = tmp_path / "missing" / "campaign.sqlite"
    with pytest.raises(ValueError, match="existing"):
        make_model(request, missing, "development")
    assert not missing.exists()
    path = tmp_path / "budget" / "campaign.sqlite"
    BudgetAccount(path)
    with pytest.raises(ValueError, match="phase"):
        make_model(request, path, "formal")


def test_development_seed_is_identical_across_unique_slot_run_ids(tmp_path):
    from evals.adapters.remediation_worker import development_seed

    first, agent, _ = request_for(tmp_path, mode="disabled")
    second, _, _ = request_for(tmp_path, mode="semantic_only")
    third, _, _ = request_for(tmp_path, mode="hybrid")
    assert len({first.run_id, second.run_id, third.run_id}) == 3
    assert (
        development_seed(first, agent)
        == development_seed(second, agent)
        == development_seed(third, agent)
    )


def test_original_budget_identity_rejects_empty_compatible_account_and_tracks_prefix(
    tmp_path,
):
    from evals.adapters.remediation_worker import (
        read_budget_identity,
        require_existing_budget,
    )

    original = BudgetAccount(tmp_path / "original.sqlite")
    first = original.reserve("historic-known", 0.3, "development")
    original.settle(first, 0.15)
    second = original.reserve("historic-unknown", 0.2, "formal")
    original.settle(second, None)
    before = sha256(original.path.read_bytes()).hexdigest()
    identity = read_budget_identity(original.path)
    assert identity["baseline_count"] == identity["baseline_max_rowid"] == 2
    require_existing_budget(original.path, identity)
    assert sha256(original.path.read_bytes()).hexdigest() == before
    empty = BudgetAccount(tmp_path / "compatible-empty.sqlite")
    with pytest.raises(ValueError, match="identity"):
        require_existing_budget(empty.path, identity)
    original.reserve("new-v2-append", 0.1, "formal")
    require_existing_budget(original.path, identity)
    with sqlite3.connect(original.path) as db:
        db.execute("UPDATE reservations SET actual=0.14 WHERE id=?", (first,))
    with pytest.raises(ValueError, match="identity"):
        require_existing_budget(original.path, identity)


def test_original_budget_identity_is_mandatory_and_strict(tmp_path):
    from evals.adapters.remediation_worker import require_existing_budget

    path = tmp_path / "compatible.sqlite"
    BudgetAccount(path)
    for identity in [
        None,
        {},
        {
            "schema_version": "task13-original-budget-identity-v1",
            "baseline_count": True,
            "baseline_max_rowid": 1,
            "baseline_sha256": "a" * 64,
        },
    ]:
        with pytest.raises(ValueError, match="identity"):
            require_existing_budget(path, identity)


class Answer(BaseModel):
    verdict: str


@pytest.mark.asyncio
async def test_stable_call_wrapper_records_final_prompt_and_prevents_random_hint_replay(
    tmp_path, monkeypatch
):
    from evals.adapters.remediation_worker import PayloadRecorder, make_model

    request, _, source = request_for(tmp_path)
    path, output = worker_environment(monkeypatch, tmp_path, request, source)
    sent = []

    def respond(http_request):
        sent.append(http_request)
        return httpx.Response(
            200,
            json={
                "id": "synthetic-provider-id",
                "model": "synthetic-v1",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"verdict":"benign"}'},
                    }
                ],
            },
        )

    recorder = PayloadRecorder(output)
    model = make_model(
        request,
        path,
        "development",
        transport=httpx.MockTransport(respond),
        payload_sink=recorder,
    )
    await model.structured("analyze", Answer, {"_model_call_id": "first-random-hint"})
    await model.structured("analyze", Answer, {"_model_call_id": "first-random-hint"})
    assert len({item["logical_call_id"] for item in model.ledger}) == 1
    assert [item["physical_attempt"] for item in model.ledger] == [1, 2]
    assert all(
        item["slot_id"] == request.slot_id and item["run_id"] == request.run_id
        for item in model.ledger
    )
    assert (
        model.account.supplement_summary()["purposes"]["development"]["known_cny"] > 0
    )
    assert recorder.records[0]["request_sha256"] == model.ledger[0]["request_sha256"]
    body = (output / recorder.records[0]["http_body_path"]).read_bytes()
    assert body == sent[0].content
    assert ENTRY_PROMPT in body.decode()
    assert "synthetic-secret-must-not-be-recorded" not in body.decode()
    reopened = make_model(
        request, path, "development", transport=httpx.MockTransport(respond)
    )
    with pytest.raises(BudgetLimit, match="already"):
        await reopened.structured(
            "analyze", Answer, {"_model_call_id": "different-random-hint-after-crash"}
        )
    assert len(sent) == 2


@pytest.mark.asyncio
async def test_regression_delegates_to_original_adapter_with_bound_factory(
    tmp_path, monkeypatch
):
    from evals.adapters import remediation_worker as worker

    request, agent, source = request_for(tmp_path, purpose="regression")
    path, _ = worker_environment(monkeypatch, tmp_path, request, source)
    monkeypatch.setattr(worker.os, "getpid", lambda: 1)
    seen = []

    async def original(spec, agent_dir, *, model_factory):
        model = model_factory(spec, "formal")
        seen.append((spec, agent_dir, model))
        return AdapterResult(product_status="original-B3-path")

    monkeypatch.setattr(worker, "run_case", original)
    result = await worker.run_remediation(request, agent)
    assert result.product_status == "original-B3-path"
    assert seen[0][0] == request.worker_spec()
    assert seen[0][1] == agent
    assert seen[0][2].account.path == path
    assert seen[0][2].account.request_binding() == request.budget_binding()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["disabled", "semantic_only", "hybrid"])
@pytest.mark.parametrize("outcome", ["benign", "unknown", "invalid"])
async def test_development_uses_fresh_state_fixed_query_and_analysis_only(
    tmp_path, monkeypatch, mode, outcome
):
    from evidencesoc.agents.models import AnalysisOutput

    from evals.adapters import remediation_worker as worker

    request, agent, source = request_for(tmp_path, mode=mode)
    _, output = worker_environment(monkeypatch, tmp_path, request, source)
    monkeypatch.setattr(worker.os, "getpid", lambda: 1)
    environments, lookup_modes = [], []

    @contextmanager
    def environment(spec, seed):
        assert spec.run_id == request.run_id
        value = SimpleNamespace(incident_id="IN-" + spec.run_id, sessions=None)
        environments.append(value)
        yield value

    async def probe(spec, environment, seed):
        return {"status": "passed", "latency_ms": 0}

    async def lookup(environment, request):
        assert request.initial_query == "password guessing"
        lookup_modes.append(request.rag_mode)
        return [
            {
                "knowledge_chunk_id": "KC-synthetic",
                "technique_id": "T1110",
                "source_uri": "https://attack.mitre.org/techniques/T1110/",
                "summary": "synthetic public knowledge",
            }
        ]

    sent, payloads = [], []

    def respond(http_request):
        payload = json.loads(http_request.content)
        payloads.append(payload)
        state = json.loads(payload["messages"][-1]["content"])
        sent.append(state)
        assert ENTRY_PROMPT in json.dumps(payload, ensure_ascii=False)
        evidence_id = state["evidence"][0]["evidence_id"]
        return httpx.Response(
            200,
            json={
                "id": "synthetic-provider",
                "model": "synthetic-v1",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps(
                                {
                                    "origin": None,
                                    "classification": None,
                                    "diagnosis": None,
                                }
                                if outcome == "invalid"
                                else {
                                    "origin": None,
                                    "classification": None,
                                    "diagnosis": {
                                        "verdict": outcome,
                                        "taxonomy_status": "not_applicable"
                                        if outcome == "benign"
                                        else "unknown",
                                        "evidence_ids": [evidence_id]
                                        if outcome == "benign"
                                        else [],
                                    },
                                }
                            )
                        },
                    }
                ],
            },
        )

    original_factory = worker.make_model
    monkeypatch.setattr(
        worker,
        "make_model",
        lambda *args, **kwargs: original_factory(
            *args, transport=httpx.MockTransport(respond), **kwargs
        ),
    )
    monkeypatch.setattr(worker, "case_environment", environment)
    monkeypatch.setattr(worker, "run_service_probe", probe)
    monkeypatch.setattr(worker, "lookup_knowledge", lookup)
    monkeypatch.setattr(worker, "export_tool_ledger", lambda environment: [])
    result = await worker.run_remediation(request, agent)
    actual_schema = json.loads(
        next(
            message["content"].split("JSON schema:\n", 1)[1]
            for message in payloads[0]["messages"]
            if "JSON schema:\n" in message["content"]
        )
    )
    assert actual_schema == AnalysisOutput.model_json_schema()
    assert result.diagnosis_status == (
        "failed" if outcome == "invalid" else "succeeded"
    ), result.errors
    assert result.execution_status == (
        "failed" if outcome == "invalid" else "completed"
    )
    assert result.product_status == "analysis_only"
    assert len(environments) == 1
    assert len(sent) == (3 if outcome == "invalid" else 1)
    assert lookup_modes == ([] if mode == "disabled" else [mode])
    assert len(sent[0]["knowledge"]) == (0 if mode == "disabled" else 1)
    detail = result.resources["development"]
    assert detail["mode"] == mode
    assert detail["initial_query_sha256"] == request.initial_query_sha256
    assert (
        detail["knowledge_returned"]
        == detail["knowledge_in_context"]
        == len(sent[0]["knowledge"])
    )
    assert detail["entry_schema"] == "AnalysisOutput"
    assert detail["entry_schema_sha256"] == canonical_hash(
        AnalysisOutput.model_json_schema()
    )
    if outcome == "invalid":
        assert result.diagnostic_snapshot is None
        assert detail["citations"] == []
        assert len(result.errors) == 3
    else:
        assert (
            detail["citations"]
            == result.diagnostic_snapshot["diagnosis"]["evidence_ids"]
        )
        assert result.diagnostic_snapshot["origin"] is None
        assert result.diagnostic_snapshot["classification"] is None
    assert (output / "development-condition.json").is_file()
    assert result.model_ledger[0]["campaign_id"] == CAMPAIGN


@pytest.mark.asyncio
async def test_runtime_remediation_wrapper_preserves_request_and_requires_v2(
    tmp_path, monkeypatch
):
    from scripts import task13_worker_runtime as runtime

    request, agent, _ = request_for(tmp_path)
    calls = []

    async def run(spec, agent_dir, options):
        calls.append((spec, agent_dir, options))
        return {"execution_status": "completed"}

    monkeypatch.setattr(runtime, "run_container", run)
    assert (await runtime.run_remediation_container(request, agent, {}))[
        "execution_status"
    ] == "completed"
    assert calls == [(request.model_dump(mode="json"), agent, {})]
    with pytest.raises(ValueError, match="dedicated"):
        await runtime.run_remediation_container(request.worker_spec(), agent, {})


@pytest.mark.asyncio
async def test_runtime_routes_dedicated_review_contract_and_adapter(
    monkeypatch, tmp_path
):
    from scripts import task13_worker_runtime as runtime

    calls = []
    parsed = SimpleNamespace(schema_version="task13-remediation-review-worker-v2")
    module = ModuleType("evals.adapters.remediation_review")

    class ReviewContract:
        @classmethod
        def model_validate(cls, value):
            calls.append(value)
            return parsed

    async def run(request, agent):
        calls.append((request, agent))
        return AdapterResult()

    module.RemediationReviewRequest = ReviewContract
    module.run_remediation_review = run
    monkeypatch.setitem(sys.modules, module.__name__, module)
    spec = {"schema_version": parsed.schema_version}
    assert runtime._worker_request(spec) is parsed
    await runtime._invoke_adapter(parsed, tmp_path)
    assert calls == [spec, (parsed, tmp_path)]


@pytest.mark.asyncio
async def test_review_wrapper_refuses_models_for_read_and_decision(
    monkeypatch, tmp_path
):
    from scripts import task13_worker_runtime as runtime

    async def injected_paid_result(*args):
        return {"model_ledger": [{"physical_request_id": "unexpected"}]}

    monkeypatch.setattr(runtime, "run_container", injected_paid_result)
    for operation in ("read_packet", "decision"):
        with pytest.raises(ValueError, match="cannot make model"):
            await runtime.run_remediation_review_container(
                {
                    "schema_version": "task13-remediation-review-worker-v2",
                    "operation": operation,
                },
                tmp_path,
                {},
            )
    with pytest.raises(ValueError, match="dedicated"):
        await runtime.run_remediation_review_container(
            {
                "schema_version": "task13-source-review-worker-v1",
                "operation": "renew_plan",
            },
            tmp_path,
            {},
        )


def test_shared_export_binding_accepts_only_already_validated_review_fields(
    tmp_path, monkeypatch
):
    from evals.adapters.remediation_worker import validate_exported_source

    request, agent, source = request_for(tmp_path)
    worker_environment(monkeypatch, tmp_path, request, source)
    validated_review = SimpleNamespace(
        source_commit=request.source_commit,
        agent_sha256=request.agent_sha256,
        source_sha256=request.source_sha256,
    )
    validate_exported_source(validated_review, agent, source)
    (source / "worker.py").write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="source"):
        validate_exported_source(validated_review, agent, source)


@pytest.mark.asyncio
@pytest.mark.parametrize("purpose", ["development", "f8"])
@pytest.mark.parametrize("operation", ["read_packet", "decision", "renew_plan"])
async def test_review_runtime_keeps_workflow_phase_and_only_renewal_credentials(
    tmp_path, monkeypatch, purpose, operation
):
    from evals.adapters.worker_errors import WorkerInfrastructureError
    from evals.tests.test_remediation_review import inputs
    from scripts import task13_worker_runtime as runtime

    request, agent, source, budget, _ = inputs(
        tmp_path, purpose=purpose, operation=operation
    )
    dependencies = tmp_path / "deps"
    for name in (
        "mcp",
        "langgraph",
        "langchain_openai",
        "fastembed",
        "pydantic",
        "sqlalchemy",
        "httpx",
    ):
        (dependencies / name).mkdir(parents=True)
    (dependencies / "task13_dependencies.json").write_text(
        json.dumps(
            {
                "lock_sha256": "a" * 64,
                "platform": "linux-amd64",
                "tree_sha256": "b" * 64,
                "python_version": "3.12.14",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(runtime, "_validate_source", lambda *args: None)
    monkeypatch.setattr(runtime, "dependency_tree_hash", lambda *args: "b" * 64)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-renewal-only")
    environments = []

    async def stop_before_docker(*args, **kwargs):
        environments.append(kwargs["env"])
        raise OSError("synthetic startup boundary")

    monkeypatch.setattr(runtime.asyncio, "create_subprocess_exec", stop_before_docker)
    options = {
        "source_dir": str(source),
        "source_commit": request.source_commit,
        "dependencies_dir": str(dependencies),
        "dependencies_lock_sha256": "a" * 64,
        "knowledge_dir": str(tmp_path / "knowledge"),
        "knowledge_sha256": "b" * 64,
        "budget_dir": str(budget.parent),
        "budget_identity": request.budget_identity,
        "output_dir": str(tmp_path / "runtime-output"),
        "image_id": "sha256:" + "c" * 64,
        "network": "task13",
        "phase": "verification",
    }
    with pytest.raises(WorkerInfrastructureError, match="startup"):
        await runtime.run_remediation_review_container(request, agent, options)
    assert environments[0]["TASK13_PHASE"] == "verification"
    assert ("DEEPSEEK_API_KEY" in environments[0]) == (operation == "renew_plan")


def analysis_answer(state, verdict="benign"):
    return {
        "origin": None,
        "classification": None,
        "diagnosis": {
            "verdict": verdict,
            "taxonomy_status": {
                "benign": "not_applicable",
                "unknown": "unknown",
                "attack": "out_of_taxonomy",
            }[verdict],
            "evidence_ids": []
            if verdict == "unknown"
            else [state["evidence"][0]["evidence_id"]],
        },
    }


async def invoke_development_analysis(tmp_path, monkeypatch, outcomes):
    from evals.adapters import remediation_worker as worker

    request, agent, source = request_for(tmp_path, mode="disabled")
    budget_path, output = worker_environment(monkeypatch, tmp_path, request, source)
    seed = worker.development_seed(request, agent)
    state = {
        "incident_id": "IN-synthetic",
        "alerts": seed["alerts"],
        "evidence": seed["evidence"],
        "knowledge": [],
    }
    payloads = []

    def respond(http_request):
        payload = json.loads(http_request.content)
        payloads.append(payload)
        outcome = outcomes[min(len(payloads) - 1, len(outcomes) - 1)]
        if outcome == "timeout":
            raise httpx.ReadTimeout(
                "synthetic transport interruption", request=http_request
            )
        result = outcome(state) if callable(outcome) else outcome
        return httpx.Response(
            200,
            json={
                "id": f"synthetic-{len(payloads)}",
                "model": "synthetic-v1",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(result)},
                    }
                ],
            },
        )

    recorder = worker.PayloadRecorder(output)
    model = worker.make_model(
        request,
        budget_path,
        "development",
        transport=httpx.MockTransport(respond),
        payload_sink=recorder,
    )
    result, errors = await worker.one_development_analysis(
        model, state, seed["registry"]
    )
    return result, errors, model, payloads, recorder, state, seed["registry"]


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", ["attack", "benign", "unknown"])
async def test_development_analysis_uses_exact_product_schema_and_accepts_model_unknown(
    tmp_path, monkeypatch, verdict
):
    from evidencesoc.agents.models import AnalysisOutput

    from evals.adapters import remediation_worker as worker

    result, errors, model, payloads, recorder, *_ = await invoke_development_analysis(
        tmp_path, monkeypatch, [lambda state: analysis_answer(state, verdict)]
    )
    assert worker.DEVELOPMENT_ANALYSIS_SCHEMA is AnalysisOutput
    assert result["diagnosis"]["verdict"] == verdict
    assert result["origin"] is result["classification"] is None
    assert errors == []
    assert len(payloads) == len(model.ledger) == 1
    schema = json.loads(
        next(
            item["content"].split("JSON schema:\n", 1)[1]
            for item in payloads[0]["messages"]
            if "JSON schema:\n" in item["content"]
        )
    )
    assert schema == AnalysisOutput.model_json_schema()
    assert recorder.records[0]["request_sha256"] == model.ledger[0]["request_sha256"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "bare_diagnosis",
        "missing_diagnosis",
        "foreign_citation",
        "unobserved_origin",
        "unsupported_technique",
        "evaluation_label",
        "answered_without_citation",
        "claim_without_citation",
    ],
)
async def test_development_analysis_preserves_schema_fact_and_citation_failures_without_fallback(
    tmp_path, monkeypatch, failure
):
    def invalid(state):
        answer = analysis_answer(state)
        if failure == "bare_diagnosis":
            return answer["diagnosis"]
        if failure == "missing_diagnosis":
            answer["diagnosis"] = None
        elif failure == "foreign_citation":
            answer["diagnosis"]["evidence_ids"] = ["EV-" + "Z" * 26]
        elif failure == "unobserved_origin":
            answer["origin"] = {
                "observed_source_ip": None,
                "entry_host": "not-in-observed-evidence",
                "entry_service": None,
                "first_seen_at": None,
                "source_scope": "unknown",
                "confidence": 0.5,
                "evidence_ids": answer["diagnosis"]["evidence_ids"],
            }
        elif failure in {"unsupported_technique", "evaluation_label"}:
            answer = analysis_answer(state, "attack")
            answer["classification"] = {
                "primary_type": "remote_command_execution",
                "attack_types": ["remote_command_execution"],
                "dataset_labels": ["forbidden-label"]
                if failure == "evaluation_label"
                else [],
                "attack_phase": None,
                "technique_ids": ["T1059"]
                if failure == "unsupported_technique"
                else [],
                "confidence": 0.5,
                "evidence_ids": answer["diagnosis"]["evidence_ids"],
            }
        elif failure == "answered_without_citation":
            answer["diagnosis"]["evidence_ids"] = []
        elif failure == "claim_without_citation":
            answer["diagnosis"]["claims"] = [
                {
                    "claim_id": "claim",
                    "text": "unsupported factual claim",
                    "evidence_ids": [],
                }
            ]
        return answer

    result, errors, model, payloads, *_ = await invoke_development_analysis(
        tmp_path, monkeypatch, [invalid]
    )
    assert result is None
    assert len(errors) == len(payloads) == len(model.ledger) == 3
    assert [item["physical_attempt"] for item in model.ledger] == [1, 2, 3]
    assert len({item["logical_call_id"] for item in model.ledger}) == 1
    assert all(item["cost_cny"] > 0 and item["finished_at"] for item in model.ledger)
    assert all(item["stage"] == "analysis" for item in errors)


@pytest.mark.asyncio
async def test_development_analysis_retries_preserve_unknown_usage_and_one_logical_cap(
    tmp_path, monkeypatch
):
    from evals.adapters import remediation_worker as worker

    (
        result,
        errors,
        model,
        payloads,
        _,
        state,
        registry,
    ) = await invoke_development_analysis(
        tmp_path,
        monkeypatch,
        [
            "timeout",
            {"diagnosis": None},
            lambda state: analysis_answer(state, "unknown"),
        ],
    )
    assert result["diagnosis"]["verdict"] == "unknown"
    assert len(errors) == 2
    assert errors[0]["category"] == "transport"
    assert len(payloads) == len(model.ledger) == 3
    assert len({item["logical_call_id"] for item in model.ledger}) == 1
    assert len({item["messages"][-1]["content"] for item in payloads}) == 1
    assert model.account.supplement_summary()["unknown_count"] == 1
    with pytest.raises(BudgetLimit):
        await worker.one_development_analysis(model, state, registry)
    assert len(payloads) == 3


@pytest.mark.asyncio
async def test_development_modes_and_repeats_send_identical_context_except_knowledge(
    tmp_path, monkeypatch
):
    from evals.adapters import remediation_worker as worker

    first, agent, source = request_for(tmp_path)
    monkeypatch.setattr(worker.os, "getpid", lambda: 1)
    contexts, actual_incidents = [], []

    @contextmanager
    def environment(spec, seed):
        identity = "IN-" + spec.run_id
        actual_incidents.append(identity)
        yield SimpleNamespace(incident_id=identity)

    async def probe(*args):
        return {"status": "passed", "latency_ms": 0}

    async def lookup(resource, request):
        assert resource.incident_id in actual_incidents
        return [
            {
                "knowledge_chunk_id": "KC-fixed",
                "technique_id": "T1110",
                "source_uri": "https://attack.mitre.org/techniques/T1110/",
                "summary": "same frozen knowledge",
            }
        ]

    def respond(http_request):
        state = json.loads(json.loads(http_request.content)["messages"][-1]["content"])
        contexts.append(state)
        return httpx.Response(
            200,
            json={
                "id": "synthetic",
                "model": "synthetic-v1",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps(analysis_answer(state, "unknown"))
                        },
                    }
                ],
            },
        )

    original_factory = worker.make_model
    monkeypatch.setattr(
        worker,
        "make_model",
        lambda *args, **kwargs: original_factory(
            *args, transport=httpx.MockTransport(respond), **kwargs
        ),
    )
    monkeypatch.setattr(worker, "case_environment", environment)
    monkeypatch.setattr(worker, "run_service_probe", probe)
    monkeypatch.setattr(worker, "lookup_knowledge", lookup)
    monkeypatch.setattr(worker, "export_tool_ledger", lambda resource: [])
    for mode in ("disabled", "semantic_only", "hybrid"):
        for repeat in (1, 2):
            slot = "development-" + canonical_hash([mode, repeat])[:24]
            request = RemediationRequest.model_validate(
                {
                    **first.model_dump(mode="json"),
                    "slot_id": slot,
                    "run_id": CAMPAIGN + "-" + canonical_hash([slot, 1])[:16],
                    "rag_mode": mode,
                    "repeat": repeat,
                }
            )
            worker_environment(monkeypatch, tmp_path, request, source)
            await worker.run_remediation(request, agent)
    assert len(set(actual_incidents)) == 6
    assert all("incident_id" not in context for context in contexts)
    without_knowledge = [
        {key: value for key, value in context.items() if key != "knowledge"}
        for context in contexts
    ]
    assert all(value == without_knowledge[0] for value in without_knowledge)


def test_development_http_bytes_are_stable_across_fresh_hash_seed_processes(tmp_path):
    # Reuse the independent audit/analysis-context-order-probe.py experiment in a
    # self-contained regression: two fresh interpreters, three recorded modes.
    child = r"""
import asyncio, json, sys
from pathlib import Path
from types import SimpleNamespace
import httpx
from evals.adapters.model_client import BudgetAccount, TrackedModel
from evals.adapters.remediation_worker import development_seed, one_development_analysis
from evals.contracts import ModelConfig, WorkerRunSpec

async def main():
    root, tag = Path(sys.argv[1]), sys.argv[2]
    spec = WorkerRunSpec(run_id="synthetic-order-probe", case_id="ait-" + "0" * 24, group="B3", config_sha256="c" * 64)
    seed = development_seed(SimpleNamespace(worker_spec=lambda: spec), root / "agent")
    payloads = []
    def respond(request):
        payloads.append(json.loads(request.content))
        return httpx.Response(200, json={"id": "synthetic", "model": "synthetic", "usage": {"prompt_tokens": 20, "completion_tokens": 5}, "choices": [{"finish_reason": "stop", "message": {"content": '{"diagnosis":{"verdict":"unknown","taxonomy_status":"unknown"}}'}}]})
    for mode in ("disabled", "semantic_only", "hybrid"):
        model = TrackedModel(ModelConfig(), api_key="synthetic-never-sent", account=BudgetAccount(root / (tag + mode + ".sqlite")), phase="development", transport=httpx.MockTransport(respond))
        state = {"alerts": seed["alerts"], "evidence": seed["evidence"], "knowledge": [] if mode == "disabled" else [{"knowledge_chunk_id": "KC-fixed", "summary": "same frozen knowledge"}]}
        result, errors = await one_development_analysis(model, state, seed["registry"])
        assert result["diagnosis"]["verdict"] == "unknown" and not errors
    print(json.dumps(payloads, ensure_ascii=False))
asyncio.run(main())
"""
    agent = tmp_path / "agent"
    agent.mkdir()
    (agent / "events.jsonl").write_text(
        json.dumps(
            {
                "source": "synthetic-review",
                "observed_at": "2026-10-22T00:00:00Z",
                "event_type": "observation",
                "severity": "info",
                "host": "synthetic-host",
                "source_ip": "198.51.100.10",
                "service": "http",
                "username": "synthetic-user",
                "message": "synthetic ordinary observation",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    root = Path(__file__).resolve().parents[2]
    payloads = []
    for seed in ("1", "2"):
        environment = {
            **os.environ,
            "PYTHONHASHSEED": seed,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(root / "services/backend/src") + os.pathsep + str(root),
        }
        payloads.extend(
            json.loads(
                subprocess.check_output(
                    [sys.executable, "-X", "utf8", "-c", child, str(tmp_path), seed],
                    cwd=root,
                    env=environment,
                    timeout=60,
                )
            )
        )
    masked = []
    for payload in payloads:
        context = json.loads(payload["messages"][-1]["content"])
        context["knowledge"] = "<only knowledge is masked>"
        payload["messages"][-1]["content"] = json.dumps(context, ensure_ascii=False)
        # Preserve every other dict's actual insertion order; sorting this test
        # output would hide the cross-worker serialization bug being tested.
        masked.append(json.dumps(payload, ensure_ascii=False))
    assert len(payloads) == 6
    assert len(set(masked)) == 1
