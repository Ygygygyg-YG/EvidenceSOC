"""Synthetic bound review requests, local accounts and MockTransport only."""

from __future__ import annotations

import importlib
import json
import sqlite3
from contextlib import asynccontextmanager
from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace

import httpx
import pytest
from pydantic import BaseModel, ValidationError

from evals.adapters.model_client import BudgetAccount, BudgetLimit, TrackedModel
from evals.adapters.remediation_contracts import CAMPAIGN
from evals.adapters.remediation_worker import read_budget_identity
from evals.adapters.verification_worker import SourceReviewRequest
from evals.contracts import ModelConfig, canonical_hash
from evals.tests.test_budget_v2 import started
from evals.tests.test_verification_plan import cases, fixture_source


def inputs(tmp_path, *, operation="renew_plan", purpose="f8"):
    module = importlib.import_module("evals.adapters.remediation_review")
    agent, source = tmp_path / "agent", tmp_path / "source"
    agent.mkdir(exist_ok=True)
    source.mkdir(exist_ok=True)
    (agent / "events.jsonl").write_text("{}\n", encoding="utf-8")
    (source / "worker.py").write_text("# frozen synthetic source\n", encoding="utf-8")
    receipt = {
        "source_commit": "a" * 40,
        "files": {"worker.py": sha256((source / "worker.py").read_bytes()).hexdigest()},
    }
    (source / "source_receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
    account = BudgetAccount(tmp_path / "campaign.sqlite")
    historic = account.reserve("synthetic-original-history", 0.01, "formal")
    account.settle(historic, 0.001)
    original = fixture_source()
    original["state"].update(status="awaiting_approval", approval=None)
    from evals.adapters.retained_workflow import build_approval_packet

    packet = build_approval_packet(cases()[0], original["state"])
    slot = purpose + "-review-" + "d" * 24
    values = {
        "campaign_id": CAMPAIGN,
        "run_id": CAMPAIGN + "-" + canonical_hash([slot, 1])[:16],
        "slot_id": slot,
        "attempt": 1,
        "purpose": purpose,
        "group": "B3",
        "source_sha256": canonical_hash(receipt),
        "config_sha256": "b" * 64,
        "budget_identity": read_budget_identity(account.path),
        "request_id": "c" * 32,
        "namespace": "d" * 32,
        "case_id": cases()[0]["case_id"],
        "dataset": "ait",
        "agent_sha256": sha256((agent / "events.jsonl").read_bytes()).hexdigest(),
        "source_commit": "a" * 40,
        "source_resources": original["resources"],
        "incident_id": original["state"]["incident_id"],
        "operation": operation,
    }
    if operation != "read_packet":
        values["packet"] = packet
    if operation == "decision":
        values.update(decision="rejected", reason="SYNTHETIC user decision only")
    return (
        module.RemediationReviewRequest(**values),
        agent,
        source,
        account.path,
        original["state"],
    )


def environment(monkeypatch, tmp_path, request, source, budget):
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-only")
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", request.source_commit)
    monkeypatch.setenv("TASK13_SOURCE_DIR", str(source))
    monkeypatch.setenv("TASK13_PHASE", "verification")
    monkeypatch.setenv("TASK13_BUDGET_DB", str(budget))
    output = tmp_path / "output"
    output.mkdir(exist_ok=True)
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(output))
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-secret-not-for-output")
    module = importlib.import_module("evals.adapters.remediation_review")
    monkeypatch.setattr(module.os, "getpid", lambda: 1)
    return output


@pytest.mark.parametrize("operation", ["read_packet", "decision", "renew_plan"])
def test_v2_review_contract_preserves_original_explicit_review_semantics(
    tmp_path, operation
):
    request, *_ = inputs(tmp_path, operation=operation)
    original = request.source_review_request()
    assert type(original) is SourceReviewRequest
    assert original.operation == request.operation
    assert original.reviewer == "user"
    assert original.packet == request.packet
    assert original.model == request.model
    assert request.budget_binding()["purpose"] == "f8"
    assert request.schema_version == "task13-remediation-review-worker-v2"
    for updates in (
        {"decision": "approved", "reason": None},
        {"group": "B2"},
        {"purpose": "regression"},
        {"run_id": "arbitrary-run"},
        {"attempt": True},
        {"budget_identity": {}},
        {"campaign_id": "old-v1"},
    ):
        with pytest.raises(ValidationError):
            type(request).model_validate({**request.model_dump(mode="json"), **updates})


@pytest.mark.parametrize(
    "purpose,phase", [("f8", "verification"), ("development", "development")]
)
def test_renewal_model_has_exact_bound_supplement_account_and_phase(
    tmp_path, monkeypatch, purpose, phase
):
    from evals.adapters.budget_v2 import SupplementBudgetAccount
    from evals.adapters.remediation_worker import StableCallModel

    module = importlib.import_module("evals.adapters.remediation_review")
    request, _, _, budget, _ = inputs(tmp_path, purpose=purpose)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic")
    model = module.make_review_model(request, budget)
    assert type(model) is StableCallModel
    assert type(model.account) is SupplementBudgetAccount
    assert model.phase == phase
    assert model.config == request.model
    assert model.account.request_binding() == request.budget_binding()
    assert model.model.max_calls == 3 and model.model.max_logical_calls == 1


def test_factory_rejects_foreign_empty_or_tampered_original_history_before_writes(
    tmp_path, monkeypatch
):
    module = importlib.import_module("evals.adapters.remediation_review")
    request, _, _, budget, _ = inputs(tmp_path)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic")
    empty = BudgetAccount(tmp_path / "empty.sqlite")
    before = sha256(empty.path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="identity"):
        module.make_review_model(request, empty.path)
    assert sha256(empty.path.read_bytes()).hexdigest() == before
    with sqlite3.connect(budget) as db:
        db.execute("UPDATE reservations SET actual=0.002")
    before = sha256(budget.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="identity"):
        module.make_review_model(request, budget)
    assert sha256(budget.read_bytes()).hexdigest() == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "purpose,phase", [("f8", "verification"), ("development", "development")]
)
async def test_review_payload_and_cost_are_bound_and_reopen_cannot_replay(
    tmp_path, monkeypatch, purpose, phase
):
    from evals.adapters.remediation_worker import PayloadRecorder

    module = importlib.import_module("evals.adapters.remediation_review")
    request, _, source, budget, _ = inputs(tmp_path, purpose=purpose)
    output = environment(monkeypatch, tmp_path, request, source, budget)
    sent = []

    def respond(http_request):
        sent.append(http_request)
        return httpx.Response(
            200,
            json={
                "id": "synthetic-provider",
                "model": "synthetic-model",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"verdict":"unknown"}'},
                    }
                ],
            },
        )

    class Answer(BaseModel):
        verdict: str

    recorder = PayloadRecorder(output)
    model = module.make_review_model(
        request, budget, transport=httpx.MockTransport(respond), payload_sink=recorder
    )
    await model.structured("respond", Answer, {"_model_call_id": "random-product-hint"})
    assert len(sent) == len(recorder.records) == 1
    assert (output / recorder.records[0]["http_body_path"]).read_bytes() == sent[
        0
    ].content
    assert "synthetic-secret-not-for-output" not in sent[0].content.decode()
    assert model.ledger[0]["purpose"] == purpose
    assert model.ledger[0]["slot_id"] == request.slot_id
    assert model.ledger[0]["attempt"] == request.attempt
    assert model.account.supplement_summary()["purposes"][purpose]["known_cny"] > 0
    with sqlite3.connect(budget) as db:
        assert (
            db.execute(
                "SELECT phase FROM reservations ORDER BY rowid DESC LIMIT 1"
            ).fetchone()[0]
            == phase
        )
    reopened = module.make_review_model(
        request, budget, transport=httpx.MockTransport(respond)
    )
    with pytest.raises(BudgetLimit, match="already"):
        await reopened.structured(
            "respond", Answer, {"_model_call_id": "new-random-hint-after-crash"}
        )
    assert len(sent) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "purpose,phase", [("f8", "verification"), ("development", "development")]
)
async def test_renewal_cannot_escape_six_yuan_purpose_cap(
    tmp_path, monkeypatch, purpose, phase
):
    module = importlib.import_module("evals.adapters.remediation_review")
    request, _, _, budget, _ = inputs(tmp_path, purpose=purpose)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic")
    model = module.make_review_model(
        request,
        budget,
        transport=httpx.MockTransport(
            lambda _: pytest.fail("exhausted budget must not dispatch")
        ),
    )
    model.account.reserve("synthetic-prefill", 6.0, phase, metadata=started("prefill"))

    class Answer(BaseModel):
        verdict: str

    with pytest.raises(BudgetLimit, match=purpose):
        await model.structured("respond", Answer, {"_model_call_id": "hint"})
    assert model.ledger == []


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["read_packet", "decision"])
async def test_free_review_operations_delegate_original_without_model_or_budget_mutation(
    tmp_path, monkeypatch, operation
):
    module = importlib.import_module("evals.adapters.remediation_review")
    request, agent, source, budget, _ = inputs(tmp_path, operation=operation)
    environment(monkeypatch, tmp_path, request, source, budget)
    monkeypatch.delenv("DEEPSEEK_API_KEY")
    calls = []

    async def original(original_request, directory, *, model_factory):
        calls.append((original_request, directory))
        return {
            "status": "completed",
            "model_ledger": [],
            "input_sha256": canonical_hash(original_request),
        }

    monkeypatch.setattr(module, "run_source_review", original)
    monkeypatch.setattr(
        module,
        "make_review_model",
        lambda *a, **k: pytest.fail("free operation must not build a model"),
    )
    before = sha256(budget.read_bytes()).hexdigest()
    result = await module.run_remediation_review(request, agent)
    assert calls == [(request.source_review_request(), agent)]
    assert result["input_sha256"] == canonical_hash(request)
    assert result["model_ledger"] == []
    assert sha256(budget.read_bytes()).hexdigest() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["source", "receipt", "agent", "phase", "commit"])
async def test_review_rejects_worker_binding_drift_before_original_operation(
    tmp_path, monkeypatch, tamper
):
    module = importlib.import_module("evals.adapters.remediation_review")
    request, agent, source, budget, _ = inputs(tmp_path, operation="read_packet")
    environment(monkeypatch, tmp_path, request, source, budget)
    if tamper == "source":
        (source / "worker.py").write_text("changed", encoding="utf-8")
    elif tamper == "receipt":
        (source / "source_receipt.json").write_text("{}", encoding="utf-8")
    elif tamper == "agent":
        (agent / "events.jsonl").write_text("changed", encoding="utf-8")
    elif tamper == "phase":
        monkeypatch.setenv("TASK13_PHASE", "development")
    else:
        monkeypatch.setenv("TASK13_SOURCE_COMMIT", "f" * 40)

    async def original(*a, **k):
        pytest.fail("drifted worker must not open retained state")

    monkeypatch.setattr(module, "run_source_review", original)
    with pytest.raises((ValueError, PermissionError)):
        await module.run_remediation_review(request, agent)


@pytest.mark.parametrize("purpose", ["f8", "development"])
def test_retained_guard_accepts_only_exact_stable_supplement_bound_review(
    tmp_path, monkeypatch, purpose
):
    module = importlib.import_module("evals.adapters.remediation_review")
    from evals.adapters import retained_workflow
    from evals.adapters.remediation_worker import StableCallModel

    request, _, source, budget, _ = inputs(tmp_path, purpose=purpose)
    environment(monkeypatch, tmp_path, request, source, budget)
    model = module.make_review_model(request, budget)
    reference = {"source_commit": request.source_commit}
    retained_workflow._require_inspected_renewal_model(model, reference)
    with pytest.raises(PermissionError):
        retained_workflow._require_inspected_renewal_model(model.model, reference)
    impostor = SimpleNamespace(
        account=model.account, phase=model.phase, config=model.config
    )
    with pytest.raises(PermissionError):
        retained_workflow._require_inspected_renewal_model(impostor, reference)
    raw_account_model = StableCallModel(
        TrackedModel(
            ModelConfig(),
            api_key="synthetic",
            account=BudgetAccount(budget),
            phase="verification",
        ),
        request.slot_id,
        request.run_id,
    )
    with pytest.raises(PermissionError):
        retained_workflow._require_inspected_renewal_model(raw_account_model, reference)
    model.model.phase = "formal"
    with pytest.raises(PermissionError):
        retained_workflow._require_inspected_renewal_model(model, reference)


@pytest.mark.asyncio
async def test_original_review_optional_factory_is_renewal_only(tmp_path, monkeypatch):
    from evals.adapters import retained_workflow, verification_worker

    request, agent, source, budget, state = inputs(tmp_path)
    output = environment(monkeypatch, tmp_path, request, source, budget)
    model = SimpleNamespace(ledger=[])
    calls = []

    class Workflow:
        services = SimpleNamespace(_sessions=None)

        async def get_state(self, incident_id):
            return deepcopy(state)

    @asynccontextmanager
    async def opened(reference, *, model):
        calls.append(("open", model))
        yield Workflow()

    async def renew(workflow, packet, *, requested_by):
        model.ledger.append({"role": "respond", "parse_status": "valid"})
        return deepcopy(state)

    monkeypatch.setattr(retained_workflow, "open_retained_workflow", opened)
    monkeypatch.setattr(retained_workflow, "renew_expired_plan", renew)
    monkeypatch.setattr(
        verification_worker, "Ledger", lambda _: SimpleNamespace(calls=lambda *a: [])
    )

    def factory(original):
        calls.append(("factory", original))
        return model

    result = await verification_worker.run_source_review(
        request.source_review_request(), agent, model_factory=factory
    )
    assert result["status"] == "completed"
    assert calls[0] == ("factory", request.source_review_request())
    assert calls[1] == ("open", model)
    for path in output.iterdir():
        path.unlink()
    read = SourceReviewRequest.model_validate(
        {
            **request.source_review_request().model_dump(mode="json"),
            "operation": "read_packet",
            "packet": None,
        }
    )
    calls.clear()
    result = await verification_worker.run_source_review(
        read, agent, model_factory=lambda _: pytest.fail("read must not build model")
    )
    assert result["status"] == "completed"
    assert calls == [("open", None)]


@pytest.mark.asyncio
@pytest.mark.parametrize("purpose", ["f8", "development"])
async def test_bound_review_renewal_uses_original_operation_and_records_real_http_boundary(
    tmp_path, monkeypatch, purpose
):
    module = importlib.import_module("evals.adapters.remediation_review")
    from evals.adapters import retained_workflow, verification_worker

    request, agent, source, budget, state = inputs(tmp_path, purpose=purpose)
    output = environment(monkeypatch, tmp_path, request, source, budget)
    sent, received_models = [], []

    def respond(http_request):
        sent.append(http_request)
        return httpx.Response(
            200,
            json={
                "id": "synthetic-provider",
                "model": "synthetic-model",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"verdict":"unknown"}'},
                    }
                ],
            },
        )

    make = module.make_review_model
    monkeypatch.setattr(
        module,
        "make_review_model",
        lambda *a, **k: make(*a, **k, transport=httpx.MockTransport(respond)),
    )

    class Workflow:
        services = SimpleNamespace(_sessions=None)

        async def get_state(self, incident_id):
            return deepcopy(state)

    @asynccontextmanager
    async def opened(reference, *, model):
        received_models.append(model)
        retained_workflow._require_inspected_renewal_model(model, reference)
        yield Workflow()

    class Answer(BaseModel):
        verdict: str

    async def renew(workflow, packet, *, requested_by):
        assert requested_by == "user" and packet == request.packet
        await received_models[0].structured(
            "respond", Answer, {"_model_call_id": "synthetic-random-hint"}
        )
        return deepcopy(state)

    monkeypatch.setattr(retained_workflow, "open_retained_workflow", opened)
    monkeypatch.setattr(retained_workflow, "renew_expired_plan", renew)
    monkeypatch.setattr(
        verification_worker, "Ledger", lambda _: SimpleNamespace(calls=lambda *a: [])
    )
    result = await module.run_remediation_review(request, agent)
    assert result["status"] == "completed"
    assert result["operation"] == "renew_plan"
    assert result["input_sha256"] == canonical_hash(request)
    assert result["source_review_input_sha256"] == canonical_hash(
        request.source_review_request()
    )
    assert len(sent) == len(result["model_ledger"]) == len(result["payloads"]) == 1
    assert result["model_ledger"][0]["purpose"] == purpose
    assert (
        json.loads((output / "review-payloads.json").read_text()) == result["payloads"]
    )
