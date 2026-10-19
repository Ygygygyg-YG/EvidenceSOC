import json
from datetime import datetime

import pytest

from evals.adapters.diagnosis import validate_diagnosis
from evals.adapters.seed import load_seed
from evals.contracts import WorkerRunSpec


def write_case(tmp_path):
    agent = tmp_path / "agent"
    agent.mkdir()
    rows = [
        {
            "source": "test",
            "event_type": "observation",
            "severity": "info",
            "external_id": str(i),
            "observed_at": f"2026-01-01T00:00:{i:02d}+00:00",
            "host": "host-a",
            "message": "event " + str(i),
        }
        for i in range(30)
    ]
    (agent / "events.jsonl").write_text(
        "".join(json.dumps(x) + "\n" for x in reversed(rows)), encoding="utf-8"
    )
    return agent


def test_seed_is_mechanical_deterministic_and_bounded(tmp_path):
    agent = write_case(tmp_path)
    spec = WorkerRunSpec(
        run_id="run", case_id="case1", group="B0", config_sha256="a" * 64
    )
    first = load_seed(spec, agent)
    second = load_seed(spec, agent)
    assert first == second
    assert len(first["evidence"]) == 20
    assert datetime.fromisoformat(first["evidence"][0]["observed_at"]).second == 0
    assert first["alerts"][0]["title"] == "Observed security events"
    assert all(x.startswith("EV-") and len(x) == 29 for x in first["registry"])
    assert len({x["event_id"] for x in first["events"]}) == 30


def test_seed_rejects_answer_fields_and_outside_symlink(tmp_path):
    agent = write_case(tmp_path)
    (agent / "events.jsonl").write_text('{"is_attack":true}\n', encoding="utf-8")
    spec = WorkerRunSpec(
        run_id="run", case_id="case1", group="B0", config_sha256="a" * 64
    )
    with pytest.raises(ValueError, match="answer"):
        load_seed(spec, agent)


def test_diagnosis_does_not_turn_out_of_taxonomy_attack_into_benign():
    registry = {"EV-known": {"case_id": "case1"}}
    diagnosis = validate_diagnosis(
        {
            "verdict": "attack",
            "taxonomy_status": "out_of_taxonomy",
            "evidence_ids": ["EV-known"],
        },
        registry,
    )
    assert diagnosis.verdict == "attack"
    with pytest.raises(ValueError, match="citation"):
        validate_diagnosis(
            {
                "verdict": "attack",
                "taxonomy_status": "out_of_taxonomy",
                "evidence_ids": ["EV-other"],
            },
            registry,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("group", ["B0", "B1", "B2", "B3", "A1", "A2", "A3", "A4"])
async def test_all_groups_use_the_canonical_diagnosis_and_original_graph_when_required(
    tmp_path, monkeypatch, group
):
    from evidencesoc.config import Settings
    from langgraph.checkpoint.memory import InMemorySaver

    from evals.adapters.evidencesoc import run_with_services

    spec = WorkerRunSpec(
        run_id="run", case_id="case1", group=group, config_sha256="a" * 64
    )
    seed = load_seed(spec, write_case(tmp_path))
    diagnosis = {
        "verdict": "benign",
        "taxonomy_status": "not_applicable",
        "evidence_ids": [seed["evidence"][0]["evidence_id"]],
    }

    class Model:
        def __init__(self):
            self.calls = []

        async def structured(self, role, schema, state):
            self.calls.append(role)
            if schema.__name__ == "AnalysisOutput":
                return schema.model_validate(
                    {"diagnosis": diagnosis, "origin": None, "classification": None}
                )
            return schema.model_validate(diagnosis)

    class Services:
        def __init__(self):
            self.roles = []

        async def load_incident(self, incident_id):
            return {"alerts": seed["alerts"]}

        async def start_run(self, state, role):
            self.roles.append(role)
            return "run-" + role

        async def finish_run(self, *args):
            pass

        async def collect(self, state, run_id):
            return {"evidence": [], "knowledge": []}

        async def save_result(self, state):
            pass

    model, service = Model(), Services()
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(
        "evidencesoc.rag.retriever.retrieve_knowledge", lambda *args, **kwargs: []
    )
    result = await run_with_services(
        spec,
        seed,
        service,
        Settings(_env_file=None, llm_mode="deepseek"),
        model,
        InMemorySaver(),
        "IN-case1",
    )
    assert result["diagnostic_snapshot"]["diagnosis"]["verdict"] == "benign"
    assert result["diagnosis_status"] == "succeeded"
    assert model.calls == ["analyze"]
    assert service.roles == (
        ["triage", "collect", "analyze"]
        if group not in {"B0", "B1", "B2"}
        else ["collect"]
        if group == "B2"
        else []
    )


@pytest.mark.asyncio
async def test_baseline_and_original_graph_enforce_the_same_technique_provenance(
    tmp_path,
):
    from evals.adapters.evidencesoc import one_diagnosis

    spec = WorkerRunSpec(
        run_id="run", case_id="case1", group="B0", config_sha256="a" * 64
    )
    seed = load_seed(spec, write_case(tmp_path))

    class Model:
        async def structured(self, role, schema, state):
            return schema.model_validate(
                {
                    "verdict": "attack",
                    "taxonomy_status": "out_of_taxonomy",
                    "technique_ids": ["T1059"],
                    "evidence_ids": [seed["evidence"][0]["evidence_id"]],
                }
            )

    result, errors = await one_diagnosis(
        Model(), {"evidence": seed["evidence"], "knowledge": []}, seed["registry"]
    )
    assert result is None
    assert len(errors) == 3


@pytest.mark.asyncio
async def test_baseline_preserves_each_failure_category_for_rerun_policy():
    import httpx

    from evals.adapters.evidencesoc import one_diagnosis

    class Model:
        calls = 0

        async def structured(self, *args):
            self.calls += 1
            if self.calls == 1:
                raise ValueError("invalid citation")
            raise httpx.ConnectError("synthetic transport")

    model = Model()
    diagnosis, errors = await one_diagnosis(model, {}, {})
    assert diagnosis is None
    assert model.calls == 3
    assert [error["category"] for error in errors] == [
        "application",
        "transport",
        "transport",
    ]


@pytest.mark.asyncio
async def test_worker_failure_exports_charged_tool_ledger_before_case_cleanup(
    tmp_path, monkeypatch
):
    import sys
    from contextlib import asynccontextmanager, contextmanager
    from dataclasses import dataclass
    from types import SimpleNamespace

    from evals.adapters import evidencesoc as adapter

    spec = WorkerRunSpec(
        run_id="run", case_id="case1", group="B3", config_sha256="a" * 64
    )
    agent = write_case(tmp_path)
    monkeypatch.setattr(adapter.os, "getpid", lambda: 1)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "test-nonce")
    monkeypatch.setenv("TASK13_PHASE", "development")
    monkeypatch.setenv("TASK13_BUDGET_DB", str(tmp_path / "budget.sqlite"))
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-no-http")
    monkeypatch.setitem(
        sys.modules,
        "resource",
        SimpleNamespace(
            RUSAGE_SELF=0, getrusage=lambda _: SimpleNamespace(ru_maxrss=1)
        ),
    )

    @contextmanager
    def environment(*args):
        yield (SimpleNamespace(database_url="test"), object(), "IN-test")

    @asynccontextmanager
    async def checkpointer(*args):
        yield object()

    closed = []

    class Services:
        def __init__(self, *args, **kwargs):
            pass

        async def aclose(self):
            closed.append(True)

    @dataclass
    class Call:
        call_id: str = "logical-tool"
        tool_name: str = "get_alert_context"
        charged: bool = True
        attempts: int = 2

    class Ledger:
        def __init__(self, *args):
            pass

        def calls(self, incident, round_no):
            return [Call()] if round_no == 1 else []

    async def fail_after_tool(*args):
        raise RuntimeError("synthetic failure after logical tool")

    monkeypatch.setattr(adapter, "case_environment", environment)
    monkeypatch.setattr(adapter, "open_checkpointer", checkpointer)
    monkeypatch.setattr(adapter, "PostgresWorkflowServices", Services)
    monkeypatch.setattr(adapter, "Ledger", Ledger)
    monkeypatch.setattr(adapter, "run_with_services", fail_after_tool)
    result = await adapter.run_case(spec, agent)
    assert result.execution_status == "failed"
    assert result.errors[-1]["category"] == "application"
    assert result.tool_ledger[0]["attempts"] == 2
    assert closed == [True]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "usage,expected",
    [
        (None, None),
        ({}, None),
        ([], None),
        ({"prompt_tokens": 3}, None),
        ({"prompt_tokens": 3, "completion_tokens": None}, None),
        ({"prompt_tokens": True, "completion_tokens": 4}, None),
        ({"prompt_tokens": 3, "completion_tokens": False}, None),
        ({"prompt_tokens": -1, "completion_tokens": 4}, None),
        ({"prompt_tokens": 3, "completion_tokens": -1}, None),
        ({"prompt_tokens": "3", "completion_tokens": 4}, None),
        ({"prompt_tokens": 3, "completion_tokens": 4.0}, None),
        ({"prompt_tokens": 0, "completion_tokens": 0}, (2, 3)),
        ({"prompt_tokens": 5, "completion_tokens": 7}, (7, 10)),
    ],
)
async def test_worker_retains_sealed_diagnosis_and_ledger_when_usage_is_incomplete(
    tmp_path, monkeypatch, usage, expected
):
    import sys
    from contextlib import asynccontextmanager, contextmanager
    from types import SimpleNamespace

    from evals.adapters import evidencesoc as adapter

    spec = WorkerRunSpec(
        run_id="run", case_id="case1", group="B0", config_sha256="a" * 64
    )
    agent = write_case(tmp_path)
    snapshot = {
        "diagnosis": {"verdict": "benign", "taxonomy_status": "not_applicable"},
        "sealed_after": "analyze",
    }
    ledger = [
        {
            "logical_call_id": "first",
            "usage": {"prompt_tokens": 2, "completion_tokens": 3},
            "cost_cny": 0.001,
        },
        {
            "logical_call_id": "second",
            "usage": usage,
            "cost_cny": None if expected is None else 0.002,
        },
    ]
    monkeypatch.setattr(adapter.os, "getpid", lambda: 1)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-test-only")
    monkeypatch.setenv("TASK13_PHASE", "development")
    monkeypatch.setenv("TASK13_BUDGET_DB", str(tmp_path / "budget.sqlite"))
    monkeypatch.setitem(
        sys.modules,
        "resource",
        SimpleNamespace(
            RUSAGE_SELF=0, getrusage=lambda _: SimpleNamespace(ru_maxrss=1)
        ),
    )
    monkeypatch.setattr(
        adapter, "TrackedModel", lambda *args, **kwargs: SimpleNamespace(ledger=ledger)
    )

    @contextmanager
    def environment(*args):
        yield SimpleNamespace(database_url="synthetic-test"), object(), "IN-test"

    @asynccontextmanager
    async def checkpointer(*args):
        yield object()

    class Services:
        def __init__(self, *args, **kwargs):
            pass

        async def aclose(self):
            pass

    class Ledger:
        def __init__(self, *args):
            pass

        def calls(self, *args):
            return []

    async def diagnosed(*args):
        return {
            "diagnostic_snapshot": snapshot,
            "diagnosis_status": "succeeded",
            "execution_status": "completed",
        }

    monkeypatch.setattr(adapter, "case_environment", environment)
    monkeypatch.setattr(adapter, "open_checkpointer", checkpointer)
    monkeypatch.setattr(adapter, "PostgresWorkflowServices", Services)
    monkeypatch.setattr(adapter, "Ledger", Ledger)
    monkeypatch.setattr(adapter, "run_with_services", diagnosed)
    result = await adapter.run_case(spec, agent)
    assert result.execution_status == "completed"
    assert result.diagnosis_status == "succeeded"
    assert result.diagnostic_snapshot == snapshot
    assert result.model_ledger == ledger
    assert result.resources["input_tokens"] == (
        None if expected is None else expected[0]
    )
    assert result.resources["output_tokens"] == (
        None if expected is None else expected[1]
    )
    assert result.resources["cost"] == (None if expected is None else 0.003)
    assert result.resources["missing_reason"] == (
        "usage_or_cost_unavailable" if expected is None else None
    )
