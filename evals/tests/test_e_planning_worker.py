"""Free E2 worker tests: synthetic authorities, services and in-memory graph only."""

from __future__ import annotations

import importlib.util


def test_dedicated_planning_worker_exists():
    assert importlib.util.find_spec("evals.adapters.e_planning_worker") is not None


def test_product_has_typed_existing_claim_admission():
    from evidencesoc.agents import analysis_import

    assert hasattr(analysis_import, "PlanningAdmission")


import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from evals.contracts import canonical_hash
from evals.e_planning import planning_requests
from evals.tests.test_e_planning_contracts import registration_fixture


def request_fixture():
    return planning_requests(registration_fixture())[0]


@pytest.mark.asyncio
async def test_respond_retries_share_one_stable_slot_hint_and_three_attempts():
    from evals.adapters.e_planning_worker import RespondOnlyModel

    hints = []

    class Model:
        def __init__(self):
            self.ledger = []

        async def structured(self, role, schema, state):
            hints.append(state["_model_call_id"])
            raise RuntimeError("synthetic")

    wrapped = RespondOnlyModel(Model(), request_fixture().planning_slot_id)
    for hint in ["random-one", "different-retry", "another-retry"]:
        with pytest.raises(RuntimeError):
            await wrapped.structured("respond", dict, {"_model_call_id": hint})
    assert len(set(hints)) == 1
    with pytest.raises(PermissionError):
        await wrapped.structured("respond", dict, {"_model_call_id": "fourth"})
    with pytest.raises(PermissionError):
        await RespondOnlyModel(Model(), "slot").structured("analyze", dict, {})
    assert len(hints) == 3


@pytest.mark.asyncio
async def test_worker_rejects_host_before_any_preflight_or_model(monkeypatch, tmp_path):
    from evals.adapters import e_planning_worker as worker

    monkeypatch.setattr(worker.os, "getpid", lambda: 99)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic")

    def forbidden(*args, **kwargs):
        pytest.fail("worker reached external access before PID1 rejection")

    monkeypatch.setattr(worker, "validate_exported_source", forbidden)
    monkeypatch.setattr(worker, "make_model", forbidden)
    with pytest.raises(PermissionError):
        await worker.run_e_planning(request_fixture(), tmp_path)


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["", "formal", "development-analysis"])
async def test_worker_rejects_wrong_phase_before_source_or_model(
    monkeypatch, tmp_path, phase
):
    from evals.adapters import e_planning_worker as worker

    monkeypatch.setattr(worker.os, "getpid", lambda: 1)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic")
    monkeypatch.setenv("TASK13_PHASE", phase)
    monkeypatch.setattr(
        worker,
        "validate_exported_source",
        lambda *a, **k: pytest.fail("source accessed"),
    )
    with pytest.raises(ValueError, match="phase"):
        await worker.run_e_planning(request_fixture(), tmp_path)


def pending_state():
    now = datetime.now(UTC)
    seal = {
        "sealed_after": "analysis_import",
        "analysis_import_provenance": {"synthetic": True},
    }
    return {
        "incident_id": "IN-synthetic",
        "status": "awaiting_approval",
        "approval": None,
        "diagnostic_snapshot": seal,
        "diagnostic_snapshot_sha256": canonical_hash(seal),
        "analysis_import_provenance": {"synthetic": True},
        "response_plan": {
            "response_plan_id": "RP-synthetic",
            "incident_id": "IN-synthetic",
            "summary": "Synthetic plan",
            "actions": [
                {
                    "action_id": "ACT-1",
                    "action": "block_ip_simulated",
                    "target": "192.0.2.1",
                    "risk": "low",
                    "impact": "low",
                    "preview": "preview",
                    "rollback": "rollback",
                    "verification_query": {"filters": {"source_ip": "192.0.2.1"}},
                    "parameters": {"source_ip": "192.0.2.1"},
                    "evidence_ids": ["EV-1"],
                }
            ],
            "evidence_ids": ["EV-1"],
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=1800)).isoformat(),
        },
    }


def test_retain_validation_requires_real_table_and_checkpoint_consistency():
    from evidencesoc.domain.models import ResponsePlan

    from evals.adapters.e_planning_worker import validate_persisted_pending

    state = pending_state()
    plan = ResponsePlan.model_validate(state["response_plan"])
    state["response_plan"] = plan.model_dump(mode="json")
    row = SimpleNamespace(**plan.model_dump())
    incident = SimpleNamespace(status="awaiting_approval")
    snapshot = SimpleNamespace(next=("approval",), values=state)
    assert (
        validate_persisted_pending(
            snapshot, row, incident, state["analysis_import_provenance"]
        )
        == state
    )
    for change in [
        "table",
        "checkpoint",
        "ttl",
        "expired",
        "seal",
        "provenance",
        "incident",
    ]:
        s = deepcopy(state)
        r = SimpleNamespace(**plan.model_dump())
        i = SimpleNamespace(status="awaiting_approval")
        next_node = ("approval",)
        if change == "table":
            r.summary = "changed"
        elif change == "checkpoint":
            next_node = ()
        elif change == "ttl":
            p = deepcopy(s["response_plan"])
            p["expires_at"] = (plan.created_at + timedelta(seconds=1799)).isoformat()
            s["response_plan"] = p
        elif change == "expired":
            s["response_plan"]["created_at"] = (
                datetime.now(UTC) - timedelta(hours=2)
            ).isoformat()
            s["response_plan"]["expires_at"] = (
                datetime.now(UTC) - timedelta(minutes=90)
            ).isoformat()
        elif change == "seal":
            s["diagnostic_snapshot_sha256"] = "0" * 64
        elif change == "provenance":
            s["analysis_import_provenance"] = {}
        elif change == "incident":
            i.status = "received"
        with pytest.raises(ValueError):
            validate_persisted_pending(
                SimpleNamespace(next=next_node, values=s),
                r,
                i,
                state["analysis_import_provenance"],
            )


def test_received_response_gate_does_not_turn_transport_failure_into_success():
    from evals.adapters.e_planning_worker import require_received_response

    for ledger in [
        [],
        [{"http_status": 401}],
        [{"http_status": 200, "raw_response": None}],
        [{"parse_status": "not_received"}],
    ]:
        with pytest.raises(ValueError):
            require_received_response(ledger)
    require_received_response(
        [
            {
                "http_status": 200,
                "raw_response": {"choices": []},
                "parse_status": "schema_error",
            }
        ]
    )


def product_source(tmp_path):
    from evidencesoc.agents.analysis_import import ImportedAnalysis

    from evals.adapters.analysis_import import verify_analysis_source
    from evals.tests.test_analysis_import import artifact_source

    original = verify_analysis_source(artifact_source(tmp_path / "source"))
    values = original.product_values()
    values.pop("analysis_import_provenance")
    provenance = {**original.provenance, "source_package_manifest_sha256": "d" * 64}

    def check():
        original.revalidate()
        return values, provenance

    return ImportedAnalysis._from_verified_artifacts(values, provenance, check)


def product_registration(source):
    from evals.e_planning import build_e_planning_registration
    from evals.tests.test_e_planning_contracts import selection_receipt

    old = registration_fixture()
    selection = selection_receipt()
    for key in selection["selected_sources"][0]:
        selection["selected_sources"][0][key] = source.provenance[key]
        selection["rows"][0][key] = source.provenance[key]
    return build_e_planning_registration(
        selection,
        registration_id=old["registration_id"],
        source_package_manifest_sha256="d" * 64,
        epoch_binding=old["epoch_binding"],
        budget_source_receipt_sha256=old["epoch_binding"]["source_sha256"],
        core_config=old["core_config"],
        synthetic=True,
    )


class ProductServices:
    def __init__(self, evidence):
        self.evidence = evidence
        self.runs, self.saved = [], []

    async def load_incident(self, incident_id):
        return {"status": "received", "alerts": []}

    async def hydrate_evidence(self, incident_id, values):
        return deepcopy(self.evidence) if values == self.evidence else []

    async def start_run(self, state, role):
        self.runs.append({"role": role})
        return str(len(self.runs))

    async def finish_run(self, run_id, delta, status):
        self.runs[int(run_id) - 1]["status"] = status

    async def save_result(self, state):
        self.saved.append(deepcopy(state))


class ProductTape:
    def __init__(self):
        self.calls = []

    async def structured(self, role, schema, state):
        from evidencesoc.agents.fallback import respond

        self.calls.append(role)
        return schema.model_validate(respond(state).model_dump(mode="json"))


@pytest.mark.asyncio
async def test_three_registered_same_source_product_imports_are_distinct_and_pending_reopen_is_read_only(
    tmp_path,
):
    from evidencesoc.agents.analysis_import import PlanningAdmission
    from evidencesoc.agents.graph import InvestigationWorkflow
    from evidencesoc.config import Settings
    from langgraph.checkpoint.memory import InMemorySaver

    from evals.adapters.e_planning_worker import _claim_binding
    from evals.tests.test_e_planning_journal import open_fixture, register_fixture

    source = product_source(tmp_path)
    original_provenance = deepcopy(source.provenance)
    registration = product_registration(source)
    path = tmp_path / "synthetic-dispatch.sqlite"
    _, authority, _ = register_fixture(path, registration)
    journal = open_fixture(path, registration, authority)
    states = []
    for request in planning_requests(registration):
        claim = journal.claim_planning_slot(request)
        binding = _claim_binding(request, claim)
        admission = PlanningAdmission._from_existing_claim(
            binding, lambda q=request: _claim_binding(q, journal.validate_request(q))
        )
        services = ProductServices(source.product_values()["evidence"])
        model = ProductTape()
        flow = InvestigationWorkflow.for_analysis_import(
            imported_analysis=source,
            planning_admission=admission,
            services=services,
            settings=Settings(_env_file=None, llm_mode="deepseek"),
            checkpointer=InMemorySaver(),
            model=model,
        )
        state = await flow.import_analysis(request.incident_id, source)
        assert state["status"] == "awaiting_approval"
        assert [r["role"] for r in services.runs] == ["analysis_import", "respond"]
        assert model.calls == ["respond"]
        assert (
            state["analysis_import_provenance"]["planning_admission"][
                "planning_slot_id"
            ]
            == request.planning_slot_id
        )
        assert (
            state["diagnostic_snapshot"]["analysis_import_provenance"]
            == state["analysis_import_provenance"]
        )
        assert await flow.import_analysis(request.incident_id, source) == state
        assert model.calls == ["respond"]
        with pytest.raises(PermissionError):
            await flow.import_analysis("IN-other", source)
        assert len(services.saved) >= 2
        states.append(state)
    assert source.provenance == original_provenance
    assert len({s["incident_id"] for s in states}) == 3
    assert len({s["response_plan"]["response_plan_id"] for s in states}) == 3
    assert len({canonical_hash(s["analysis_import_provenance"]) for s in states}) == 3
    with pytest.raises(PermissionError):
        journal.claim_planning_slot(planning_requests(registration)[0])


from contextlib import asynccontextmanager, contextmanager


@pytest.fixture(scope="module")
def frozen_product_source(tmp_path_factory):
    from evidencesoc.agents.analysis_import import ImportedAnalysis

    source = product_source(tmp_path_factory.mktemp("e-planning-original"))
    provenance = source.provenance
    values = source.product_values()
    values.pop("analysis_import_provenance")
    return ImportedAnalysis._from_verified_artifacts(
        values, provenance, lambda: (values, provenance)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode,retained",
    [
        ("valid", True),
        ("http200_invalid", True),
        ("transport", False),
        ("probe", False),
        ("table", False),
        ("ttl", False),
        ("empty", False),
        ("empty_reason", False),
        ("empty_blank", False),
        ("empty_close", False),
        ("empty_cleanup", False),
        ("empty_export", False),
        ("empty_table", False),
        ("empty_table_close", False),
        ("empty_table_cleanup", False),
        ("empty_table_checkpoint_close", False),
        ("empty_table_all_cleanup", False),
        ("empty_checkpoint", False),
        ("empty_incident", False),
        ("tool_export", False),
        ("save", False),
        ("close", False),
    ],
)
async def test_worker_real_graph_retains_only_verified_persisted_pending(
    monkeypatch, tmp_path, frozen_product_source, mode, retained
):
    from evidencesoc.agents.graph import InvestigationWorkflow
    from evidencesoc.config import Settings
    from evidencesoc.domain.models import ResponsePlan
    from langgraph.checkpoint.memory import InMemorySaver

    from evals.adapters import e_planning_worker as worker
    from evals.tests.test_e_planning_journal import open_fixture, register_fixture

    source = frozen_product_source
    registration = product_registration(source)
    request = planning_requests(registration)[0]
    path = tmp_path / "dispatch.sqlite"
    _, authority, _ = register_fixture(path, registration)
    journal = open_fixture(path, registration, authority)
    settings = Settings(_env_file=None, llm_mode="deepseek")
    environment = SimpleNamespace(
        incident_id=request.incident_id,
        retained=False,
        cleaned=False,
        settings=settings,
    )
    environment.plans = []
    environment.incident = SimpleNamespace(status="received")

    def reference():
        return {
            "schema_version": "task13-case-resource-v1",
            "incident_id": request.incident_id,
            "run_id": request.run_id,
            "case_id": request.case_id,
            "database_name": "synthetic-db",
            "index_name": "synthetic-index",
            "status": "retained_for_human_approval",
        }

    environment.reference = reference
    environment.retain = lambda: setattr(environment, "retained", True)

    class Session:
        def scalars(self, query):
            return SimpleNamespace(all=lambda: environment.plans)

        def get(self, table, key):
            return environment.incident

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    environment.sessions = Session

    @contextmanager
    def case(spec, seed):
        try:
            yield environment
        finally:
            environment.cleaned = not environment.retained
            if mode in {
                "empty_cleanup",
                "empty_table_cleanup",
                "empty_table_all_cleanup",
            }:
                raise RuntimeError("synthetic cleanup failure")

    class Services(ProductServices):
        def __init__(self, *args, **kwargs):
            super().__init__(source.product_values()["evidence"])

        async def save_result(self, state):
            if mode == "save":
                raise RuntimeError("synthetic persistence failure")
            await super().save_result(state)
            environment.incident.status = state["status"]
            if state.get("response_plan"):
                plan = ResponsePlan.model_validate(state["response_plan"])
                environment.plans = [SimpleNamespace(**plan.model_dump())]
                if mode == "table":
                    environment.plans[0].summary = "substitution"

        async def aclose(self):
            if mode in {"empty_table_close", "empty_table_all_cleanup"}:
                raise OSError("synthetic close failure with sensitive message")
            if mode in {"close", "empty_close"}:
                raise RuntimeError("synthetic close failure")

    class Tape(ProductTape):
        def __init__(self):
            super().__init__()
            self.ledger = []

        async def structured(self, role, schema, state):
            self.ledger.append(
                {
                    "role": role,
                    "logical_call_id": "one-logical",
                    "physical_attempt": len(self.ledger) + 1,
                    "request_ordinal": len(self.ledger) + 1,
                    "request_id": "synthetic-provider-id",
                    "physical_request_id": "synthetic-physical-id",
                    "parse_status": "not_received"
                    if mode == "transport"
                    else "schema_error"
                    if mode == "http200_invalid"
                    else "valid",
                    "http_status": 0 if mode == "transport" else 200,
                    "raw_response": None if mode == "transport" else {"choices": []},
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                    "cost_cny": 0.000001,
                }
            )
            if mode in {"transport", "http200_invalid"}:
                self.calls.append(role)
                raise RuntimeError("synthetic provider or schema failure")
            value = await super().structured(role, schema, state)
            data = value.model_dump(mode="json")
            if mode.startswith("empty"):
                data["response_plan"] = None
                if mode == "empty_reason":
                    data["no_plan_reason"] = "No safe candidate"
                elif mode == "empty_blank":
                    data["no_plan_reason"] = "  "
            if mode == "ttl":
                plan = data["response_plan"]
                plan["expires_at"] = (
                    datetime.fromisoformat(plan["created_at"]) + timedelta(seconds=1799)
                ).isoformat()
            raw_content = json.dumps(data)
            self.ledger[-1]["raw_response"] = {
                "choices": [
                    {"finish_reason": "stop", "message": {"content": raw_content}}
                ]
            }
            payload = {"messages": [{"role": "user", "content": "{}"}]}
            body = json.dumps(payload).encode()
            from hashlib import sha256

            self.ledger[-1]["request_sha256"] = canonical_hash(payload)
            self.recorder(
                {
                    "physical_request_id": "synthetic-physical-id",
                    "payload": payload,
                    "http_body": body,
                    "http_body_sha256": sha256(body).hexdigest(),
                }
            )
            return schema.model_validate(data)

    class FreeWorkflow(InvestigationWorkflow):
        @asynccontextmanager
        async def _exclusive(self, incident_id):
            yield

        async def import_analysis(self, *args):
            state = await super().import_analysis(*args)
            if mode.startswith("empty_table"):
                environment.plans = [SimpleNamespace(response_plan_id="contradiction")]
            if mode == "empty_incident":
                environment.incident.status = "awaiting_approval"
            if mode == "empty_checkpoint":
                original = self.graph.aget_state

                async def inconsistent(*args):
                    snapshot = await original(*args)
                    return SimpleNamespace(values=snapshot.values, next=("approval",))

                self.graph.aget_state = inconsistent
            return state

    @asynccontextmanager
    async def checkpointer(url):
        try:
            yield InMemorySaver()
        finally:
            if mode in {"empty_table_checkpoint_close", "empty_table_all_cleanup"}:
                raise ConnectionError("synthetic checkpointer close failure")

    model = Tape()
    calls = []

    def make(*args, **kwargs):
        calls.append("model")
        model.recorder = kwargs["payload_sink"]
        return model

    async def probe(*args):
        calls.append("probe")
        return {"status": "failed" if mode == "probe" else "passed", "latency_ms": 0}

    monkeypatch.setattr(
        worker,
        "validate_planning_inputs",
        lambda *args: (request, source, journal, tmp_path / "unused-budget.sqlite"),
    )
    monkeypatch.setattr(
        worker,
        "development_seed",
        lambda *args: {"registry": {}, "input_sha256": "a" * 64},
    )
    monkeypatch.setattr(worker, "case_environment", case)
    monkeypatch.setattr(worker, "PostgresWorkflowServices", Services)
    monkeypatch.setattr(worker, "InvestigationWorkflow", FreeWorkflow)
    monkeypatch.setattr(worker, "open_checkpointer", checkpointer)
    monkeypatch.setattr(worker, "make_model", make)
    monkeypatch.setattr(worker, "run_service_probe", probe)

    def export(*args):
        if mode in {"tool_export", "empty_export"}:
            raise RuntimeError("synthetic tool export failure")
        return []

    monkeypatch.setattr(worker, "export_tool_ledger", export)
    monkeypatch.setenv("TASK13_OUTPUT_DIR", str(tmp_path))
    result = await worker.run_e_planning(request, tmp_path)
    assert environment.retained is retained
    assert environment.cleaned is (not retained)
    assert journal.validate_request(request)["status"] == "started"
    assert (tmp_path / "model-ledger.json").is_file()
    assert (tmp_path / "model-payloads.json").is_file()
    assert calls[0] == "probe"
    if mode == "probe":
        assert calls == ["probe"]
    if mode in {"empty", "empty_reason", "empty_blank"}:
        assert result.execution_status == "completed"
        assert result.diagnosis_status == "succeeded"
        assert result.product_status == "manual_review"
        assert result.verification["status"] == "no_plan"
        assert result.verification["timing_eligible"] is False
        assert result.verification["no_plan_reason"] == (
            "No safe candidate" if mode == "empty_reason" else None
        )
        assert result.verification["no_plan_reason_missing"] is (mode != "empty_reason")
        assert not result.errors
        assert not (tmp_path / "case-resource.json").exists()
        assert len(result.model_ledger) == 1
    elif retained:
        assert result.execution_status == "completed"
        assert result.product_status == "awaiting_approval"
        state = json.loads(
            (tmp_path / "investigation-state.json").read_text(encoding="utf-8")
        )
        assert state["analysis_import_provenance"] == json.loads(
            (tmp_path / "import-provenance.json").read_text(encoding="utf-8")
        )
        assert result.verification["case_reference"]["state_sha256"] == canonical_hash(
            state
        )
        assert set(model.calls) == {"respond"}
        if mode == "http200_invalid":
            assert state["plan_source"] == "rule_fallback"
            assert len(result.model_ledger) == 3
            assert not any(r["parse_status"] == "valid" for r in result.model_ledger)
    else:
        assert result.execution_status == "failed"
        assert result.errors
        assert result.verification is None
    if mode == "transport":
        assert len(result.model_ledger) == 3
    if mode.startswith("empty_table_"):
        expected = [
            {"stage": "e_planning", "type": "ValueError", "category": "application"}
        ]
        if mode in {"empty_table_checkpoint_close", "empty_table_all_cleanup"}:
            expected.append(
                {
                    "stage": "checkpointer_close",
                    "type": "ConnectionError",
                    "category": "transport",
                }
            )
        if mode in {"empty_table_close", "empty_table_all_cleanup"}:
            expected.append(
                {
                    "stage": "workflow_service_close",
                    "type": "OSError",
                    "category": "infrastructure",
                }
            )
        if mode in {"empty_table_cleanup", "empty_table_all_cleanup"}:
            expected.append(
                {
                    "stage": "case_environment_cleanup",
                    "type": "RuntimeError",
                    "category": "application",
                }
            )
        assert result.errors == expected
        assert result.diagnosis_status == result.product_status == "failed"
        assert not (tmp_path / "case-resource.json").exists()
        assert len(result.model_ledger) == 1


@pytest.mark.parametrize(
    "tamper",
    [
        "none",
        "source",
        "budget",
        "epoch",
        "runtime",
        "entrypoint",
        "journal",
        "package",
        "lineage",
    ],
)
def test_all_readonly_admission_inputs_precede_model_or_resources(
    monkeypatch, tmp_path, tamper
):
    from evidencesoc.agents.analysis_import import ImportedAnalysis

    from evals.adapters import analysis_package
    from evals.adapters import e_planning_worker as worker

    request = request_fixture()
    source_dir = tmp_path / "export"
    source_dir.mkdir()
    entries = {
        name: "a" * 64
        for name in (
            "scripts/task13_worker_runtime.py",
            "evals/adapters/e_planning_worker.py",
            "evals/adapters/e_planning_contracts.py",
            "evals/adapters/e_planning_journal.py",
            "evals/adapters/analysis_package.py",
            "evals/adapters/analysis_import.py",
            "evals/e_planning.py",
        )
    }
    files = dict(entries)
    # A host-only controller entrypoint deliberately is not in minimal worker export.
    entries["evals/remediation.py"] = "b" * 64
    if tamper == "entrypoint":
        files["evals/e_planning.py"] = "c" * 64
    (source_dir / "source_receipt.json").write_text(
        json.dumps({"files": files}), encoding="utf-8"
    )
    epoch = {
        "source_commit": request.source_commit,
        "runtime_binding": {"synthetic": True},
        "entrypoints": entries,
    }
    provenance = {
        "case_id": request.case_id,
        "source_row_id": request.source_row_id,
        "request_sha256": request.original_request_sha256,
        "manifest_sha256": request.original_manifest_sha256,
        "analysis_output_sha256": request.analysis_output_sha256,
        "imported_values_sha256": request.imported_values_sha256,
        "source_package_manifest_sha256": request.source_package_manifest_sha256,
    }
    if tamper == "lineage":
        provenance["manifest_sha256"] = "0" * 64
    source = ImportedAnalysis._from_verified_artifacts(
        {}, provenance, lambda: ({}, provenance)
    )
    calls = []

    def stage(name, result=None):
        def run(*args, **kwargs):
            calls.append(name)
            if tamper == name:
                raise ValueError("synthetic " + name + " rejection")
            return result

        return run

    journal = SimpleNamespace(
        validate_request=stage("registered_request", {"status": "unclaimed"})
    )
    for key, value in {
        "TASK13_WORKER_NONCE": "synthetic",
        "TASK13_PHASE": "development",
        "TASK13_SOURCE_DIR": str(source_dir),
        "TASK13_BUDGET_DB": str(tmp_path / "campaign.sqlite"),
        "TASK13_RUNTIME_BINDING": json.dumps({"synthetic": tamper != "runtime"}),
        "TASK13_IMPORT_DISPATCH_DB": str(tmp_path / "dispatch.sqlite"),
        "TASK13_IMPORT_AUTHORITY_SHA256": "b" * 64,
        "TASK13_IMPORT_SOURCE_DIR": str(tmp_path / "package"),
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(worker.os, "getpid", lambda: 1)
    monkeypatch.setattr(worker, "validate_exported_source", stage("source"))
    monkeypatch.setattr(worker, "require_existing_budget", stage("budget"))
    monkeypatch.setattr(worker, "require_registered_epoch", stage("epoch", epoch))
    monkeypatch.setattr(
        worker.EPlanningDispatchJournal, "open_existing", stage("journal", journal)
    )
    monkeypatch.setattr(
        analysis_package, "verify_portable_analysis_package", stage("package", source)
    )
    monkeypatch.setattr(
        worker, "make_model", lambda *a, **k: pytest.fail("model before admission")
    )
    monkeypatch.setattr(
        worker,
        "case_environment",
        lambda *a, **k: pytest.fail("resources before admission"),
    )
    if tamper == "none":
        q, actual_source, actual_journal, _budget = worker.validate_planning_inputs(
            request, tmp_path
        )
        assert q == request and actual_source is source and actual_journal is journal
        assert calls == [
            "source",
            "budget",
            "epoch",
            "journal",
            "registered_request",
            "package",
        ]
    else:
        with pytest.raises(ValueError):
            worker.validate_planning_inputs(request, tmp_path)
        if tamper in {"source", "budget", "epoch"}:
            assert calls[-1] == tamper
        if tamper in {"runtime", "entrypoint"}:
            assert calls == ["source", "budget", "epoch"]


def test_model_factory_keeps_epoch_and_original_development_account(
    monkeypatch, tmp_path
):
    from evals.adapters import remediation_worker

    request = request_fixture()
    captured = {}
    monkeypatch.setattr(
        remediation_worker,
        "require_existing_budget",
        lambda path, identity: captured.update(path=path, identity=identity),
    )

    class Account:
        def __init__(self, path, **binding):
            captured["binding"] = binding

    class Tracked:
        def __init__(self, config, **kwargs):
            captured["tracked"] = kwargs
            self.account = kwargs["account"]
            self.ledger = []

    monkeypatch.setattr(remediation_worker, "SupplementBudgetAccount", Account)
    monkeypatch.setattr(remediation_worker, "TrackedModel", Tracked)
    model = remediation_worker.make_model(
        request, tmp_path / "original-campaign.sqlite", "development"
    )
    assert captured["binding"] == request.budget_binding()
    assert captured["binding"]["epoch_id"] == request.epoch_id
    assert captured["identity"] == request.budget_identity
    assert captured["tracked"]["max_calls"] == 3
    assert captured["tracked"]["max_logical_calls"] == 1
    assert model.slot_id == request.planning_slot_id
