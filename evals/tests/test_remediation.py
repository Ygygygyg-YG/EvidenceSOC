"""New supplemental control boundaries; all fixtures are synthetic, never paid."""

import importlib
import importlib.util
from copy import deepcopy
from hashlib import sha256

import pytest
from pydantic import ValidationError

from evals.contracts import canonical_hash

CAMPAIGN = "task13-repair-202610-v2"


def budget_config():
    return {
        "budget_identity": {
            "schema_version": "task13-original-budget-identity-v1",
            "baseline_count": 3350,
            "baseline_max_rowid": 3350,
            "baseline_sha256": "9" * 64,
        },
        "active_budget_path": "D:/synthetic-controller-fixture/campaign.sqlite",
    }


def module(name="evals.remediation"):
    assert importlib.util.find_spec(name) is not None, (
        "dedicated v2 entry point is required"
    )
    return importlib.import_module(name)


def request_values(purpose="development"):
    slot = purpose + "-" + "a" * 24
    query = "fixed observable query"
    result = {
        "run_id": CAMPAIGN + "-" + canonical_hash([slot, 1])[:16],
        "case_id": "ait-" + "a" * 24,
        "group": "B3",
        "slot_id": slot,
        "purpose": purpose,
        "source_commit": "a" * 40,
        "source_sha256": "b" * 64,
        "config_sha256": "c" * 64,
        "agent_sha256": "d" * 64,
        "budget_identity": budget_config()["budget_identity"],
    }
    if purpose == "development":
        result.update(
            initial_query=query,
            initial_query_sha256=sha256(query.encode()).hexdigest(),
            rag_mode="semantic_only",
        )
    return result


def test_request_preserves_original_group_contract_and_exports_no_gold():
    m = module("evals.adapters.remediation_contracts")
    value = m.RemediationRequest(**request_values())
    assert value.worker_spec().capabilities.rag_mode == "hybrid"
    assert value.rag_mode == "semantic_only"
    assert value.entry_prompt == m.ENTRY_PROMPT
    assert value.budget_binding()["purpose"] == "development"
    for field in (
        "gold",
        "dataset",
        "labels",
        "is_attack",
        "source_path",
        "scoring_path",
    ):
        with pytest.raises(ValidationError):
            m.RemediationRequest(**request_values(), **{field: "forbidden"})


@pytest.mark.parametrize(
    "patch",
    [
        {"run_id": "task13-campaign"},
        {"purpose": "regression"},
        {"initial_query": "changed"},
        {"attempt": 2},
        {"entry_prompt": "use labels"},
        {"group": "B2"},
        {"repeat": 4},
    ],
)
def test_request_rejects_unregistered_scope_and_drift(patch):
    m = module("evals.adapters.remediation_contracts")
    with pytest.raises(ValidationError):
        m.RemediationRequest(**{**request_values(), **patch})


def test_regression_request_keeps_exact_b2_b3_rag_policy():
    m = module("evals.adapters.remediation_contracts")
    value = m.RemediationRequest(**{**request_values("regression"), "group": "B2"})
    assert value.worker_spec().capabilities.verification_enabled is False
    assert value.worker_spec().capabilities.rag_mode == "hybrid"
    with pytest.raises(ValidationError):
        m.RemediationRequest(**{**request_values("regression"), "rag_mode": "disabled"})


def registration():
    cases = ["ait-" + f"{i:024x}" for i in range(22)] + [
        "dedale-" + f"{i:016x}" for i in range(66)
    ]
    rows = []
    for case_id in cases:
        for group in ("B2", "B3"):
            rows.append(
                {
                    "slot_id": "regression-" + canonical_hash([case_id, group])[:24],
                    "case_id": case_id,
                    "dataset": case_id.split("-")[0],
                    "group": group,
                    "input_hashes": {
                        "events.jsonl": "d" * 64,
                        "manifest.json": "e" * 64,
                    },
                    "status": "not_started",
                    "sequence": len(rows) + 1,
                }
            )
    return {
        "schema_version": "task13-v2-regression-registration-v1",
        "campaign_id": CAMPAIGN,
        "seed": 42,
        "rows": rows,
        "executable": False,
        "order_sha256": canonical_hash([(r["case_id"], r["group"]) for r in rows]),
    }


def test_all_176_registered_rows_become_distinct_answer_free_requests():
    m = module()
    reg = registration()
    before = deepcopy(reg)
    bundle = m.prepare_bundle(
        reg, source_commit="a" * 40, source_sha256="b" * 64, config=budget_config()
    )
    assert reg == before
    assert (
        len(bundle["rows"])
        == len({r["request"]["run_id"] for r in bundle["rows"]})
        == 176
    )
    assert bundle["registration_sha256"] == canonical_hash(reg)
    assert bundle["executable"] is False
    assert [r["slot_id"] for r in bundle["rows"]] == [r["slot_id"] for r in reg["rows"]]
    assert not any("dataset" in r["request"] for r in bundle["rows"])


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "order", "labels"])
def test_bundle_rejects_incomplete_or_drifted_registration(mutation):
    m = module()
    reg = registration()
    if mutation == "missing":
        reg["rows"].pop()
    elif mutation == "duplicate":
        reg["rows"][1] = deepcopy(reg["rows"][0])
    elif mutation == "order":
        reg["rows"].reverse()
    else:
        reg["rows"][0]["labels"] = ["forbidden"]
    with pytest.raises(ValueError):
        m.prepare_bundle(
            reg, source_commit="a" * 40, source_sha256="b" * 64, config=budget_config()
        )


def setup_execution(tmp_path):
    import json

    m = module()
    reg = registration()
    cid = reg["rows"][0]["case_id"]
    agent = tmp_path / "cases" / cid / "agent"
    agent.mkdir(parents=True)
    events = b'{"message":"synthetic controller fixture"}\n'
    (agent / "events.jsonl").write_bytes(events)
    manifest = {
        "case_id": cid,
        "events_file": "events.jsonl",
        "events_sha256": sha256(events).hexdigest(),
    }
    (agent / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    for row in reg["rows"][:2]:
        row["input_hashes"] = {
            name: sha256((agent / name).read_bytes()).hexdigest()
            for name in ("manifest.json", "events.jsonl")
        }
    bundle = m.prepare_bundle(
        reg, source_commit="a" * 40, source_sha256="b" * 64, config=budget_config()
    )
    return m, bundle, agent


def gate_for(bundle):
    return {
        "schema_version": "task13-v2-execution-gate-v1",
        "status": "verified",
        "scope": "offline_contract_test",
        **{
            key: bundle[key]
            for key in (
                "bundle_sha256",
                "campaign_id",
                "purpose",
                "source_commit",
                "source_sha256",
                "config_sha256",
                "budget_identity_sha256",
            )
        },
    }


def test_registration_alone_never_authorizes_dispatch(tmp_path):
    m, bundle, _ = setup_execution(tmp_path)
    calls = []

    async def worker(*args):
        calls.append(args)

    with pytest.raises(PermissionError):
        m.execute_bundle(
            bundle,
            tmp_path / "outputs",
            case_roots={"ait": tmp_path / "cases"},
            offline_worker=worker,
            row_limit=1,
        )
    assert calls == []


def test_dispatched_unknown_is_preserved_and_never_replayed(tmp_path):
    m, bundle, _ = setup_execution(tmp_path)
    calls = []

    async def worker(request, agent):
        calls.append(request.slot_id)
        raise ConnectionError("synthetic uncertain dispatch")

    def admit(_identity):
        return gate_for(bundle)

    options = {
        "case_roots": {"ait": tmp_path / "cases"},
        "admitter": admit,
        "offline_worker": worker,
        "row_limit": 1,
    }
    one = m.execute_bundle(bundle, tmp_path / "outputs", **options)
    assert one["planned_n"] == 176 and one["counts"]["unknown"] == 1
    assert one["counts"]["not_started"] == 175
    assert one["scope"] == "offline_contract_test"
    two = m.execute_bundle(bundle, tmp_path / "outputs", **options)
    assert calls == [bundle["rows"][0]["slot_id"]]
    assert two["counts"]["unknown"] == 1


def test_completed_slot_is_immutable_and_input_drift_stops_before_dispatch(tmp_path):
    m, bundle, agent = setup_execution(tmp_path)
    calls = []

    async def worker(request, _agent):
        calls.append(request.slot_id)
        return {"execution_status": "completed", "diagnosis_status": "succeeded"}

    options = {
        "case_roots": {"ait": tmp_path / "cases"},
        "admitter": lambda _identity: gate_for(bundle),
        "offline_worker": worker,
        "row_limit": 1,
    }
    first = m.execute_bundle(bundle, tmp_path / "outputs", **options)
    assert first["counts"]["completed"] == 1
    before = (
        tmp_path / "outputs" / bundle["rows"][0]["slot_id"] / "result.json"
    ).read_bytes()
    (agent / "events.jsonl").write_bytes(b"changed")
    with pytest.raises(ValueError):
        m.execute_bundle(bundle, tmp_path / "outputs", **options)
    assert len(calls) == 1
    assert (
        tmp_path / "outputs" / bundle["rows"][0]["slot_id"] / "result.json"
    ).read_bytes() == before


def test_gate_drift_or_real_scope_cannot_authorize_fixture_results(tmp_path):
    m, bundle, _ = setup_execution(tmp_path)

    async def worker(*_args):
        pytest.fail("invalid admission dispatched")

    for patch in ({"source_sha256": "f" * 64}, {"scope": "real_execution"}):
        with pytest.raises(PermissionError):
            m.execute_bundle(
                bundle,
                tmp_path / "outputs",
                case_roots={"ait": tmp_path / "cases"},
                admitter=lambda _identity, change=patch: {**gate_for(bundle), **change},
                offline_worker=worker,
                row_limit=1,
            )


def test_pre_dispatch_directory_interruption_can_resume_without_replay(tmp_path):
    m, bundle, _ = setup_execution(tmp_path)
    root = tmp_path / "outputs"
    directory = root / bundle["rows"][0]["slot_id"]
    directory.mkdir(parents=True)
    calls = []

    async def worker(request, _agent):
        calls.append(request.slot_id)
        return {"execution_status": "completed", "diagnosis_status": "succeeded"}

    result = m.execute_bundle(
        bundle,
        root,
        case_roots={"ait": tmp_path / "cases"},
        admitter=lambda _identity: gate_for(bundle),
        offline_worker=worker,
        row_limit=1,
    )
    assert result["counts"]["completed"] == 1
    assert calls == [bundle["rows"][0]["slot_id"]]


def test_rehashed_bundle_cannot_remove_one_group_or_change_frozen_model():
    m = module()
    for mutation in ("group", "model"):
        bundle = m.prepare_bundle(
            registration(),
            source_commit="a" * 40,
            source_sha256="b" * 64,
            config=budget_config(),
        )
        if mutation == "group":
            bundle["rows"][0]["request"]["group"] = "B3"
        else:
            bundle["rows"][0]["request"]["model"]["max_tokens"] = 512
        bundle["bundle_sha256"] = canonical_hash(
            {k: v for k, v in bundle.items() if k != "bundle_sha256"}
        )
        with pytest.raises(ValueError):
            m.validate_bundle(bundle)


def development_registration():
    reg = registration()
    cases = [reg["rows"][i] for i in (0, 2, 44, 46)]
    selected, rows = [], []
    for case in cases:
        query = "fixed observable query " + case["case_id"]
        selected.append(
            {
                "case_id": case["case_id"],
                "input_hashes": case["input_hashes"],
                "initial_query": query,
            }
        )
        for mode in ("empty", "semantic", "hybrid"):
            for repeat in (1, 2, 3):
                rows.append(
                    {
                        "slot_id": "development-"
                        + canonical_hash([case["case_id"], mode, repeat])[:24],
                        "case_id": case["case_id"],
                        "rag_condition": mode,
                        "repeat": repeat,
                        "initial_query_sha256": sha256(query.encode()).hexdigest(),
                        "status": "not_started",
                        "sequence": len(rows) + 1,
                    }
                )
    return {
        "schema_version": "task13-v2-development-registration-v1",
        "campaign_id": CAMPAIGN,
        "cases": selected,
        "rows": rows,
        "order_sha256": canonical_hash(
            [(r["case_id"], r["rag_condition"], r["repeat"]) for r in rows]
        ),
    }


def test_development_matrix_binds_same_query_in_all_nine_conditions():
    m = module()
    reg = development_registration()
    bundle = m.prepare_bundle(
        reg, source_commit="a" * 40, source_sha256="b" * 64, config=budget_config()
    )
    requests = m.validate_bundle(bundle)
    assert len(requests) == 36
    for cid in {r.case_id for r in requests}:
        selected = [r for r in requests if r.case_id == cid]
        assert len({r.initial_query for r in selected}) == 1
        assert {(r.rag_mode, r.repeat) for r in selected} == {
            (mode, repeat)
            for mode in ("disabled", "semantic_only", "hybrid")
            for repeat in (1, 2, 3)
        }


def test_original_budget_identity_required_even_with_complete_matrix():
    with pytest.raises(ValueError):
        module().prepare_bundle(
            registration(), source_commit="a" * 40, source_sha256="b" * 64, config={}
        )


def test_current_admission_receipt_is_bound_after_pre_dispatch_crash(tmp_path):
    import json

    m, bundle, _ = setup_execution(tmp_path)
    root = tmp_path / "outputs"
    directory = root / bundle["rows"][0]["slot_id"]
    directory.mkdir(parents=True)
    original = {**gate_for(bundle), "checked_at": "earlier"}
    (directory / "admission.json").write_text(json.dumps(original), encoding="utf-8")
    current = {**gate_for(bundle), "checked_at": "dispatch-time"}

    async def worker(*_args):
        return {"execution_status": "completed", "diagnosis_status": "succeeded"}

    m.execute_bundle(
        bundle,
        root,
        case_roots={"ait": tmp_path / "cases"},
        admitter=lambda _: current,
        offline_worker=worker,
        row_limit=1,
    )
    started = json.loads((directory / "started.json").read_text(encoding="utf-8"))
    assert started["admission_sha256"] == canonical_hash(current)
    assert (
        json.loads(
            (root / "gates" / (started["admission_sha256"] + ".json")).read_text(
                encoding="utf-8"
            )
        )
        == current
    )
    assert (
        json.loads((directory / "admission.json").read_text(encoding="utf-8"))
        == original
    )
