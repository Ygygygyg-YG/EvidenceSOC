"""Synthetic records exercise the bridge; they are never real review credit."""

import importlib
import json
from hashlib import sha256
from pathlib import Path

import pytest

ROOT = Path("D:/传智杯/data/task13")
PLAN = ROOT / "control/task13-repair-202610-v2/human-plan.json"
ORDER = ROOT / "supplements/task13-repair-202610-v2/human/presentation-order.json"


def pin(path):
    return {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}


def test_prepare_retains_original16_missing_without_judgment(tmp_path):
    m = importlib.import_module("evals.human_review_v2")
    plan = json.loads(PLAN.read_text(encoding="utf8"))
    rows = [
        {
            "slot_id": s["regression_slot_id"],
            "case_id": s["case_id"],
            "group": s["group"],
            "result": None,
            "output_sha256": None,
            "execution_status": "missing",
        }
        for s in plan["slots"]
    ]
    prepared = m.prepare_reviews(pin(PLAN), pin(ORDER), rows)
    assert len(prepared["records"]) == 16
    assert [r["sequence"] for r in prepared["records"]] == list(range(1, 17))
    assert all(r["unavailable_reason"] == "missing_output" for r in prepared["records"])
    assert all(r["claims"] == [] for r in prepared["records"])
    path = tmp_path / "prepared.json"
    path.write_text(json.dumps(prepared), encoding="utf8")
    result = m.validate_reviews(pin(path), [], rows)
    assert len(result) == 16 and all(not r["reviewed"] for r in result.values())
    assert all(r["measured_duration_seconds"] is None for r in result.values())
    rows[0]["case_id"] = "changed"
    with pytest.raises(ValueError):
        m.validate_reviews(pin(path), [], rows)


def test_old_plan_hash_cannot_be_replaced(tmp_path):
    m = importlib.import_module("evals.human_review_v2")
    altered = tmp_path / "plan.json"
    altered.write_bytes(PLAN.read_bytes() + b" ")
    with pytest.raises(ValueError):
        m.prepare_reviews(pin(altered), pin(ORDER), [])


def test_score_bridge_exists_and_keeps_missing_f8_pairs():
    m = importlib.import_module("evals.scoring_v2")
    summary = m.score_f8(
        {
            "records": [],
            "planned_slots": [
                {"pair_id": "p", "case_id": "ait-example", "condition": "success"}
            ],
        }
    )
    assert summary["ait"]["planned_pairs"] == 1
    assert summary["ait"]["complete_pairs"] == 0
    assert summary["ait"]["cost"] is None


def test_f8_join_rejects_self_signed_four_field_scope(tmp_path):
    from types import SimpleNamespace

    from evals.contracts import canonical_hash
    from evals.scoring_v2 import validate_f8_scope

    campaign = SimpleNamespace(root=tmp_path / "f8", _registration={"fixture": True})
    bundle = {"bundle_sha256": "a" * 64}
    path = tmp_path / "joint.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "task13-rolling-joint-scope-v1",
                "bundle_sha256": bundle["bundle_sha256"],
                "f8_registration_sha256": canonical_hash(campaign._registration),
                "f8_output_dir": str(campaign.root.resolve()),
            }
        )
    )
    with pytest.raises((ValueError, PermissionError)):
        validate_f8_scope(pin(path), bundle, campaign)


def test_reply_question_item_cannot_be_reused_across_slots(tmp_path):
    from copy import deepcopy

    m, rows, pp, start, reply, store = completed_fixture(tmp_path)
    captures = store()
    second = json.loads(Path(pp["path"]).read_text())["records"][1]
    start2, reply2 = deepcopy(start), deepcopy(reply)
    for item in (start2, reply2):
        item.update(
            slot_id=second["slot_id"],
            title=f"{second['display_code']} factual review {pp['sha256']}",
            question=json.dumps(second, ensure_ascii=False, sort_keys=True),
            captured_at="2026-10-31T20:01:00.123456+08:00",
        )
    reply2["record_id"] = "distinct-second-reply"
    p1, p2 = tmp_path / "start2.json", tmp_path / "reply2.json"
    p1.write_text(json.dumps(start2))
    p2.write_text(json.dumps(reply2))
    captures.append({"presentation": pin(p1), "reply": pin(p2)})
    with pytest.raises(ValueError, match="question"):
        m.validate_reviews(pp, captures, rows)


def completed_fixture(tmp_path):
    m = importlib.import_module("evals.human_review_v2")
    plan = json.loads(PLAN.read_text(encoding="utf8"))
    rows = [
        {
            "slot_id": s["regression_slot_id"],
            "case_id": s["case_id"],
            "group": s["group"],
            "result": {
                "diagnostic_snapshot": {
                    "claims": [
                        {
                            "claim_id": "c",
                            "text": "fixture claim",
                            "evidence_ids": ["e"],
                        }
                    ]
                }
            },
            "output_sha256": "a" * 64,
            "execution_status": "completed",
        }
        for s in plan["slots"]
    ]
    prepared = m.prepare_reviews(pin(PLAN), pin(ORDER), rows)
    path = tmp_path / "prepared.json"
    path.write_text(json.dumps(prepared), encoding="utf8")
    pp = pin(path)
    r = prepared["records"][0]
    common = {
        "prepared_sha256": pp["sha256"],
        "slot_id": r["slot_id"],
        "synthetic_control_fixture": False,
        "automatic_approval": False,
        "question_item_id": json.dumps(["request_user_input_async", "call_fixture", 0]),
        "title": f"{r['display_code']} factual review {pp['sha256']}",
        "question": json.dumps(r, ensure_ascii=False, sort_keys=True),
    }
    start = {
        **common,
        "origin": "actual_tool_question",
        "captured_at": "2026-10-31T20:00:00.123456+08:00",
    }
    reply = {
        **common,
        "origin": "actual_user",
        "role": "user",
        "record_id": "fixture-only",
        "captured_at": "2026-10-31T20:00:20.123456+08:00",
        "text": json.dumps(
            {
                "claims": [
                    {
                        "claim_id": "c",
                        "judgment": "uncertain",
                        "basis": "fixture evidence",
                    }
                ],
                "relevance": {"e": "uncertain"},
            }
        ),
    }

    def store():
        paths = []
        for name, data in [("presentation", start), ("reply", reply)]:
            file = tmp_path / (name + ".json")
            file.write_text(json.dumps(data), encoding="utf8")
            paths.append(pin(file))
        return [{"presentation": paths[0], "reply": paths[1]}]

    return m, rows, pp, start, reply, store


def test_actual_capture_shape_no_wall_time_duration(tmp_path):
    m, rows, pp, start, reply, store = completed_fixture(tmp_path)
    result = m.validate_reviews(pp, store(), rows)
    assert sum(r["reviewed"] for r in result.values()) == 1
    assert result[rows[0]["slot_id"]]["measured_duration_seconds"] is None
    start.update(clock_session_id="fixture", monotonic_ns=100)
    reply.update(clock_session_id="fixture", monotonic_ns=2_000_000_100)
    assert (
        m.validate_reviews(pp, store(), rows)[rows[0]["slot_id"]][
            "measured_duration_seconds"
        ]
        == 2
    )


@pytest.mark.parametrize(
    "change",
    [
        "model",
        "oldpacket",
        "claims",
        "citation",
        "future",
        "clock",
        "reordered",
        "editedquestion",
        "fixture",
    ],
)
def test_rejects_nonactual_or_unbound_reviews(tmp_path, change):
    m, rows, pp, _start, reply, store = completed_fixture(tmp_path)
    if change == "model":
        reply["role"] = "assistant"
    if change == "oldpacket":
        reply["prepared_sha256"] = "b" * 64
    if change == "claims":
        reply["text"] = json.dumps({"claims": [], "relevance": {"e": "supported"}})
    if change == "citation":
        reply["text"] = json.dumps(
            {
                "claims": [
                    {"claim_id": "c", "judgment": "supported", "basis": "fixture"}
                ],
                "relevance": {},
            }
        )
    if change == "future":
        reply["captured_at"] = "2099-01-01T20:00:00+08:00"
    if change == "clock":
        reply["monotonic_ns"] = 1
    if change == "editedquestion":
        reply["question"] = "approve"
    if change == "fixture":
        reply["synthetic_control_fixture"] = True
    captures = store()
    if change == "reordered":
        captures += captures
    with pytest.raises((ValueError, KeyError)):
        m.validate_reviews(pp, captures, rows)


ORIGINAL = (
    ROOT / "control/preregister-11aff6cf08e5d4246e252c4b0031126716e761bb/final-20261020"
)


def test_selfsigned_original_plan_is_rejected(tmp_path):
    from evals.contracts import canonical_hash
    from evals.scoring_v2 import load_original_plans

    value = json.loads((ORIGINAL / "ait-plan.json").read_text(encoding="utf8"))
    value["controller"]["case_root"] = str(tmp_path)
    value["plan_sha256"] = canonical_hash(
        {k: v for k, v in value.items() if k != "plan_sha256"}
    )
    altered = tmp_path / "forged.json"
    altered.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="trusted original"):
        load_original_plans(
            {"ait": pin(altered), "dedale": pin(ORIGINAL / "dedale-plan.json")}
        )


def test_original_gold_and_agent_binding_are_readonly(monkeypatch):
    import evals.scoring_v2 as m

    plans = m.load_original_plans(
        {d: pin(ORIGINAL / (d + "-plan.json")) for d in ("ait", "dedale")}
    )
    original = next(r for r in plans["ait"]["rows"] if r["group"] == "B2")
    row = {**original, "dataset": "ait"}
    root, _ = m.validate_scoring_row(row, plans)
    row["input_hashes"] = {"manifest.json": "0" * 64, "events.jsonl": "0" * 64}
    with pytest.raises(ValueError, match="agent input"):
        m.validate_scoring_row(row, plans)
    row["input_hashes"] = original["input_hashes"]
    read = m._read_rolling
    monkeypatch.setattr(
        m,
        "_read_rolling",
        lambda path: (
            b'{"is_attack":true}'
            if Path(path) == root / "scoring" / "gold.jsonl"
            else read(path)
        ),
    )
    with pytest.raises(ValueError, match="scoring artifact"):
        m.validate_scoring_row(row, plans)


def frozen_view(tmp_path):
    """Pure frozen-binding unit fixture, never an actual approval or live host."""
    from types import SimpleNamespace

    import evals.task13_rolling as m
    from evals.tests.test_verification_v2 import registration
    from scripts.task13_e_trial import _bytes

    def save(name, value):
        target = tmp_path / (name + ".json")
        target.write_bytes(_bytes(value))
        return pin(target)

    view = object.__new__(m.NativeRollingOperations)
    plan = registration()
    files = {
        str(Path(m.__file__).resolve().parents[1] / r): sha256(
            (Path(m.__file__).resolve().parents[1] / r).read_bytes()
        ).hexdigest()
        for r in (
            "evals/task13_rolling.py",
            "evals/timing_pool.py",
            "evals/verification_v2.py",
            "scripts/task13_regression.py",
        )
    }
    core = {"f8_plan_sha256": m.canonical_hash(plan)}
    rows = [
        {"case_id": cid, "request": {"group": group}}
        for cid in dict.fromkeys(s["case_id"] for s in plan["slots"])
        for group in ("B2", "B3")
    ]
    bundle = {
        "campaign_id": "task13-repair-202610-v2",
        "bundle_sha256": "b" * 64,
        "source_commit": "c" * 40,
        "config_sha256": m.canonical_hash(core),
        "rows": rows,
    }
    manifest = {
        "schema_version": "task13-regression-host-v1",
        "deadline_at": m.DEADLINE,
        "inputs": {
            "final_freeze": {"sha256": "f" * 64},
            "e_timing_receipt": {"sha256": "e" * 64},
        },
    }
    data = {
        "bundle": bundle,
        "core_config": core,
        "final_freeze": {"source_files": files},
        "runtime_options": {},
    }
    view.host = SimpleNamespace(
        _manifest=manifest,
        _load=lambda: data,
        _scope=lambda *_: pytest.fail("execution deadline gate invoked"),
        _now=lambda: pytest.fail("execution clock invoked"),
    )
    view.campaign = SimpleNamespace(
        plan=plan,
        _registration={"fixture": True},
        config=core,
        source_files=files,
        root=tmp_path / "f8",
    )
    view.identity = {
        "campaign_id": bundle["campaign_id"],
        "source_commit": bundle["source_commit"],
        "source_sha256": m.canonical_hash(files),
        "config_sha256": bundle["config_sha256"],
        "plan_sha256": core["f8_plan_sha256"],
    }
    view.rows = rows
    view.options = {"phase": "verification"}
    auth = {"fixture_only": True}
    view.policy = {
        "schema_version": "task13-e-participation-policy-v1",
        "dispatch_window": "anytime",
        "user_presence_required": False,
        "plan_approval": "individual-user-decision-v1",
        "authorization_record_sha256": m.canonical_hash(auth),
    }
    view.scope = {
        "schema_version": "task13-rolling-joint-scope-v1",
        "regression_host_proposal_sha256": m.canonical_hash(
            m.regression_host_proposal(manifest)
        ),
        "campaign_id": bundle["campaign_id"],
        "bundle_sha256": bundle["bundle_sha256"],
        "final_freeze_sha256": "f" * 64,
        "timing_receipt_sha256": "e" * 64,
        "f8_registration_sha256": m.canonical_hash(view.campaign._registration),
        "f8_output_dir": str(view.campaign.root.resolve()),
        "deadline_at": m.DEADLINE,
        "admitted_operation_may_finish": True,
        "registered_rows": 176,
        "registered_cases": 88,
        "registered_pairs": 264,
        "registered_branches": 528,
        "formal_order_sha256": m.canonical_hash(
            [(r["case_id"], r["request"]["group"]) for r in rows]
        ),
        "f8_cross_case_order": "formal-seed42-arrival",
        "per_plan_approval": "individual-user-decision-v1",
        "f8_model_calls": 0,
        "logical_calls_per_row": 16,
        "physical_attempts_per_logical": 3,
        "budgets": {
            "original_total": 100,
            "original_development": 15,
            "supplement": 30,
            "development": 6,
            "regression": 16,
            "f8": 6,
            "held": 2,
        },
        "verification_runtime_options": save("options", view.options),
        "participation_policy": save("policy", view.policy),
        "participation_authorization": save("auth", auth),
    }
    view.scope_pin = save("scope", view.scope)
    view.decision = {
        "schema_version": "task13-rolling-joint-user-decision-v1",
        "role": "user",
        "decision": "approved",
        "scope_packet_sha256": view.scope_pin["sha256"],
        "record_id": "synthetic-unit-fixture",
        "text": "fixture only; not real consent",
        "decided_at": "2026-10-31T20:00:00+08:00",
    }
    view.decision_pin = save("decision", view.decision)
    packet, decision = m.materialize_regression_scope(
        m.regression_host_proposal(manifest),
        view.scope,
        view.scope_pin["sha256"],
        view.decision,
        view.decision_pin["sha256"],
    )
    data.update(scope_packet=packet, scope_decision=decision)
    return view


def test_frozen_scope_remains_auditable_after_deadline_without_admission(
    tmp_path, monkeypatch
):
    from datetime import UTC, datetime

    import evals.task13_rolling as m

    class AfterDeadline(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 11, 6, tzinfo=UTC)

    view = frozen_view(tmp_path)
    monkeypatch.setattr(m, "datetime", AfterDeadline)
    assert view._check_frozen_scope()["bundle"]["bundle_sha256"] == "b" * 64
    view.campaign.root = tmp_path / "wrong-f8"
    with pytest.raises(PermissionError):
        view._check_frozen_scope()


@pytest.mark.parametrize(
    "field", ["decision", "freeze", "source_mapping", "derived_reply"]
)
def test_frozen_scope_rejects_rebound_authority(tmp_path, field):
    view = frozen_view(tmp_path)
    if field == "decision":
        view.decision["decision"] = "rejected"
    if field == "freeze":
        view.host._manifest["inputs"]["final_freeze"]["sha256"] = "0" * 64
    if field == "source_mapping":
        view.campaign.source_files = {}
    if field == "derived_reply":
        view.host._load()["scope_decision"]["text"] = "edited"
    with pytest.raises(PermissionError):
        view._check_frozen_scope()


def test_collector_reads_native_real_execution_scope_and_keeps176(tmp_path):
    from evals.contracts import AdapterResult, canonical_hash
    from evals.remediation import prepare_bundle
    from evals.runners.score import _resource_coverage, _resources
    from evals.scoring_v2 import collect_regression
    from evals.tests.test_remediation import budget_config, registration

    bundle = prepare_bundle(
        registration(),
        source_commit="a" * 40,
        source_sha256="b" * 64,
        config=budget_config(),
    )
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    root = tmp_path / "output"
    root.mkdir()
    first = bundle["rows"][0]
    directory = root / first["slot_id"]
    directory.mkdir()
    gate = {"bundle_sha256": bundle["bundle_sha256"]}
    digest = canonical_hash(gate)
    (root / "gates").mkdir()
    (root / "gates" / (digest + ".json")).write_text(json.dumps(gate))
    start = {
        "bundle_sha256": bundle["bundle_sha256"],
        "request_sha256": canonical_hash(first["request"]),
        "scope": "real_execution",
        "slot_id": first["slot_id"],
        "input_hashes": first["input_hashes"],
        "admission_sha256": digest,
        "started_at": "2026-10-31T20:00:00+08:00",
    }
    (directory / "started.json").write_text(json.dumps(start))
    result = AdapterResult(
        execution_status="failed",
        diagnosis_status="failed",
        model_ledger=[
            {"usage": {"prompt_tokens": 3, "completion_tokens": 4}, "cost_cny": 0.02},
            {"usage": None, "cost_cny": None},
        ],
    ).model_dump(mode="json")
    (directory / "result.json").write_text(json.dumps(result))
    attempt = {
        "bundle_sha256": bundle["bundle_sha256"],
        "scope": "real_execution",
        "slot_id": first["slot_id"],
        "status": "failed",
        "started_at": start["started_at"],
        "finished_at": "2026-10-31T20:00:02+08:00",
        "result_sha256": sha256((directory / "result.json").read_bytes()).hexdigest(),
    }
    (directory / "attempt.json").write_text(json.dumps(attempt))
    rows = collect_regression(pin(path), root)
    assert len(rows) == 176 and rows[0]["execution_status"] == "failed"
    assert sum(r["execution_status"] == "missing" for r in rows) == 175
    assert _resources(rows[0]["attempts"])[0]["cost"] is None
    assert _resources(rows[0]["attempts"])[3] == 2000
    assert _resource_coverage(rows[0]["attempts"])["known_subtotals"]["cost"] == 0.02
    attempt["scope"] = "Task13supplement176regression-afterE"
    (directory / "attempt.json").write_text(json.dumps(attempt))
    with pytest.raises(ValueError, match="binding"):
        collect_regression(pin(path), root)
