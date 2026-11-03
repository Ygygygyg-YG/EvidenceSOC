"""Free native offline fixtures; no consent, provider or real scoring credit."""

import importlib
import importlib.util
import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from evals.contracts import canonical_hash
from evals.tests.test_human_review_anytime import AUTH
from evals.tests.test_human_review_v2 import ORDER, PLAN, pin


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf8")
    return pin(path)


@pytest.fixture(scope="module")
def native(tmp_path_factory):
    """Seal176 once with the native free executor, not176 live admissions per test."""
    from evals.remediation import execute_bundle
    from evals.tests import test_remediation
    from evals.tests.test_regression_only_host import fixture

    original = json.loads(PLAN.with_name("regression-plan.json").read_text())
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(test_remediation, "registration", lambda: deepcopy(original))
        f = fixture.__wrapped__(tmp_path_factory.mktemp("score-native"))
    root = Path(__file__).resolve().parents[2]
    for relative in (
        "evals/regression_only_authority.py",
        "evals/scoring_v2.py",
        "evals/human_review_v2.py",
    ):
        path = root / relative
        # Before implementation the direct existence test is the intentional RED.
        f.final["source_files"][str(path)] = sha256(path.read_bytes()).hexdigest()
    engineering = f.values["engineering_receipt"]
    engineering["source_files_sha256"] = canonical_hash(f.final["source_files"])
    refs = f.manifest["inputs"]
    refs["engineering_receipt"] = save(f.root / "engineering_receipt.json", engineering)
    f.final["bindings"]["engineering_receipt"] = refs["engineering_receipt"]["sha256"]
    refs["final_freeze"] = save(f.root / "final_freeze.json", f.final)
    f.scope["final_freeze_sha256"] = refs["final_freeze"]["sha256"]
    f.scope["human_review_participation"] = {
        "schema_version": "task13-human16-participation-v1",
        "review_window": "anytime",
        "reviewer": "user",
        "applies_to": "new-registered-sixteen-slot-sample-only",
        "judgment_mode": "individual-actual-user",
        "campaign_id": f.values["bundle"]["campaign_id"],
        "bundle_sha256": f.values["bundle"]["bundle_sha256"],
        "human_plan": pin(PLAN),
        "presentation_order": pin(ORDER),
        "anytime_authorization": pin(AUTH),
    }
    refs["scope_packet"] = save(f.root / "scope.json", f.scope)
    f.decision["scope_packet_sha256"] = refs["scope_packet"]["sha256"]
    refs["scope_decision"] = save(f.root / "decision.json", f.decision)
    host = f.host()
    f.host_pin = deepcopy(host._pin)
    f.output = host._root
    f.output.mkdir()
    (f.output / "host-binding.json").write_bytes(host._raw)

    async def worker(request, agent):
        f.calls.append(request.slot_id)
        if len(f.calls) == 1:
            return {"execution_status": "failed"}
        if (
            request.slot_id
            == json.loads(PLAN.read_text())["slots"][0]["regression_slot_id"]
        ):
            return {"execution_status": "completed"}
        return {
            "execution_status": "completed",
            "diagnosis_status": "succeeded",
            "diagnostic_snapshot": {
                "verdict": "unknown",
                "claims": [
                    {
                        "claim_id": "c",
                        "text": "free fixture claim",
                        "evidence_ids": ["e"],
                    }
                ],
            },
            "evidence_registry": {
                "e": {"case_id": request.case_id, "content_sha256": "e" * 64}
            },
        }

    result = execute_bundle(
        f.values["bundle"],
        f.output,
        case_roots=f.manifest["case_roots"],
        admitter=lambda identity: {
            **identity,
            "schema_version": "task13-v3-execution-gate-v1",
            "status": "verified",
            "scope": "offline_contract_test",
        },
        offline_worker=worker,
    )
    assert result["counts"] == {
        "completed": 175,
        "failed": 1,
        "unknown": 0,
        "not_started": 0,
    }
    f.frozen_authority = host.validate_frozen_scope()
    return f


@pytest.fixture
def audited_native(native, monkeypatch):
    """Reuse the independently audited native snapshot for pure bridge tests.

    Native integration/corruption tests below do not use this fixture. This
    patches only the filesystem audit boundary, never caller row validation,
    human policy, capture parsing, original-pin checks or metric arithmetic.
    """
    from scripts.task13_regression_only import RegressionOnlyHost

    monkeypatch.setattr(
        RegressionOnlyHost,
        "validate_frozen_scope",
        lambda self: deepcopy(native.frozen_authority),
    )
    return native


def test_dedicated_offline_authority_and_score_entrypoint():
    assert importlib.util.find_spec("evals.regression_only_authority") is not None, (
        "independently pinned native offline authority adapter required"
    )
    scoring = importlib.import_module("evals.scoring_v2")
    assert callable(getattr(scoring, "score_regression_only", None))


def authority(f, **kwargs):
    from evals.regression_only_authority import validate_regression_only_scope

    return validate_regression_only_scope(f.host_pin, **kwargs)


def test_native_complete176_retains_failed_seals_and_is_readonly(native):
    f = native
    before = list(f.calls)
    result = authority(
        f, bundle_pin=f.manifest["inputs"]["bundle"], output_root=f.output
    )
    assert len(result["rows"]) == 176
    assert result["rows"][0]["execution_status"] == "failed"
    assert result["rows"][0]["result"]["execution_status"] == "failed"
    assert all(r["output_sha256"] for r in result["rows"])
    assert result["synthetic"] is True
    assert f.calls == before


@pytest.mark.parametrize("fault", ["bundle", "output", "manifest", "incomplete"])
def test_adapter_rejects_rebound_or_incomplete_authority(native, tmp_path, fault):
    from evals.regression_only_authority import validate_regression_only_scope

    f = native
    hp = f.host_pin
    kwargs = {"bundle_pin": f.manifest["inputs"]["bundle"], "output_root": f.output}
    if fault == "bundle":
        kwargs["bundle_pin"] = save(tmp_path / "wrong.json", {"wrong": True})
    if fault == "output":
        kwargs["output_root"] = tmp_path / "wrong"
    if fault == "manifest":
        hp = {"authority": authority(f)}
    if fault == "incomplete":
        value = deepcopy(f.manifest)
        value["output_dir"] = str(tmp_path / "empty-output")
        hp = save(tmp_path / "partial-host.json", value)
        kwargs["output_root"] = Path(value["output_dir"])
    with pytest.raises((ValueError, PermissionError)):
        validate_regression_only_scope(hp, **kwargs)


def test_new_human_packet_binds_native_rows_and_exact_sample(audited_native, tmp_path):
    native = audited_native
    from evals.human_review_v2 import prepare_reviews, validate_reviews

    rows = authority(native)["rows"]
    value = prepare_reviews(
        pin(PLAN), pin(ORDER), rows, regression_only_host_pin=native.host_pin
    )
    assert value["schema_version"] == "task13-human-review-prepared-v4"
    assert (
        value["human_review_participation"]
        == native.scope["human_review_participation"]
    )
    assert len(value["records"]) == 16
    assert [r["sequence"] for r in value["records"]] == list(range(1, 17))
    assert not any(
        '"case_id"' in json.dumps(r) or '"group"' in json.dumps(r)
        for r in value["records"]
    )
    pp = save(tmp_path / "prepared.json", value)
    result = validate_reviews(pp, [], rows, regression_only_host_pin=native.host_pin)
    assert len(result) == 16 and not any(r["reviewed"] for r in result.values())
    assert all(r["measured_duration_seconds"] is None for r in result.values())
    with pytest.raises(ValueError):
        prepare_reviews(
            pin(PLAN),
            pin(ORDER),
            rows,
            regression_only_host_pin=native.host_pin,
            joint_scope_pin={},
        )


@pytest.mark.parametrize(
    "fault", ["claim", "citation", "report", "order", "output", "evidence"]
)
def test_human_cannot_rebind_native_report(audited_native, fault):
    native = audited_native
    from evals.human_review_v2 import prepare_reviews

    rows = authority(native)["rows"]
    slot = json.loads(PLAN.read_text())["slots"][1]["regression_slot_id"]
    row = next(r for r in rows if r["slot_id"] == slot)
    if fault == "claim":
        row["result"]["diagnostic_snapshot"]["claims"][0]["text"] = "edited"
    if fault == "citation":
        row["result"]["diagnostic_snapshot"]["claims"][0]["evidence_ids"] = ["other"]
    if fault == "report":
        row["result"]["diagnostic_snapshot"]["verdict"] = "attack"
    if fault == "order":
        rows.reverse()
    if fault == "output":
        row["output_sha256"] = "f" * 64
    if fault == "evidence":
        row["result"]["evidence_registry"] = {}
    with pytest.raises(ValueError, match="sealed"):
        prepare_reviews(
            pin(PLAN), pin(ORDER), rows, regression_only_host_pin=native.host_pin
        )


def test_offline_score_preserves_denominators_and_defers_f8(
    audited_native, tmp_path, monkeypatch
):
    native = audited_native
    import evals.scoring_v2 as scoring

    assert callable(getattr(scoring, "score_regression_only", None)), (
        "dedicated scorer required"
    )
    # Only original gold admission is isolated: synthetic agent bytes cannot
    # impersonate original scoring cases. Native host/seals and metrics are real.
    plans = {d: {"controller": {"dataset": d}} for d in ("ait", "dedale")}
    monkeypatch.setattr(scoring, "load_original_plans", lambda _: plans)
    monkeypatch.setattr(scoring, "validate_scoring_row", lambda *a: (tmp_path, {}))
    monkeypatch.setattr(
        scoring, "load_gold", lambda *a: ({"verdict": "benign"}, {"binary": True}, {})
    )
    save(tmp_path / "agent/manifest.json", {"scenario": "free_fixture"})
    result = scoring.score_regression_only(
        native.manifest["inputs"]["bundle"],
        native.output,
        scoring_plan_pins={d: {"sha256": "f" * 64} for d in plans},
        formal_host_pin=native.host_pin,
    )
    assert result["metadata"]["formal_complete"] is False
    assert result["metadata"]["synthetic"] is True
    assert result["metadata"]["scope"] == "offline_contract_test"
    assert result["metadata"]["human_metrics_complete"] is False
    assert result["verification"] == {}
    assert result["deferred"] == {"E3": "deferred", "F8": "deferred"}
    assert result["verification_identity"] is None
    assert result["verification_journal_head_sha256"] is None
    assert result["groups"]["ait"]["B2"]["coverage"]["planned_n"] == 22
    assert result["groups"]["dedale"]["B3"]["coverage"]["planned_n"] == 66
    assert (
        sum(
            v["coverage"]["execution_status"].get("failed", 0)
            for gs in result["groups"].values()
            for v in gs.values()
        )
        == 1
    )
    assert all(
        v["evidence"]["p_at_5_lower"] is None
        for gs in result["groups"].values()
        for v in gs.values()
    )


def test_default_scorer_still_requires_rolling_f8(native):
    import evals.scoring_v2 as scoring
    from evals.tests.test_human_review_v2 import ORIGINAL

    with pytest.raises(ValueError, match="sealed native host"):
        scoring.score_bundle(
            native.manifest["inputs"]["bundle"],
            native.output,
            scoring_plan_pins={
                d: pin(ORIGINAL / (d + "-plan.json")) for d in ("ait", "dedale")
            },
            formal_host_pin=native.host_pin,
        )


def captured_reviews(native, tmp_path):
    from evals.human_review_v2 import prepare_reviews

    rows = authority(native)["rows"]
    prepared = prepare_reviews(
        pin(PLAN), pin(ORDER), rows, regression_only_host_pin=native.host_pin
    )
    pp = save(tmp_path / "prepared.json", prepared)
    captures = []
    for record in prepared["records"]:
        if record["unavailable_reason"]:
            continue
        sequence = record["sequence"]
        common = {
            "prepared_sha256": pp["sha256"],
            "slot_id": record["slot_id"],
            "synthetic_control_fixture": False,
            "automatic_approval": False,
            "question_item_id": json.dumps(
                ["request_user_input_async", f"call_offline_fixture_{sequence}", 0]
            ),
            "title": f"{record['display_code']} factual review {pp['sha256']}",
            "question": json.dumps(record, ensure_ascii=False, sort_keys=True),
        }
        start = {
            **common,
            "origin": "actual_tool_question",
            "captured_at": f"2026-11-01T09:{sequence:02d}:00+08:00",
        }
        reply = {
            **common,
            "origin": "actual_user",
            "role": "user",
            "record_id": f"offline-fixture-reply-{sequence}",
            "captured_at": f"2026-11-01T09:{sequence:02d}:20+08:00",
            "text": json.dumps(
                {
                    "claims": [
                        {
                            "claim_id": c["claim_id"],
                            "judgment": "uncertain",
                            "basis": "free fixture only",
                        }
                        for c in record["claims"]
                    ],
                    "relevance": {key: "uncertain" for key in record["evidence_ids"]},
                }
            ),
        }
        captures.append(
            {
                "presentation": save(tmp_path / f"start-{sequence}.json", start),
                "reply": save(tmp_path / f"reply-{sequence}.json", reply),
            }
        )
    return rows, pp, captures


def test_actual_shape_captures_anytime_keep_objectively_unreviewable_slots(
    audited_native, tmp_path
):
    native = audited_native
    from evals.human_review_v2 import validate_reviews

    rows, pp, captures = captured_reviews(native, tmp_path)
    result = validate_reviews(
        pp, captures, rows, regression_only_host_pin=native.host_pin
    )
    assert len(result) == 16
    assert sum(r["reviewed"] for r in result.values()) == len(captures) == 15
    assert sum(r.get("reason") == "no_report" for r in result.values()) == 1
    assert all(r["measured_duration_seconds"] is None for r in result.values())


@pytest.mark.parametrize(
    "fault",
    ["before_activation", "approval_text", "reordered", "wrong_host", "legacy_schema"],
)
def test_regression_only_capture_cannot_infer_or_rebind_judgment(
    audited_native, tmp_path, fault
):
    native = audited_native
    from evals.human_review_v2 import validate_reviews

    rows, pp, captures = captured_reviews(native, tmp_path)
    hp = native.host_pin
    if fault == "before_activation":
        for name in ("presentation", "reply"):
            value = json.loads(Path(captures[0][name]["path"]).read_text())
            value["captured_at"] = "2026-10-24T09:00:00+08:00"
            captures[0][name] = save(tmp_path / (name + "-early.json"), value)
    if fault == "approval_text":
        value = json.loads(Path(captures[0]["reply"]["path"]).read_text())
        value["text"] = "I approve the response plan"
        captures[0]["reply"] = save(tmp_path / "approval.json", value)
    if fault == "reordered":
        captures.reverse()
    if fault == "wrong_host":
        hp = {**native.host_pin, "sha256": "0" * 64}
    if fault == "legacy_schema":
        value = json.loads(Path(pp["path"]).read_text())
        value["schema_version"] = "task13-human-review-prepared-v2"
        pp = save(tmp_path / "legacy-prepared.json", value)
    with pytest.raises((ValueError, PermissionError)):
        validate_reviews(pp, captures, rows, regression_only_host_pin=hp)


@pytest.mark.parametrize("count", [0, 14, 15])
def test_human_metric_completeness_requires_all16_slots(
    audited_native, tmp_path, monkeypatch, count
):
    native = audited_native
    import evals.scoring_v2 as scoring

    _rows, pp, captures = captured_reviews(native, tmp_path)
    monkeypatch.setattr(scoring, "load_original_plans", lambda _: {})
    # Completeness is an authority/human state decision, independent of metric
    # arithmetic already tested with all176 rows above and the existing suite.
    monkeypatch.setattr(scoring, "_assemble_score_groups", lambda *a: ({}, {}))
    result = scoring.score_regression_only(
        native.manifest["inputs"]["bundle"],
        native.output,
        scoring_plan_pins={},
        formal_host_pin=native.host_pin,
        prepared_pin=pp,
        captures=captures[:count],
    )
    assert result["metadata"]["human_metrics_complete"] is (count == 15)
    assert result["human_review"]["resolved_slots"] == count + 1
    assert result["human_review"]["response_plan_approval_credit"] == 0
    assert result["metadata"]["formal_complete"] is False
    assert result["metadata"]["scope"] == "offline_contract_test"


def test_offline_audit_skips_live_and_expired_admission(native, monkeypatch):
    from scripts.task13_regression_only import RegressionOnlyHost

    def forbidden(*args, **kwargs):
        pytest.fail("offline scoring attempted live admission/runtime/worker access")

    for name in ("_runtime", "_preflight", "_prior_results", "_timing", "readiness"):
        monkeypatch.setattr(RegressionOnlyHost, name, forbidden)
    assert authority(native)["summary"]["counts"]["completed"] == 175


@pytest.mark.parametrize("fault", ["unknown", "corrupt_result"])
def test_adapter_refuses_unknown_or_changed_raw_seal(native, fault):
    directory = native.output / native.values["bundle"]["rows"][0]["slot_id"]
    path = directory / ("attempt.json" if fault == "unknown" else "result.json")
    before = path.read_bytes()
    try:
        if fault == "unknown":
            value = json.loads(before)
            value["status"] = "unknown"
            path.write_text(json.dumps(value))
        else:
            path.write_bytes(b"{}")
        with pytest.raises(PermissionError):
            authority(native)
    finally:
        path.write_bytes(before)


@pytest.mark.parametrize(
    "relative",
    [
        "evals/regression_only_authority.py",
        "evals/scoring_v2.py",
        "evals/human_review_v2.py",
    ],
)
def test_adapter_requires_each_exact_actual_bridge_in_freeze(
    native, tmp_path, relative
):
    from evals.regression_only_authority import validate_regression_only_scope

    f = native
    manifest, final, engineering = (
        deepcopy(f.manifest),
        deepcopy(f.final),
        deepcopy(f.values["engineering_receipt"]),
    )
    final["source_files"].pop(str(Path(__file__).resolve().parents[2] / relative))
    engineering["source_files_sha256"] = canonical_hash(final["source_files"])
    refs = manifest["inputs"]
    refs["engineering_receipt"] = save(tmp_path / "engineering.json", engineering)
    final["bindings"]["engineering_receipt"] = refs["engineering_receipt"]["sha256"]
    refs["final_freeze"] = save(tmp_path / "freeze.json", final)
    scope = deepcopy(f.scope)
    scope["final_freeze_sha256"] = refs["final_freeze"]["sha256"]
    refs["scope_packet"] = save(tmp_path / "scope.json", scope)
    decision = deepcopy(f.decision)
    decision["scope_packet_sha256"] = refs["scope_packet"]["sha256"]
    refs["scope_decision"] = save(tmp_path / "decision.json", decision)
    hp = save(tmp_path / "host.json", manifest)
    path = f.output / "host-binding.json"
    before = path.read_bytes()
    try:
        path.write_bytes(Path(hp["path"]).read_bytes())
        with pytest.raises(PermissionError, match="bridge is outside freeze"):
            validate_regression_only_scope(hp)
    finally:
        path.write_bytes(before)


def test_scoring_cannot_omit_external_output_root(monkeypatch):
    import evals.regression_only_authority as adapter
    import evals.scoring_v2 as scoring

    monkeypatch.setattr(
        adapter,
        "validate_regression_only_scope",
        lambda *a, **k: pytest.fail("missing external output root reached host"),
    )
    with pytest.raises(ValueError, match="external.*output"):
        scoring.score_regression_only(
            {"path": "unused", "sha256": "0" * 64},
            None,
            scoring_plan_pins={},
            formal_host_pin={"path": "unused", "sha256": "0" * 64},
        )


@pytest.mark.parametrize("fault", ["missing", "registration", "automatic"])
def test_native_scope_policy_is_required_even_without_human_packet(
    audited_native, monkeypatch, fault
):
    from scripts.task13_regression_only import RegressionOnlyHost

    native = audited_native
    snapshot = deepcopy(native.frozen_authority)
    if fault == "missing":
        snapshot["scope_packet"].pop("human_review_participation")
    if fault == "registration":
        snapshot["scope_packet"]["human_review_participation"]["human_plan"][
            "sha256"
        ] = "0" * 64
    if fault == "automatic":
        snapshot["scope_decision"]["automatic_approval"] = True
    # The native host validates execution scope but intentionally leaves this
    # additional Task2 human policy requirement to its offline adapter.
    monkeypatch.setattr(
        RegressionOnlyHost, "validate_frozen_scope", lambda self: deepcopy(snapshot)
    )
    with pytest.raises((ValueError, PermissionError)):
        authority(native)
