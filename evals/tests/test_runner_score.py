"""Independent scorer keeps missing rows and never invents masked gold."""

from __future__ import annotations

import importlib
import importlib.util
import json
from pathlib import Path

import pytest
from test_runner_manifest import fixture_config


def test_score_keeps_all_planned_denominators_and_no_fake_human_review(tmp_path):
    assert importlib.util.find_spec("evals.runners.score") is not None
    scorer = importlib.import_module("evals.runners.score")
    manifest = importlib.import_module("evals.runners.manifest")
    config = fixture_config(tmp_path)
    for number, case in enumerate(Path(config["case_root"]).iterdir()):
        scoring = case / "scoring"
        scoring.mkdir()
        (scoring / "manifest.json").write_text(
            json.dumps(
                {
                    "case_id": case.name,
                    "counts": {"attack": number, "normal": 1 - number},
                }
            ),
            encoding="utf-8",
        )
        (scoring / "gold.jsonl").write_text(
            json.dumps(
                {
                    "is_attack": bool(number),
                    "attack_types": ["brute_force"] if number else [],
                    "external_id": "e1",
                }
            )
            + "\n",
            encoding="utf-8",
        )
    plan = manifest.build_plan(config)
    result = scorer.score_plan(plan, tmp_path / "attempts")
    for group in manifest.GROUPS:
        scores = result["groups"]["ait"][group]
        assert scores["coverage"]["planned_n"] == 2
        assert scores["classification"]["binary"]["applicable_n"] == 2
        assert scores["classification"]["binary"]["accuracy"] == 0
        assert scores["evidence"]["ucr_lower"] is None
        assert scores["classification"]["techniques"]["status"] == "not_applicable"
        assert scores["resources"]["tool_ledger_missing_count"] == 2
        assert scores["resources"]["tool_logical_calls"] is None
        assert scores["resources"]["tool_physical_attempts"] is None
        assert scores["resources"]["known_subtotals"]["tool_logical_calls"] is None
    assert result["metadata"]["formal_complete"] is False


def test_dedale_case_binary_truth_uses_manifest_not_related_events(tmp_path):
    assert importlib.util.find_spec("evals.runners.score") is not None
    scorer = importlib.import_module("evals.runners.score")
    root = tmp_path / "scoring"
    root.mkdir()
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "case_is_attack": True,
                "case_applicability": {
                    "attack_binary": True,
                    "six_class": False,
                    "techniques": False,
                    "phases": False,
                    "origin": False,
                },
            }
        )
    )
    (root / "gold.jsonl").write_text(
        json.dumps({"is_attack": None, "source_label": "malicious-related"}) + "\n"
    )
    gold, mask, _ = scorer.load_gold(tmp_path, "dedale")
    assert (
        gold["is_attack"] is True
        and mask["attack_binary"] is True
        and mask["six_class"] is False
    )


def test_interrupted_attempt_usage_cannot_disappear_from_rerun_total():
    scorer = importlib.import_module("evals.runners.score")
    usage, _, _, latency = scorer._resources(
        [
            {"record": {"started_at": "2026-10-18T12:00:00+00:00"}, "result": None},
            {
                "record": {
                    "started_at": "2026-10-18T12:01:00+00:00",
                    "finished_at": "2026-10-18T12:01:02+00:00",
                },
                "result": {
                    "resources": {"input_tokens": 8, "output_tokens": 1, "cost": 0.02}
                },
            },
        ]
    )
    assert usage == {"input_tokens": None, "output_tokens": None, "cost": None}
    assert latency is None


def test_model_ledger_does_not_hide_usage_from_another_attempt():
    scorer = importlib.import_module("evals.runners.score")
    usage, _, _, _ = scorer._resources(
        [
            {
                "record": {},
                "result": {
                    "resources": {"input_tokens": 7, "output_tokens": 0, "cost": 0.01}
                },
            },
            {
                "record": {},
                "result": {
                    "model_ledger": [
                        {
                            "usage": {"prompt_tokens": 8, "completion_tokens": 1},
                            "cost_cny": 0.02,
                        }
                    ]
                },
            },
        ]
    )
    assert usage["input_tokens"] == 15 and usage["output_tokens"] == 1
    assert abs(usage["cost"] - 0.03) < 1e-12


@pytest.mark.parametrize(
    "results,complete",
    [
        ([], False),
        ([None], False),
        ([{"resources": {"tool_ledger_complete": False}, "tool_ledger": []}], False),
        ([{"resources": {"tool_ledger_complete": True}, "tool_ledger": []}], True),
        ([{"tool_ledger": []}], True),
        ([{"resources": {}}], False),
        (
            [None, {"resources": {"tool_ledger_complete": True}, "tool_ledger": []}],
            False,
        ),
    ],
)
def test_tool_ledger_completeness_preserves_unknown_attempts(results, complete):
    scorer = importlib.import_module("evals.runners.score")
    assert hasattr(scorer, "_tool_ledger_complete")
    attempts = [{"record": {}, "result": result} for result in results]
    assert scorer._tool_ledger_complete(attempts) is complete


@pytest.mark.parametrize("bad_usage", ["unavailable", [1], 7])
def test_non_mapping_model_usage_keeps_totals_unknown_without_losing_calls(bad_usage):
    scorer = importlib.import_module("evals.runners.score")
    usage, calls, tools, _ = scorer._resources([{
        "record": {},
        "result": {
            "model_ledger": [{"logical_call_id": "paid-call", "usage": bad_usage, "cost_cny": None}],
            "tool_ledger": [{"call_id": "observed-tool"}],
        },
    }])
    assert usage == {"input_tokens": None, "output_tokens": None, "cost": None}
    assert calls == [{"logical_call_id": "paid-call", "physical_attempts": 1}]
    assert tools == [{"call_id": "observed-tool"}]


@pytest.mark.parametrize("source", ["model_ledger", "resources"])
@pytest.mark.parametrize("bad_tokens", [-1, 1.5, True, False, "3", None])
def test_resource_totals_require_nonnegative_nonboolean_integer_tokens(source, bad_tokens):
    scorer = importlib.import_module("evals.runners.score")
    if source == "model_ledger":
        result = {source: [{"usage": {"prompt_tokens": bad_tokens, "completion_tokens": 4}, "cost_cny": .02}]}
    else:
        result = {source: {"input_tokens": bad_tokens, "output_tokens": 4, "cost": .02}}
    usage, _, _, _ = scorer._resources([{"record": {}, "result": result}])
    assert usage == {"input_tokens": None, "output_tokens": 4, "cost": .02}


@pytest.mark.parametrize("source", ["model_ledger", "resources"])
@pytest.mark.parametrize("bad_cost", [-.01, float("inf"), float("nan"), True, ".02", None])
def test_resource_totals_require_nonnegative_finite_cost(source, bad_cost):
    scorer = importlib.import_module("evals.runners.score")
    if source == "model_ledger":
        result = {source: [{"usage": {"prompt_tokens": 3, "completion_tokens": 4}, "cost_cny": bad_cost}]}
    else:
        result = {source: {"input_tokens": 3, "output_tokens": 4, "cost": bad_cost}}
    usage, _, _, _ = scorer._resources([{"record": {}, "result": result}])
    assert usage == {"input_tokens": 3, "output_tokens": 4, "cost": None}


def test_resource_cost_total_cannot_overflow_to_infinity():
    scorer = importlib.import_module("evals.runners.score")
    usage, _, _, _ = scorer._resources([{
        "record": {}, "result": {"model_ledger": [
            {"usage": {"prompt_tokens": 0, "completion_tokens": 0}, "cost_cny": 1e308}
            for _ in range(2)
        ]},
    }])
    assert usage == {"input_tokens": 0, "output_tokens": 0, "cost": None}


def test_unknown_usage_preserves_group_known_subtotals_and_missing_coverage():
    from evals.metrics import score_resources

    scorer = importlib.import_module("evals.runners.score")
    known, _, _, _ = scorer._resources([{
        "record": {}, "result": {"model_ledger": [{
            "usage": {"prompt_tokens": 3, "completion_tokens": 4}, "cost_cny": .02,
        }]},
    }])
    unknown, _, _, _ = scorer._resources([{
        "record": {}, "result": {"model_ledger": [{"usage": "unavailable", "cost_cny": None}]},
    }])
    scores = score_resources([{"usage": known}, {"usage": unknown}])
    assert scores["input_tokens"] is None and scores["output_tokens"] is None and scores["cost"] is None
    assert scores["known_subtotals"]["input_tokens"] == 3
    assert scores["known_subtotals"]["output_tokens"] == 4
    assert scores["known_subtotals"]["cost"] == .02
    assert scores["input_tokens_missing_count"] == 1
    assert scores["output_tokens_missing_count"] == 1
    assert scores["cost_missing_count"] == 1
