"""Plot replay tests use synthetic scores in temporary directories only."""
import csv
import hashlib
import json
from importlib.util import find_spec

import pytest


def generate():
    assert find_spec("evals.plots") is not None, "Task13 plotting implementation missing"
    from evals.plots.generate import generate_bundle
    return generate_bundle


def test_empty_scores_render_all_required_artifacts_without_fake_values(tmp_path):
    source = tmp_path / "scores.json"
    source.write_text(json.dumps({"schema_version": 1, "run_id": "synthetic-test-only",
                                 "metadata": {"model": "SYNTHETIC TEST ONLY"},
                                 "groups": {"ait": {}, "dedale": {}}}), encoding="utf-8")
    manifest = generate()(source, tmp_path / "figures")
    assert len(manifest["figures"]) == 15
    assert manifest["input_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert manifest["status"] == "incomplete"
    assert manifest["font"]["sha256"]
    for entry in manifest["figures"]:
        assert entry["status"] == "no_computable_data"
        for kind in ("png", "svg", "csv", "caption"):
            output = tmp_path / "figures" / "synthetic-test-only" / entry["outputs"][kind]["path"]
            assert output.exists()
            assert hashlib.sha256(output.read_bytes()).hexdigest() == entry["outputs"][kind]["sha256"]
        png = tmp_path / "figures" / "synthetic-test-only" / entry["outputs"]["png"]["path"]
        from PIL import Image
        with Image.open(png) as image:
            assert image.width >= 1800
            assert image.info["dpi"][0] == pytest.approx(300, abs=.1)
        svg = tmp_path / "figures" / "synthetic-test-only" / entry["outputs"]["svg"]["path"]
        assert "<text" in svg.read_text(encoding="utf-8")
    assert not (tmp_path / "figures/synthetic-test-only/dedale/six_class_f1.png").exists()
    preserved = {item["path"]: item["sha256"] for entry in manifest["figures"]
                 for item in entry["outputs"].values()}
    source.write_text(json.dumps({"run_id": "synthetic-test-only", "groups": {"ait": {}}}), encoding="utf-8")
    with pytest.raises(ValueError, match="Conflicting"):
        generate()(source, tmp_path / "figures")
    for relative, digest in preserved.items():
        assert hashlib.sha256((tmp_path / "figures/synthetic-test-only" / relative).read_bytes()).hexdigest() == digest


def test_ablation_delta_negative_and_missing_remain_distinct(tmp_path):
    source = tmp_path / "scores.json"
    source.write_text(json.dumps({"schema_version": 1, "run_id": "delta-test-only",
        "groups": {"ait": {
            "B3": {"classification": {"binary": {"f1": .8, "applicable_n": 22, "applicable_case_ids": ["same-case"]}}},
            "A1": {"classification": {"binary": {"f1": .6, "applicable_n": 22, "applicable_case_ids": ["same-case"]}}},
            "A2": {"classification": {"binary": {"f1": None, "applicable_n": 22, "applicable_case_ids": ["same-case"]}}},
            "A3": {"classification": {"binary": {"f1": .9, "applicable_n": 22, "applicable_case_ids": ["different-case"]}}}},
            "dedale": {}}}), encoding="utf-8")
    manifest = generate()(source, tmp_path / "figures")
    target = tmp_path / "figures/delta-test-only/ait/ablation_delta.csv"
    with target.open(encoding="utf-8-sig", newline="") as stream:
        records = list(csv.DictReader(stream))
    actual = next(row for row in records if row["group"] == "A1" and row["metric"] == "binary_f1")
    missing = next(row for row in records if row["group"] == "A2" and row["metric"] == "binary_f1")
    assert float(actual["value"]) == pytest.approx(-20)
    assert missing["value"] == ""
    assert missing["status"] == "not_available"
    wrong_cases = next(row for row in records if row["group"] == "A3" and row["metric"] == "binary_f1")
    assert wrong_cases["value"] == ""
    assert manifest["figures"][1]["status"] == "partial"


def test_unsafe_run_id_rejected_before_files_created(tmp_path):
    source = tmp_path / "scores.json"
    source.write_text(json.dumps({"run_id": "../escape", "groups": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="run_id"):
        generate()(source, tmp_path / "figures")


def test_first_and_last_bars_have_room_and_na_is_not_a_zero_bar():
    from matplotlib import pyplot as plt

    from evals.plots.common import bars, canvas
    figure, axes = canvas("test", 1, columns=1)
    bars(axes[0], ["A1", "A2", "A3", "A4"], [-20, None, None, None], "delta", zero=True)
    assert axes[0].get_xlim()[0] < -.31
    assert axes[0].get_xlim()[1] > 3.31
    assert len(axes[0].patches) == 1
    plt.close(figure)


def test_merge_preserves_both_input_hashes_and_rejects_identity_mismatch(tmp_path):
    from evals.plots import generate as module
    assert hasattr(module, "merge_scores"), "Frozen per-dataset score merge missing"
    paths = []
    for dataset in ("ait", "dedale"):
        path = tmp_path / f"{dataset}.json"
        path.write_text(json.dumps({"run_id": "same-run", "metadata": {
            "source_commit": "a" * 40, "requested_model": "same-model", "published_version": "v1"},
            "groups": {dataset: {"B0": {}}}, "source_hashes": {"plan": dataset}}), encoding="utf-8")
        paths.append(path)
    merged = module.merge_scores(paths)
    assert set(merged["groups"]) == {"ait", "dedale"}
    assert len(merged["merged_inputs"]) == 2
    assert merged["merged_inputs"][0]["sha256"] == hashlib.sha256(paths[0].read_bytes()).hexdigest()
    wrong = json.loads(paths[1].read_text(encoding="utf-8"))
    wrong["metadata"]["source_commit"] = "b" * 40
    paths[1].write_text(json.dumps(wrong), encoding="utf-8")
    with pytest.raises(ValueError, match="identity"):
        module.merge_scores(paths)


def test_conflicting_run_outputs_are_not_overwritten(tmp_path):
    source = tmp_path / "scores.json"
    source.write_text(json.dumps({"run_id": "existing-run", "groups": {}}), encoding="utf-8")
    root = tmp_path / "figures/existing-run"
    root.mkdir(parents=True)
    marker = root / "figure_manifest.json"
    marker.write_text(json.dumps({"input_sha256": "other-frozen-score"}), encoding="utf-8")
    with pytest.raises(ValueError, match="Conflicting"):
        generate()(source, tmp_path / "figures")
    assert json.loads(marker.read_text())["input_sha256"] == "other-frozen-score"


def test_cli_repeated_scores_passes_both_frozen_inputs(monkeypatch, capsys):
    import sys

    from evals.plots import generate as module
    received = {}

    def capture(paths, output_root, *, font_path):
        received.update(paths=paths, output_root=output_root, font_path=font_path)
        return {"run_id": "paired-input-test", "status": "incomplete", "figures": [None] * 15}

    monkeypatch.setattr(module, "generate_bundle", capture)
    monkeypatch.setattr(sys, "argv", ["plots", "--scores", "ait.json", "--scores", "dedale.json",
                                    "--output-root", "test-output", "--font-path", "test-font.ttc"])
    module.main()
    assert received == {"paths": ["ait.json", "dedale.json"], "output_root": "test-output", "font_path": "test-font.ttc"}
    assert json.loads(capsys.readouterr().out)["figures"] == 15


def test_resource_time_display_uses_seconds_and_exports_original_milliseconds():
    from copy import deepcopy

    from matplotlib import pyplot as plt

    from evals.plots.resources import build

    groups = {"B3": {"coverage": {"planned_n": 22}, "resources": {
        "latency_p50_ms": 1500, "latency_p95_ms": 3250,
        "latency_observed_n": 20, "latency_missing_n": 2,
    }}}
    original = deepcopy(groups)
    figure, rows, caption = build("ait", groups)
    try:
        values = {row["metric"]: row for row in rows if row["group"] == "B3"}
        assert values["latency_p50_s"]["value"] == 1.5
        assert values["latency_p95_s"]["value"] == 3.25
        assert values["latency_p50_ms"]["value"] == 1500
        assert values["latency_p50_s"]["unit"] == "秒"
        assert values["latency_p50_s"]["denominator"] == 20
        assert "计划 n=22" in values["latency_p50_s"]["note"]
        assert "缺测 n=2" in values["latency_p50_s"]["note"]
        assert "控制器" in caption
        assert groups == original
    finally:
        plt.close(figure)


def test_long_chinese_footer_stays_within_export_canvas():
    from matplotlib import pyplot as plt

    from evals.plots.common import canvas, finish
    from evals.plots.generate import _font

    _font(None)
    figure, _ = canvas("test", 1)
    finish(figure, "run=" + "r" * 80 + " · no_computable_data · " + "独立克隆配对模拟完整槽位费用不能证明真实阻断" * 4)
    figure.canvas.draw()
    bounds = figure.texts[-1].get_window_extent(figure.canvas.get_renderer())
    assert bounds.x1 <= figure.bbox.x1
    assert bounds.y0 >= 0
    plt.close(figure)


def test_verification_figure_draws_unverified_cost_and_both_false_success_conditions():
    from matplotlib import pyplot as plt

    from evals.metrics import score_verification
    from evals.plots.verification import build

    slots = [{"pair_id": condition, "case_id": "case", "condition": condition}
             for condition in ("success", "failure", "no_change")]
    records = []
    for condition, outcome in (("success", "success"), ("failure", "failure"), ("no_change", "insufficient_evidence")):
        for branch in ("enabled", "disabled"):
            records.append({"pair_id": condition, "branch": branch, "status": "completed",
                "approval_status": "approved", "outcome": outcome if branch == "enabled" else "unverified", "cost": .1})
    figure, rows, _ = build("ait", score_verification(records, slots))
    assert len(figure.axes) == 8
    assert any("无变化：误报成功率" in axis.get_title(loc="left") for axis in figure.axes)
    unverified = next(axis for axis in figure.axes if "未验证比例" in axis.get_title(loc="left"))
    assert [bar.get_height() for bar in unverified.patches] == [0, 1, 0, 1, 0, 1]
    costs = next(axis for axis in figure.axes if "额外费用" in axis.get_title(loc="left"))
    assert costs.get_ylabel() == "人民币元"
    assert [bar.get_height() for bar in costs.patches] == pytest.approx([.6, .6])
    assert next(item for item in rows if item["metric"] == "additional_cost")["value"] == pytest.approx(.6)
    plt.close(figure)
