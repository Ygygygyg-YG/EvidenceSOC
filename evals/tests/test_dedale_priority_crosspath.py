"""Independent v4 verification uses tiny real archives and own member checkpoints."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from evals.datasets.dedale.common import canonical, read_json, sha256, write_new
from evals.tests import test_dedale_scan as scan_fixtures
from evals.tests.test_dedale_neutralize import (
    finalized_inputs as finalized_inputs,  # noqa: PLC0414 -- pytest fixture re-export
)

scanner = scan_fixtures.scanner


def test_scan_fixture_preserves_one_module_identity_for_package_and_direct_imports(scanner):
    import importlib
    import sys

    from evals.datasets.dedale import scan

    assert scan is scanner
    assert importlib.import_module("evals.datasets.dedale.scan") is scanner
    assert sys.modules["evals.datasets.dedale.scan"] is scanner


@pytest.fixture
def checker():
    try:
        from scripts import dedale_task12_priority_crosspath
    except ImportError:
        pytest.fail("Independent public-priority cross-path implementation is missing")
    return dedale_task12_priority_crosspath


@pytest.fixture
def own_inputs(finalized_inputs, tmp_path, monkeypatch, checker):
    from evals.datasets.dedale import neutralize
    from evals.datasets.dedale.scan import prepare_dataset

    args, _preparation = finalized_inputs
    neutralize.finalize_dataset(**args)
    second_raw = tmp_path / "second-raw"
    shutil.copytree(args["data_root"], second_raw)
    second_prepared, second_checkpoints = tmp_path / "second-v2", tmp_path / "second-checkpoints"
    prepare_dataset(sources=args["sources"], splits=args["scan_splits"], label_policy=args["label_policy"],
                    data_root=second_raw, output_root=second_prepared, workers=1,
                    checkpoint_root=second_checkpoints)
    second_neutral = tmp_path / "second-v3"
    neutralize.finalize_dataset(**{**args, "data_root": second_raw, "prepared_root": second_prepared,
        "preparation_checkpoints": second_checkpoints, "output_root": second_neutral})
    policy = read_json(Path(__file__).resolve().parents[2] / "data/manifests/dedale-public-priority-v4.json")
    policy.update(neutral_policy_sha256=sha256(args["splits"]),
                  preparation_selection_sha256=sha256(args["prepared_root"] / "selection.json"),
                  preparation_splits_sha256=sha256(args["scan_splits"]))
    policy["preregistration_revision"]["previous_policy_sha256"] = sha256(args["splits"])
    v4_policy = tmp_path / "priority.json"
    write_new(v4_policy, policy)
    monkeypatch.setattr(checker, "EXPECTED_PREPARATION_MEMBERS", 4)
    return {"sources": args["sources"], "scan_splits": args["scan_splits"], "splits": v4_policy,
        "neutral_policy": args["splits"], "label_policy": args["label_policy"],
        "data_root": args["data_root"], "prepared_root": args["prepared_root"],
        "preparation_checkpoints": args["preparation_checkpoints"], "neutral_root": args["output_root"],
        "cases_root": tmp_path / "original-v4", "rebuild_data_root": second_raw,
        "rebuild_prepared_root": second_prepared, "rebuild_preparation_checkpoints": second_checkpoints,
        "rebuild_neutral_root": second_neutral, "rebuild_root": tmp_path / "second-v4", "workers": 1,
        "original_wait_seconds": 0}


def original_build(inputs):
    from evals.datasets.dedale.public_priority import finalize_dataset
    names = ("sources", "scan_splits", "splits", "neutral_policy", "label_policy", "data_root",
             "prepared_root", "preparation_checkpoints", "neutral_root", "workers")
    return finalize_dataset(**{name: inputs[name] for name in names}, output_root=inputs["cases_root"])


def test_real_own_raw_checkpoints_and_all_three_artifact_trees(checker, own_inputs):
    original_build(own_inputs)
    report = checker.rebuild_and_compare(**own_inputs)
    assert report["all_equal"] is True
    assert report["selection_equal"] is True
    assert report["preparation_comparison"]["all_equal"] is True
    assert report["neutral_comparison"]["all_equal"] is True
    assert report["checkpoint_verification"]["rebuild"]["members_verified"] == 4
    assert report["source_verification"]["verified"] is True
    assert report["rebuild_source_verification"]["verified"] is True
    assert all(row["crc_checked"] for row in report["rebuild_source_verification"]["archives"])
    assert set(report["input_files"]) == {"sources", "splits", "label_policy"}
    assert set(report["preparation_input_files"]) == {"scan_splits", "neutral_policy"}
    assert report["formal_model_runs"] == 0


def test_original_can_be_published_while_independent_build_runs(checker, own_inputs, monkeypatch):
    assert not own_inputs["cases_root"].exists()
    original_finalize = checker.finalize_dataset

    def both_publish(**kwargs):
        assert kwargs["data_root"] == own_inputs["rebuild_data_root"].resolve()
        assert kwargs["neutral_root"] == own_inputs["rebuild_neutral_root"].resolve()
        assert kwargs["splits"].is_relative_to(own_inputs["rebuild_data_root"])
        assert not own_inputs["cases_root"].exists()
        result = original_finalize(**kwargs)
        original_build(own_inputs)
        return result

    monkeypatch.setattr(checker, "finalize_dataset", both_publish)
    assert checker.rebuild_and_compare(**own_inputs)["all_equal"] is True


def test_waits_only_for_final_original_publication_after_own_rebuild(checker, own_inputs, monkeypatch):
    own_inputs["original_wait_seconds"] = 10
    waits = []

    def publish_after_poll(seconds):
        assert (own_inputs["rebuild_root"] / "selection.json").is_file()
        assert not own_inputs["cases_root"].exists()
        waits.append(seconds)
        original_build(own_inputs)

    monkeypatch.setattr(checker.time, "sleep", publish_after_poll)
    assert checker.rebuild_and_compare(**own_inputs)["all_equal"] is True
    assert len(waits) == 1


@pytest.mark.parametrize("alias", ["rebuild_data_root", "rebuild_prepared_root",
                                  "rebuild_preparation_checkpoints", "rebuild_neutral_root"])
def test_shared_or_nested_roots_fail_closed(checker, own_inputs, alias):
    own_inputs[alias] = own_inputs[alias.removeprefix("rebuild_")]
    with pytest.raises(ValueError, match="distinct|overlap|disjoint"):
        checker.rebuild_and_compare(**own_inputs)


@pytest.mark.parametrize("which", ["prepared_root", "rebuild_prepared_root", "neutral_root", "rebuild_neutral_root"])
def test_equal_declared_selection_cannot_hide_corrupt_artifact(checker, own_inputs, which):
    selection = read_json(own_inputs[which] / "selection.json")
    case = selection["cases"][0]
    path = own_inputs[which] / "test" / case["case_id"] / "agent/events.jsonl"
    path.write_bytes(path.read_bytes() + b"corrupt\n")
    with pytest.raises(ValueError, match="artifacts|artifact"):
        checker.rebuild_and_compare(**own_inputs)


def test_existing_copied_raw_bytes_are_actually_reverified(checker, own_inputs):
    path = own_inputs["rebuild_data_root"] / "system_logs_auditbeat.zip"
    with path.open("r+b") as stream:
        stream.write(b"damaged")
    with pytest.raises(ValueError, match="MD5|CRC|archive|SHA256"):
        checker.rebuild_and_compare(**own_inputs)
    assert not own_inputs["rebuild_root"].exists()


def test_swapped_independent_checkpoint_owner_is_rejected(checker, own_inputs, tmp_path):
    copied = tmp_path / "copied-checkpoints"
    shutil.copytree(own_inputs["preparation_checkpoints"], copied)
    own_inputs["rebuild_preparation_checkpoints"] = copied
    with pytest.raises(ValueError, match="checkpoint|owner"):
        checker.rebuild_and_compare(**own_inputs)


def test_corrupt_checkpoint_payload_is_rejected(checker, own_inputs):
    path = next(own_inputs["rebuild_preparation_checkpoints"].glob("member-*.json"))
    value = read_json(path)
    value["payload_sha256"] = "0" * 64
    path.write_text(canonical(value), encoding="utf-8")
    with pytest.raises(ValueError, match="checkpoint|payload"):
        checker.rebuild_and_compare(**own_inputs)


def test_missing_original_at_comparison_cannot_be_accepted(checker, own_inputs):
    with pytest.raises((OSError, ValueError, TimeoutError), match="selection|original"):
        checker.rebuild_and_compare(**own_inputs)
    assert (own_inputs["rebuild_root"] / "selection.json").is_file()


def test_original_artifact_corruption_after_second_build_is_detected(checker, own_inputs, monkeypatch):
    selection = original_build(own_inputs)
    original_finalize = checker.finalize_dataset

    def corrupt_original(**kwargs):
        result = original_finalize(**kwargs)
        path = own_inputs["cases_root"] / "test" / selection["cases"][0]["case_id"] / "agent/events.jsonl"
        path.write_bytes(b"corrupted final artifact")
        return result

    monkeypatch.setattr(checker, "finalize_dataset", corrupt_original)
    assert checker.rebuild_and_compare(**own_inputs)["all_equal"] is False


@pytest.mark.parametrize("target", ["source", "configuration", "checkpoint"])
def test_actual_inputs_changed_during_second_build_fail_closed(checker, own_inputs, monkeypatch, target):
    original_build(own_inputs)
    original_finalize = checker.finalize_dataset

    def change_input_after_build(**kwargs):
        result = original_finalize(**kwargs)
        if target == "source":
            path = own_inputs["data_root"] / "metadata.json"
        elif target == "configuration":
            path = own_inputs["splits"]
        else:
            path = next(own_inputs["rebuild_preparation_checkpoints"].glob("member-*.json"))
        path.write_bytes(path.read_bytes() + b" ")
        return result

    monkeypatch.setattr(checker, "finalize_dataset", change_input_after_build)
    with pytest.raises(ValueError, match="changed during"):
        checker.rebuild_and_compare(**own_inputs)


@pytest.mark.parametrize("destination", ["neutral_root", "rebuild_root", "rebuild_preparation_checkpoints"])
def test_cli_refuses_reports_inside_input_or_output_trees(checker, own_inputs, destination, monkeypatch):
    argv = []
    for name in (*checker.CONFIG_NAMES, *checker.ROOT_NAMES):
        argv.extend(["--" + name.replace("_", "-"), str(own_inputs[name])])
    argv.extend(["--output", str(own_inputs[destination] / "report.json")])
    monkeypatch.setattr(checker, "rebuild_and_compare", lambda **kwargs: pytest.fail("unsafe report path reached rebuild"))
    with pytest.raises(SystemExit) as error:
        checker.main(argv)
    assert error.value.code == 2
