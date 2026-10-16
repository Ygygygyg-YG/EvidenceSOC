"""Pure byte-comparison checks; these fixtures are not a production rebuild."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts/dedale_task12_crosspath_check.py"
)


@pytest.fixture
def checker():
    if not SCRIPT.is_file():

        class MissingChecker:
            def __getattr__(self, name):
                pytest.fail(
                    "DEDALE cross-path artifact checker has not been implemented"
                )

        return MissingChecker()
    spec = importlib.util.spec_from_file_location("dedale_crosspath_check", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_tree(root):
    payloads = {
        "agent/events.jsonl": b'{"message":"Inventory completed."}\n',
        "agent/manifest.json": b'{"title":"Historical event review"}\n',
        "scoring/gold.jsonl": b'{"is_attack":false}\n',
        "scoring/source-gold.json": b'{"applicability":{"origin":false}}\n',
        "scoring/manifest.json": b'{"stage_review":"pending"}\n',
    }
    hashes = {}
    for relative, content in payloads.items():
        target = root / "test" / "dedale-example" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        hashes[relative] = hashlib.sha256(content).hexdigest()
    selection = {
        "schema_version": 1,
        "dataset_id": "dedale-v2.1",
        "N_D": 1,
        "M_D": 1,
        "cases": [{"case_id": "dedale-example", "split": "test", "artifacts": hashes}],
        "input_sha256": {
            "sources": "a" * 64,
            "splits": "b" * 64,
            "label_policy": "c" * 64,
        },
        "candidate_ledger": [{"reason": "selected_normal"}],
    }
    (root / "selection.json").write_text(
        json.dumps(selection, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "scan-summary.json").write_bytes(b'{"full_archive_scan":true}\n')
    return selection


def trees(tmp_path):
    original, rebuilt = tmp_path / "original", tmp_path / "another-absolute-root"
    selection = write_tree(original)
    assert write_tree(rebuilt) == selection
    return original, rebuilt, selection


def test_compares_every_case_artifact_and_side_file_across_absolute_roots(
    checker, tmp_path
):
    original, rebuilt, selection = trees(tmp_path)
    report = checker.compare_artifacts(original, rebuilt, selection)
    assert report["all_equal"] is True
    assert report["different_absolute_roots"] is True
    assert report["selection_equal"] is True
    assert report["original_cases_root"] == str(original.resolve())
    assert report["rebuild_cases_root"] == str(rebuilt.resolve())
    assert report["input_sha256"] == selection["input_sha256"]
    assert (
        report["selection_sha256"]
        == hashlib.sha256((original / "selection.json").read_bytes()).hexdigest()
    )
    rows = report["artifacts"]
    assert {
        row["relative_path"] for row in rows if row["case_id"] == "dedale-example"
    } == set(selection["cases"][0]["artifacts"])
    assert all(row["original_sha256"] == row["rebuild_sha256"] for row in rows)
    assert {row["relative_path"] for row in rows if row["case_id"] is None} == {
        "scan-summary.json"
    }


@pytest.mark.parametrize(
    "relative", ["agent/events.jsonl", "scoring/gold.jsonl", "scoring/manifest.json"]
)
def test_detects_modified_actual_artifact_even_when_selection_is_identical(
    checker, tmp_path, relative
):
    original, rebuilt, selection = trees(tmp_path)
    (rebuilt / "test/dedale-example" / relative).write_bytes(b"modified\n")
    report = checker.compare_artifacts(original, rebuilt, selection)
    assert report["selection_equal"] is True
    assert report["all_equal"] is False
    assert any(not row["equal"] for row in report["artifacts"])


def test_detects_same_tampering_in_both_roots_against_selection_hash(checker, tmp_path):
    original, rebuilt, selection = trees(tmp_path)
    for root in (original, rebuilt):
        (root / "test/dedale-example/agent/events.jsonl").write_bytes(
            b"same unexpected bytes\n"
        )
    report = checker.compare_artifacts(original, rebuilt, selection)
    assert report["all_equal"] is False


def test_detects_missing_and_extra_files(checker, tmp_path):
    original, rebuilt, selection = trees(tmp_path)
    (rebuilt / "test/dedale-example/scoring/gold.jsonl").unlink()
    (rebuilt / "extra-side.json").write_bytes(b"{}\n")
    report = checker.compare_artifacts(original, rebuilt, selection)
    assert report["all_equal"] is False
    assert any(row["rebuild_sha256"] is None for row in report["artifacts"])
    assert any(row["original_sha256"] is None for row in report["artifacts"])


def test_compares_full_selection_and_not_only_case_ids(checker, tmp_path):
    original, rebuilt, selection = trees(tmp_path)
    changed = {**selection, "candidate_ledger": [{"reason": "modified"}]}
    (rebuilt / "selection.json").write_text(json.dumps(changed), encoding="utf-8")
    report = checker.compare_artifacts(original, rebuilt, selection)
    assert report["selection_equal"] is False
    assert report["all_equal"] is False


def test_detects_side_file_tampering(checker, tmp_path):
    original, rebuilt, selection = trees(tmp_path)
    (rebuilt / "scan-summary.json").write_bytes(b"changed\n")
    assert checker.compare_artifacts(original, rebuilt, selection)["all_equal"] is False


def test_same_absolute_root_cannot_prove_cross_path_rebuild(checker, tmp_path):
    root = tmp_path / "same"
    selection = write_tree(root)
    report = checker.compare_artifacts(root, root, selection)
    assert report["different_absolute_roots"] is False
    assert report["all_equal"] is False


def test_rejects_traversal_from_selection_artifact_paths(checker, tmp_path):
    original, rebuilt, selection = trees(tmp_path)
    selection["cases"][0]["artifacts"]["../../outside.json"] = "d" * 64
    report = checker.compare_artifacts(original, rebuilt, selection)
    assert report["all_equal"] is False
    assert report["errors"]


def test_binds_archive_and_config_hashes_from_complete_scan(checker):
    manifests = {"sources": "a" * 64, "splits": "b" * 64, "label_policy": "c" * 64}
    verification = {
        "archives": [{"path": "system_logs_auditbeat.zip", "sha256": "d" * 64}]
    }
    expected = {**manifests, "archive:system_logs_auditbeat.zip": "d" * 64}
    assert (
        checker._bind_input_hashes({"input_sha256": expected}, manifests, verification)
        == expected
    )


@pytest.mark.parametrize("archive_hash", [None, "e" * 64])
def test_rejects_missing_or_changed_archive_input_binding(checker, archive_hash):
    manifests = {"sources": "a" * 64}
    verification = {
        "archives": [{"path": "system_logs_auditbeat.zip", "sha256": "d" * 64}]
    }
    declared = dict(manifests)
    if archive_hash is not None:
        declared["archive:system_logs_auditbeat.zip"] = archive_hash
    with pytest.raises(ValueError, match="bound"):
        checker._bind_input_hashes({"input_sha256": declared}, manifests, verification)


@pytest.mark.parametrize("complete_original", [True, False])
@pytest.mark.parametrize("reuse_sources", [True, False])
def test_parallel_rebuild_requires_completed_original_before_success(
    checker, tmp_path, monkeypatch, complete_original, reuse_sources
):
    """Synthetic I/O only: the production verifier has no bypass option."""
    from evals.datasets.dedale import scan

    raw = tmp_path / "raw"
    raw.mkdir()
    archive = raw / "system_logs_auditbeat.zip"
    archive.write_bytes(b"synthetic source bytes\n")
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    metadata = raw / "metadata.json"
    metadata.write_bytes(b"synthetic metadata\n")
    configs = {}
    for name in ("sources", "splits", "label_policy"):
        path = tmp_path / f"{name}.json"
        value = {"metadata_snapshot": {
            "path": "metadata.json",
            "sha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
        }} if name == "sources" else {"synthetic": name}
        path.write_text(json.dumps(value), encoding="utf-8")
        configs[name] = path
    expected = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in configs.items()}
    expected["archive:system_logs_auditbeat.zip"] = archive_hash
    verification = {"archives": [{
        "path": archive.name, "sha256": archive_hash,
    }]}
    monkeypatch.setattr(checker, "verify_sources", lambda *args: verification)
    original, rebuilt = tmp_path / "original", tmp_path / "rebuild"
    copied_raw = tmp_path / "copied-raw"
    checkpoints = tmp_path / "rebuild-checkpoints"
    if reuse_sources:
        copied_raw.mkdir()
        (copied_raw / archive.name).write_bytes(archive.read_bytes())
        (copied_raw / metadata.name).write_bytes(metadata.read_bytes())
        (copied_raw / "crosspath-inputs").mkdir()
        for name, path in configs.items():
            (copied_raw / f"crosspath-inputs/{name}.json").write_bytes(path.read_bytes())

    def prepare(**kwargs):
        assert kwargs["late_projection"] is True
        assert kwargs["workers"] == 3
        assert kwargs["checkpoint_root"] == checkpoints.resolve()
        assert not (original / "selection.json").exists()
        assert (kwargs["data_root"] / archive.name).read_bytes() == archive.read_bytes()
        selection = write_tree(kwargs["output_root"])
        selection["input_sha256"] = expected
        (kwargs["output_root"] / "selection.json").write_text(
            json.dumps(selection, sort_keys=True) + "\n", encoding="utf-8"
        )
        if complete_original:
            write_tree(original)
            (original / "selection.json").write_text(
                json.dumps(selection, sort_keys=True) + "\n", encoding="utf-8"
            )
        return selection

    monkeypatch.setattr(scan, "prepare_dataset", prepare)
    kwargs = {
        **configs, "data_root": raw, "cases_root": original,
        "rebuild_root": rebuilt, "rebuild_data_root": copied_raw,
        "workers": 3, "late_projection": True, "checkpoint_root": checkpoints,
        "reuse_copied_sources": reuse_sources,
    }
    if complete_original:
        report = checker.rebuild_and_compare(**kwargs)
        assert report["all_equal"]
        assert report["input_sha256"] == expected
        assert report["rebuild_mode"] == "full-copy-and-full-archive-scan"
        assert report["source_copy_mode"] == ("reverified-existing-copy" if reuse_sources else "new-copy")
    else:
        with pytest.raises(FileNotFoundError):
            checker.rebuild_and_compare(**kwargs)


def test_existing_copy_requires_explicit_reverification_and_exact_bytes(checker, tmp_path):
    original, copied = tmp_path / "original.bin", tmp_path / "copy.bin"
    original.write_bytes(b"expected bytes\n")
    digest = hashlib.sha256(original.read_bytes()).hexdigest()
    checker._copy_or_reverify(original, copied, digest, reuse=False)
    with pytest.raises(FileExistsError):
        checker._copy_or_reverify(original, copied, digest, reuse=False)
    assert checker._copy_or_reverify(original, copied, digest, reuse=True)["sha256"] == digest
    copied.write_bytes(b"corrupted existing bytes\n")
    with pytest.raises(ValueError, match="existing copied source SHA256 mismatch"):
        checker._copy_or_reverify(original, copied, digest, reuse=True)
    assert copied.read_bytes() == b"corrupted existing bytes\n"
