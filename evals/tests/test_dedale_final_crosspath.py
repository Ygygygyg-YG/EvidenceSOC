"""Independent final curation must use its own verified raw preparation."""
from __future__ import annotations

import pytest

from evals.datasets.dedale.common import read_json, sha256, write_new


@pytest.fixture
def checker():
    try:
        from scripts import dedale_task12_final_crosspath
    except ImportError:
        pytest.fail("Independent v3 final rebuild has not been implemented")
    return dedale_task12_final_crosspath


def fixture(tmp_path):
    roots = {name: tmp_path / name for name in (
        "data_root", "rebuild_data_root", "cases_root", "rebuild_root",
        "prepared_root", "rebuild_prepared_root", "preparation_checkpoints",
        "rebuild_preparation_checkpoints",
    )}
    for name, path in roots.items():
        if name != "rebuild_root":
            path.mkdir()
    configs = {}
    for name in ("sources", "scan_splits", "splits", "label_policy"):
        path = tmp_path / (name + ".json")
        write_new(path, {"metadata_snapshot": {"path": "metadata.json"}}
                  if name == "sources" else {"name": name})
        configs[name] = path
    for root in (roots["data_root"], roots["rebuild_data_root"]):
        (root / "archive.zip").write_bytes(b"synthetic archive")
        (root / "metadata.json").write_bytes(b"synthetic metadata")
    verification = {
        "archives": [{"path": "archive.zip", "sha256": sha256(roots["data_root"] / "archive.zip")}],
        "metadata_sha256": sha256(roots["data_root"] / "metadata.json"),
    }
    for root in (roots["prepared_root"], roots["rebuild_prepared_root"]):
        write_new(root / "selection.json", {"status": "prepared_not_frozen", "cases": []})
    inputs = {name: sha256(configs[name]) for name in ("sources", "splits", "label_policy")}
    inputs["archive:archive.zip"] = verification["archives"][0]["sha256"]
    selection = {"protocol": "dedale-neutral-v3", "input_sha256": inputs,
                 "cases": [], "preparation_selection_sha256": sha256(roots["prepared_root"] / "selection.json")}
    write_new(roots["cases_root"] / "selection.json", selection)
    return roots, configs, verification, selection


def test_rebuilds_from_own_raw_and_preparation_before_comparison(checker, tmp_path, monkeypatch):
    roots, configs, verification, selection = fixture(tmp_path)
    calls = []
    monkeypatch.setattr(checker, "verify_sources", lambda sources, data_root: verification)

    def finalize(**kwargs):
        calls.append(kwargs)
        assert kwargs["data_root"] == roots["rebuild_data_root"].resolve()
        assert kwargs["prepared_root"] == roots["rebuild_prepared_root"].resolve()
        assert kwargs["preparation_checkpoints"] == roots["rebuild_preparation_checkpoints"].resolve()
        assert kwargs["scan_splits"].is_relative_to(roots["rebuild_data_root"])
        assert read_json(kwargs["splits"]) == read_json(configs["splits"])
        write_new(kwargs["output_root"] / "selection.json", selection)
        return selection

    monkeypatch.setattr(checker, "finalize_dataset", finalize)
    report = checker.rebuild_and_compare(**roots, **configs, workers=3)
    assert report["all_equal"] is True
    assert report["rebuild_mode"] == "independent-v2-full-scan-and-v3-targeted-raw-rescan"
    assert set(report["input_files"]) == {"sources", "splits", "label_policy"}
    assert set(report["preparation_input_files"]) == {"scan_splits"}
    assert len(calls) == 1
    assert calls[0]["workers"] == 3


@pytest.mark.parametrize("alias", ["rebuild_data_root", "rebuild_prepared_root", "rebuild_preparation_checkpoints"])
def test_rejects_shared_preparation_or_raw_roots(checker, tmp_path, alias):
    roots, configs, _, _ = fixture(tmp_path)
    roots[alias] = roots[alias.removeprefix("rebuild_")]
    with pytest.raises(ValueError, match="distinct|overlap"):
        checker.rebuild_and_compare(**roots, **configs)


def test_corrupt_copied_archive_stops_before_finalizing(checker, tmp_path, monkeypatch):
    roots, configs, verification, _ = fixture(tmp_path)
    (roots["rebuild_data_root"] / "archive.zip").write_bytes(b"damaged copy")
    monkeypatch.setattr(checker, "verify_sources", lambda *args: verification)
    monkeypatch.setattr(checker, "finalize_dataset", lambda **kwargs: pytest.fail("must not rebuild damaged bytes"))
    with pytest.raises(ValueError, match="SHA256|hash|copy"):
        checker.rebuild_and_compare(**roots, **configs)


def test_mismatched_original_policy_binding_cannot_report_success(checker, tmp_path, monkeypatch):
    roots, configs, verification, selection = fixture(tmp_path)
    selection["input_sha256"]["splits"] = "0" * 64
    (roots["cases_root"] / "selection.json").write_text(__import__("json").dumps(selection), encoding="utf-8")
    monkeypatch.setattr(checker, "verify_sources", lambda *args: verification)
    monkeypatch.setattr(checker, "finalize_dataset", lambda **kwargs: pytest.fail("must reject stale inputs"))
    with pytest.raises(ValueError, match="bound|binding"):
        checker.rebuild_and_compare(**roots, **configs)


def test_different_actual_preparation_files_stop_before_finalizing(checker, tmp_path, monkeypatch):
    roots, configs, _, _ = fixture(tmp_path)
    (roots["rebuild_prepared_root"] / "unexpected.json").write_bytes(b"unexpected copied data")
    monkeypatch.setattr(checker, "finalize_dataset", lambda **kwargs: pytest.fail("must reject mismatched v2"))
    with pytest.raises(ValueError, match="preparation.*artifacts"):
        checker.rebuild_and_compare(**roots, **configs)
