import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def cli_module():
    path = (
        Path(__file__).resolve().parents[2] / "scripts/ait_task12_portable_rebuild.py"
    )
    spec = importlib.util.spec_from_file_location("portable_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verified_copy_checks_expected_hash_before_writing(tmp_path):
    cli = cli_module()
    source = tmp_path / "source.bin"
    source.write_bytes(b"verified input")
    destination = tmp_path / "destination.bin"
    with pytest.raises(ValueError, match="hash"):
        cli.copy_verified_file(source, destination, "0" * 64)
    assert not destination.exists()
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    cli.copy_verified_file(source, destination, expected)
    assert destination.read_bytes() == source.read_bytes()
    source.write_bytes(b"different input")
    with pytest.raises(ValueError, match="hash"):
        cli.copy_verified_file(source, destination, expected)
    assert destination.read_bytes() == b"verified input"


def test_portable_source_manifest_rejects_changed_copied_input(tmp_path):
    cli = cli_module()
    source = tmp_path / "archive.zip"
    source.write_bytes(b"archive fixture")
    value = {
        "schema_version": 1,
        "path_base": "data_root",
        "files": {
            "archive.zip": {
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "bytes": source.stat().st_size,
            }
        },
    }
    cli.verify_inputs(value, tmp_path)
    source.write_bytes(b"corrupt fixture")
    with pytest.raises(ValueError, match="hash"):
        cli.verify_inputs(value, tmp_path)


def test_rebuild_regenerates_selection_and_compares_it_to_freeze(tmp_path, monkeypatch):
    cli = cli_module()
    frozen, relocated = tmp_path / "frozen", tmp_path / "relocated"
    frozen.mkdir()
    relocated.mkdir()
    case = frozen / "ait/cases/test/ait-000000000000000000000000"
    for artifact in cli.ARTIFACTS:
        path = case / artifact
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact, encoding="utf-8")
    selection = "manifests/selection.json"
    value = {
        "split": "test",
        "cases": [
            {
                "case_id": case.name,
                "scoring_manifest_sha256": cli.sha256(case / "scoring/manifest.json"),
                "agent_manifest_sha256": cli.sha256(case / "agent/manifest.json"),
                "rebuild_verified": True,
            }
        ],
    }
    cli.write_new(frozen / selection, cli.json_bytes(value))
    cli.write_new(frozen / cli.INPUT_MANIFEST, b"{}")
    taxonomy = SimpleNamespace(
        _data_root=lambda path: Path(path),
        _resolve_reference=lambda path, root: root / path,
    )

    def rebuild_case(*, manifest, output_dir, data_root):
        assert data_root == relocated
        for artifact in cli.ARTIFACTS:
            cli.write_new(output_dir / artifact, (case / artifact).read_bytes())

    monkeypatch.setattr(
        cli,
        "load_builder",
        lambda: SimpleNamespace(_taxonomy=taxonomy, rebuild_case=rebuild_case),
    )
    monkeypatch.setattr(cli, "verify_inputs", lambda value, root: None)
    report = tmp_path / "report.json"
    cli.rebuild(
        data_root=relocated, frozen_root=frozen, selection=selection, report=report
    )
    assert (relocated / selection).read_bytes() == (frozen / selection).read_bytes()
    proof = json.loads(report.read_bytes())
    assert proof["selection_identical"] is True
    assert proof["relocated_selection_sha256"] == cli.sha256(frozen / selection)


@pytest.mark.parametrize("command", ["freeze", "rebuild"])
@pytest.mark.parametrize(
    "changed", [{"split": "../../outside"}, {"case_id": "../outside"}]
)
def test_selection_cannot_control_paths_outside_data_root(
    tmp_path, monkeypatch, command, changed
):
    cli = cli_module()
    frozen, relocated = tmp_path / "frozen", tmp_path / "relocated"
    frozen.mkdir()
    relocated.mkdir()
    value = {
        "split": "test",
        "cases": [{"case_id": "ait-" + "0" * 24, "scenario": "shaw", **changed}],
    }
    selection = "manifests/selection.json"
    for root in (frozen, relocated):
        cli.write_new(root / selection, cli.json_bytes(value))
        cli.write_new(root / cli.INPUT_MANIFEST, b"{}")
    monkeypatch.setattr(cli, "verify_inputs", lambda value, root: None)
    with pytest.raises(ValueError, match="selection"):
        if command == "freeze":
            cli.freeze(data_root=relocated, selection=selection, report=tmp_path / "r")
        else:
            cli.rebuild(
                data_root=relocated,
                frozen_root=frozen,
                selection=selection,
                report=tmp_path / "r",
            )
    assert not (tmp_path / "outside").exists()
