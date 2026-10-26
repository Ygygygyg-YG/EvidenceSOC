"""Synthetic portable packages; original artifacts are never executed."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.adapters.analysis_import import (
    validation_source_hashes,
    verify_analysis_source,
)
from evals.tests.test_analysis_import import artifact_source, change


def anchored_source(root, **kwargs):
    anchor = artifact_source(root, **kwargs)
    (root / "source-anchor.json").write_text(
        json.dumps(anchor.model_dump(mode="json"), indent=2), encoding="utf-8"
    )
    return anchor


def export(root, destination):
    from evals.adapters.analysis_package import export_portable_analysis_package

    return export_portable_analysis_package(anchored_source(root), destination)


def rebind_manifest(root, edit):
    path = root / "manifest.json"
    value = json.loads(path.read_bytes())
    edit(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    return sha256(path.read_bytes()).hexdigest()


def rewrite_ref(root, ref, value):
    raw = json.dumps(value).encode()
    (root / ref["path"]).write_bytes(raw)
    ref.update(size=len(raw), sha256=sha256(raw).hexdigest())


def rebind_lineage(package, edit):
    """Rebind all outer hashes to exercise replay instead of byte mismatch."""
    manifest = json.loads((package / "manifest.json").read_bytes())
    lineage = manifest["lineage"]
    original = json.loads((package / lineage["original_manifest"]["path"]).read_bytes())
    anchor = json.loads((package / lineage["original_anchor"]["path"]).read_bytes())
    edit(manifest, original, anchor)
    rewrite_ref(package, lineage["original_manifest"], original)
    anchor["manifest_sha256"] = lineage["original_manifest"]["sha256"]
    rewrite_ref(package, lineage["original_anchor"], anchor)
    return rebind_manifest(package, lambda value: value.update(manifest))


def test_exports_exact_bytes_and_replays_after_original_removed_and_package_moved(
    tmp_path,
):
    from evals.adapters.analysis_package import verify_portable_analysis_package

    original, package = tmp_path / "original", tmp_path / "package"
    anchor = anchored_source(original)
    v1 = json.loads((original / "manifest.json").read_bytes())
    expected = verify_analysis_source(anchor)
    from evals.adapters.analysis_package import export_portable_analysis_package

    receipt = export_portable_analysis_package(anchor, package)
    manifest = json.loads((package / "manifest.json").read_bytes())
    assert manifest["schema_version"] == "task13-analysis-artifacts-v2"
    assert manifest["validation_source_sha256"] == validation_source_hashes()
    for name, ref in manifest["artifacts"].items():
        assert (package / ref["path"]).read_bytes() == __import__("pathlib").Path(
            v1["artifacts"][name]["path"]
        ).read_bytes()
    for key, source in (
        ("original_anchor", "source-anchor.json"),
        ("original_manifest", "manifest.json"),
    ):
        assert (package / manifest["lineage"][key]["path"]).read_bytes() == (
            original / source
        ).read_bytes()
    moved = tmp_path / "moved"
    package.rename(moved)
    shutil.rmtree(original)
    actual = verify_portable_analysis_package(moved, receipt["manifest_sha256"])
    assert actual.source_identity == expected.source_identity
    assert actual.provenance["manifest_sha256"] == anchor.manifest_sha256
    assert (
        actual.provenance["source_package_manifest_sha256"]
        == receipt["manifest_sha256"]
    )
    assert (
        actual.provenance["analysis_output_sha256"]
        == expected.provenance["analysis_output_sha256"]
    )
    actual.revalidate()


def test_refreshes_stale_replay_hash_only_in_new_package(tmp_path):
    from evals.adapters.analysis_package import (
        export_portable_analysis_package,
        verify_portable_analysis_package,
    )

    root = tmp_path / "original"
    anchor = anchored_source(root)
    manifest = json.loads((root / "manifest.json").read_bytes())
    manifest["validation_source_sha256"]["artifact_verifier"] = "a" * 64
    raw = json.dumps(manifest).encode()
    (root / "manifest.json").write_bytes(raw)
    anchor = anchor.model_copy(update={"manifest_sha256": sha256(raw).hexdigest()})
    (root / "source-anchor.json").write_text(
        json.dumps(anchor.model_dump()), encoding="utf-8"
    )
    before = {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    }
    with pytest.raises(ValueError, match="source drift"):
        verify_analysis_source(anchor)
    receipt = export_portable_analysis_package(anchor, tmp_path / "new")
    verify_portable_analysis_package(tmp_path / "new", receipt["manifest_sha256"])
    assert before == {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    }


@pytest.mark.parametrize(
    "relative",
    [
        "",
        ".",
        "../seed.json",
        "a/../seed.json",
        "/seed.json",
        "C:/seed.json",
        "a\\seed.json",
        "a//seed.json",
        "./seed.json",
        "seed.json/",
        "C:seed.json",
    ],
)
def test_rejects_noncanonical_or_escaping_relative_paths(tmp_path, relative):
    from evals.adapters.analysis_package import verify_portable_analysis_package

    package = tmp_path / "package"
    export(tmp_path / "original", package)
    digest = rebind_manifest(
        package, lambda v: v["artifacts"]["seed"].update(path=relative)
    )
    with pytest.raises(ValueError):
        verify_portable_analysis_package(package, digest)


@pytest.mark.parametrize(
    "kind",
    [
        "extra",
        "missing",
        "tamper",
        "duplicate",
        "analysis_hash",
        "old_manifest",
        "old_anchor",
    ],
)
def test_rejects_inventory_tamper_and_false_lineage(tmp_path, kind):
    from evals.adapters.analysis_package import verify_portable_analysis_package

    package = tmp_path / "package"
    receipt = export(tmp_path / "original", package)
    digest = receipt["manifest_sha256"]
    manifest = json.loads((package / "manifest.json").read_bytes())
    seed = package / manifest["artifacts"]["seed"]["path"]
    if kind == "extra":
        (package / "unlisted.json").write_text("{}")
    elif kind == "missing":
        seed.unlink()
    elif kind == "tamper":
        seed.write_bytes(seed.read_bytes() + b" ")
    elif kind == "duplicate":
        digest = rebind_manifest(
            package, lambda v: v["artifacts"]["seed"].update(v["artifacts"]["registry"])
        )
    elif kind == "analysis_hash":
        digest = rebind_manifest(
            package, lambda v: v.update(source_analysis_output_sha256="f" * 64)
        )
    else:
        key = "original_manifest" if kind == "old_manifest" else "original_anchor"
        target = package / manifest["lineage"][key]["path"]
        target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises((ValueError, OSError)):
        verify_portable_analysis_package(package, digest)


def test_revalidate_rejects_later_extra_file(tmp_path):
    from evals.adapters.analysis_package import verify_portable_analysis_package

    package = tmp_path / "package"
    receipt = export(tmp_path / "original", package)
    source = verify_portable_analysis_package(package, receipt["manifest_sha256"])
    (package / "extra").write_text("x")
    with pytest.raises(ValueError):
        source.revalidate()


def test_export_refuses_invalid_original_reply_and_never_overwrites_destination(
    tmp_path,
):
    from evals.adapters.analysis_package import export_portable_analysis_package

    root = tmp_path / "original"
    anchor = anchored_source(root, original_reject=True)
    with pytest.raises(ValueError, match="original validator"):
        export_portable_analysis_package(anchor, tmp_path / "rejected")
    package = tmp_path / "existing"
    package.mkdir()
    with pytest.raises((ValueError, FileExistsError)):
        export_portable_analysis_package(anchored_source(tmp_path / "valid"), package)


def test_rejects_forged_original_result_even_after_all_outer_hashes_rebound(tmp_path):
    from evals.adapters.analysis_package import export_portable_analysis_package

    root = tmp_path / "original"
    anchor = artifact_source(root)
    anchor = change(
        anchor,
        "result",
        lambda v: v["diagnostic_snapshot"]["diagnosis"].update(verdict="benign"),
        rebind=True,
    )
    (root / "source-anchor.json").write_text(
        json.dumps(anchor.model_dump()), encoding="utf-8"
    )
    with pytest.raises(ValueError):
        export_portable_analysis_package(anchor, tmp_path / "package")


def test_rejects_multiple_hardlinks(tmp_path):
    from evals.adapters.analysis_package import verify_portable_analysis_package

    package = tmp_path / "package"
    receipt = export(tmp_path / "original", package)
    manifest = json.loads((package / "manifest.json").read_bytes())
    (tmp_path / "alias").hardlink_to(package / manifest["artifacts"]["seed"]["path"])
    with pytest.raises(ValueError, match="regular file"):
        verify_portable_analysis_package(package, receipt["manifest_sha256"])


def test_retains_original_source_path_binding_even_if_lineage_is_rehashed(tmp_path):
    from evals.adapters.analysis_package import verify_portable_analysis_package

    package = tmp_path / "package"
    export(tmp_path / "original", package)

    def edit(manifest, original, anchor):
        key = "original_source:evals/adapters/seed.py"
        original["artifacts"][key]["path"] = str(
            Path(anchor["root"]) / "substituted" / "seed.py"
        )

    digest = rebind_lineage(package, edit)
    with pytest.raises(ValueError, match="original source path binding"):
        verify_portable_analysis_package(package, digest)


@pytest.mark.parametrize(
    "artifact",
    ["body_1", "seed", "registry", "knowledge", "condition", "result", "row", "bundle"],
)
def test_replays_semantics_after_every_outer_artifact_hash_is_refreshed(
    tmp_path, artifact
):
    from evals.adapters.analysis_package import verify_portable_analysis_package

    package = tmp_path / "package"
    export(tmp_path / "original", package)

    def edit(manifest, original, anchor):
        ref = manifest["artifacts"][artifact]
        value = json.loads((package / ref["path"]).read_bytes())
        if artifact == "body_1":
            value["messages"][-1]["content"] = "{}"
        elif artifact == "seed":
            value["evidence"][0]["raw"]["host"] = "another-host"
        elif artifact == "registry":
            next(iter(value.values()))["case_id"] = "ait-" + "1" * 24
        elif artifact == "knowledge":
            value.append({"knowledge_chunk_id": "KC-not-actual-context"})
        elif artifact == "condition":
            value["entry_schema_sha256"] = "f" * 64
        elif artifact == "result":
            value["diagnostic_snapshot"]["diagnosis"]["verdict"] = "benign"
        elif artifact == "row":
            value["case_id"] = "ait-" + "1" * 24
        else:
            value["rows"].reverse()
        rewrite_ref(package, ref, value)
        original["artifacts"][artifact].update(size=ref["size"], sha256=ref["sha256"])

    digest = rebind_lineage(package, edit)
    with pytest.raises(ValueError):
        verify_portable_analysis_package(package, digest)


def test_old_unmanifested_bundle_gets_separate_lineage_without_changing_v1(tmp_path):
    from evals.adapters.analysis_package import (
        export_portable_analysis_package,
        verify_portable_analysis_package,
    )

    original = tmp_path / "original"
    anchor = anchored_source(original)
    manifest = json.loads((original / "manifest.json").read_bytes())
    bundle = Path(manifest["artifacts"].pop("bundle")["path"])
    (original / "original-bundle36.json").write_bytes(bundle.read_bytes())
    raw = json.dumps(manifest).encode()
    (original / "manifest.json").write_bytes(raw)
    anchor = anchor.model_copy(update={"manifest_sha256": sha256(raw).hexdigest()})
    (original / "source-anchor.json").write_text(
        json.dumps(anchor.model_dump()), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="provenance incomplete"):
        verify_analysis_source(anchor)
    receipt = export_portable_analysis_package(anchor, tmp_path / "package")
    verify_portable_analysis_package(tmp_path / "package", receipt["manifest_sha256"])
    assert (original / "manifest.json").read_bytes() == raw


@pytest.mark.parametrize("kind", ["symlink", "junction", "root-junction"])
def test_rejects_links_and_junctions_even_to_identical_bytes(tmp_path, kind):
    from evals.adapters.analysis_package import verify_portable_analysis_package

    package = tmp_path / "package"
    receipt = export(tmp_path / "original", package)
    manifest = json.loads((package / "manifest.json").read_bytes())
    target = package / manifest["artifacts"]["events"]["path"]
    if kind == "symlink":
        copy = tmp_path / "same-events.jsonl"
        copy.write_bytes(target.read_bytes())
        target.unlink()
        try:
            target.symlink_to(copy)
        except OSError as error:
            if getattr(error, "winerror", None) != 1314:
                raise
            pytest.skip(
                "native symlink creation needs an unavailable Windows privilege"
            )
    else:
        if os.name != "nt":
            link = (
                tmp_path / "linked-root" if kind == "root-junction" else target.parent
            )
            if kind == "junction":
                target.parent.rename(tmp_path / "same-agent")
            link.symlink_to(
                package if kind == "root-junction" else tmp_path / "same-agent",
                target_is_directory=True,
            )
        else:
            if kind == "junction":
                target.parent.rename(tmp_path / "same-agent")
            link = (
                tmp_path / "linked-root" if kind == "root-junction" else target.parent
            )
            subprocess.run(
                [
                    "cmd",
                    "/c",
                    "mklink",
                    "/J",
                    str(link),
                    str(
                        package if kind == "root-junction" else tmp_path / "same-agent"
                    ),
                ],
                check=True,
                capture_output=True,
            )
        if kind == "root-junction":
            package = link
    with pytest.raises(ValueError, match="link|reparse"):
        verify_portable_analysis_package(package, receipt["manifest_sha256"])


def test_symlink_mode_is_rejected_before_any_target_can_be_read(tmp_path, monkeypatch):
    from evals.adapters.analysis_package import _no_link

    path = tmp_path / "synthetic-symlink"
    real_lstat = Path.lstat

    def lstat(value, *args, **kwargs):
        if value == path:
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_file_attributes=0)
        return real_lstat(value, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ValueError, match="link|reparse"):
        _no_link(path)


def test_rejects_validly_hashed_original_python_without_executing_it(
    tmp_path, monkeypatch
):
    from evals.adapters.analysis_package import export_portable_analysis_package

    project_root = Path(__file__).resolve().parents[2]
    nodes = project_root / "services/backend/src/evidencesoc/agents/nodes/__init__.py"
    marker = tmp_path / "artifact-was-executed"
    side_effect = (
        "\n__import__('pathlib').Path("
        + repr(str(marker))
        + ").write_text('executed')\n"
    ).encode()
    real_read = Path.read_bytes

    def source_bytes(path):
        return real_read(path) + (side_effect if path == nodes else b"")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_bytes", source_bytes)
        anchor = anchored_source(tmp_path / "original")
    with pytest.raises(ValueError, match="original validator is not equivalent"):
        export_portable_analysis_package(anchor, tmp_path / "package")
    assert not marker.exists()


@pytest.mark.parametrize(
    "kind",
    [
        "empty-directory",
        "duplicate-json-member",
        "package-verifier",
        "source-receipt-path",
    ],
)
def test_rejects_additional_inventory_and_replay_identity_forgery(tmp_path, kind):
    from evals.adapters.analysis_package import verify_portable_analysis_package

    package = tmp_path / "package"
    receipt = export(tmp_path / "original", package)
    digest = receipt["manifest_sha256"]
    if kind == "empty-directory":
        (package / "unlisted-directory").mkdir()
    elif kind == "duplicate-json-member":
        path = package / "manifest.json"
        path.write_bytes(b'{"order_index": 0,' + path.read_bytes()[1:])
        digest = sha256(path.read_bytes()).hexdigest()
    elif kind == "package-verifier":
        digest = rebind_manifest(
            package, lambda v: v.update(package_verifier_sha256="f" * 64)
        )
    else:
        manifest = json.loads((package / "manifest.json").read_bytes())
        ref = manifest["artifacts"]["source_receipt"]
        (package / "artifacts" / "source_receipt.json").write_bytes(
            (package / ref["path"]).read_bytes()
        )
        (package / ref["path"]).unlink()
        digest = rebind_manifest(
            package,
            lambda v: v["artifacts"]["source_receipt"].update(
                path="artifacts/source_receipt.json"
            ),
        )
    with pytest.raises(ValueError):
        verify_portable_analysis_package(package, digest)
