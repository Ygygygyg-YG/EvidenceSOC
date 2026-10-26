"""Relocatable, exact-inventory replay of immutable original analysis bytes.

Original absolute paths are provenance only. No copied Python is imported or
executed; source equivalence and replay use the controlled local implementation.
"""

from __future__ import annotations

import json
import re
import stat
from hashlib import sha256
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal

from evidencesoc.agents.analysis_import import ImportedAnalysis
from pydantic import Field

from evals.adapters.analysis_import import (
    AnalysisArtifactManifest,
    Artifact,
    SourceAnchor,
    _read_original_artifacts,
    _regular,
    _verify_artifact_blobs,
    validation_source_hashes,
)
from evals.contracts import SHA256, Contract


class PackageLineage(Contract):
    original_anchor: Artifact
    original_manifest: Artifact
    # Older immutable v1 manifests omitted their separately saved bundle. This
    # optional original byte file is still bound by the anchor's canonical hash.
    original_bundle: Artifact | None = None


class PortableAnalysisManifest(Contract):
    schema_version: Literal["task13-analysis-artifacts-v2"]
    order_index: int = Field(ge=0, le=35)
    source_row_id: str
    successful_physical_request_id: str
    validation_source_sha256: dict[str, str]
    package_verifier_sha256: str = Field(pattern=SHA256)
    source_analysis_output_sha256: str = Field(pattern=SHA256)
    artifacts: dict[str, Artifact]
    lineage: PackageLineage


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique)


def _parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("a canonical POSIX relative artifact path is required")
    parts = relative.split("/")
    for part in parts:
        if (
            part in {"", ".", ".."}
            or part.rstrip(". ") != part
            or any(ord(c) < 32 or c in '<>:"|?*' for c in part)
            or part.split(".")[0].upper()
            in {
                "CON",
                "PRN",
                "AUX",
                "NUL",
                *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10)),
            }
        ):
            raise ValueError("a canonical portable relative artifact path is required")
    return tuple(parts)


def _no_link(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("links/reparse points are forbidden")
    return info


def _root(root: Path) -> Path:
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("an absolute package root is required")
    for path in (root, *root.parents):
        _no_link(path)
    if not root.is_dir():
        raise ValueError("package root must be a directory")
    return root.resolve(strict=True)


def _resolve(root, relative):
    path = root.joinpath(*_parts(relative))
    for part in (path, *path.parents):
        _no_link(part)
    info = path.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or not path.resolve(strict=True).is_relative_to(root)
    ):
        raise ValueError("artifact must be a single regular file within package")
    return path


def _read_ref(root, ref):
    path = _resolve(root, ref.path)
    raw = path.read_bytes()
    if len(raw) != ref.size or sha256(raw).hexdigest() != ref.sha256:
        raise ValueError("package artifact hash or size differs: " + ref.path)
    return path, raw


def _inventory(root, refs):
    expected = {"manifest.json"}
    identities = {"manifest.json"}
    for ref in refs:
        _parts(ref.path)
        if ref.path.casefold() in identities:
            raise ValueError("duplicate package artifact path")
        identities.add(ref.path.casefold())
        expected.add(ref.path)
    directories = {
        "/".join(parts[:index])
        for path in expected
        for parts in [_parts(path)]
        for index in range(1, len(parts))
    }
    actual = set()

    def visit(parent):
        for path in parent.iterdir():
            info = _no_link(path)
            relative = path.relative_to(root).as_posix()
            _parts(relative)
            if stat.S_ISDIR(info.st_mode):
                if relative not in directories:
                    raise ValueError("extra package directory")
                visit(path)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                actual.add(relative)
            else:
                raise ValueError("package entry must be a single regular file")

    visit(root)
    if actual != expected:
        raise ValueError("package has missing or extra inventory")


def _original_path_bindings(anchor, manifest):
    """Check old host path relationships as metadata, without opening them."""
    path_type = (
        PureWindowsPath if PureWindowsPath(anchor.root).is_absolute() else PurePosixPath
    )
    original_root = path_type(anchor.root)
    if not original_root.is_absolute() or ".." in original_root.parts:
        raise ValueError("original source root binding differs")
    for value in [
        anchor.manifest_path,
        *(ref.path for ref in manifest.artifacts.values()),
    ]:
        path = path_type(value)
        if (
            not path.is_absolute()
            or ".." in path.parts
            or not path.is_relative_to(original_root)
        ):
            raise ValueError("original artifact path binding differs")
    receipt = manifest.artifacts.get("source_receipt")
    if receipt is None:
        raise ValueError("original validator source export missing")
    source_root = path_type(receipt.path).parent
    for name, ref in manifest.artifacts.items():
        if name.startswith("original_source:"):
            parts = _parts(name.removeprefix("original_source:"))
            if path_type(ref.path) != source_root.joinpath(*parts):
                raise ValueError("original source path binding differs")


def _verify(root, manifest_sha256):
    root = _root(root)
    manifest_path = _resolve(root, "manifest.json")
    raw = manifest_path.read_bytes()
    if sha256(raw).hexdigest() != manifest_sha256:
        raise ValueError("package manifest hash differs")
    manifest = PortableAnalysisManifest.model_validate(_json(raw))
    if (
        manifest.validation_source_sha256 != validation_source_hashes()
        or manifest.package_verifier_sha256
        != sha256(Path(__file__).read_bytes()).hexdigest()
    ):
        raise ValueError("portable replay validator source drift")
    refs = list(manifest.artifacts.values()) + [
        manifest.lineage.original_anchor,
        manifest.lineage.original_manifest,
    ]
    if manifest.lineage.original_bundle is not None:
        refs.append(manifest.lineage.original_bundle)
    _inventory(root, refs)
    _, anchor_raw = _read_ref(root, manifest.lineage.original_anchor)
    _, original_raw = _read_ref(root, manifest.lineage.original_manifest)
    anchor = SourceAnchor.model_validate(_json(anchor_raw))
    original = AnalysisArtifactManifest.model_validate(_json(original_raw))
    if (
        anchor.manifest_sha256 != manifest.lineage.original_manifest.sha256
        or anchor.source_row_id != original.source_row_id
        or anchor.order_index != original.order_index
        or original.source_row_id != manifest.source_row_id
        or original.order_index != manifest.order_index
        or original.successful_physical_request_id
        != manifest.successful_physical_request_id
        or original.artifacts.keys() != manifest.artifacts.keys()
    ):
        raise ValueError("original anchor/manifest lineage binding differs")
    _original_path_bindings(anchor, original)
    paths, blobs = {}, {}
    for name, ref in manifest.artifacts.items():
        old = original.artifacts[name]
        if (ref.size, ref.sha256) != (old.size, old.sha256):
            raise ValueError("package artifact differs from immutable original lineage")
        paths[name], blobs[name] = _read_ref(root, ref)
    if manifest.lineage.original_bundle is not None:
        if "bundle" in blobs:
            raise ValueError("duplicate original bundle provenance")
        paths["bundle"], blobs["bundle"] = _read_ref(
            root, manifest.lineage.original_bundle
        )
    required = {
        "row",
        "request",
        "bundle",
        "started",
        "attempt",
        "result",
        "stdout",
        "seed",
        "registry",
        "events",
        "knowledge",
        "condition",
        "source_receipt",
    }
    if not required <= blobs.keys():
        raise ValueError("original artifact provenance incomplete")
    # load_seed has an intentional fixed filename. Do not allow an unlisted
    # sibling to supply bytes other than the already verified events artifact.
    if paths["events"].name != "events.jsonl":
        raise ValueError("original events must retain the fixed seed filename")
    values, provenance = _verify_artifact_blobs(
        anchor, original, blobs, artifact_paths=paths
    )
    if manifest.source_analysis_output_sha256 != provenance["analysis_output_sha256"]:
        raise ValueError("source analysis output differs from actual successful reply")
    provenance = {
        **provenance,
        "source_package_schema_version": manifest.schema_version,
        "source_package_manifest_sha256": manifest_sha256,
        "source_package_validation_source_sha256": manifest.validation_source_sha256,
        "source_package_verifier_sha256": manifest.package_verifier_sha256,
        "original_anchor_sha256": manifest.lineage.original_anchor.sha256,
        "original_anchor_size": manifest.lineage.original_anchor.size,
        "original_manifest_sha256": anchor.manifest_sha256,
        "original_manifest_size": manifest.lineage.original_manifest.size,
    }
    return values, provenance


def verify_portable_analysis_package(
    root: Path, manifest_sha256: str
) -> ImportedAnalysis:
    """Re-read the entire package and independently replay the original reply."""
    root = Path(root)
    if not re.fullmatch(SHA256, manifest_sha256):
        raise ValueError("a SHA256 package manifest binding is required")
    values, provenance = _verify(root, manifest_sha256)
    return ImportedAnalysis._from_verified_artifacts(
        values, provenance, lambda: _verify(root, manifest_sha256)
    )


def export_portable_analysis_package(anchor: SourceAnchor, destination: Path) -> dict:
    """Create a new package only after byte verification and controlled replay."""
    anchor = SourceAnchor.model_validate(anchor).model_copy(deep=True)
    destination = Path(destination)
    if not destination.is_absolute() or ".." in destination.parts:
        raise ValueError("an absolute new package destination is required")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("portable package destination already exists")
    destination = _root(destination.parent) / destination.name
    source_root = Path(anchor.root).resolve(strict=True)
    if destination.is_relative_to(source_root):
        raise ValueError("portable export must not modify the original source tree")
    original, blobs = _read_original_artifacts(anchor)
    anchor_path = _regular(source_root / "source-anchor.json", source_root)
    anchor_raw = anchor_path.read_bytes()
    if SourceAnchor.model_validate(_json(anchor_raw)) != anchor:
        raise ValueError("saved original anchor differs from trusted export anchor")
    manifest_raw = _regular(Path(anchor.manifest_path), source_root).read_bytes()
    if sha256(manifest_raw).hexdigest() != anchor.manifest_sha256:
        raise ValueError("original manifest changed during export")
    extra_bundle = None
    paths = {name: Path(ref.path) for name, ref in original.artifacts.items()}
    if "bundle" not in blobs:
        bundle_path = _regular(source_root / "original-bundle36.json", source_root)
        extra_bundle = bundle_path.read_bytes()
        blobs["bundle"] = extra_bundle
        paths["bundle"] = bundle_path
    required = {
        "row",
        "request",
        "bundle",
        "started",
        "attempt",
        "result",
        "stdout",
        "seed",
        "registry",
        "events",
        "knowledge",
        "condition",
        "source_receipt",
    }
    if not required <= blobs.keys():
        raise ValueError("original artifact provenance incomplete")
    _, provenance = _verify_artifact_blobs(
        anchor, original, blobs, artifact_paths=paths
    )
    pending = {}

    def ref(relative, data):
        _parts(relative)
        if relative in pending:
            raise ValueError("duplicate export artifact path")
        pending[relative] = data
        return Artifact(path=relative, size=len(data), sha256=sha256(data).hexdigest())

    artifacts = {}
    for name in original.artifacts:
        if name.startswith("original_source:"):
            relative = "original_source/" + name.removeprefix("original_source:")
        elif name == "source_receipt":
            relative = "original_source/source_receipt.json"
        elif name == "events":
            relative = "artifacts/agent/events.jsonl"
        else:
            if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
                raise ValueError("unsupported original artifact name")
            relative = "artifacts/" + name + ".json"
        artifacts[name] = ref(relative, blobs[name])
    lineage = PackageLineage(
        original_anchor=ref("lineage/source-anchor.json", anchor_raw),
        original_manifest=ref("lineage/manifest-v1.json", manifest_raw),
        original_bundle=(
            ref("lineage/original-bundle36.json", extra_bundle)
            if extra_bundle is not None
            else None
        ),
    )
    manifest = PortableAnalysisManifest(
        schema_version="task13-analysis-artifacts-v2",
        order_index=original.order_index,
        source_row_id=original.source_row_id,
        successful_physical_request_id=original.successful_physical_request_id,
        validation_source_sha256=validation_source_hashes(),
        package_verifier_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        source_analysis_output_sha256=provenance["analysis_output_sha256"],
        artifacts=artifacts,
        lineage=lineage,
    )
    manifest_bytes = json.dumps(
        manifest.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2
    ).encode()
    digest = sha256(manifest_bytes).hexdigest()
    destination.mkdir(exist_ok=False)
    for relative, data in pending.items():
        path = destination.joinpath(*_parts(relative))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    with (destination / "manifest.json").open("xb") as stream:
        stream.write(manifest_bytes)
    verified = verify_portable_analysis_package(destination, digest)
    return {
        "schema_version": "task13-analysis-portable-export-v1",
        "manifest_sha256": digest,
        "source_identity": verified.source_identity,
        "source_analysis_output_sha256": provenance["analysis_output_sha256"],
        "original_anchor_sha256": lineage.original_anchor.sha256,
        "original_manifest_sha256": anchor.manifest_sha256,
        "file_count": len(pending) + 1,
        "total_bytes": sum(map(len, pending.values())) + len(manifest_bytes),
    }
