"""Rebuild DEDALE from copied sources and compare every output byte.

This production CLI always verifies the fixed official sources. It copies the
archives and metadata to a different, empty data root before a complete rebuild;
it never deletes or replaces an existing build. Synthetic unit tests exercise
only the pure compare_artifacts helper, without a source-verification bypass.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path
from typing import Any
from zipfile import BadZipFile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evals.datasets.dedale.common import (
    is_hash,
    read_json,
    safe_file,
    sha256,
    verify_sources,
    write_new,
)


def _inventory(root: Path) -> dict[str, str]:
    """Hash all files while rejecting links before any directory traversal."""
    safe_file(root, "selection.json")
    if not root.is_dir():
        raise ValueError("artifact root is not an existing directory")
    result = {}
    for current, directories, files in os.walk(root, followlinks=False):
        for name in sorted([*directories, *files]):
            path = Path(current) / name
            if path.is_symlink() or path.is_junction():
                raise ValueError("artifact tree contains a filesystem link")
        for name in sorted(files):
            path = Path(current) / name
            result[path.relative_to(root).as_posix()] = sha256(path)
    return result


def compare_artifacts(
    originalroot: Path, rebuildroot: Path, selection: dict
) -> dict[str, Any]:
    """Rehash actual cases and side files; never trust saved success flags.

    Compare complete selection JSON and its bytes, both complete inventories,
    and each actual case artifact against its selection-declared SHA256. An
    equal modification to both trees therefore cannot evade the expected hash.
    """
    originalroot, rebuildroot = (
        Path(originalroot).absolute(),
        Path(rebuildroot).absolute(),
    )
    report: dict[str, Any] = {
        "schema_version": 1,
        "original_cases_root": str(originalroot.resolve()),
        "rebuild_cases_root": str(rebuildroot.resolve()),
        "different_absolute_roots": originalroot.resolve() != rebuildroot.resolve(),
        "input_sha256": selection.get("input_sha256", {}),
        "selection_sha256": None,
        "rebuild_selection_sha256": None,
        "selection_equal": False,
        "artifacts": [],
        "errors": [],
        "all_equal": False,
    }
    try:
        original = _inventory(originalroot)
        rebuild = _inventory(rebuildroot)
        original_selection = read_json(safe_file(originalroot, "selection.json"))
        rebuilt_selection = read_json(safe_file(rebuildroot, "selection.json"))
        report["selection_sha256"] = original.get("selection.json")
        report["rebuild_selection_sha256"] = rebuild.get("selection.json")
        report["selection_equal"] = (
            original_selection == selection == rebuilt_selection
            and report["selection_sha256"] == report["rebuild_selection_sha256"]
        )
        expected = {}
        case_ids = set()
        for case in selection["cases"]:
            case_id, split = case["case_id"], case.get("split", "test")
            if not isinstance(case_id, str) or case_id in case_ids:
                raise ValueError("duplicate or invalid case identity")
            case_ids.add(case_id)
            if split != "test":
                raise ValueError("unexpected selected case split")
            case_root = safe_file(originalroot, f"{split}/{case_id}")
            if not isinstance(case["artifacts"], dict) or not case["artifacts"]:
                raise ValueError("selected case has no artifact hashes")
            for relative, digest in case["artifacts"].items():
                path = safe_file(case_root, relative)
                if not is_hash(digest):
                    raise ValueError("invalid expected artifact SHA256")
                logical = path.relative_to(originalroot).as_posix()
                expected[logical] = (case_id, relative, digest)
        for logical in sorted(
            (original.keys() | rebuild.keys() | expected.keys()) - {"selection.json"}
        ):
            case_id, relative, digest = expected.get(logical, (None, logical, None))
            first, second = original.get(logical), rebuild.get(logical)
            equal = (
                first is not None
                and first == second
                and (digest is None or first == digest)
            )
            report["artifacts"].append(
                {
                    "case_id": case_id,
                    "relative_path": relative,
                    "artifact_path": logical,
                    "expected_sha256": digest,
                    "original_sha256": first,
                    "rebuild_sha256": second,
                    "equal": equal,
                }
            )
        report["all_equal"] = bool(
            report["different_absolute_roots"]
            and report["selection_equal"]
            and all(row["equal"] for row in report["artifacts"])
        )
    except (OSError, ValueError, TypeError, KeyError) as exc:
        report["errors"].append({"error": type(exc).__name__, "message": str(exc)})
    return report


def _checked_root(path: Path) -> Path:
    # Check before resolve, so a link cannot disappear into its target spelling.
    path = Path(path).absolute()
    safe_file(path, "crosspath-root-check")
    return path.resolve()


def _empty_destination(path: Path) -> None:
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise FileExistsError(f"rebuild destination is not empty: {path}")


def _distinct_roots(roots: list[Path]) -> None:
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if (
                root == other
                or root.is_relative_to(other)
                or other.is_relative_to(root)
            ):
                raise ValueError(
                    "original and rebuilt data/case roots must be distinct and disjoint"
                )


def _copy_verified(source: Path, destination: Path, expected_sha256: str) -> dict:
    if destination.exists():
        raise FileExistsError(f"copy destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive destination creation prevents overwriting another process's file.
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, length=4 * 1024 * 1024)
    digest = sha256(destination)
    if digest != expected_sha256:
        raise ValueError("copied source SHA256 mismatch")
    return {"sha256": digest, "bytes": destination.stat().st_size}


def _copy_or_reverify(
    source: Path, destination: Path, expected_sha256: str, *, reuse: bool
) -> dict:
    if reuse and destination.exists():
        if sha256(destination) != expected_sha256:
            raise ValueError("existing copied source SHA256 mismatch")
        return {"sha256": expected_sha256, "bytes": destination.stat().st_size}
    return _copy_verified(source, destination, expected_sha256)


def _bind_input_hashes(
    selection: dict, manifest_hashes: dict, verification: dict
) -> dict:
    hashes = {
        **manifest_hashes,
        **{f"archive:{row['path']}": row["sha256"] for row in verification["archives"]},
    }
    if selection.get("input_sha256") != hashes:
        raise ValueError(
            "original selection is not bound to supplied manifests and verified archives"
        )
    return hashes


def rebuild_and_compare(
    *,
    sources: Path,
    splits: Path,
    label_policy: Path,
    data_root: Path,
    cases_root: Path,
    rebuild_root: Path,
    rebuild_data_root: Path,
    workers: int = 4,
    late_projection: bool = False,
    checkpoint_root: Path | None = None,
    reuse_copied_sources: bool = False,
) -> dict[str, Any]:
    """Verify, copy, rebuild and compare; no partial/unchecked source mode."""
    data_root, cases_root, rebuild_root, rebuild_data_root = [
        _checked_root(path)
        for path in (data_root, cases_root, rebuild_root, rebuild_data_root)
    ]
    _distinct_roots([data_root, cases_root, rebuild_root, rebuild_data_root])
    _empty_destination(rebuild_root)
    if not reuse_copied_sources:
        _empty_destination(rebuild_data_root)
    if checkpoint_root is not None:
        checkpoint_root = _checked_root(checkpoint_root)
        _distinct_roots(
            [data_root, cases_root, rebuild_root, rebuild_data_root, checkpoint_root]
        )
    configs = {
        "sources": Path(sources),
        "splits": Path(splits),
        "label_policy": Path(label_policy),
    }
    input_hashes = {name: sha256(path) for name, path in configs.items()}
    original_verification = verify_sources(configs["sources"], data_root)
    input_hashes.update(
        {
            f"archive:{row['path']}": row["sha256"]
            for row in original_verification["archives"]
        }
    )
    original_selection_path = safe_file(cases_root, "selection.json")
    # An independent rebuild may run alongside original preparation. Require
    # the completed original and exact input binding before comparing or
    # reporting success; copying and scanning need no original case content.
    if original_selection_path.exists():
        _bind_input_hashes(
            read_json(original_selection_path),
            {name: input_hashes[name] for name in configs},
            original_verification,
        )
    source_config = read_json(configs["sources"])
    copied = {}
    # Copy every fixed archive and verify its bytes against the source report.
    for archive in original_verification["archives"]:
        relative = archive["path"]
        copied[relative] = _copy_or_reverify(
            safe_file(data_root, relative),
            safe_file(rebuild_data_root, relative),
            archive["sha256"],
            reuse=reuse_copied_sources,
        )
    metadata = source_config["metadata_snapshot"]
    copied[metadata["path"]] = _copy_or_reverify(
        safe_file(data_root, metadata["path"]),
        safe_file(rebuild_data_root, metadata["path"]),
        metadata["sha256"],
        reuse=reuse_copied_sources,
    )
    copied_configs = {}
    input_files = {}
    for name, path in configs.items():
        relative = f"crosspath-inputs/{name}.json"
        target = safe_file(rebuild_data_root, relative)
        copied[relative] = _copy_or_reverify(
            path, target, input_hashes[name], reuse=reuse_copied_sources
        )
        copied_configs[name] = target
        input_files[name] = {
            "original_path": str(path.resolve()),
            "rebuild_path": str(target.resolve()),
            "sha256": input_hashes[name],
        }
    # prepare_dataset independently repeats official MD5/CRC verification on the
    # copied root before scanning all members. No copied normalized inputs exist.
    from evals.datasets.dedale.scan import prepare_dataset

    preparation_options = {}
    if checkpoint_root is not None:
        preparation_options["checkpoint_root"] = checkpoint_root
    rebuilt = prepare_dataset(
        **copied_configs,
        data_root=rebuild_data_root,
        output_root=rebuild_root,
        workers=workers,
        late_projection=late_projection,
        **preparation_options,
    )
    if any(sha256(path) != input_hashes[name] for name, path in configs.items()):
        raise ValueError("original input manifests changed during the rebuild")
    selection = read_json(original_selection_path)
    _bind_input_hashes(
        selection,
        {name: input_hashes[name] for name in configs},
        original_verification,
    )
    report = compare_artifacts(cases_root, rebuild_root, selection)
    if rebuilt != selection:
        report["all_equal"] = False
        report["errors"].append(
            {"error": "SelectionMismatch", "message": "full rebuild selection differs"}
        )
    report.update(
        {
            "original_data_root": str(data_root),
            "rebuild_data_root": str(rebuild_data_root),
            "different_data_roots": data_root != rebuild_data_root,
            "input_sha256": input_hashes,
            "input_files": input_files,
            "source_files": copied,
            "source_verification": original_verification,
            "rebuild_mode": "full-copy-and-full-archive-scan",
            "source_copy_mode": "reverified-existing-copy" if reuse_copied_sources else "new-copy",
            "checkpoint_root": str(checkpoint_root) if checkpoint_root is not None else None,
        }
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "sources",
        "splits",
        "label-policy",
        "data-root",
        "cases-root",
        "rebuild-root",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--rebuild-data-root", type=Path)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--checkpoint-root", type=Path)
    parser.add_argument(
        "--reuse-copied-sources", action="store_true",
        help="Rehash existing copied input bytes; never reuse original build checkpoints",
    )
    parser.add_argument(
        "--late-projection", action="store_true",
        help="Use validated lazy projection; frozen bytes remain identical",
    )
    args = parser.parse_args(argv)
    if args.rebuild_data_root is None:
        args.rebuild_data_root = args.rebuild_root.with_name(
            args.rebuild_root.name + "-data"
        )
    output = _checked_root(args.output)
    if output.exists():
        parser.error("output already exists; preserve previous evidence")
    for root in (
        args.data_root,
        args.cases_root,
        args.rebuild_root,
        args.rebuild_data_root,
    ):
        checked = _checked_root(root)
        if output == checked or output.is_relative_to(checked):
            parser.error(
                "comparison report must be outside all original and rebuild roots"
            )
    report: dict[str, Any]
    try:
        report = rebuild_and_compare(
            **{key: value for key, value in vars(args).items() if key != "output"}
        )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RuntimeError,
        ImportError,
        EOFError,
        BadZipFile,
    ) as exc:
        report = {
            "schema_version": 1,
            "all_equal": False,
            "original_cases_root": str(args.cases_root.resolve()),
            "rebuild_cases_root": str(args.rebuild_root.resolve()),
            "original_data_root": str(args.data_root.resolve()),
            "rebuild_data_root": str(args.rebuild_data_root.resolve()),
            "errors": [{"error": type(exc).__name__, "message": str(exc)}],
        }
    write_new(output, report)
    print(
        "Cross-path artifact comparison passed."
        if report["all_equal"]
        else "Cross-path artifact comparison failed."
    )
    return 0 if report["all_equal"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
