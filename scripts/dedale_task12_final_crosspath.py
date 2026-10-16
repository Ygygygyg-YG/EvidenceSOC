"""Rebuild neutral v3 cases from a separately completed raw v2 preparation."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from zipfile import BadZipFile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evals.datasets.dedale.common import (
    canonical,
    read_json,
    safe_file,
    sha256,
    verify_sources,
    write_new,
)
from evals.datasets.dedale.neutralize import finalize_dataset
from scripts.dedale_task12_crosspath_check import (
    _checked_root,
    _copy_or_reverify,
    _distinct_roots,
    _empty_destination,
    compare_artifacts,
)


def rebuild_and_compare(*, sources: Path, scan_splits: Path, splits: Path,
                        label_policy: Path, data_root: Path, rebuild_data_root: Path,
                        cases_root: Path, rebuild_root: Path, prepared_root: Path,
                        rebuild_prepared_root: Path, preparation_checkpoints: Path,
                        rebuild_preparation_checkpoints: Path, workers: int = 4,
                        work_root: Path | None = None) -> dict:
    roots = {name: _checked_root(path) for name, path in {
        "data_root": data_root, "rebuild_data_root": rebuild_data_root,
        "cases_root": cases_root, "rebuild_root": rebuild_root,
        "prepared_root": prepared_root, "rebuild_prepared_root": rebuild_prepared_root,
        "preparation_checkpoints": preparation_checkpoints,
        "rebuild_preparation_checkpoints": rebuild_preparation_checkpoints,
    }.items()}
    if work_root is not None:
        work_root = _checked_root(work_root)
    _distinct_roots([*roots.values(), *([work_root] if work_root else [])])
    _empty_destination(roots["rebuild_root"])
    for name in ("prepared_root", "rebuild_prepared_root"):
        read_json(safe_file(roots[name], "selection.json"))
    if sha256(roots["prepared_root"] / "selection.json") != sha256(roots["rebuild_prepared_root"] / "selection.json"):
        raise ValueError("independent full raw preparations differ")
    preparation_comparison = compare_artifacts(
        roots["prepared_root"], roots["rebuild_prepared_root"],
        read_json(roots["prepared_root"] / "selection.json"))
    if preparation_comparison["all_equal"] is not True:
        raise ValueError("independent preparation artifacts differ")
    configs = {"sources": Path(sources), "splits": Path(splits),
               "label_policy": Path(label_policy), "scan_splits": Path(scan_splits)}
    hashes = {name: sha256(path) for name, path in configs.items()}
    verification = verify_sources(configs["sources"], roots["data_root"])
    selection = read_json(safe_file(roots["cases_root"], "selection.json"))
    if selection.get("protocol") != "dedale-neutral-v3":
        raise ValueError("original is not a neutral v3 final selection")
    expected = {name: hashes[name] for name in ("sources", "splits", "label_policy")}
    expected.update({"archive:" + row["path"]: row["sha256"] for row in verification["archives"]})
    if any(selection.get("input_sha256", {}).get(name) != value for name, value in expected.items()):
        raise ValueError("original final selection is not bound to verified inputs")
    metadata = read_json(configs["sources"])["metadata_snapshot"]
    copies = {}
    for row in [*verification["archives"], {"path": metadata["path"], "sha256": verification["metadata_sha256"]}]:
        relative = row["path"]
        # These are actual source copies from the independent full scan. Rehash
        # them; never replace a mismatched copy or normalize from original cases.
        target = safe_file(roots["rebuild_data_root"], relative)
        if not target.is_file() or sha256(target) != row["sha256"]:
            raise ValueError("copied raw SHA256 mismatch: " + relative)
        copies[relative] = {"original_path": str(safe_file(roots["data_root"], relative)),
                            "rebuild_path": str(target), "sha256": row["sha256"]}
    copied_configs, bindings = {}, {}
    for name, path in configs.items():
        relative = "final-inputs/" + name + ".json"
        target = safe_file(roots["rebuild_data_root"], relative)
        _copy_or_reverify(path, target, hashes[name], reuse=True)
        copied_configs[name] = target
        bindings[name] = {"original_path": str(path.resolve()), "rebuild_path": str(target), "sha256": hashes[name]}
    options = {"work_root": work_root} if work_root is not None else {}
    rebuilt = finalize_dataset(**copied_configs, data_root=roots["rebuild_data_root"],
        prepared_root=roots["rebuild_prepared_root"],
        preparation_checkpoints=roots["rebuild_preparation_checkpoints"],
        output_root=roots["rebuild_root"], workers=workers, **options)
    if any(sha256(path) != hashes[name] for name, path in configs.items()):
        raise ValueError("original final input changed during rebuild")
    report = compare_artifacts(roots["cases_root"], roots["rebuild_root"], selection)
    if rebuilt != selection:
        report["all_equal"] = False
        report["errors"].append({"error": "SelectionMismatch", "message": "independent v3 selection differs"})
    report.update({
        "original_data_root": str(roots["data_root"]),
        "rebuild_data_root": str(roots["rebuild_data_root"]), "different_data_roots": True,
        "input_sha256": selection["input_sha256"],
        "input_files": {name: bindings[name] for name in ("sources", "splits", "label_policy")},
        "preparation_input_files": {"scan_splits": bindings["scan_splits"]},
        "source_files": copies, "source_verification": verification,
        "original_prepared_root": str(roots["prepared_root"]),
        "rebuild_prepared_root": str(roots["rebuild_prepared_root"]),
        "original_preparation_checkpoints": str(roots["preparation_checkpoints"]),
        "rebuild_preparation_checkpoints": str(roots["rebuild_preparation_checkpoints"]),
        "preparation_selection_sha256": sha256(roots["prepared_root"] / "selection.json"),
        "preparation_comparison": preparation_comparison,
        "rebuild_mode": "independent-v2-full-scan-and-v3-targeted-raw-rescan",
        "source_copy_mode": "reverified-existing-copy", "formal_model_runs": 0,
    })
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sources", "scan-splits", "splits", "label-policy", "data-root",
                 "rebuild-data-root", "cases-root", "rebuild-root", "prepared-root",
                 "rebuild-prepared-root", "preparation-checkpoints", "rebuild-preparation-checkpoints", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--work-root", type=Path)
    args = vars(parser.parse_args(argv))
    output = _checked_root(args.pop("output"))
    if output.exists():
        parser.error("comparison report already exists; preserve prior evidence")
    for name, value in args.items():
        if isinstance(value, Path) and name.endswith(("root", "checkpoints")):
            root = _checked_root(value)
            if output == root or output.is_relative_to(root):
                parser.error("report must stay outside all raw, prepared, checkpoint and final roots")
    try:
        report = rebuild_and_compare(**args)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, EOFError, BadZipFile) as exc:
        report = {"schema_version": 1, "all_equal": False,
                  "errors": [{"error": type(exc).__name__, "message": str(exc)}]}
    write_new(output, report)
    print(canonical({"all_equal": report["all_equal"], "report": str(output), "formal_model_runs": 0}))
    return 0 if report["all_equal"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
