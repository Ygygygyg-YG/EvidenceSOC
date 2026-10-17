"""Independently rebuild public-priority v4 from verified own raw, v2, and v3 roots.

The second raw archives and full v2/v3 builds must already exist. Every archive
is freshly hashed with official MD5 and ZIP CRC verification; every own member
checkpoint and all five case artifacts are checked before the v4 raw reread.
An original v4 build may publish concurrently, but must exist for comparison.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
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
from evals.datasets.dedale.join_labels import load_label_index
from evals.datasets.dedale.neutralize import (
    ARTIFACTS,
    load_member_index,
)
from evals.datasets.dedale.neutralize import (
    implementation_hashes as neutral_implementation_hashes,
)
from scripts.dedale_task12_crosspath_check import (
    _checked_root,
    _copy_verified,
    _distinct_roots,
    _empty_destination,
    _inventory,
    compare_artifacts,
)

PROTOCOL = "dedale-public-priority-v4"
EXPECTED_PREPARATION_MEMBERS = 1344
ROOT_NAMES = ("data_root", "rebuild_data_root", "cases_root", "rebuild_root", "prepared_root",
              "rebuild_prepared_root", "preparation_checkpoints", "rebuild_preparation_checkpoints",
              "neutral_root", "rebuild_neutral_root")
CONFIG_NAMES = ("sources", "scan_splits", "splits", "neutral_policy", "label_policy")


def finalize_dataset(**kwargs):
    from evals.datasets.dedale.public_priority import finalize_dataset as build
    return build(**kwargs)


def implementation_hashes():
    from evals.datasets.dedale.public_priority import implementation_hashes as hashes
    return hashes()


def _regular(path: Path) -> Path:
    path = Path(path).absolute()
    safe_file(path.parent, path.name)
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("input must be a regular file without filesystem links: " + str(path))
    return path.resolve()


def _snapshot(root: Path) -> dict:
    inventory = _inventory(root)
    for relative in inventory:
        _regular(safe_file(root, relative))
    return inventory


def _selection(root: Path, protocol: str | None = None) -> dict:
    selection = read_json(_regular(safe_file(root, "selection.json")))
    if not isinstance(selection, dict) or (protocol and selection.get("protocol") != protocol):
        raise ValueError("selection protocol differs: " + str(root))
    if not selection.get("cases"):
        raise ValueError("selection must contain actual case artifacts")
    if any(set(case.get("artifacts", {})) != set(ARTIFACTS) for case in selection["cases"]):
        raise ValueError("selection must declare all five case artifacts")
    return selection


def _compare_layer(first: Path, second: Path, *, protocol=None, name: str) -> tuple[dict, dict]:
    selection = _selection(first, protocol)
    _selection(second, protocol)
    _snapshot(first)
    _snapshot(second)
    report = compare_artifacts(first, second, selection)
    if report["all_equal"] is not True:
        raise ValueError("independent " + name + " artifacts differ")
    return selection, report


def _bind(selection: dict, expected: dict, *, code=None) -> None:
    if any(selection.get("input_sha256", {}).get(name) != value for name, value in expected.items()):
        raise ValueError("selection is not bound to verified source/configuration inputs")
    if code is not None and selection.get("finalizer_code_sha256") != code:
        raise ValueError("selection finalizer implementation binding differs")


def _checkpoints(*, data_root, prepared_root, preparation_checkpoints, selection, scan_splits) -> dict:
    before = _snapshot(preparation_checkpoints)
    labels = load_label_index(safe_file(data_root, "system_logs_labels.zip"), exhaustive=True)
    index, binding = load_member_index(data_root=data_root, prepared_root=prepared_root,
        preparation_checkpoints=preparation_checkpoints, selection=selection, labels=labels,
        scan_splits=read_json(scan_splits))
    files = [name for name in before if name.startswith("member-") and name.endswith(".json")]
    if (len(index) != EXPECTED_PREPARATION_MEMBERS or len(files) != EXPECTED_PREPARATION_MEMBERS
            or any(row.get("jsonl_md5_verified") is not True for row in index)):
        raise ValueError("actual own preparation checkpoint coverage differs")
    if _snapshot(preparation_checkpoints) != before:
        raise ValueError("preparation checkpoints changed during verification")
    return {"members_verified": len(index), "checkpoint_files_verified": len(files),
            "binding": binding, "files_sha256": before}


def _wait_for_original(root: Path, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while not safe_file(root, "selection.json").is_file():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("original v4 selection was not published before the comparison deadline")
        time.sleep(min(1.0, remaining))


def rebuild_and_compare(*, sources: Path, scan_splits: Path, splits: Path, neutral_policy: Path,
                        label_policy: Path, data_root: Path, rebuild_data_root: Path,
                        cases_root: Path, rebuild_root: Path, prepared_root: Path,
                        rebuild_prepared_root: Path, preparation_checkpoints: Path,
                        rebuild_preparation_checkpoints: Path, neutral_root: Path,
                        rebuild_neutral_root: Path, workers: int = 4,
                        work_root: Path | None = None, original_wait_seconds: int = 7200) -> dict:
    if type(workers) is not int or not 1 <= workers <= 8:
        raise ValueError("workers must be an integer from 1 to 8")
    if type(original_wait_seconds) is not int or not 0 <= original_wait_seconds <= 86400:
        raise ValueError("original wait seconds must be an integer from 0 to 86400")
    supplied = locals()
    roots = {name: _checked_root(supplied[name]) for name in ROOT_NAMES}
    if work_root is not None:
        work_root = _checked_root(work_root)
    _distinct_roots([*roots.values(), *([work_root] if work_root else [])])
    _empty_destination(roots["rebuild_root"])
    configs = {name: _regular(supplied[name]) for name in CONFIG_NAMES}
    hashes = {name: sha256(path) for name, path in configs.items()}
    code = implementation_hashes()
    neutral_code = neutral_implementation_hashes()

    # Both are fresh actual archive checks, including official MD5 and full ZIP
    # CRC exhaustion. Prior preparation reports cannot substitute for either.
    verification = verify_sources(configs["sources"], roots["data_root"], check_crc=True)
    second_verification = verify_sources(configs["sources"], roots["rebuild_data_root"], check_crc=True)
    if verification != second_verification or verification.get("verified") is not True:
        raise ValueError("independent raw archive verification differs")
    metadata = read_json(configs["sources"])["metadata_snapshot"]
    source_files = {}
    for row in [*verification["archives"], {"path": metadata["path"], "sha256": verification["metadata_sha256"]}]:
        first = _regular(safe_file(roots["data_root"], row["path"]))
        second = _regular(safe_file(roots["rebuild_data_root"], row["path"]))
        if os.path.samefile(first, second):
            raise ValueError("independent raw sources must not share filesystem links")
        source_files[row["path"]] = {"original_path": str(first), "rebuild_path": str(second),
                                     "sha256": row["sha256"]}

    preparation, prep_report = _compare_layer(roots["prepared_root"], roots["rebuild_prepared_root"], name="v2 preparation")
    neutral, neutral_report = _compare_layer(roots["neutral_root"], roots["rebuild_neutral_root"],
                                            protocol="dedale-neutral-v3", name="v3 neutral")
    archives = {"archive:" + row["path"]: row["sha256"] for row in verification["archives"]}
    prep_expected = {"sources": hashes["sources"], "splits": hashes["scan_splits"],
                     "label_policy": hashes["label_policy"], **archives}
    _bind(preparation, prep_expected)
    if preparation.get("source_verification") != verification:
        raise ValueError("preparation source verification binding differs")
    neutral_expected = {**prep_expected, "splits": hashes["neutral_policy"],
                        "preparation_splits": hashes["scan_splits"],
                        "preparation_selection": sha256(roots["prepared_root"] / "selection.json")}
    _bind(neutral, neutral_expected, code=neutral_code)
    checkpoints = {}
    for side, prefix in (("original", ""), ("rebuild", "rebuild_")):
        checkpoints[side] = _checkpoints(data_root=roots[prefix + "data_root"],
            prepared_root=roots[prefix + "prepared_root"],
            preparation_checkpoints=roots[prefix + "preparation_checkpoints"],
            selection=preparation, scan_splits=configs["scan_splits"])

    # Configuration copies have a unique exclusive folder; no original cases,
    # observations, or original checkpoints are ever copied into the rebuild.
    input_folder = safe_file(roots["rebuild_data_root"], "priority-inputs-" + uuid.uuid4().hex)
    input_folder.mkdir(exist_ok=False)
    copied_configs, bindings = {}, {}
    for name, path in configs.items():
        target = safe_file(input_folder, name + ".json")
        _copy_verified(path, target, hashes[name])
        copied_configs[name] = target
        bindings[name] = {"original_path": str(path), "rebuild_path": str(target), "sha256": hashes[name]}
    rebuilt = finalize_dataset(**copied_configs, data_root=roots["rebuild_data_root"],
        prepared_root=roots["rebuild_prepared_root"],
        preparation_checkpoints=roots["rebuild_preparation_checkpoints"],
        neutral_root=roots["rebuild_neutral_root"], output_root=roots["rebuild_root"],
        workers=workers, **({"work_root": work_root} if work_root is not None else {}))

    # Only the final published selection path is polled. Input/code/artifact
    # postchecks run after this wait so concurrent publication cannot make
    # the final report depend on stale checks made hours earlier.
    _wait_for_original(roots["cases_root"], original_wait_seconds)

    if code != implementation_hashes() or neutral_code != neutral_implementation_hashes():
        raise ValueError("implementation changed during independent rebuild")
    for name, path in configs.items():
        if sha256(_regular(path)) != hashes[name] or sha256(_regular(copied_configs[name])) != hashes[name]:
            raise ValueError("configuration changed during independent rebuild")
    for row in source_files.values():
        if any(sha256(_regular(Path(row[key]))) != row["sha256"] for key in ("original_path", "rebuild_path")):
            raise ValueError("actual source bytes changed during independent rebuild")
    for side, prefix in (("original", ""), ("rebuild", "rebuild_")):
        if _snapshot(roots[prefix + "preparation_checkpoints"]) != checkpoints[side]["files_sha256"]:
            raise ValueError("actual preparation checkpoints changed during independent rebuild")
    # Rehash all lineage artifacts after the raw reread as well as before it.
    _, prep_after = _compare_layer(roots["prepared_root"], roots["rebuild_prepared_root"], name="v2 preparation")
    _, neutral_after = _compare_layer(roots["neutral_root"], roots["rebuild_neutral_root"],
                                     protocol="dedale-neutral-v3", name="v3 neutral")
    if prep_after != prep_report or neutral_after != neutral_report:
        raise ValueError("actual lineage artifacts changed during independent rebuild")

    # Deliberately first read original v4 only AFTER the second own raw rebuild.
    selection = _selection(roots["cases_root"], PROTOCOL)
    expected = {**neutral_expected, "splits": hashes["splits"], "neutral_policy": hashes["neutral_policy"],
                "neutral_selection": sha256(roots["neutral_root"] / "selection.json")}
    _bind(selection, expected, code=code)
    _bind(rebuilt, expected, code=code)
    _selection(roots["rebuild_root"], PROTOCOL)
    _snapshot(roots["cases_root"])
    _snapshot(roots["rebuild_root"])
    report = compare_artifacts(roots["cases_root"], roots["rebuild_root"], selection)
    if rebuilt != selection:
        report["all_equal"] = False
        report["errors"].append({"error": "SelectionMismatch", "message": "independent v4 selection differs"})
    report.update({"protocol": PROTOCOL,
        "original_data_root": str(roots["data_root"]), "rebuild_data_root": str(roots["rebuild_data_root"]),
        "different_data_roots": True, "input_sha256": selection["input_sha256"],
        "input_files": {name: bindings[name] for name in ("sources", "splits", "label_policy")},
        "preparation_input_files": {name: bindings[name] for name in ("scan_splits", "neutral_policy")},
        "source_files": source_files, "source_verification": verification,
        "rebuild_source_verification": second_verification, "code_sha256": code,
        "neutral_code_sha256": neutral_code, "checkpoint_verification": checkpoints,
        "preparation_comparison": prep_report, "neutral_comparison": neutral_report,
        "preparation_selection_sha256": sha256(roots["prepared_root"] / "selection.json"),
        "rebuild_preparation_selection_sha256": sha256(roots["rebuild_prepared_root"] / "selection.json"),
        "neutral_selection_sha256": sha256(roots["neutral_root"] / "selection.json"),
        "rebuild_neutral_selection_sha256": sha256(roots["rebuild_neutral_root"] / "selection.json"),
        "rebuild_mode": "independent-own-v2-v3-and-v4-full-selected-member-raw-reread",
        "source_copy_mode": "reverified-existing-copy", "formal_model_runs": 0})
    for name in ("prepared_root", "neutral_root", "preparation_checkpoints"):
        report["original_" + name] = str(roots[name])
        report["rebuild_" + name] = str(roots["rebuild_" + name])
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (*CONFIG_NAMES, *ROOT_NAMES, "output"):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--original-wait-seconds", type=int, default=7200,
                        help="Wait 0..86400 seconds for original final publication after the independent build")
    args = vars(parser.parse_args(argv))
    output = _checked_root(args.pop("output"))
    if output.exists():
        parser.error("comparison report already exists; preserve prior evidence")
    for name in (*ROOT_NAMES, "work_root"):
        if args[name] is not None:
            root = _checked_root(args[name])
            if output == root or output.is_relative_to(root):
                parser.error("report must stay outside all raw, prepared, neutral, checkpoint, work and final roots")
    try:
        report = rebuild_and_compare(**args)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, ImportError, EOFError, BadZipFile) as exc:
        report = {"schema_version": 1, "protocol": PROTOCOL, "all_equal": False,
                  "formal_model_runs": 0, "original_wait_seconds": args["original_wait_seconds"],
                  "original_cases_root": str(args["cases_root"].resolve()),
                  "rebuild_cases_root": str(args["rebuild_root"].resolve()),
                  "errors": [{"error": type(exc).__name__, "message": str(exc)}]}
    write_new(output, report)
    print(canonical({"all_equal": report["all_equal"], "report": str(output), "formal_model_runs": 0}))
    return 0 if report["all_equal"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
