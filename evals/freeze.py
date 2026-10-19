"""Deterministic unfrozen controls and complete evaluated-source freeze checks.

Generated controls belong under data/task13/control, outside committed source.
This module never approves gates, calls models or changes accepted Task12 inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from evals.contracts import ControllerRunSpec, canonical_hash

SOURCE_PATHS = (
    "services/backend/src",
    "services/backend/tests",
    "services/backend/pyproject.toml",
    "services/backend/uv.lock",
    "evals",
    "scripts",
    "docs/evaluations/protocol.md",
)
GENERATED_FREEZE = "evals/configs/freeze_manifest.json"


def _source_file(path: Path, repository: Path) -> bool:
    relative = path.relative_to(repository)
    return (
        path.is_file()
        and not {
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            ".task13_test_tmp",
        }.intersection(relative.parts)
        and path.suffix not in {".pyc", ".pyo"}
        and relative.as_posix() != GENERATED_FREEZE
    )


def required_freeze_files(repository: Path) -> list[str]:
    """Bind source, tests, templates, protocol and dependencies, including new files."""
    repository = Path(repository)
    paths = set()
    for name in SOURCE_PATHS:
        root = repository / name
        candidates = root.rglob("*") if root.is_dir() else [root]
        for path in candidates:
            if _source_file(path, repository):
                if path.is_symlink() or path.is_junction():
                    raise ValueError("evaluated source cannot contain filesystem links")
                paths.add(path.relative_to(repository).as_posix())
    return sorted(paths)


def _hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_freeze_file_coverage(freeze: dict, *, repository: Path) -> None:
    from evals.datasets.dedale.common import safe_file

    required = set(required_freeze_files(repository))
    files = freeze.get("files", {})
    if not isinstance(files, dict) or not required.issubset(files):
        raise ValueError("freeze coverage omits evaluated implementation or tests")
    if GENERATED_FREEZE in files or any(
        name.startswith("data/task13/control/") for name in files
    ):
        raise ValueError("generated control artifacts cannot be frozen as source")
    for relative, digest in files.items():
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid evaluated source hash")
        if _hash(safe_file(repository, relative)) != digest:
            raise ValueError("frozen evaluated implementation file hash mismatch")


def validate_committed_sources(repository: Path, source_commit: str) -> None:
    options = {"cwd": repository, "capture_output": True, "text": True}
    head = subprocess.run(["git", "rev-parse", "HEAD"], check=False, **options)
    pathspec = [*SOURCE_PATHS, f":(exclude){GENERATED_FREEZE}"]
    dirty = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--", *pathspec], check=False, **options
    )
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "-z", "--", *pathspec],
        check=False,
        **options,
    )
    if (
        head.returncode != 0
        or head.stdout.strip() != source_commit
        or dirty.returncode != 0
        or untracked.returncode != 0
        or any(
            _source_file(Path(repository) / name, Path(repository))
            for name in untracked.stdout.split("\0")
            if name
        )
    ):
        raise ValueError(
            "formal execution requires committed tested sources; dirty or untracked evaluated source remains"
        )


def accepted_isolation_receipt(receipt: dict, source_commit: str) -> bool:
    invocations = receipt.get("real_model_invocations")
    return (
        receipt.get("status") == "passed"
        and receipt.get("source_commit") == source_commit
        and type(invocations) is int
        and invocations >= 1
        and type(receipt.get("critical_skips")) is int
        and receipt["critical_skips"] == 0
        and receipt.get("cross_case_denied") is True
    )


def build_unfrozen_artifacts(
    repository: Path, source_commit: str, run_id: str
) -> tuple[dict, dict]:
    """Return honest pending freeze plus real controllers, with no fabricated evidence."""
    repository = Path(repository).resolve()
    controllers = {}
    inputs = {
        "ait": (
            ".backups/task12-readiness/data/ait/cases/test",
            ".backups/task12-readiness/data/manifests/ait-task11-test-selection.json",
            "docs/acceptance/task12-ait-hashes.json",
        ),
        "dedale": (
            "data/dedale/priority-cases-v4/test",
            "data/dedale/priority-cases-v4/selection.json",
            "docs/acceptance/task12-dedale-freeze-2026-10-17.json",
        ),
    }
    for dataset, (cases, selection, admission) in inputs.items():
        controllers[dataset] = ControllerRunSpec(
            run_id=run_id,
            dataset=dataset,
            split="test",
            source_commit=source_commit,
            case_root=str(repository / cases),
            selection_path=str(repository / selection),
            selection_sha256=_hash(repository / selection),
            admission_paths=[str(repository / admission)],
        ).model_dump(mode="json")
    files = {
        name: _hash(repository / name) for name in required_freeze_files(repository)
    }
    freeze = {
        "schema_version": "task13-freeze-v1",
        "status": "prepared_not_frozen",
        "source_commit": source_commit,
        "run_id": run_id,
        "gates": dict.fromkeys(["G1", "G2", "G3", "G4", "G5"], "pending"),
        "files": files,
        "bindings": {
            "protocol": files.get("docs/evaluations/protocol.md"),
            "dependencies": files.get("services/backend/uv.lock"),
            "knowledge": None,
            "model": canonical_hash(controllers["ait"]["model"]),
            "prompts": canonical_hash(
                {k: v for k, v in files.items() if "/agents/" in k}
            ),
            "tools": canonical_hash(
                {
                    k: v
                    for k, v in files.items()
                    if "/tools/" in k or "/mcp_server/" in k
                }
            ),
            "scoring": canonical_hash(
                {
                    k: v
                    for k, v in files.items()
                    if k.startswith(("evals/metrics/", "evals/runners/score"))
                }
            ),
            "review": files.get("evals/review.py"),
            "plots": canonical_hash(
                {k: v for k, v in files.items() if k.startswith("evals/plots/")}
            ),
            "dataset_admission": canonical_hash(
                {
                    dataset: {
                        path: _hash(Path(path)) for path in config["admission_paths"]
                    }
                    for dataset, config in controllers.items()
                }
            ),
        },
        "isolation": None,
        "reviewer": "user",
        "review_window": "19:00-00:00 Asia/Shanghai",
        "pending_reasons": [
            "G1-G5 require recorded acceptance",
            "real source-bound model-worker isolation is absent",
            "knowledge snapshot and measured development acceptance require binding",
        ],
    }
    return freeze, controllers


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New generated control directory under data/task13/control",
    )
    args = parser.parse_args()
    repository = args.repository.resolve()
    output = args.output.resolve()
    if not output.is_relative_to(repository / "data/task13/control"):
        raise ValueError(
            "generated control artifacts must be outside committed source under data/task13/control"
        )
    freeze, controllers = build_unfrozen_artifacts(
        repository, args.source_commit, args.run_id
    )
    output.mkdir(parents=True, exist_ok=False)
    for name, value in {"freeze_manifest": freeze, **controllers}.items():
        with (output / (name + ".json")).open(
            "x", encoding="utf-8", newline="\n"
        ) as stream:
            stream.write(
                json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
            )
    print(
        json.dumps(
            {
                "status": freeze["status"],
                "output": str(output),
                "file_count": len(freeze["files"]),
            }
        )
    )


if __name__ == "__main__":
    main()
