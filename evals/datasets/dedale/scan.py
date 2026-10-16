"""Verify fixed DEDALE inputs, stream every log member, and prepare cases.

Worker results contain only bounded window projections and aggregate scan
state. Labels remain in each worker's initializer context; no raw archive is
extracted. Optional complete-member checkpoints use bounded, validated JSON;
all official input archives are still verified on every invocation.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from collections import Counter, deque
from collections.abc import Iterator
from concurrent.futures import Future, ProcessPoolExecutor
from itertools import islice
from pathlib import Path
from typing import Any

from .build_manifests import WindowCollector, emit_cases, validate_splits
from .checkpoint import MemberCheckpoints
from .common import canonical, read_json, safe_file, sha256, verify_sources
from .join_labels import EXHAUSTIVE_HOSTS, LabelIndex, load_label_index
from .parse import (
    ARCHIVE_SOURCES,
    decode_event,
    iter_archive_lines,
    parse_event,
    read_archive_manifest,
)

# Invalid external data consistently raises ValueError at this boundary.
# ruff: noqa: TRY004

_WORKER_LABELS: LabelIndex | None = None
_WORKER_SPLITS: dict | None = None
_WORKER_LATE_PROJECTION = False
_ERROR_LIMIT_PER_MEMBER = 20
_ERROR_LIMIT_TOTAL = 100
_ERROR_CODES = frozenset(
    {
        "INVALID_JSON_EVENT",
        "INVALID_JSON_EVENT_OBJECT_REQUIRED",
        "INVALID_JSON_SOURCE_OBJECT_REQUIRED",
        "INVALID_JSON_CANONICAL_EVENT",
        "INVALID_TIMESTAMP_EXPLICIT_TIMEZONE_REQUIRED",
        "INVALID_TIMESTAMP",
        "MISSING_HOST",
    }
)


def _progress(output_root: Path, stage: str, **counts) -> None:
    """Keep long-running preparation observable without changing frozen bytes."""
    path = output_root.with_name(output_root.name + "-progress.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(".pending")
    pending.write_text(canonical({"schema_version": 1, "pid": os.getpid(), "stage": stage, **counts}) + "\n", encoding="utf-8")
    pending.replace(path)


def _validate_scan_splits(config: dict) -> None:
    validate_splits(config)
    expected = {
        "schema_version": 1,
        "timezone": "UTC",
        "bounds": "[start,end)",
        "recent_months": 24,
        "max_records": 100,
        "event_sort": ["observed_at", "external_id"],
        "dedup_key": "source+canonical_event_fingerprint",
        "campaign_id": "dedale-v2.1-single-campaign",
        "benign_per_host_day": 1,
        "attack_window_rule": "greedy_class1_timestamp_nonoverlapping",
    }
    for key, value in expected.items():
        if key not in config or canonical(config[key]) != canonical(value):
            raise ValueError(f"split policy differs from preregistered values: {key}")


def _validate_policy(policy: dict) -> None:
    expected = {
        "schema_version": 1,
        "dataset_id": "dedale-v2.1",
        "original_labels": ["benign", "malicious", "malicious-related"],
        "class_1": "malicious",
        "class_1_and_2_minus_class_1": "malicious-related",
        "unmatched": "benign only for checked official exhaustive label archive and documented source/host scope; otherwise unscorable",
        "scorable_hosts": {
            source: sorted(hosts) for source, hosts in EXHAUSTIVE_HOSTS.items()
        },
        "attack_decision": {
            "malicious": True,
            "malicious-related": None,
            "benign": False,
            "unscorable": None,
        },
        "attack_types": [],
        "taxonomy_status": "out_of_taxonomy",
        "attack_version": None,
    }
    if not isinstance(policy, dict):
        raise ValueError("label policy must be an object")
    for key, value in expected.items():
        # Canonical JSON distinguishes false from 0 and true from 1.
        if key not in policy or canonical(policy[key]) != canonical(value):
            raise ValueError(
                f"label policy differs from verified semantics/scope: {key}"
            )


def _require_labels(labels: LabelIndex) -> None:
    if not labels.official_verified or not labels.exhaustive:
        raise ValueError(
            "complete official label archive and exhaustive policy are mandatory"
        )
    if not labels.summary.get("crc_complete") or not labels.summary.get(
        "labels_complete_read"
    ):
        raise ValueError(
            "official label archive must be read completely with CRC checks"
        )


def collector_state(collector: WindowCollector) -> dict[str, Any]:
    """Transport bounded state without copying the full label index or config."""
    return {
        "windows": {
            key: {
                "raw_count": value["raw_count"],
                "labels": Counter(value["labels"]),
                "records": list(value["records"]),
                "kept": set(value["kept"]),
                "duplicate_retained_rows": value["duplicate_retained_rows"],
            }
            for key, value in collector.windows.items()
        },
        "stats": Counter(collector.stats),
        "hosts": Counter(collector.hosts),
        "days": Counter(collector.days),
        "original_labels": Counter(collector.original_labels),
        "matched_labels": set(collector.matched_labels),
        "minimum": collector.minimum,
        "maximum": collector.maximum,
    }


def merge_collector_state(collector: WindowCollector, state: dict[str, Any]) -> None:
    """Merge complete member state, retaining the globally earliest unique rows.

    Each input window already retains its earliest K unique fingerprints, so
    their union contains the earliest K unique events of the combined window.
    Counts cover every raw/parsed row, including rows outside the projection.
    """
    for name in ("stats", "hosts", "days", "original_labels"):
        getattr(collector, name).update(state[name])
    collector.matched_labels.update(state["matched_labels"])
    if state["minimum"] is not None:
        collector.minimum = (
            state["minimum"]
            if collector.minimum is None
            else min(collector.minimum, state["minimum"])
        )
    if state["maximum"] is not None:
        collector.maximum = (
            state["maximum"]
            if collector.maximum is None
            else max(collector.maximum, state["maximum"])
        )
    for key, incoming in state["windows"].items():
        existing = collector.windows.setdefault(
            key,
            {
                "raw_count": 0,
                "labels": Counter(),
                "records": [],
                "kept": set(),
                "duplicate_retained_rows": 0,
            },
        )
        existing["raw_count"] += incoming["raw_count"]
        existing["labels"].update(incoming["labels"])
        existing["duplicate_retained_rows"] += incoming["duplicate_retained_rows"]
        candidates: dict[str, tuple] = {}
        for row in sorted(
            [*existing["records"], *incoming["records"]], key=lambda item: item[0]
        ):
            fingerprint = row[1]["event_fingerprint"]
            if fingerprint in candidates:
                if row[2] != candidates[fingerprint][2]:
                    raise ValueError(
                        "conflicting source labels while merging one fingerprint"
                    )
                existing["duplicate_retained_rows"] += 1
            else:
                candidates[fingerprint] = row
        existing["records"] = sorted(candidates.values(), key=lambda item: item[0])[
            : collector.splits["max_records"]
        ]
        existing["kept"] = {row[1]["event_fingerprint"] for row in existing["records"]}


def scan_member(
    archive_path: Path,
    member: str,
    *,
    labels: LabelIndex,
    splits: dict,
    late_projection: bool = False,
) -> dict[str, Any]:
    """Exhaust a single ZIP/BZ2 stream; only parser row errors are recoverable.

    BZ2/ZIP/manifest failures and calibration-policy violations abort the task.
    Exhaustion is necessary for parse.py's original JSONL MD5 verification.
    """
    archive_path = Path(archive_path)
    collector = WindowCollector(labels=labels, splits=splits)
    collector.stats.update({"raw_rows": 0, "invalid_rows": 0, "parsed_rows": 0})
    errors = []
    for actual_member, line_number, raw_line in iter_archive_lines(
        archive_path, member_names={member}
    ):
        collector.stats["raw_rows"] += 1
        try:
            event = (decode_event if late_projection else parse_event)(
                raw_line,
                archive=archive_path.name,
                relative_log_path=actual_member,
                line_number=line_number,
            )
        except ValueError as exc:
            collector.stats["invalid_rows"] += 1
            if len(errors) < _ERROR_LIMIT_PER_MEMBER:
                # Exception messages are never copied: a decoder may mention
                # input details. Persist only a fixed category and provenance.
                code = str(exc).partition(":")[0]
                errors.append(
                    {
                        "archive": archive_path.name,
                        "relative_log_path": actual_member,
                        "line_number": line_number,
                        "error_code": code if code in _ERROR_CODES else "INVALID_EVENT",
                    }
                )
            continue
        if late_projection:
            collector.add_decoded(event)
        else:
            collector.add(event)
    return {
        **collector_state(collector),
        "archive": archive_path.name,
        "member": member,
        "completed": True,
        "jsonl_md5_verified": True,
        "invalid_examples": errors,
    }


def initialize_worker(label_archive: str, splits: dict, late_projection: bool = False) -> None:
    """Load one complete label index per process, reused across all its tasks."""
    global _WORKER_LABELS, _WORKER_SPLITS, _WORKER_LATE_PROJECTION
    labels = load_label_index(Path(label_archive), exhaustive=True)
    _require_labels(labels)
    _validate_scan_splits(splits)
    _WORKER_LABELS, _WORKER_SPLITS = labels, splits
    _WORKER_LATE_PROJECTION = late_projection


def worker_scan_member(task: tuple[str, str]) -> dict[str, Any]:
    if _WORKER_LABELS is None or _WORKER_SPLITS is None:
        raise RuntimeError("scan worker was not initialized")
    archive_path, member = task
    return scan_member(
        Path(archive_path), member, labels=_WORKER_LABELS, splits=_WORKER_SPLITS,
        late_projection=_WORKER_LATE_PROJECTION,
    )


def _bounded_member_results(
    pool: ProcessPoolExecutor, tasks: list[tuple[str, str]], *, limit: int,
    checkpoints: MemberCheckpoints | None = None,
) -> Iterator[dict[str, Any]]:
    """Keep at most limit submitted results, yielding in canonical task order.

    Python 3.12 Executor.map eagerly submits the entire iterable. A slow first
    hour would otherwise leave hundreds of completed window projections queued
    in the parent process. Refill only after the preceding state was consumed.
    """
    def submit(task):
        cached = checkpoints.load(task) if checkpoints is not None else None
        if cached is not None:
            return cached, None
        future = pool.submit(worker_scan_member, task)
        if checkpoints is None:
            return None, future
        persisted = Future()

        def completed(result):
            # Persist in completion order, independently of canonical merge.
            # Exceptions reach the consumer rather than the callback logger.
            try:
                state = result.result()
                checkpoints.save(state)
                persisted.set_result(state)
            except BaseException as exc:  # noqa: BLE001 - propagate callback failures through its Future
                persisted.set_exception(exc)

        future.add_done_callback(completed)
        return None, persisted

    remaining = iter(tasks)
    pending = deque(submit(task) for task in islice(remaining, limit))
    while pending:
        cached, future = pending.popleft()
        yield cached if cached is not None else future.result()
        next_task = next(remaining, None)
        if next_task is not None:
            pending.append(submit(next_task))


def _label_coverage(labels: LabelIndex, matched: set[tuple[str, str]]) -> dict:
    coverage = {
        source: {
            label: {"expected": 0, "matched": 0, "unmatched": 0}
            for label in ("malicious", "malicious-related")
        }
        for source in sorted(EXHAUSTIVE_HOSTS)
    }
    for key, entry in labels.entries.items():
        row = coverage[entry["source"]][entry["label"]]
        row["expected"] += 1
        row["matched" if key in matched else "unmatched"] += 1
    return coverage


def _check_output_root(output_root: Path, data_root: Path) -> None:
    target, source = output_root.absolute(), data_root.absolute()
    for path in [*target.parents, target]:
        if path.is_symlink() or path.is_junction():
            raise ValueError("output root must not traverse a filesystem link")
    if target.resolve().is_relative_to(
        source.resolve()
    ) or source.resolve().is_relative_to(target.resolve()):
        raise ValueError("output root must be separate from raw data")
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise FileExistsError("output root is not empty; preserve prior build")


def prepare_dataset(
    *,
    sources: Path,
    splits: Path,
    label_policy: Path,
    data_root: Path,
    output_root: Path,
    workers: int = 4,
    late_projection: bool = False,
    checkpoint_root: Path | None = None,
) -> dict:
    """Prepare all fixed inputs; missing or interrupted members cannot complete.

    A successful scan still produces ``prepared_not_frozen`` artifacts. Invalid
    rows or unmatched labels are measured and block the scan's freezing gate;
    source integrity, manifest, and task failures raise before any cases emit.
    """
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be a positive integer")
    if not isinstance(late_projection, bool):
        raise ValueError("late_projection must be boolean")
    sources, splits, label_policy = Path(sources), Path(splits), Path(label_policy)
    data_root, output_root = Path(data_root), Path(output_root)
    _progress(output_root, "verifying_sources")
    verification = verify_sources(sources, data_root, check_crc=True)
    expected_archives = {*ARCHIVE_SOURCES, "system_logs_labels.zip"}
    verified_rows = verification.get("archives", [])
    if (
        verification.get("verified") is not True
        or len(verified_rows) != 3
        or {row["path"] for row in verified_rows} != expected_archives
        or any(row.get("crc_checked") is not True for row in verified_rows)
    ):
        raise ValueError(
            "all three official archives must pass complete source verification"
        )
    split_config, policy = read_json(splits), read_json(label_policy)
    _validate_scan_splits(split_config)
    _validate_policy(policy)
    label_archive = safe_file(data_root, "system_logs_labels.zip")
    labels = load_label_index(label_archive, exhaustive=True)
    _require_labels(labels)
    _check_output_root(output_root, data_root)
    input_hashes = {
        "sources": sha256(sources),
        "splits": sha256(splits),
        "label_policy": sha256(label_policy),
        **{f"archive:{row['path']}": row["sha256"] for row in verified_rows},
    }
    tasks: list[tuple[str, str]] = []
    member_md5 = {}
    manifests = []
    for archive_name in sorted(ARCHIVE_SOURCES):
        archive_path = safe_file(data_root, archive_name)
        manifest = read_archive_manifest(archive_path)
        if manifest is None:
            raise ValueError(
                f"official JSONL MD5 manifest is mandatory: {archive_name}"
            )
        checksums = manifest["checksums"]
        if not checksums or manifest["unique_members"] != len(checksums):
            raise ValueError("archive manifest has incomplete member coverage")
        manifests.append(
            {
                "archive": archive_name,
                "member": manifest["member"],
                "unique_members": manifest["unique_members"],
                "duplicate_entries": manifest["duplicate_entries"],
                "checksums_sha256": hashlib.sha256(
                    canonical(checksums).encode("utf-8")
                ).hexdigest(),
            }
        )
        tasks.extend((str(archive_path), member) for member in sorted(checksums))
        member_md5.update({(archive_name, member): digest for member, digest in checksums.items()})
    collector = WindowCollector(labels=labels, splits=split_config)
    member_summaries, errors = [], []
    _progress(output_root, "scanning", members_completed=0, members_expected=len(tasks), parsed_rows=0)
    pool, checkpoints = None, None
    try:
        if checkpoint_root is not None:
            checkpoints = MemberCheckpoints(
                checkpoint_root, data_root=data_root, output_root=output_root,
                input_hashes=input_hashes, member_md5=member_md5,
                labels=labels, splits=split_config,
            )
        if workers == 1:
            def scan_or_resume(task):
                cached = checkpoints.load(task) if checkpoints is not None else None
                return cached if cached is not None else scan_member(
                    Path(task[0]), task[1], labels=labels, splits=split_config,
                    late_projection=late_projection,
                )

            results = (
                scan_or_resume(task) for task in tasks
            )
        else:
            pool = ProcessPoolExecutor(
                max_workers=workers,
                initializer=initialize_worker,
                initargs=((str(label_archive), split_config, True) if late_projection
                          else (str(label_archive), split_config)),
            )
            results = _bounded_member_results(pool, tasks, limit=workers * 2, checkpoints=checkpoints)
        for task, state in zip(tasks, results, strict=True):
            if (
                state.get("completed") is not True
                or state.get("jsonl_md5_verified") is not True
                or (state.get("archive"), state.get("member"))
                != (Path(task[0]).name, task[1])
            ):
                raise ValueError("incomplete or mismatched member scan result")
            if checkpoints is not None:
                # Save only after complete iterator exhaustion/JSONL MD5. A
                # restart begins with an empty collector and merges once.
                checkpoints.save(state)
            merge_collector_state(collector, state)
            member_summaries.append(
                {
                    "archive": state["archive"],
                    "member": state["member"],
                    "raw_rows": state["stats"]["raw_rows"],
                    "parsed_rows": state["stats"]["parsed_rows"],
                    "invalid_rows": state["stats"]["invalid_rows"],
                    "jsonl_md5_verified": True,
                }
            )
            errors.extend(
                state["invalid_examples"][: max(0, _ERROR_LIMIT_TOTAL - len(errors))]
            )
            _progress(output_root, "scanning", members_completed=len(member_summaries), members_expected=len(tasks),
                      parsed_rows=collector.stats["parsed_rows"], invalid_rows=collector.stats["invalid_rows"],
                      label_fingerprints_matched=len(collector.matched_labels))
        if checkpoints is not None:
            checkpoints.verify_code_unchanged()
    finally:
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        if checkpoints is not None:
            checkpoints.close()
    if len(member_summaries) != len(tasks):
        raise ValueError("full archive scan did not complete every required member")
    for name, path in (
        ("sources", sources),
        ("splits", splits),
        ("label_policy", label_policy),
    ):
        if sha256(path) != input_hashes[name]:
            raise ValueError("input configuration changed during archive scan")
    scan = {
        **collector.finish(),
        "full_archive_scan": True,
        "members_expected": len(tasks),
        "members_completed": len(member_summaries),
        "archive_manifests": manifests,
        "member_summaries": member_summaries,
        "invalid_rows": collector.stats["invalid_rows"],
        "invalid_examples": errors,
        "invalid_example_limit": _ERROR_LIMIT_TOTAL,
        "label_coverage": _label_coverage(labels, collector.matched_labels),
        "duplicate_count_scope": "duplicates observed while locally retained plus duplicate retained candidates during canonical member merge",
        "freeze_eligible": collector.stats["invalid_rows"] == 0
        and not (set(labels.entries) - collector.matched_labels),
    }
    selection = emit_cases(
        collector, output_root=output_root, input_hashes=input_hashes
    )
    selection_path = output_root / "selection.json"
    # emit_cases created this exact file in this run. Never overwrite a prior
    # artifact, and serialize the returned enriched result into the same file.
    if selection_path.read_text(encoding="utf-8") != canonical(selection) + "\n":
        raise ValueError(
            "newly created selection changed before scan metadata was attached"
        )
    selection["scan"], selection["source_verification"] = scan, verification
    selection_path.write_text(
        canonical(selection) + "\n", encoding="utf-8", newline="\n"
    )
    _progress(output_root, "prepared_not_frozen", members_completed=len(member_summaries), members_expected=len(tasks),
              parsed_rows=collector.stats["parsed_rows"], invalid_rows=collector.stats["invalid_rows"], N_D=selection["N_D"], M_D=selection["M_D"])
    return selection


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sources", "splits", "label-policy", "data-root", "output-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--late-projection", action="store_true",
                        help="Use validated lazy projection; frozen bytes remain identical")
    parser.add_argument("--checkpoint-root", type=Path,
                        help="Reuse complete verified members from this build's JSON checkpoint directory")
    args = parser.parse_args(argv)
    result = prepare_dataset(**vars(args))
    print(
        canonical(
            {"status": result["status"], "N_D": result["N_D"], "M_D": result["M_D"]}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
