"""Stream one AIT annotation mirror into isolated scoring records."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import Any

_spec = importlib.util.spec_from_file_location(
    "_ait_join_parser", Path(__file__).with_name("parse.py")
)
assert _spec is not None and _spec.loader is not None
_parser = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_parser)


def _object(raw: bytes) -> dict[str, Any]:
    def reject_constant(value):
        raise ValueError(f"nonfinite JSON constant is forbidden: {value}")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSONL encoding or JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("JSONL record must be an object")  # noqa: TRY004
    return value


def _number(value: Any, previous: int) -> int:
    if type(value) is not int or value <= previous:
        raise ValueError(
            "physical line numbers must be positive and strictly increasing"
        )
    return value


def join_labels(
    *,
    dataset_root: Path,
    dataset_id: str,
    relative_log_path: str,
    events: Path,
    output: Path,
    report: Path,
    max_events: int | None = None,
) -> dict[str, Any]:
    """Join ordered streams, preserving absent annotations as unknown."""
    _parser._validate_dataset_id(dataset_id)
    relative_log_path = _parser._log_path(relative_log_path)
    if max_events is not None and (type(max_events) is not int or max_events < 1):
        raise ValueError("max_events must be a positive integer")
    for path in (dataset_root, events, output, report):
        _parser._reject_path_links(Path(path))
    root, events = Path(dataset_root).resolve(), Path(events).resolve()
    gather = root / "gather"
    source = gather / relative_log_path
    _parser._reject_path_links(source)
    if os.name == "nt":
        source = _parser._windows_canonical_source(gather, relative_log_path)
    relative_log_path = _parser._log_path(source.relative_to(gather).as_posix())
    annotations = root / "labels" / relative_log_path
    _parser._reject_path_links(annotations)
    for path in (source, annotations, events):
        if not path.is_file():
            raise FileNotFoundError(path)
    output, report = Path(output).resolve(), Path(report).resolve()
    if output == report:
        raise ValueError("output and report must be distinct")
    for path in (output, report):
        if path.is_relative_to(root) or path.is_relative_to(events.parent):
            raise ValueError(
                "gold and report must be outside raw and Agent input directories"
            )
        if path.exists():
            raise FileExistsError(path)
    summary = {
        "dataset_id": dataset_id,
        "relative_log_path": relative_log_path,
        "read_events": 0,
        "labeled_events": 0,
        "unlabeled_unknown_events": 0,
        "matched_annotation_lines": 0,
        "unmatched_annotation_lines": 0,
        "read_annotation_lines": 0,
        "truncated": False,
        "labels_complete_read": False,
        "raw_line_count": 0,
        "label_bounds_verified": False,
        "labels_sha256": "",
        "labels_hash_scope": "prefix",
    }
    created = []
    annotation_hash = hashlib.sha256()
    previous_annotation = 0
    previous_event = 0
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        report.parent.mkdir(parents=True, exist_ok=True)
        with (
            source.open("rb") as raw_file,
            annotations.open("rb") as label_file,
            events.open("rb") as event_file,
            output.open("x", encoding="utf-8", newline="\n") as gold_file,
        ):
            created.append(output)

            def next_annotation():
                nonlocal previous_annotation
                raw = label_file.readline()
                if not raw:
                    summary["labels_complete_read"] = True
                    return None
                annotation_hash.update(raw)
                summary["read_annotation_lines"] += 1
                row = _object(raw)
                previous_annotation = _number(row.get("line"), previous_annotation)
                labels, rules = row.get("labels"), row.get("rules")
                if (
                    not isinstance(labels, list)
                    or any(not isinstance(x, str) or not x for x in labels)
                    or not isinstance(rules, dict)
                    or any(
                        not isinstance(k, str)
                        or not isinstance(v, list)
                        or any(not isinstance(x, str) or not x for x in v)
                        for k, v in rules.items()
                    )
                ):
                    raise ValueError("invalid annotation labels or rules")
                if set(labels) != set(rules):
                    raise ValueError("annotation labels and rule keys must agree")
                return row

            pending = next_annotation()
            while max_events is None or summary["read_events"] < max_events:
                raw_event = event_file.readline()
                if not raw_event:
                    break
                event = _object(raw_event)
                number = _number(event.get("line_number"), previous_event)
                previous_event = number
                if {
                    "labels",
                    "rules",
                    "dataset_labels",
                    "annotation_status",
                    "is_attack",
                    "attack_types",
                } & event.keys():
                    raise ValueError(
                        "ground truth fields are forbidden in Agent events"
                    )
                if (
                    event.get("dataset_id") != dataset_id
                    or event.get("relative_log_path") != relative_log_path
                ):
                    raise ValueError(
                        "event source does not match the requested dataset and log"
                    )
                key = json.dumps(
                    [dataset_id, relative_log_path, number],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                if event.get("external_id") != "ait:" + hashlib.sha256(key).hexdigest():
                    raise ValueError("external_id does not match source key")
                while summary["raw_line_count"] < number:
                    raw_line = raw_file.readline()
                    if not raw_line:
                        raise ValueError("event references a nonexistent physical line")
                    summary["raw_line_count"] += 1
                if event.get("raw_line_sha256") != hashlib.sha256(raw_line).hexdigest():
                    raise ValueError("raw line SHA256 mismatch")
                while pending is not None and pending["line"] < number:
                    summary["unmatched_annotation_lines"] += 1
                    pending = next_annotation()
                matched = pending is not None and pending["line"] == number
                labels = pending["labels"] if matched else []
                rules = pending["rules"] if matched else {}
                status = "labeled" if labels else "unlabeled_unknown"
                gold = {
                    k: event[k]
                    for k in (
                        "dataset_id",
                        "relative_log_path",
                        "line_number",
                        "external_id",
                        "raw_line_sha256",
                    )
                }
                gold.update(labels=labels, rules=rules, annotation_status=status)
                gold_file.write(json.dumps(gold, ensure_ascii=False) + "\n")
                summary["read_events"] += 1
                summary[status + "_events"] += 1
                if matched:
                    summary["matched_annotation_lines"] += 1
                    # Consume the next label only when another event needs it.
                    pending = None
                if matched and (
                    max_events is None or summary["read_events"] < max_events
                ):
                    pending = next_annotation()
            summary["truncated"] = (
                event_file.tell() < os.fstat(event_file.fileno()).st_size
            )
            if not summary["truncated"]:
                for _ in raw_file:
                    summary["raw_line_count"] += 1
                if pending is not None:
                    summary["unmatched_annotation_lines"] += 1
                if not summary["labels_complete_read"]:
                    while next_annotation() is not None:
                        summary["unmatched_annotation_lines"] += 1
                if previous_annotation > summary["raw_line_count"]:
                    raise ValueError(
                        "annotation references a nonexistent physical line"
                    )
                summary["label_bounds_verified"] = True
            summary["labels_sha256"] = annotation_hash.hexdigest()
            summary["labels_hash_scope"] = (
                "complete" if summary["labels_complete_read"] else "prefix"
            )
        with report.open("x", encoding="utf-8", newline="\n") as report_file:
            created.append(report)
            report_file.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return summary


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    for flag in ("dataset-root", "events", "output", "report"):
        cli.add_argument("--" + flag, type=Path, required=True)
    cli.add_argument("--dataset-id", required=True)
    cli.add_argument("--log-path", required=True)
    cli.add_argument("--max-events", type=int)
    args = vars(cli.parse_args(argv))
    args["relative_log_path"] = args.pop("log_path")
    try:
        summary = join_labels(**args)
    except (OSError, ValueError) as exc:
        cli.error(str(exc))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
