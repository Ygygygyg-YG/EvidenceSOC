"""Audit final DEDALE v3/v4 cases without changing or freezing any dataset."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evals.datasets.dedale.audit import audit_prepared
from evals.datasets.dedale.common import (
    canonical,
    read_json,
    safe_file,
    sha256,
    write_new,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sources", "scan-splits", "splits", "label-policy", "data-root", "cases-root",
                 "prepared-root", "preparation-checkpoints", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("live-report", "live-events", "live-raw-events", "cross-path-report", "stage-review", "resource-report",
                 "neutral-root", "neutral-policy", "leak-review"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--replay-workers", type=int, choices=range(1, 9), default=1,
                        help="v4 independent raw replay processes (default: serial)")
    args = parser.parse_args(argv)
    errors = []

    def load(path):
        if path is None:
            return None
        try:
            value = read_json(path)
            if not isinstance(value, dict):
                raise TypeError("report must be an object")
            return value
        except (ValueError, TypeError, OSError) as exc:
            errors.append({"file": str(path), "error": type(exc).__name__})
            return None

    try:
        selection_path = safe_file(args.cases_root, "selection.json")
        selection = load(selection_path)
    except (ValueError, OSError) as exc:
        selection_path, selection = None, None
        errors.append({"file": "selection.json", "error": type(exc).__name__})
    if not isinstance(selection, dict) or selection.get("protocol") not in {"dedale-neutral-v3", "dedale-public-priority-v4"}:
        errors.append({"file": "selection.json", "error": "MissingNeutralProtocol"})
        selection = {"protocol": "dedale-neutral-v3"}
    report = audit_prepared(
        selection, args.cases_root, sources=args.sources, data_root=args.data_root,
        prepared_root=args.prepared_root, preparation_checkpoints=args.preparation_checkpoints,
        splits=args.splits, scan_splits=args.scan_splits, label_policy=args.label_policy,
        live_report=load(args.live_report), live_events_path=args.live_events,
        live_raw_events_path=args.live_raw_events, cross_path_report=load(args.cross_path_report),
        review_report=load(args.stage_review), resource_report=load(args.resource_report),
        neutral_root=args.neutral_root, neutral_policy=args.neutral_policy,
        leak_review=load(args.leak_review), replay_workers=args.replay_workers,
    )
    report["input_errors"] = errors
    report["selection_sha256"] = sha256(selection_path) if selection_path and selection_path.is_file() else None
    if errors:
        report["accepted"] = False
    # Preserve prior acceptance evidence; the command never rewrites case data.
    write_new(args.output, report)
    print(canonical({"accepted": report["accepted"], "failed_gates": report["failed_gates"], "report": str(args.output)}))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
