"""Audit fixed DEDALE sources and prepared cases; any unmet gate exits nonzero."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evals.datasets.dedale.audit import audit_prepared
from evals.datasets.dedale.common import read_json, sha256


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sources", "selection", "data-root", "cases-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("live-report", "live-events", "live-raw-events", "resource-report", "crosspath-report", "stage-review", "output"):
        parser.add_argument("--" + name, type=Path)
    for name in ("prepared-root", "preparation-checkpoints", "splits", "scan-splits", "label-policy"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args(argv)
    research = args.data_root.parent / "research"
    errors = []

    def load(path, *, required=False):
        if path is None:
            return None
        try:
            return read_json(path)
        except (ValueError, OSError) as exc:
            if required or path.exists():
                errors.append({"file": path.name, "error": type(exc).__name__})
            return None

    selection = load(args.selection, required=True) or {"cases": [], "counts": {}, "N_D": None, "M_D": None}
    neutral = selection.get("protocol") == "dedale-neutral-v3"
    report = audit_prepared(
        selection, args.cases_root, sources=args.sources, data_root=args.data_root,
        prepared_root=args.prepared_root, preparation_checkpoints=args.preparation_checkpoints,
        splits=args.splits, scan_splits=args.scan_splits, label_policy=args.label_policy,
        live_report=load(args.live_report or research / "task12-live-report.json"),
        live_events_path=args.live_events or research / "benign-events.jsonl",
        live_raw_events_path=args.live_raw_events or research / "benign-raw.jsonl",
        resource_report=load(args.resource_report or research / "normal-resource-probe.json"),
        cross_path_report=load(args.crosspath_report or research / ("task12-final-crosspath-report.json" if neutral else "task12-crosspath-report.json")),
        review_report=load(args.stage_review or research / ("task12-stage-review-final-v3.json" if neutral else "task12-stage-review.json")),
    )
    report["input_errors"] = errors
    report["selection_sha256"] = sha256(args.selection) if args.selection.is_file() else None
    report["sources_manifest_sha256"] = sha256(args.sources) if args.sources.is_file() else None
    if errors:
        report["accepted"] = False
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
