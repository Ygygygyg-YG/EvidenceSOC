"""Controller-only plan, dispatch and independent score commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evals.contracts import AdapterResult
from evals.datasets.dedale.common import read_json
from evals.runners.execute import collect_rows, create_rerun_permit, execute_plan
from evals.runners.manifest import build_plan, validate_plan, write_immutable_json


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    plan = commands.add_parser(
        "plan", help="Freeze the full case × eight-group matrix without model calls"
    )
    plan.add_argument("--config", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    execute = commands.add_parser(
        "execute", help="Dispatch immutable single-case Docker workers"
    )
    execute.add_argument("--plan", type=Path, required=True)
    execute.add_argument("--output-root", type=Path, required=True)
    execute.add_argument("--runtime-config", type=Path)
    execute.add_argument("--allow-final-test", action="store_true")
    execute.add_argument(
        "--fixture",
        action="store_true",
        help="Synthetic pipeline check only; refused for final test",
    )
    execute.add_argument("--row-limit", type=int)
    execute.add_argument("--rerun-permit", type=Path, action="append", default=[])
    score = commands.add_parser(
        "score", help="Read gold in this scoring process after attempts are sealed"
    )
    score.add_argument("--plan", type=Path, required=True)
    score.add_argument("--output-root", type=Path, required=True)
    score.add_argument("--output", type=Path, required=True)
    score.add_argument("--reviews", type=Path)
    score.add_argument("--verification", type=Path)
    permit = commands.add_parser(
        "authorize-rerun",
        help="Record explicit named approval of eligible infrastructure/transport rerun",
    )
    permit.add_argument("--plan", type=Path, required=True)
    permit.add_argument("--output-root", type=Path, required=True)
    permit.add_argument("--row-id", required=True)
    permit.add_argument("--approved-by", required=True)
    permit.add_argument(
        "--reason", choices=["infrastructure", "transport"], required=True
    )
    permit.add_argument("--output", type=Path, required=True)
    return root


async def _fixture(spec, _agent_dir):
    return AdapterResult(
        diagnostic_snapshot={
            "verdict": "unknown",
            "attack_types": [],
            "taxonomy_status": "unknown",
            "evidence_ids": [],
        },
        diagnosis_status="succeeded",
        degradation=[
            {"kind": "synthetic_pipeline_fixture", "real_model_invocations": 0}
        ],
        resources={"input_tokens": 0, "output_tokens": 0, "cost": 0},
    )


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    try:
        if args.command == "plan":
            value = build_plan(read_json(args.config))
            write_immutable_json(args.output, value)
            summary = {
                "status": "planned",
                "run_id": value["controller"]["run_id"],
                "planned": len(value["rows"]),
                "plan_sha256": value["plan_sha256"],
                "real_model_invocations": 0,
            }
        else:
            plan = validate_plan(read_json(args.plan))
            if args.command == "execute":
                runtime = (
                    read_json(args.runtime_config) if args.runtime_config else None
                )
                summary = execute_plan(
                    plan,
                    args.output_root,
                    worker=_fixture if args.fixture else None,
                    runtime_options=runtime,
                    row_limit=args.row_limit,
                    rerun_permits=[read_json(path) for path in args.rerun_permit],
                    allow_final_test=args.allow_final_test,
                )
                summary["mode"] = (
                    "synthetic_fixture" if args.fixture else "real_docker_worker"
                )
            elif args.command == "score":
                from evals.runners.score import write_scores

                reviews = None
                if args.reviews:
                    from evals.review import validated_reviews

                    reviews = validated_reviews(
                        args.reviews, collect_rows(plan, args.output_root)
                    )
                verification = (
                    read_json(args.verification) if args.verification else None
                )
                value = write_scores(
                    plan,
                    args.output_root,
                    args.output,
                    reviews=reviews,
                    verification=verification,
                )
                summary = {
                    "status": "scored",
                    "run_id": value["run_id"],
                    "formal_complete": False,
                    "score_status": value["metadata"]["score_status"],
                }
            else:
                row = next(
                    (
                        row
                        for row in collect_rows(plan, args.output_root)
                        if row["row_id"] == args.row_id
                    ),
                    None,
                )
                if row is None:
                    raise ValueError("rerun row is absent from plan")
                value = create_rerun_permit(
                    plan,
                    row,
                    approved_by=args.approved_by,
                    reason=args.reason,
                    output=args.output,
                )
                summary = {
                    "status": "rerun_authorized",
                    "row_id": args.row_id,
                    "permit_sha256": value["permit_sha256"],
                }
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True, allow_nan=False))
        return 0
    except Exception as error:  # noqa: BLE001 - CLI boundary sanitizes secret-bearing exceptions.
        # Exception strings may carry connection URLs or provider response text.
        # Detailed sanitized state remains in the protected immutable artifacts.
        print(json.dumps({"status": "failed", "error_type": type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
