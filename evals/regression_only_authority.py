"""Read-only native authority for independent regression scoring and human16.

The external raw host pin is the trust input. Decoded authority dictionaries,
workers, live admission, timing and F8 campaigns are never accepted here.
"""

from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from evals.remediation import validate_bundle
from scripts.task13_regression_only import FreeDependencies, RegressionOnlyHost

FROZEN_BRIDGES = (
    "evals/regression_only_authority.py",
    "evals/scoring_v2.py",
    "evals/human_review_v2.py",
)


def _offline_only(*args, **kwargs):
    raise PermissionError("offline authority cannot dispatch or validate a runtime")


def validate_regression_only_scope(
    formal_host_pin, *, bundle_pin=None, output_root=None
):
    """Independently validate native seals and return all176 normalized rows.

    Synthetic hosts receive only fail-closed dependency sentinels to satisfy the
    native constructor; their evidence remains offline_contract_test throughout.
    Neither caller authority dictionaries nor admission results are trusted.
    """
    from evals.human_review_v2 import _participation_policy, _strict_pin
    from evals.task13_rolling import _plain_rolling

    manifest = _strict_pin(formal_host_pin)
    dependencies = (
        FreeDependencies(_offline_only, _offline_only, lambda: datetime.now(UTC))
        if manifest.get("synthetic") is True
        else None
    )
    host = RegressionOnlyHost(
        formal_host_pin["path"],
        formal_host_pin["sha256"],
        free_dependencies=dependencies,
    )
    authority = host.validate_frozen_scope()
    if (
        authority.get("schema_version") != "task13-regression-only-frozen-authority-v1"
        or authority.get("status") != "verified"
        or authority.get("mode") != "regression_only"
        or authority.get("manifest_pin") != formal_host_pin
    ):
        raise PermissionError("independently verified regression-only host required")
    if bundle_pin is not None and bundle_pin != authority["input_pins"]["bundle"]:
        raise PermissionError("external bundle pin differs from frozen host")
    if output_root is not None and _plain_rolling(output_root) != host._root:
        raise PermissionError("external output root differs from frozen host")
    root = Path(__file__).resolve().parents[1]
    for relative in FROZEN_BRIDGES:
        path = root / relative
        if (
            authority["final_freeze"]["source_files"].get(str(path))
            != sha256(path.read_bytes()).hexdigest()
        ):
            raise PermissionError(
                "actual scoring/review authority bridge is outside freeze"
            )
    decision = authority["scope_decision"]
    if decision.get("automatic_approval", False) is not False or (
        not authority["synthetic"]
        and decision.get("synthetic_control_fixture", False) is not False
    ):
        raise PermissionError("actual regression-only human16 scope approval required")
    authority["human_review_participation"] = _participation_policy(
        authority["scope_packet"]
    )
    summary, attempts = authority["summary"], authority["attempts"]
    registered = authority["bundle"]["rows"]
    if (
        len(registered) != 176
        or summary["planned_n"] != 176
        or summary["counts"]["completed"] + summary["counts"]["failed"] != 176
        or summary["counts"]["unknown"]
        or summary["counts"]["not_started"]
        or len(attempts) != 176
        or [a["slot_id"] for a in attempts] != [r["slot_id"] for r in registered]
    ):
        raise PermissionError("complete176 sealed determinate outputs required")
    rows = []
    for row, request, attempt in zip(
        registered, validate_bundle(authority["bundle"]), attempts, strict=True
    ):
        artifacts = attempt["artifacts"]
        # The native validator read and checked these exact raw seals. Normalize
        # its detached snapshot, without reopening a second inconsistent view.
        result = artifacts["result"]["value"]
        rows.append(
            {
                "slot_id": row["slot_id"],
                "input_hashes": row["input_hashes"],
                "case_id": request.case_id,
                "group": request.group,
                "dataset": request.case_id.split("-", 1)[0],
                "request": request.model_dump(mode="json"),
                "result": result,
                "output_sha256": artifacts["result"]["pin"]["sha256"],
                "attempts": [
                    {"record": artifacts["attempt"]["value"], "result": result}
                ],
                "execution_status": attempt["status"],
                "diagnosis_status": result.get("diagnosis_status", "missing"),
            }
        )
    authority["rows"] = rows
    return authority
