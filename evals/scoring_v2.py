"""Read-only host bridge from native supplemental artifacts to existing metrics.

collect_regression -> prepare_reviews (separate blinded user review) ->
score_bundle -> write_immutable_json -> plots.generate.generate_bundle.
Never rewrite runner attempts or supply original 64-slot judgments. Score output
remains explicitly intermediate: completeness is independently adjudicated.
"""

import json
from hashlib import sha256
from math import isfinite
from pathlib import Path

from evals.contracts import AdapterResult, canonical_hash
from evals.human_review_v2 import read_pin, validate_reviews
from evals.metrics import score_rows
from evals.metrics.verification import score_verification
from evals.remediation import _summary, validate_bundle
from evals.runners.manifest import validate_plan
from evals.runners.score import (
    _resource_coverage,
    _resources,
    _tool_ledger_complete,
    load_gold,
)
from evals.task13_rolling import _plain_rolling, _read_rolling

SCOPE = "real_execution"
ORIGINAL_PLAN_SHA256 = {
    "ait": "50548d6b9d04705457622c056c76b5817ac180cb2e2eb12fbfa60e8d18e3eba5",
    "dedale": "b9e5c240ed02839428154da4f69cf26069ef3f800ef541aca7f8b1f0ec181540",
}


def load_original_plans(pins):
    if set(pins) != set(ORIGINAL_PLAN_SHA256) or any(
        pins[d]["sha256"] != digest for d, digest in ORIGINAL_PLAN_SHA256.items()
    ):
        raise ValueError("trusted original frozen scoring plan raw hashes required")
    return {d: validate_plan(read_pin(pins[d])) for d in ORIGINAL_PLAN_SHA256}


def validate_scoring_row(row, plans):
    plan = plans[row["dataset"]]
    original = [
        r
        for r in plan["rows"]
        if r["case_id"] == row["case_id"] and r["group"] == row["group"]
    ]
    if len(original) != 1:
        raise ValueError("new formal row absent from original scoring plan")
    if original[0]["input_hashes"] != row["input_hashes"]:
        raise ValueError("new formal agent input differs from original scoring case")
    root = _plain_rolling(Path(plan["controller"]["case_root"]) / row["case_id"])
    for name, digest in original[0]["input_hashes"].items():
        if (
            Path(name).name != name
            or sha256(_read_rolling(root / "agent" / name)).hexdigest() != digest
        ):
            raise ValueError("original scoring agent input changed")
    bound = original[0]["scoring_hashes"]
    if not {"manifest.json", "gold.jsonl"} <= bound.keys():
        raise ValueError("original frozen gold hashes missing")
    for name, digest in bound.items():
        if (
            Path(name).name != name
            or sha256(_read_rolling(root / "scoring" / name)).hexdigest() != digest
        ):
            raise ValueError("original frozen scoring artifact changed")
    return root, bound


def collect_regression(bundle_pin, output_root):
    bundle = read_pin(bundle_pin)
    requests = validate_bundle(bundle)
    if bundle["purpose"] != "regression" or len(requests) != 176:
        raise ValueError("only the new formal 176 regression is scoreable here")
    identities = [(r.case_id, r.group) for r in requests]
    if len(set(identities)) != 176 or any(
        sum(cid.startswith(dataset + "-") for cid, _ in identities) != count
        for dataset, count in [("ait", 44), ("dedale", 132)]
    ):
        raise ValueError("formal 22/66 cases and B2/B3 pairs required")
    root = _plain_rolling(output_root)
    # Inspect every existing input before the original parser reads it.
    for path in root.rglob("*.json"):
        _read_rolling(path)
    summary = _summary(bundle, root, SCOPE)
    rows = []
    for registered, request, status in zip(
        bundle["rows"], requests, summary["rows"], strict=True
    ):
        directory = root / registered["slot_id"]
        result, attempt, output_hash = None, None, None
        if (directory / "attempt.json").exists():
            attempt = json.loads(_read_rolling(directory / "attempt.json"))
            raw = _read_rolling(directory / "result.json")
            output_hash = sha256(raw).hexdigest()
            if output_hash != attempt["result_sha256"] or attempt["scope"] != SCOPE:
                raise ValueError("sealed attempt/output binding differs")
            value = json.loads(raw)
            start = json.loads(_read_rolling(directory / "started.json"))
            if (
                start.get("scope") != SCOPE
                or start.get("slot_id") != registered["slot_id"]
                or start.get("input_hashes") != registered["input_hashes"]
                or attempt.get("slot_id") != registered["slot_id"]
                or attempt.get("started_at") != start.get("started_at")
            ):
                raise ValueError("actual attempt identity differs")
            if status["status"] != "unknown":
                result = AdapterResult.model_validate(value).model_dump(mode="json")
                expected_status = (
                    "completed"
                    if result["execution_status"] == "completed"
                    else "failed"
                )
                if status["status"] != expected_status:
                    raise ValueError("sealed result and attempt status differ")
            else:
                result = value
        rows.append(
            {
                "slot_id": registered["slot_id"],
                "input_hashes": registered["input_hashes"],
                "case_id": request.case_id,
                "group": request.group,
                "dataset": request.case_id.split("-", 1)[0],
                "request": request.model_dump(mode="json"),
                "result": result,
                "output_sha256": output_hash,
                "attempts": [{"record": attempt, "result": result}] if attempt else [],
                "execution_status": status["status"]
                if status["status"] != "not_started"
                else "missing",
                "diagnosis_status": (result or {}).get("diagnosis_status", "missing"),
            }
        )
    return rows


def score_f8(snapshot):
    """Pure existing scorer; records must come from native journal adapter below."""
    return {
        dataset: score_verification(
            [r for r in snapshot["records"] if r["case_id"].startswith(dataset + "-")],
            [
                s
                for s in snapshot["planned_slots"]
                if s["case_id"].startswith(dataset + "-")
            ],
        )
        for dataset in ("ait", "dedale")
    }


def native_f8(campaign):
    from evals.verification_v2 import VerificationCampaign

    if type(campaign) is not VerificationCampaign:
        raise TypeError("native verification campaign required")
    # Read-only verified journal under its writer lock, not mutable projection.
    with campaign._lock():
        campaign._guard()
        campaign._load()
        snapshot = campaign._snapshot()
        for row in snapshot["records"]:
            binding = snapshot["cases"][row["case_id"]].get("binding")
            receipt = (
                campaign._blob("approvals", binding["approval_receipt_sha256"])
                if binding
                else None
            )
            row["approval_status"] = (
                "approved"
                if receipt and receipt.get("decision") == "approved"
                else "unavailable"
            )
            value = (
                campaign._blob("outputs", row["output_sha256"])
                if row.get("output_sha256")
                else {}
            )
            row["cost"] = value.get("cost")
            if (
                not isinstance(row["cost"], (int, float))
                or isinstance(row["cost"], bool)
                or not isfinite(row["cost"])
                or row["cost"] < 0
            ):
                row["cost"] = None
        return snapshot


def validate_f8_scope(
    joint_scope_pin,
    bundle,
    campaign,
    *,
    formal_host_pin=None,
    joint_decision_pin=None,
    output_root=None,
):
    """Audit sealed native authority; never use the execution deadline gate.

    Local JSON is a provenance record, not proof of human presence. The operator
    must retain the actual incoming reply and its original record identity.
    """
    from copy import deepcopy

    from evals.task13_rolling import NativeRollingOperations
    from evals.verification_v2 import VerificationCampaign
    from scripts.task13_regression import RegressionHost

    if formal_host_pin is None or joint_decision_pin is None or output_root is None:
        raise ValueError("sealed native host and actual joint decision required")
    if type(campaign) is not VerificationCampaign:
        raise PermissionError("actual native F8 campaign required")
    host = RegressionHost(formal_host_pin["path"], formal_host_pin["sha256"])
    if host._manifest["synthetic"] or host._free:
        raise PermissionError("synthetic host cannot confer formal scoring authority")
    if _plain_rolling(output_root) != host._root:
        raise PermissionError("actual formal output directory differs from sealed host")
    if _read_rolling(host._root / "host-binding.json") != host._raw:
        raise PermissionError("actual formal host binding differs")
    if (
        json.loads(_read_rolling(campaign.root / "registration.json"))
        != campaign._registration
    ):
        raise PermissionError("actual F8 registration differs")
    data = host._load()
    host._fixed(data)
    for name in ("human_review_v2.py", "scoring_v2.py"):
        path = Path(__file__).resolve().parent / name
        if (
            data["final_freeze"]["source_files"].get(str(path))
            != sha256(_read_rolling(path)).hexdigest()
        ):
            raise PermissionError(
                "actual scoring/review bridge is outside final freeze"
            )
    if data["bundle"] != bundle:
        raise PermissionError("actual formal bundle differs from sealed host")
    view = object.__new__(NativeRollingOperations)
    view.host, view.campaign = host, campaign
    view.scope_pin, view.decision_pin = (
        deepcopy(joint_scope_pin),
        deepcopy(joint_decision_pin),
    )
    view.scope, view.decision = read_pin(joint_scope_pin), read_pin(joint_decision_pin)
    view.options = read_pin(view.scope["verification_runtime_options"])
    view.policy = read_pin(view.scope["participation_policy"])
    view.identity, view.rows = deepcopy(campaign.identity), deepcopy(bundle["rows"])
    view._check_frozen_scope()
    return {
        "joint_scope": deepcopy(view.scope_pin),
        "joint_decision": deepcopy(view.decision_pin),
    }


def score_bundle(
    bundle_pin,
    output_root,
    *,
    scoring_plan_pins,
    prepared_pin=None,
    captures=(),
    verification_campaign=None,
    joint_scope_pin=None,
    formal_host_pin=None,
    joint_decision_pin=None,
):
    """Independent score artifact. scoring_plan_pins are original frozen plans.

    Pin the returned JSON independently; pass its path directly to generate_bundle.
    No new execution, registration, database access, or approval occurs here.
    """
    bundle = read_pin(bundle_pin)
    plans = load_original_plans(scoring_plan_pins)
    authority = validate_f8_scope(
        joint_scope_pin,
        bundle,
        verification_campaign,
        formal_host_pin=formal_host_pin,
        joint_decision_pin=joint_decision_pin,
        output_root=output_root,
    )
    rows = collect_regression(bundle_pin, output_root)
    prepared = read_pin(prepared_pin) if prepared_pin else None
    successor = (
        prepared and prepared.get("schema_version") == "task13-human-review-prepared-v3"
    )
    human_authority = (
        {
            "joint_scope_pin": authority["joint_scope"],
            "joint_decision_pin": authority["joint_decision"],
        }
        if successor
        else {}
    )
    reviews = (
        validate_reviews(prepared_pin, captures, rows, **human_authority)
        if prepared_pin
        else {}
    )
    if captures and not prepared_pin:
        raise ValueError("human capture requires the original prepared packet")
    groups, hashes = _assemble_score_groups(
        bundle_pin, scoring_plan_pins, plans, rows, reviews
    )
    verification = native_f8(verification_campaign) if verification_campaign else None
    if verification and verification["source_commit"] != bundle["source_commit"]:
        raise ValueError("F8 and formal regression source identities differ")
    return {
        "schema_version": 1,
        "run_id": bundle["campaign_id"] + "-formal176",
        "metadata": {
            "source_commit": bundle["source_commit"],
            "requested_model": rows[0]["request"]["model"]["requested_model"],
            "published_version": rows[0]["request"]["model"]["published_version"],
            "planned_n": 176,
            "formal_complete": False,
            "score_status": "independent_intermediate",
            "human_metrics_scope": "new registered sixteen-slot sample only",
        },
        "groups": groups,
        "verification": score_f8(verification) if verification else {},
        "source_hashes": hashes,
        "human_review": {
            "prepared": prepared_pin,
            "records": reviews,
            "captures": list(captures),
            "review_window": ("anytime" if successor else "19:00-00:00 Asia/Shanghai")
            if prepared
            else None,
            "human_review_participation": (
                prepared["human_review_participation"] if successor else None
            ),
            "joint_scope": authority["joint_scope"] if successor else None,
            "joint_decision": authority["joint_decision"] if successor else None,
        },
        "verification_journal_head_sha256": verification.get("journal_head_sha256")
        if verification
        else None,
        "verification_identity": {
            k: verification[k]
            for k in ("plan_sha256", "source_commit", "source_sha256", "config_sha256")
        }
        if verification
        else None,
        "joint_scope": joint_scope_pin,
        "formal_host": formal_host_pin,
        "joint_decision": joint_decision_pin,
    }


def _assemble_score_groups(bundle_pin, scoring_plan_pins, plans, rows, reviews):
    """Shared read-only gold binding; authority remains each entrypoint's duty."""
    groups = {d: {g: [] for g in ("B2", "B3")} for d in ("ait", "dedale")}
    hashes = {"bundle_raw": bundle_pin["sha256"]}
    for dataset, plan in plans.items():
        if plan["controller"]["dataset"] != dataset:
            raise ValueError("original scoring plan dataset differs")
        hashes["original_scoring_plan:" + dataset] = scoring_plan_pins[dataset][
            "sha256"
        ]
    for row in rows:
        root, _ = validate_scoring_row(row, plans)
        gold, mask, gold_hashes = load_gold(root, row["dataset"])
        hashes["gold:" + row["case_id"]] = canonical_hash(gold_hashes)
        hashes["output:" + row["slot_id"]] = row["output_sha256"]
        manifest = json.loads(_read_rolling(root / "agent" / "manifest.json"))
        usage, calls, tools, latency = _resources(row["attempts"])
        result = row["result"] or {}
        groups[row["dataset"]][row["group"]].append(
            {
                **row,
                "row_id": row["slot_id"],
                "group_id": row["group"],
                "gold": gold,
                "applicability": mask,
                "scenario": manifest.get("scenario", "unspecified"),
                "diagnosis": result.get("diagnostic_snapshot"),
                "evidence_registry": result.get("evidence_registry", {}),
                "usage": usage,
                "resource_coverage": _resource_coverage(row["attempts"]),
                "model_calls": calls,
                "tool_calls": tools,
                "tool_ledger_complete": _tool_ledger_complete(row["attempts"]),
                "latency_ms": latency,
                "human_review": reviews.get(row["slot_id"]),
                "reserved_tool_slots": row["request"]["budget"]["max_tool_calls"],
            }
        )
    return _score_groups(groups), hashes


def _score_groups(groups):
    """Pure shared metric assembly with the original formula and denominators."""
    return {
        d: {g: score_rows(values) for g, values in gs.items()}
        for d, gs in groups.items()
    }


def score_regression_only(
    bundle_pin,
    output_root,
    *,
    scoring_plan_pins,
    formal_host_pin,
    prepared_pin=None,
    captures=(),
):
    """Score complete sealed176 offline; E3/F8 remain explicitly deferred.

    Requires an independently pinned native host, original frozen gold/plans and
    v4 human16 records. Partial actual reviews may be reported, but never confer
    human completeness or response-plan approval. Synthetic evidence earns only
    offline contract-test labels. Returned JSON must be independently pinned.
    """
    from evals.regression_only_authority import validate_regression_only_scope

    if output_root is None:
        raise ValueError("explicit external regression output root required")
    authority = validate_regression_only_scope(
        formal_host_pin, bundle_pin=bundle_pin, output_root=output_root
    )
    bundle, rows = authority["bundle"], authority["rows"]
    plans = load_original_plans(scoring_plan_pins)
    prepared = read_pin(prepared_pin) if prepared_pin else None
    if prepared and prepared.get("schema_version") != "task13-human-review-prepared-v4":
        raise ValueError("regression-only scoring requires its own human16 packet")
    if captures and not prepared_pin:
        raise ValueError("human capture requires the original prepared packet")
    reviews = (
        validate_reviews(
            prepared_pin, captures, rows, regression_only_host_pin=formal_host_pin
        )
        if prepared_pin
        else {}
    )
    objective_reasons = {"missing_output", "no_report", "no_factual_claims"}
    resolved = sum(
        r["reviewed"] is True or r.get("reason") in objective_reasons
        for r in reviews.values()
    )
    human_complete = len(reviews) == 16 and resolved == 16
    groups, hashes = _assemble_score_groups(
        bundle_pin, scoring_plan_pins, plans, rows, reviews
    )
    hashes.update(
        {
            "formal_host_raw": formal_host_pin["sha256"],
            **{
                "host_input:" + key: value["sha256"]
                for key, value in authority["input_pins"].items()
            },
        }
    )
    synthetic = authority["synthetic"]
    return {
        "schema_version": 1,
        "artifact_schema": "task13-regression-only-score-v1",
        "run_id": bundle["campaign_id"] + "-regression-only176",
        "metadata": {
            "source_commit": bundle["source_commit"],
            "requested_model": rows[0]["request"]["model"]["requested_model"],
            "published_version": rows[0]["request"]["model"]["published_version"],
            "planned_n": 176,
            "formal_complete": False,
            "score_status": "offline_contract_test"
            if synthetic
            else "independent_intermediate",
            "mode": "regression_only",
            "synthetic": synthetic,
            "scope": "offline_contract_test" if synthetic else "real_execution",
            "human_metrics_scope": "new registered sixteen-slot sample only",
            "human_metrics_complete": human_complete,
        },
        "groups": groups,
        "verification": {},
        "verification_identity": None,
        "verification_journal_head_sha256": None,
        "deferred": {"E3": "deferred", "F8": "deferred"},
        "source_hashes": hashes,
        "formal_host": formal_host_pin,
        "human_review": {
            "prepared": prepared_pin,
            "records": reviews,
            "captures": list(captures),
            "review_window": "anytime" if prepared else None,
            "human_review_participation": prepared["human_review_participation"]
            if prepared
            else None,
            "resolved_slots": resolved,
            "planned_slots": 16,
            "complete": human_complete,
            "response_plan_approval_credit": 0,
        },
    }
