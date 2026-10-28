"""Control-only preparation and single-writer execution for the new supplement.

Registration never authorizes execution. Real dispatch requires an external
source-bound admission verifier; this module never creates outbound consent.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
from copy import deepcopy
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from evals.adapters.artifacts import write_immutable_json
from evals.adapters.remediation_contracts import CAMPAIGN, RemediationRequest
from evals.contracts import (
    AdapterResult,
    CallBudget,
    ModelConfig,
    SeedPolicy,
    canonical_hash,
)
from evals.runners.manifest import agent_input

MODES = {"empty": "disabled", "semantic": "semantic_only", "hybrid": "hybrid"}
ROW_FIELDS = {
    "sequence",
    "slot_id",
    "case_id",
    "dataset",
    "status",
    "attempts",
    "output_sha256",
    "group",
    "input_hashes",
    "pair_order",
    "within_pair_order",
    "replicate",
    "v1_row_id",
    "outbound_authorization",
    "source_freeze",
    "rag_condition",
    "repeat",
    "initial_query_sha256",
}


def _purpose(registration):
    schemas = {
        "task13-v2-development-registration-v1": "development",
        "task13-v2-regression-registration-v1": "regression",
    }
    if (
        registration.get("campaign_id") != CAMPAIGN
        or registration.get("schema_version") not in schemas
    ):
        raise ValueError("dedicated v2 registration is required")
    return schemas[registration["schema_version"]]


def prepare_bundle(
    registration, *, source_commit, source_sha256, config, epoch_binding=None
):
    """Project only registered observable inputs into dedicated worker requests."""
    purpose = _purpose(registration)
    request_class = RemediationRequest
    if epoch_binding is not None:
        from evals.adapters.epoch_remediation import EpochRemediationRequest

        if (
            purpose != "regression"
            or not isinstance(epoch_binding, dict)
            or set(epoch_binding)
            not in (
                {"epoch_id", "epoch_manifest_sha256"},
                {"epoch_id", "epoch_manifest_sha256", "model_identity_binding"},
            )
        ):
            raise ValueError("complete explicit regression epoch binding is required")
        request_class = EpochRemediationRequest
        reference = epoch_binding.get("model_identity_binding")
        if "model_identity_binding" in epoch_binding and reference is None:
            raise ValueError("explicit null model identity reference is invalid")
        descriptor = config.get("model_identity")
        if (reference is None) != (descriptor is None):
            raise ValueError(
                "model identity descriptor and reference must both be present"
            )
        if reference is not None:
            from evals.adapters.e_planning_contracts import ModelIdentityBinding

            parsed = ModelIdentityBinding.model_validate(reference)
            if (
                not isinstance(descriptor, dict)
                or set(descriptor) != {"id", "response_model", "fingerprint"}
                or any(
                    not isinstance(v, str) or not v.strip() for v in descriptor.values()
                )
                or descriptor["id"] != parsed.model_epoch_id
            ):
                raise ValueError("model identity descriptor differs from reference")
    if (
        not isinstance(config.get("budget_identity"), dict)
        or config["budget_identity"].get("baseline_count", 0) < 3350
        or not isinstance(config.get("active_budget_path"), str)
        or not Path(config["active_budget_path"]).is_absolute()
        or Path(config["active_budget_path"]).name != "campaign.sqlite"
    ):
        raise ValueError(
            "frozen original active ledger path and complete history identity required"
        )
    rows = registration["rows"]
    development = purpose == "development"
    expected_n = 36 if development else 176
    if (
        len(rows) != expected_n
        or len({row["slot_id"] for row in rows}) != expected_n
        or any(
            set(row) - ROW_FIELDS or row.get("status") != "not_started" for row in rows
        )
        or any(row["sequence"] != i + 1 for i, row in enumerate(rows))
    ):
        raise ValueError("registration slots are incomplete, duplicated or changed")
    cases = {row["case_id"] for row in rows}
    if development:
        selected = {case["case_id"]: case for case in registration["cases"]}
        order = [(row["case_id"], row["rag_condition"], row["repeat"]) for row in rows]
        if (
            len(cases) != 4
            or cases != set(selected)
            or len(set(order)) != 36
            or any(
                {
                    (row["rag_condition"], row["repeat"])
                    for row in rows
                    if row["case_id"] == cid
                }
                != {(mode, repeat) for mode in MODES for repeat in (1, 2, 3)}
                for cid in cases
            )
        ):
            raise ValueError(
                "all registered four by three by three conditions are required"
            )
    else:
        selected = {}
        order = [(row["case_id"], row["group"]) for row in rows]
        if (
            registration.get("seed") != 42
            or len(cases) != 88
            or len(set(order)) != 176
            or sum(case.startswith("ait-") for case in cases) != 22
            or sum(case.startswith("dedale-") for case in cases) != 66
            or any(
                rows[i]["case_id"] != rows[i + 1]["case_id"] for i in range(0, 176, 2)
            )
            or any(
                {row["group"] for row in rows if row["case_id"] == cid} != {"B2", "B3"}
                for cid in cases
            )
        ):
            raise ValueError("all 88 adjacent B2/B3 pairs are required")
    if canonical_hash(order) != registration.get("order_sha256"):
        raise ValueError("registered dispatch order hash differs")
    projected = []
    for row in rows:
        case = selected.get(row["case_id"], row)
        hashes = case["input_hashes"]
        if set(hashes) != {"manifest.json", "events.jsonl"}:
            raise ValueError("exact answer-free agent input binding is required")
        fields = {
            "run_id": CAMPAIGN + "-" + canonical_hash([row["slot_id"], 1])[:16],
            "case_id": row["case_id"],
            "slot_id": row["slot_id"],
            "purpose": purpose,
            "group": "B3" if development else row["group"],
            "source_commit": source_commit,
            "source_sha256": source_sha256,
            "config_sha256": canonical_hash(config),
            "agent_sha256": hashes["events.jsonl"],
            "budget_identity": deepcopy(config["budget_identity"]),
            **{
                key: config[key] for key in ("model", "seed", "budget") if key in config
            },
        }
        if development:
            query = case["initial_query"]
            if sha256(query.encode()).hexdigest() != row["initial_query_sha256"]:
                raise ValueError("registered initial query differs")
            fields.update(
                rag_mode=MODES[row["rag_condition"]],
                initial_query=query,
                initial_query_sha256=row["initial_query_sha256"],
                repeat=row["repeat"],
            )
        request = request_class(**fields, **(epoch_binding or {}))
        projected.append(
            {
                "slot_id": row["slot_id"],
                "case_id": row["case_id"],
                "input_hashes": deepcopy(hashes),
                "request": request.model_dump(mode="json"),
            }
        )
    payload = {
        "schema_version": "task13-remediation-bundle-v2",
        "campaign_id": CAMPAIGN,
        "purpose": purpose,
        "executable": False,
        "registration_sha256": canonical_hash(registration),
        "source_commit": source_commit,
        "source_sha256": source_sha256,
        "config_sha256": canonical_hash(config),
        "budget_identity_sha256": canonical_hash(config["budget_identity"]),
        "config": deepcopy(config),
        "rows": projected,
    }
    if epoch_binding is not None:
        payload.update(
            schema_version="task13-remediation-bundle-v3",
            registered_order_sha256=registration["order_sha256"],
            **epoch_binding,
        )
    return {**payload, "bundle_sha256": canonical_hash(payload)}


def validate_bundle(bundle):
    epoch_bound = bundle.get("schema_version") == "task13-remediation-bundle-v3"
    payload = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    if (
        canonical_hash(payload) != bundle.get("bundle_sha256")
        or bundle.get("campaign_id") != CAMPAIGN
        or bundle.get("schema_version")
        not in {"task13-remediation-bundle-v2", "task13-remediation-bundle-v3"}
        or bundle.get("executable") is not False
        or bundle.get("purpose") not in {"development", "regression"}
    ):
        raise ValueError("supplement bundle hash or campaign differs")
    request_class = RemediationRequest
    epoch_fields = {"epoch_id", "epoch_manifest_sha256", "registered_order_sha256"}
    if epoch_bound:
        from evals.adapters.epoch_remediation import EpochRemediationRequest

        if bundle["purpose"] != "regression" or not epoch_fields <= bundle.keys():
            raise ValueError("explicit regression epoch bundle binding is required")
        request_class = EpochRemediationRequest
    elif epoch_fields & bundle.keys():
        raise ValueError("epoch binding requires its dedicated v3 bundle schema")
    if canonical_hash(bundle["config"]) != bundle["config_sha256"]:
        raise ValueError("frozen configuration differs")
    if (
        canonical_hash(bundle["config"]["budget_identity"])
        != bundle["budget_identity_sha256"]
    ):
        raise ValueError("original budget identity differs")
    requests = [request_class.model_validate(row["request"]) for row in bundle["rows"]]
    if epoch_bound:
        reference = bundle.get("model_identity_binding")
        if "model_identity_binding" in bundle and reference is None:
            raise ValueError("explicit null model identity reference is invalid")
        descriptor = bundle["config"].get("model_identity")
        if (reference is None) != (descriptor is None):
            raise ValueError(
                "model identity descriptor and reference must both be present"
            )
        if reference is not None:
            from evals.adapters.e_planning_contracts import ModelIdentityBinding

            parsed = ModelIdentityBinding.model_validate(reference)
            if (
                not isinstance(descriptor, dict)
                or set(descriptor) != {"id", "response_model", "fingerprint"}
                or any(
                    not isinstance(v, str) or not v.strip() for v in descriptor.values()
                )
                or descriptor["id"] != parsed.model_epoch_id
            ):
                raise ValueError("model identity descriptor differs from reference")
        if any(
            (
                r.model_identity_binding.model_dump(mode="json")
                if r.model_identity_binding is not None
                else None
            )
            != reference
            for r in requests
        ):
            raise ValueError("regression request model identity differs from bundle")
    if len(requests) != (36 if bundle["purpose"] == "development" else 176):
        raise ValueError("complete supplemental matrix required")
    if len({request.slot_id for request in requests}) != len(requests):
        raise ValueError("duplicate supplemental slot")
    if (
        epoch_bound
        and canonical_hash([(request.case_id, request.group) for request in requests])
        != bundle["registered_order_sha256"]
    ):
        raise ValueError("registered regression epoch slot order differs")
    cases = {request.case_id for request in requests}
    if bundle["purpose"] == "development":
        if (
            len(cases) != 4
            or sum(cid.startswith("ait-") for cid in cases) != 2
            or any(
                {(r.rag_mode, r.repeat) for r in requests if r.case_id == cid}
                != {(mode, repeat) for mode in MODES.values() for repeat in (1, 2, 3)}
                for cid in cases
            )
            or any(
                len({r.initial_query_sha256 for r in requests if r.case_id == cid}) != 1
                for cid in cases
            )
        ):
            raise ValueError("complete fixed-query development matrix required")
    elif (
        len(cases) != 88
        or sum(cid.startswith("ait-") for cid in cases) != 22
        or any(
            {r.group for r in requests if r.case_id == cid} != {"B2", "B3"}
            for cid in cases
        )
        or any(requests[i].case_id != requests[i + 1].case_id for i in range(0, 176, 2))
    ):
        raise ValueError("complete adjacent paired regression matrix required")
    for row, request in zip(bundle["rows"], requests, strict=True):
        if (
            set(row) != {"slot_id", "case_id", "input_hashes", "request"}
            or set(row["input_hashes"]) != {"events.jsonl", "manifest.json"}
            or any(
                not re.fullmatch(r"[0-9a-f]{64}", value)
                for value in row["input_hashes"].values()
            )
            or request.model != ModelConfig(**bundle["config"].get("model", {}))
            or request.budget != CallBudget(**bundle["config"].get("budget", {}))
            or request.seed != SeedPolicy(**bundle["config"].get("seed", {}))
            or request.budget_identity != bundle["config"]["budget_identity"]
            or (
                epoch_bound
                and any(
                    getattr(request, key) != bundle[key]
                    for key in ("epoch_id", "epoch_manifest_sha256")
                )
            )
            or row["slot_id"] != request.slot_id
            or row["case_id"] != request.case_id
            or row["input_hashes"]["events.jsonl"] != request.agent_sha256
            or any(
                getattr(request, key) != bundle[key]
                for key in (
                    "purpose",
                    "source_commit",
                    "source_sha256",
                    "config_sha256",
                )
            )
        ):
            raise ValueError("supplement worker binding differs")
    return requests


def _summary(bundle, root, scope):
    rows = []
    for row in bundle["rows"]:
        directory = root / row["slot_id"]
        status, reason = "not_started", None
        if (directory / "started.json").exists():
            start = json.loads((directory / "started.json").read_text(encoding="utf-8"))
            if start["bundle_sha256"] != bundle["bundle_sha256"] or start[
                "request_sha256"
            ] != canonical_hash(row["request"]):
                raise PermissionError("started attempt binding differs")
            gate_digest = start["admission_sha256"]
            admitted = json.loads(
                (root / "gates" / (gate_digest + ".json")).read_text(encoding="utf-8")
            )
            if (
                canonical_hash(admitted) != gate_digest
                or admitted.get("bundle_sha256") != bundle["bundle_sha256"]
            ):
                raise PermissionError("dispatch admission artifact differs")
            status, reason = "unknown", "dispatched_without_determinate_receipt"
        if (directory / "attempt.json").exists():
            record = json.loads(
                (directory / "attempt.json").read_text(encoding="utf-8")
            )
            if (
                status == "not_started"
                or record["bundle_sha256"] != bundle["bundle_sha256"]
            ):
                raise PermissionError("attempt has no bound start receipt")
            if (
                sha256((directory / "result.json").read_bytes()).hexdigest()
                != record["result_sha256"]
            ):
                raise PermissionError("immutable result hash differs")
            status, reason = record["status"], record.get("reason")
        rows.append(
            {
                "slot_id": row["slot_id"],
                "case_id": row["case_id"],
                "status": status,
                "reason": reason,
            }
        )
    return {
        "schema_version": "task13-remediation-progress-v2",
        "campaign_id": CAMPAIGN,
        "bundle_sha256": bundle["bundle_sha256"],
        "scope": scope,
        "planned_n": len(rows),
        "rows": rows,
        "counts": {
            status: sum(row["status"] == status for row in rows)
            for status in ("not_started", "completed", "failed", "unknown")
        },
    }


async def _execute(bundle, root, case_roots, admitter, worker, scope, row_limit):
    summary = _summary(bundle, root, scope)
    # A dispatched unknown requires evidence-bound operator reconciliation.
    # Advancing past it automatically would conceal a potentially in-flight call.
    if summary["counts"]["unknown"]:
        return summary
    dispatched = 0
    for row in bundle["rows"]:
        if row_limit is not None and dispatched >= row_limit:
            break
        directory = root / row["slot_id"]
        if (directory / "started.json").exists():
            continue
        identity = {
            key: bundle[key]
            for key in (
                "bundle_sha256",
                "campaign_id",
                "purpose",
                "source_commit",
                "source_sha256",
                "config_sha256",
                "budget_identity_sha256",
            )
        }
        epoch_bound = bundle["schema_version"] == "task13-remediation-bundle-v3"
        if epoch_bound:
            identity.update(
                {key: bundle[key] for key in ("epoch_id", "epoch_manifest_sha256")}
            )
        gate = admitter(deepcopy(identity))
        gate = await gate if inspect.isawaitable(gate) else gate
        if (
            not isinstance(gate, dict)
            or gate.get("status") != "verified"
            or gate.get("schema_version")
            != (
                "task13-v3-execution-gate-v1"
                if epoch_bound
                else "task13-v2-execution-gate-v1"
            )
            or gate.get("scope") != scope
            or any(gate.get(key) != value for key, value in identity.items())
        ):
            raise PermissionError(
                "verified source-bound execution admission is required"
            )
        cid = row["case_id"]
        agent, hashes = agent_input(Path(case_roots[cid.split("-", 1)[0]]), cid)
        if hashes != row["input_hashes"]:
            raise ValueError("case input changed after preregistration")
        directory.mkdir(parents=True, exist_ok=True)
        # No dispatch is possible until started.json is durably written below.
        # A crash before that marker may leave only a directory or admission.
        if {path.name for path in directory.iterdir()} - {"admission.json"}:
            raise PermissionError(
                "unrecognized pre-dispatch artifacts require reconciliation"
            )
        admission = directory / "admission.json"
        if admission.exists():
            previous = json.loads(admission.read_text(encoding="utf-8"))
            if any(
                previous.get(key) != gate[key]
                for key in ("schema_version", "status", "scope", *identity)
            ):
                raise PermissionError("pre-dispatch admission binding differs")
        else:
            write_immutable_json(admission, gate)
        gate_digest = canonical_hash(gate)
        gate_path = root / "gates" / (gate_digest + ".json")
        gate_path.parent.mkdir(exist_ok=True)
        if gate_path.exists():
            if json.loads(gate_path.read_text(encoding="utf-8")) != gate:
                raise PermissionError("immutable admission artifact differs")
        else:
            write_immutable_json(gate_path, gate)
        started = datetime.now(UTC).isoformat()
        write_immutable_json(
            directory / "started.json",
            {
                **identity,
                "scope": scope,
                "slot_id": row["slot_id"],
                "started_at": started,
                "request_sha256": canonical_hash(row["request"]),
                "input_hashes": hashes,
                "admission_sha256": gate_digest,
            },
        )
        try:
            if epoch_bound:
                from evals.adapters.epoch_remediation import EpochRemediationRequest

                request = EpochRemediationRequest.model_validate(row["request"])
            else:
                request = RemediationRequest.model_validate(row["request"])
            value = await worker(request, agent)
            value = AdapterResult.model_validate(value).model_dump(mode="json")
            status = (
                "completed" if value["execution_status"] == "completed" else "failed"
            )
            reason = None if status == "completed" else value["execution_status"]
        except Exception as error:  # noqa: BLE001 -- dispatch can be uncertain; never replay.
            status, reason = "unknown", "worker_dispatch_uncertain"
            value = {"errors": [{"type": type(error).__name__, "stage": "dispatch"}]}
        write_immutable_json(directory / "result.json", value)
        write_immutable_json(
            directory / "attempt.json",
            {
                "bundle_sha256": bundle["bundle_sha256"],
                "scope": scope,
                "slot_id": row["slot_id"],
                "status": status,
                "reason": reason,
                "started_at": started,
                "finished_at": datetime.now(UTC).isoformat(),
                "result_sha256": sha256(
                    (directory / "result.json").read_bytes()
                ).hexdigest(),
            },
        )
        dispatched += 1
        if status == "unknown" or any(
            error.get("type") == "BudgetLimit"
            or error.get("error_type") == "BudgetLimit"
            for error in value.get("errors", [])
        ):
            break
    return _summary(bundle, root, scope)


def execute_bundle(
    bundle,
    output_root,
    *,
    case_roots,
    admitter=None,
    runtime_options=None,
    offline_worker=None,
    row_limit=None,
):
    """Run the exact new matrix, or clearly marked synthetic contract tests.

    The trusted ``admitter`` must verify fresh R1/R2, outbound consent, model,
    prices, frozen source/configuration, isolation and budget evidence. It is
    invoked again before each dispatch. Merely changing executable=false cannot
    open this API. No quality reruns or unknown redispatch are implemented.
    """
    validate_bundle(bundle)
    if admitter is None:
        raise PermissionError("registration does not authorize outbound execution")
    if row_limit is not None and (type(row_limit) is not int or row_limit < 1):
        raise ValueError("positive integer row limit required")
    scope = "offline_contract_test" if offline_worker is not None else "real_execution"
    if offline_worker is None:
        from evals.adapters.remediation_worker import require_existing_budget
        from scripts.task13_worker_runtime import run_remediation_container

        if (
            not runtime_options
            or runtime_options.get("source_commit") != bundle["source_commit"]
        ):
            raise PermissionError("matching frozen Docker runtime is required")
        actual_budget = (
            Path(runtime_options["budget_dir"]).resolve() / "campaign.sqlite"
        )
        if actual_budget != Path(bundle["config"]["active_budget_path"]).resolve():
            raise PermissionError("runtime must use the frozen original active ledger")
        require_existing_budget(actual_budget, bundle["config"]["budget_identity"])

        async def worker(request, agent):
            return await run_remediation_container(request, agent, runtime_options)
    else:
        worker = offline_worker
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    lock = root / ".writer-lock"
    try:
        lock.mkdir()
    except FileExistsError:
        raise PermissionError(
            "campaign active or stale writer needs reconciliation"
        ) from None
    try:
        binding = {"bundle_sha256": bundle["bundle_sha256"], "scope": scope}
        if (root / "binding.json").exists():
            if (
                json.loads((root / "binding.json").read_text(encoding="utf-8"))
                != binding
            ):
                raise PermissionError("execution source or evidence scope changed")
        else:
            write_immutable_json(root / "binding.json", binding)
            write_immutable_json(root / "bundle.json", bundle)
        return asyncio.run(
            _execute(bundle, root, case_roots, admitter, worker, scope, row_limit)
        )
    finally:
        lock.rmdir()
