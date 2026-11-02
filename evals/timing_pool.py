"""Read-only heterogeneous E evidence pool. No native constructors or execution.

Every observation retains its native identity. Hashes bind local evidence; they
are not a substitute for external authorization or an assertion of provenance.
"""

from __future__ import annotations

import json
import math
import stat
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from evals.adapters.verification_worker import (
    ObservationPair,
    VerificationWorkerRequest,
)
from evals.contracts import canonical_hash
from evals.e_timing import BOOTSTRAP, ORDER, ETimingCampaign, validate_registration
from evals.verification import _measurements
from evals.verification_v2 import CAMPAIGN, _time, _validated_worker_result, file_sha256

REGISTRATION_SCHEMA = "task13-e-timing-pool-registration-v1"
RECEIPT_SCHEMA = "task13-e-timing-pool-receipt-v1"
RECOVERY_REGISTRATION_SCHEMA = "task13-e-timing-pool-registration-v2"
RECOVERY_RECEIPT_SCHEMA = "task13-e-timing-pool-receipt-v2"


@dataclass(frozen=True)
class PoolPolicy:
    registration_schema: str
    receipt_schema: str
    future_logical_limit: int
    future_physical_limit: int
    historical_logical: int
    historical_physical: int


def pool_policy(pool_or_schema):
    """Select fixed budgets by an explicit version; never infer from lengths."""
    schema = (
        pool_or_schema.get("schema_version")
        if isinstance(pool_or_schema, dict)
        else pool_or_schema
    )
    if schema == REGISTRATION_SCHEMA:
        return PoolPolicy(REGISTRATION_SCHEMA, RECEIPT_SCHEMA, 6, 18, 7, 21)
    if schema == RECOVERY_REGISTRATION_SCHEMA:
        return PoolPolicy(
            RECOVERY_REGISTRATION_SCHEMA, RECOVERY_RECEIPT_SCHEMA, 5, 15, 8, 24
        )
    raise PermissionError("unsupported explicit pool policy")


def validate_recovery_bindings(grant, predecessor):
    from evals.adapters.e_planning_journal import ManualRecoveryGrant

    try:
        value = ManualRecoveryGrant.model_validate(grant).model_dump(mode="json")
        expected = {
            "pool_registration": value["predecessor_pool_registration_sha256"],
            "pool_journal": value["predecessor_pool_journal_sha256"],
            "quarantine_record": value["quarantine_record_sha256"],
        }
        if not isinstance(predecessor, dict) or set(predecessor) != set(expected) | {
            "pool_head_sha256"
        }:
            raise PermissionError("exact quarantined predecessor raw pins required")
        for key, digest in expected.items():
            ref = predecessor[key]
            if (
                not isinstance(ref, dict)
                or set(ref) != {"path", "sha256"}
                or ref["sha256"] != digest
            ):
                raise PermissionError("quarantined predecessor raw pin differs")
            path = Path(ref["path"])
            if not path.is_absolute() or ".." in path.parts:
                raise PermissionError(
                    "quarantined predecessor absolute raw pins required"
                )
        if predecessor["pool_head_sha256"] != value["predecessor_pool_head_sha256"]:
            raise PermissionError("quarantined predecessor differs from recovery grant")
        return value
    except (ValueError, TypeError) as error:
        raise PermissionError("invalid manual recovery grant or quarantine") from error


C10_TRIAL = "b99f2588f98db830904ec9dd2e63944e"
C10_REGISTRATION = "29bc66cf1fecdadd8e490c47781abc911d44e60b2a05cc7bd94d89fef54846b0"

C10_IMPORT_PINS = {
    "journal_head_sha256": "ca0743df44530fdd44a2d9b02ce32efc0b4c7ac84d3d5e09505a3e2a69e0d8d9",
    "reviewed_trial_sha256": "6b04762cc3047815bebfff0e2191108ed19484095e1a41bdda0f4b584d12dcc5",
    "decision_chat_sha256": "2a0b00dcd8c6a57d67b3fb3467fa49984c5414edb7d32dbd72c66834f3a7ea8e",
}
C10_EVIDENCE_ROOT = Path(
    r"D:\传智杯\data\task13\supplements\task13-repair-202610-v2\development\timing-v2-rebind-candidate-20261101-e5c49a24\host-output\timing"
)


def _absolute_unlinked(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise PermissionError("absolute normalized evidence path required")
    for item in (path, *path.parents):
        info = item.lstat()
        if (
            item.is_symlink()
            or (hasattr(item, "is_junction") and item.is_junction())
            or getattr(info, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise PermissionError("reparse or linked evidence forbidden")
    return path


def _plain(path):
    path = _absolute_unlinked(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PermissionError("independent regular evidence file required")
    return path


def _directory(path):
    path = _absolute_unlinked(path)
    if not path.is_dir():
        raise PermissionError("evidence directory required")
    return path


def _json(path):
    return json.loads(_plain(path).read_text(encoding="utf-8"))


def _view(root):
    root = _directory(root)
    registration = _json(root / "registration.json")
    validate_registration(registration)
    for path in root.rglob("*"):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise PermissionError("linked journal evidence forbidden")
    for path in root.rglob("*.json"):
        if path.parent != root:
            digest = path.stem.rsplit("-", 1)[-1]
            if len(digest) == 64 and file_sha256(_plain(path)) != digest:
                raise PermissionError("raw immutable journal artifact hash differs")
    for path, digest in registration["source_files"].items():
        if file_sha256(_plain(path)) != digest:
            raise PermissionError("original frozen source drift")
    view = object.__new__(ETimingCampaign)
    view.root = root
    view.registration = deepcopy(registration)
    view._frozen = deepcopy(registration)
    view.identity = {
        "campaign_id": CAMPAIGN,
        "plan_sha256": registration["f8_plan_sha256"],
        "source_commit": registration["source_commit"],
        "source_sha256": canonical_hash(registration["source_files"]),
        "config_sha256": canonical_hash(registration["core_config"]),
    }
    view._identity = deepcopy(view.identity)
    view._guard()
    view._load()
    if not view.events:
        raise PermissionError("missing journal origin")
    return view


def _branches(view, trial, used_resources, seen):
    rows = view._rows(trial["trial_id"])
    if len(rows) != 6 or trial["status"] != "completed":
        raise PermissionError("six completed branches required")
    binding = trial["binding"]
    source = view._blob("sources", binding["source_sha256"])
    _validate_source_semantics(view, trial, source)
    approval = view._blob("approvals", binding["approval_receipt_sha256"])
    view._blob("gates", binding["execution_gate_sha256"])
    if (
        approval.get("status") != "verified"
        or approval.get("source") != "original_product_database"
    ):
        raise PermissionError("persisted user approval required")
    branches, previous_end, previous_ns, bound = [], None, None, None
    for i, row in enumerate(rows):
        if row["status"] != "completed":
            raise PermissionError("incomplete timing branch")
        raw = view._blob("inputs", row["input_sha256"])
        request = VerificationWorkerRequest.model_validate(raw)
        result = view._blob("outputs", row["output_sha256"])
        _validated_worker_result(result, request, view.identity, used_resources)
        for kind, value in [
            ("request", request.request_id),
            ("namespace", request.namespace),
        ]:
            if (kind, value) in seen:
                raise PermissionError("duplicate timing request or namespace")
            seen.add((kind, value))
        state = request.approved_state
        if (
            state != source["state"]
            or request.approval_receipt != approval
            or state["approval"]["decided_by"] != "user"
        ):
            raise PermissionError("source or user approval binding differs")
        current = (
            request.case_id,
            request.source_state_sha256,
            request.approved_plan_sha256,
            request.approval_receipt_sha256,
        )
        if bound is not None and current != bound:
            raise PermissionError("mixed approved plans")
        bound = current
        condition, enabled = ORDER[i]
        observed_at = next(iter(request.observations.values())).before.observed_at
        expected = {
            k: ObservationPair.model_validate(v).model_dump(mode="json")
            for k, v in _measurements(state, condition, observed_at).items()
        }
        if request.verification_enabled != enabled or canonical_hash(
            expected
        ) != canonical_hash(raw["observations"]):
            raise PermissionError("condition pair order differs")
        if i % 2 and raw["observations"] != branches[-1]["request"]["observations"]:
            raise PermissionError("paired observations differ")
        start, end = _time(row["dispatched_at"]), _time(row["completed_at"])
        ns, end_ns = row["dispatched_monotonic_ns"], row["completed_monotonic_ns"]
        created, expires = (
            _time(state["response_plan"]["created_at"]),
            _time(state["response_plan"]["expires_at"]),
        )
        if (
            end < start
            or end_ns <= ns
            or (previous_end is not None and start < previous_end)
            or (previous_ns is not None and ns < previous_ns)
            or expires - created != timedelta(minutes=30)
            or end >= expires
            or start < created
            or _time(state["approval"]["decided_at"]) > start
        ):
            raise PermissionError("invalid timing order or approval TTL")
        previous_end, previous_ns = end, end_ns
        host = view._blob("host-receipts", row["host_receipt_sha256"])
        host_path = _plain(host["receipt_path"])
        # Native host receipts live next to host-output, never outside its campaign.
        host_path.relative_to(view.root.parent.parent / "host-termination")
        actual_host = _json(host_path)
        if (
            canonical_hash(actual_host) != host["receipt_binding_sha256"]
            or {
                k: v
                for k, v in host.items()
                if k not in {"receipt_path", "receipt_binding_sha256"}
            }
            != actual_host
            or host.get("status") != "verified"
            or host.get("container_absent") is not True
            or host.get("host_process_exited") is not True
            or host.get("process_returncode") != 0
            or host["request_sha256"] != canonical_hash(raw)
            or host["container_id"]
            != result["isolation_evidence"]["container"]["container_id"]
            or host["worker_nonce"] != result["resource_receipt"]["worker_nonce"]
        ):
            raise PermissionError("host termination proof differs")
        receipt = view._blob("receipts", row["receipt_sha256"])
        if any(
            receipt[k] != row[k]
            for k in ("input_sha256", "output_sha256", "host_receipt_sha256")
        ):
            raise PermissionError("worker receipt closure differs")
        branches.append({**deepcopy(row), "request": raw, "result": result})
    approval_id = state["approval"]["approval_id"]
    if ("approval", approval_id) in seen:
        raise PermissionError("duplicate approval")
    seen.add(("approval", approval_id))
    return branches


def _read_native_observation(
    evidence_root,
    trial_id,
    *,
    used_resources=None,
    seen=None,
    runtime_audit,
    archives=None,
):
    """Read a single real observation without fabricating a native three-trial receipt."""
    try:
        view = _view(evidence_root)
        if view.registration["synthetic"]:
            raise PermissionError("synthetic observation has no actual timing credit")
        if canonical_hash(view.registration) == C10_REGISTRATION and (
            len(view.events) != 16
            or canonical_hash(view.events[-1])
            != "ca0743df44530fdd44a2d9b02ce32efc0b4c7ac84d3d5e09505a3e2a69e0d8d9"
        ):
            raise PermissionError("C10 historical terminal snapshot differs")
        trial = deepcopy(view.trials[trial_id])
        branches = _branches(
            view,
            trial,
            used_resources if used_resources is not None else set(),
            seen if seen is not None else set(),
        )
        wall = (
            _time(trial["completed_at"]) - _time(trial["started_at"])
        ).total_seconds()
        mono = (trial["completed_monotonic_ns"] - trial["started_monotonic_ns"]) / 1e9
        if (
            not math.isfinite(mono)
            or mono <= 0
            or wall <= 0
            or abs(wall - mono) > BOOTSTRAP["clock_tolerance_seconds"]
            or mono != trial["duration_monotonic_seconds"]
            or mono > BOOTSTRAP["total_timeout_seconds"]
            or branches[0]["dispatched_monotonic_ns"] != trial["started_monotonic_ns"]
            or branches[-1]["completed_monotonic_ns"] != trial["completed_monotonic_ns"]
        ):
            raise PermissionError("monotonic/wall measurement differs")
        archives = archives or _archive_context({})
        conditions = _actual_conditions(view, trial, runtime_audit, archives)
        _finish_archives(archives)
        if any(
            b["result"]["isolation_evidence"]["container"]["image_id"]
            != conditions["image_id"]
            for b in branches
        ):
            raise PermissionError("verification branch image differs")
        return {
            **trial,
            "branches": branches,
            "identity": view.identity,
            "registration": view.registration,
            "registration_sha256": canonical_hash(view.registration),
            "journal_trials": list(deepcopy(view.trials).values()),
            "journal_head_sha256": canonical_hash(view.events[-1]),
            "duration_wall_seconds": wall,
            "actual_conditions": conditions,
        }
    except PermissionError:
        raise
    except (KeyError, ValueError, TypeError, OSError) as error:
        raise PermissionError("invalid raw native timing observation") from error


def _validated_registration(pool, runtime_audit):
    try:
        validate_pool_structure(pool)
        selected = pool_policy(pool)
        if (
            pool["target_qualified"] != 3
            or pool["future_logical_limit"] != selected.future_logical_limit
            or pool["future_physical_limit"] != selected.future_physical_limit
        ):
            raise PermissionError("pool limits differ")
        if pool["measurement_constants"] != {
            "bootstrap": BOOTSTRAP,
            "order": [list(x) for x in ORDER],
        }:
            raise PermissionError("measurement constants differ")
        if selected.registration_schema == RECOVERY_REGISTRATION_SCHEMA:
            validate_recovery_measurement_equivalence(pool)
            validate_recovery_quarantine(pool)
        else:
            validate_measurement_equivalence(pool)
        imports = pool["imported_observations"]
        if Path(imports[0]["evidence_root"]).absolute() != C10_EVIDENCE_ROOT or any(
            imports[0].get(k) != v for k, v in C10_IMPORT_PINS.items()
        ):
            raise PermissionError("C10 import snapshot pins or trusted root differ")
        if (
            len(imports) != 1
            or imports[0]["trial_id"] != C10_TRIAL
            or imports[0]["registration_sha256"] != C10_REGISTRATION
        ):
            raise PermissionError("only eligible C10 observation may be imported")
        original = _read_native_observation(
            imports[0]["evidence_root"],
            C10_TRIAL,
            runtime_audit=runtime_audit,
            archives=_archive_context(pool.get("evidence_archives", {})),
        )
        if original["registration_sha256"] != C10_REGISTRATION:
            raise PermissionError("original C10 registration differs")
        if selected.registration_schema == RECOVERY_REGISTRATION_SCHEMA:
            validate_recovery_equivalence_join(pool, original)
        children = pool["children"]
        if len(children) != 2 or len({c["child_id"] for c in children}) != 2:
            raise PermissionError("two fixed-three children required")
        if pool["condition_identity"] != {
            "core_config": original["registration"]["core_config"],
            "actual_conditions": original["actual_conditions"],
        }:
            raise PermissionError("pool baseline conditions differ")
        expected = []
        for child in children:
            r = child["registration"]
            validate_registration(r)
            if len(r["trials"]) != 3 or r["synthetic"]:
                raise PermissionError("native fixed-three actual child required")
            _validate_same_source(original["registration"], r)
            validate_condition_equivalence(
                original["registration"]["core_config"],
                r["core_config"],
                child["disclosed_control_changes"],
            )
            if (
                canonical_hash(r["core_config"]) != pool["identity"]["config_sha256"]
                or r["source_commit"] != pool["identity"]["source_commit"]
                or canonical_hash(r["source_files"])
                != pool["identity"]["source_sha256"]
                or r["f8_plan_sha256"] != pool["identity"]["plan_sha256"]
            ):
                raise PermissionError("new child host identity differs")
            epoch = r["planning_registration"]["epoch_binding"]
            if (
                r["core_config"]["model_identity"]["id"]
                != epoch["model_identity_binding"]["model_epoch_id"]
            ):
                raise PermissionError("model epoch ID differs from native registration")
            if {
                k: epoch[k]
                for k in (
                    "source_sha256",
                    "epoch_id",
                    "epoch_manifest_sha256",
                    "model_identity_binding",
                )
            } != pool["formal_binding"]:
                raise PermissionError("formal source epoch binding differs")
            old_paths = {
                _relative_host_path(p) for p in original["registration"]["source_files"]
            }
            host_root = _directory(pool["measurement_root"])
            _validate_host_coverage(r["source_files"], host_root, old_paths)
            for native in ("evals/e_timing.py", "evals/e_planning.py"):
                old_digest = next(
                    v
                    for p, v in original["registration"]["source_files"].items()
                    if _relative_host_path(p) == native
                )
                if r["source_files"].get(str(host_root / native)) != old_digest:
                    raise PermissionError("native measurement/controller bytes changed")
            expected.extend(
                {"child_id": child["child_id"], "trial_id": t["trial_id"]}
                for t in r["trials"]
            )
        if (
            pool["attempt_order"] != expected[: selected.future_logical_limit]
            or len({x["trial_id"] for x in expected}) != 6
            or C10_TRIAL in {x["trial_id"] for x in expected}
        ):
            raise PermissionError("frozen attempt order differs")
        return deepcopy(pool), original
    except PermissionError:
        raise
    except (KeyError, ValueError, TypeError, OSError) as error:
        raise PermissionError("invalid pool registration") from error


def validate_pool_receipt(receipt: dict, identity: dict) -> float:
    try:
        runtime_audit = set()
        pool, original = _validated_registration(
            receipt["pool_registration"], runtime_audit
        )
        if (
            receipt["schema_version"] != pool_policy(pool).receipt_schema
            or receipt.get("synthetic") is not False
            or receipt.get("f8_approval_credit") != 0
            or receipt.get("distinct_case_count") != 1
            or receipt.get("measurement_replicates") != 3
            or receipt["identity"] != identity
            or pool["identity"] != identity
            or receipt["pool_registration_sha256"] != canonical_hash(pool)
        ):
            raise PermissionError("pool receipt identity differs")
        refs = pool["imported_observations"][:]
        children = {c["child_id"]: c for c in pool["children"]}
        from evals.timing_pool_evidence import validate_controller_evidence

        controller = validate_controller_evidence(
            receipt["controller_evidence"], pool, original
        )
        qualified = set(controller["qualified_trial_ids"])
        for attempt in pool["attempt_order"]:
            if attempt["trial_id"] in qualified:
                child = children[attempt["child_id"]]
                refs.append(
                    {
                        "evidence_root": child["evidence_root"],
                        "trial_id": attempt["trial_id"],
                        "registration_sha256": canonical_hash(child["registration"]),
                    }
                )
        _validate_selection(
            refs, receipt["observations"], receipt["selected_trial_ids"]
        )
        if receipt["formal_binding"] != pool["formal_binding"]:
            raise PermissionError("receipt formal binding differs")
        resources, seen = set(), set()
        imported_view = _view(refs[0]["evidence_root"])
        _branches(imported_view, original, resources, seen)
        observations = [original] + [
            _read_native_observation(
                r["evidence_root"],
                r["trial_id"],
                used_resources=resources,
                seen=seen,
                runtime_audit=runtime_audit,
            )
            for r in refs[1:]
        ]
        settlements = {
            p["trial_id"]: p for p in controller["transcript"]["settlements"]
        }
        for observation in observations[1:]:
            settlement = settlements[observation["trial_id"]]
            from evals.timing_pool_evidence import native_snapshot_matches

            native_view = _view(
                next(
                    r["evidence_root"]
                    for r in refs
                    if r["trial_id"] == observation["trial_id"]
                )
            )
            if not native_snapshot_matches(
                native_view, observation, settlement["evidence"]["native"]
            ) or settlement["observed_max_seconds"] != max(
                observation["duration_wall_seconds"],
                observation["duration_monotonic_seconds"],
            ):
                raise PermissionError(
                    "controller settlement differs from actual complete observation"
                )
        if controller["transcript"]["events"][0]["payload"][
            "imported_max_seconds"
        ] != max(
            original["duration_wall_seconds"], original["duration_monotonic_seconds"]
        ):
            raise PermissionError("controller imported maximum differs")
        if any(
            o["actual_conditions"] != pool["condition_identity"]["actual_conditions"]
            for o in observations
        ):
            raise PermissionError("mixed actual measurement conditions")
        return _unified_max(observations, receipt["observed_max_seconds"])
    except PermissionError:
        raise
    except (KeyError, ValueError, TypeError, OSError) as error:
        raise PermissionError("invalid pool timing receipt") from error


def validate_measurement_equivalence(pool):
    """Anchor every original worker file, not a caller-chosen equal subset."""
    try:
        original_root = Path(pool["original_measurement_root"]).absolute()
        receipt_path = _plain(original_root / "source_receipt.json")
        if (
            file_sha256(receipt_path)
            != "035aaecf7c610dbec774288ae3e409bc3fd7fc8a8f100a70727c3e3165dbcbb4"
        ):
            raise PermissionError("original worker manifest anchor differs")
        manifest = _json(receipt_path)
        files = manifest["files"]
        if (
            len(files) != 117
            or pool["measurement_files"] != files
            or pool["original_measurement_files"] != files
        ):
            raise PermissionError("entire original 117-file map must match")
        for root in (original_root, Path(pool["measurement_root"]).absolute()):
            for relative, digest in files.items():
                path = _plain(root / relative)
                path.relative_to(root)
                if file_sha256(path) != digest:
                    raise PermissionError("measurement source changed")
        return deepcopy(files)
    except PermissionError:
        raise
    except (KeyError, ValueError, TypeError, OSError) as error:
        raise PermissionError("invalid measurement equivalence proof") from error


def _artifact(ref, root):
    path = _plain(ref["path"])
    path.relative_to(root)
    if file_sha256(path) != ref["sha256"]:
        raise PermissionError("raw artifact digest differs")
    return _json(path)


def validate_received_models(ledger, expected):
    """Match native identity checks without inventing bodies for failed attempts.

    Accounting and native attempt provenance are validated separately. A missing
    body is not evidence of a received model response or of a known zero charge.
    """
    received = 0
    for call in ledger:
        raw = call.get("raw_response")
        if call.get("http_status") != 200 and not isinstance(raw, dict):
            continue
        received += 1
        if (
            not isinstance(raw, dict)
            or call.get("response_model") != expected["response_model"]
            or call.get("system_fingerprint") != expected["fingerprint"]
            or raw.get("model") != expected["response_model"]
            or raw.get("system_fingerprint") != expected["fingerprint"]
        ):
            raise PermissionError("actual received model differs")
    if not received:
        raise PermissionError("actual received model identity is missing")
    return received


def _load_host_inputs(view, host):
    """Root child data locally and only explicit pool authority at its parent.

    Shared authority is permitted only for an exact declared native child and
    its original parent proposal. Full epoch, scope decision, readiness and
    dispatch authority validation still follows in _validate_host_semantics.
    """
    child_root = view.root.parent.parent
    references = host["inputs"]
    if "pool_authority" not in references:
        return {key: _artifact(ref, child_root) for key, ref in references.items()}
    from scripts.task13_e_trial import require_pool_membership

    parent_root = child_root.parent
    pool = _artifact(references["pool_authority"], parent_root)
    validate_pool_structure(pool)
    matches = [c for c in pool["children"] if Path(c["evidence_root"]) == view.root]
    if (
        len(matches) != 1
        or matches[0]["registration"] != view.registration
        or Path(pool["execution_journal_path"]).parent.parent != parent_root
        or Path(host["output_dir"]) != view.root.parent
    ):
        raise PermissionError("shared parent authority is not this exact native child")
    shared = {"pool_authority", "scope_packet", "scope_decision"}
    inputs = {
        key: _artifact(ref, parent_root if key in shared else child_root)
        for key, ref in references.items()
    }
    require_pool_membership(pool, inputs["scope_packet"], view.registration)
    return inputs


def _actual_conditions(view, trial, runtime_audit, archives):
    """Derive model/runtime conditions from native host-bound raw artifacts."""
    host_root = view.root.parent
    host = _json(host_root / "host-binding.json")
    inputs = _load_host_inputs(view, host)
    if (
        inputs["planning_registration"] != view.registration["planning_registration"]
        or inputs["timing_registration"] != view.registration
    ):
        raise PermissionError("host-bound native registrations differ")
    context = _validate_host_semantics(view, host, inputs)
    if context["claims"][trial["trial_id"]]["status"] != "started":
        raise PermissionError("completed observation lacks native append claim")
    slot = trial["binding"]["planning_slot_id"]
    terminal = _json(host_root / "slots" / slot / "plan-terminal.json")
    started = _json(host_root / "slots" / slot / "plan-started.json")
    request = next(
        r for r in context["reader"]._requests if r.trial_id == trial["trial_id"]
    )
    if (
        canonical_hash(started) != terminal["start_sha256"]
        or started["request"] != request.model_dump(mode="json")
        or started["request_sha256"] != canonical_hash(request)
        or started["manifest_sha256"]
        != file_sha256(_plain(host_root / "host-binding.json"))
    ):
        raise PermissionError("planning terminal origin differs")
    artifacts = {
        key: _artifact(terminal[key], host_root / "artifacts")
        for key in ("runtime_result", "resources", "retained_state", "provenance")
    }
    source = view._blob("sources", trial["binding"]["source_sha256"])
    from evals.adapters.e_planning_review import (
        build_review_request,
        validate_review_state,
    )

    original_review = build_review_request(
        request, source["resources"], operation="read_packet"
    )
    from evals.adapters.e_planning_worker import _claim_binding

    validate_review_state(
        original_review,
        source["state"],
        context["imported"],
        _claim_binding(request, context["claims"][trial["trial_id"]]),
    )
    if (
        artifacts["resources"] != source["resources"]
        or artifacts["retained_state"] != source["retained_state"]
        or artifacts["provenance"]
        != source["retained_state"]["analysis_import_provenance"]
    ):
        raise PermissionError("retained source provenance differs")
    decision = _json(host_root / "slots" / slot / "decision-terminal.json")
    decision_start = _json(host_root / "slots" / slot / "decision-started.json")
    if (
        decision["status"] != "approved"
        or canonical_hash(decision_start) != decision["start_sha256"]
    ):
        raise PermissionError("actual decision terminal differs")
    chat = _artifact(decision["chat_record"], host_root / "artifacts")
    decided = _artifact(decision["runtime_result"], host_root / "artifacts")
    if (
        decided["status"] != "completed"
        or decided["source"]["state"] != source["state"]
        or decided["approval_receipt"]
        != view._blob("approvals", trial["binding"]["approval_receipt_sha256"])
    ):
        raise PermissionError("persisted approval raw closure differs")
    if (
        chat.get("role") != "user"
        or chat.get("synthetic_control_fixture") is not False
        or chat.get("decision") != "approved"
    ):
        raise PermissionError("actual individual user decision missing")
    _validate_approval_semantics(
        context, trial, source, chat, decision_start, decided, archives
    )
    if canonical_hash(view.registration) == C10_REGISTRATION:
        if (
            decision["chat_record"]["sha256"]
            != "2a0b00dcd8c6a57d67b3fb3467fa49984c5414edb7d32dbd72c66834f3a7ea8e"
        ):
            raise PermissionError("C10 decision anchor differs")
        reviewed = Path(
            r"D:\传智杯\.tmp\task13-c10-live-preload-ordinal-1-20261101\handoff\trial.json"
        )
        _archived_json(
            {"path": str(reviewed), "sha256": C10_IMPORT_PINS["reviewed_trial_sha256"]},
            archives,
        )
    runtime = artifacts["runtime_result"]
    from evals.timing_pool_evidence import _ledger

    _validate_runtime_capture(runtime, terminal, inputs["runtime_options"], request)
    _ledger(context, request, runtime)
    options = inputs["runtime_options"]
    model = view.registration["core_config"]["model_identity"]
    if not runtime["model_ledger"]:
        raise PermissionError("actual received model evidence missing")
    model_binding = view.registration["planning_registration"]["epoch_binding"][
        "model_identity_binding"
    ]
    if (
        options["model_identity_binding"] != model_binding
        or model["id"] != model_binding["model_epoch_id"]
    ):
        raise PermissionError("runtime model epoch binding differs")
    for row in runtime["model_ledger"]:
        if (
            row["model_epoch_id"] != model_binding["model_epoch_id"]
            or row["model_identity_sha256"] != model_binding["model_identity_sha256"]
        ):
            raise PermissionError("actual model ledger epoch differs")
    validate_received_models(runtime["model_ledger"], model)
    container = runtime["isolation_evidence"]["container"]
    if container["image_id"] != options["image_id"]:
        raise PermissionError("actual image differs")
    deps = _json(Path(options["dependencies_dir"]) / "task13_dependencies.json")
    if (
        deps["lock_sha256"] != options["dependencies_lock_sha256"]
        or _runtime_tree(
            Path(options["dependencies_dir"]), deps["tree_sha256"], runtime_audit
        )
        != deps["tree_sha256"]
    ):
        raise PermissionError("dependency proof differs")
    if (
        _runtime_tree(
            Path(options["knowledge_dir"]), options["knowledge_sha256"], runtime_audit
        )
        != options["knowledge_sha256"]
    ):
        raise PermissionError("knowledge proof differs")
    return {
        "received_model": {
            "response_model": model["response_model"],
            "fingerprint": model["fingerprint"],
        },
        "image_id": container["image_id"],
        "dependencies_lock_sha256": deps["lock_sha256"],
        "dependencies_tree_sha256": deps["tree_sha256"],
        "knowledge_sha256": options["knowledge_sha256"],
    }


CONTROL_CONFIG_KEYS = frozenset(
    {
        "participation_policy",
        "model_identity",
        "user_approval_window",
        "combined_development_calls",
        "active_budget_path",
        "deadline",
    }
)


def validate_condition_equivalence(original, current, disclosure):
    changes = {
        key: {"before": original.get(key), "after": current.get(key)}
        for key in set(original) | set(current)
        if original.get(key) != current.get(key)
    }
    if set(changes) - CONTROL_CONFIG_KEYS or changes != disclosure:
        raise PermissionError(
            "measurement conditions changed or control changes undisclosed"
        )
    for key in changes:
        if key == "model_identity":
            before, after = original[key], current[key]
            if set(before) != set(after) or {
                k: v for k, v in before.items() if k != "id"
            } != {k: v for k, v in after.items() if k != "id"}:
                raise PermissionError("only disclosed model epoch ID may change")
        elif key == "participation_policy":
            before, after = original[key], current[key]
            if {
                k: v for k, v in before.items() if k != "authorization_record_sha256"
            } != {k: v for k, v in after.items() if k != "authorization_record_sha256"}:
                raise PermissionError("participation semantics cannot change")
        elif key == "combined_development_calls":
            before, after = original[key], current[key]
            if set(before) != set(after) or any(
                type(v) is not int or v < 0 for v in after.values()
            ):
                raise PermissionError(
                    "only declared nonnegative call counts may change"
                )
    return True


def validate_pool_structure(pool):
    """Pure checks for an already frozen pool; this is NOT evidence admission.

    Callers still need validate_pool_registration before initial admission and
    must guard their frozen pool and native journals during every operation.
    """
    try:
        selected = pool_policy(pool)
        if (
            pool["target_qualified"] != 3
            or type(pool["target_qualified"]) is not int
            or type(pool["future_logical_limit"]) is not int
            or type(pool["future_physical_limit"]) is not int
            or pool["future_logical_limit"] != selected.future_logical_limit
            or pool["future_physical_limit"] != selected.future_physical_limit
            or pool["measurement_constants"]
            != {"bootstrap": BOOTSTRAP, "order": [list(x) for x in ORDER]}
        ):
            raise PermissionError("pool structure/limits differ")
        journal = Path(pool["execution_journal_path"])
        if (
            not journal.is_absolute()
            or ".." in journal.parts
            or journal.name != "pool-journal.jsonl"
        ):
            raise PermissionError(
                "one exact absolute parent execution journal required"
            )
        for part in (journal, *journal.parents):
            if part.exists():
                _absolute_unlinked(part)
        if journal.exists():
            _plain(journal)
        children = pool["children"]
        imports = pool["imported_observations"]
        if (
            len(children) != 2
            or len({c["child_id"] for c in children}) != 2
            or len(imports) != 1
        ):
            raise PermissionError("pool membership differs")
        if (
            imports[0]["trial_id"] != C10_TRIAL
            or imports[0]["registration_sha256"] != C10_REGISTRATION
        ):
            raise PermissionError("pool import differs")
        order = []
        for child in children:
            validate_registration(child["registration"])
            if len(child["registration"]["trials"]) != 3:
                raise PermissionError("fixed-three native child required")
            order.extend(
                {"child_id": child["child_id"], "trial_id": t["trial_id"]}
                for t in child["registration"]["trials"]
            )
        if (
            pool["attempt_order"] != order[: selected.future_logical_limit]
            or len({x["trial_id"] for x in order}) != 6
            or C10_TRIAL in {x["trial_id"] for x in order}
        ):
            raise PermissionError("frozen attempt order differs")
        if selected.registration_schema == RECOVERY_REGISTRATION_SCHEMA:
            _validate_recovery_structure(pool, order)
        elif (
            len(pool["measurement_files"]) != 117
            or pool["measurement_files"] != pool["original_measurement_files"]
        ):
            raise PermissionError("measurement map structure differs")
        return deepcopy(pool)
    except PermissionError:
        raise
    except (KeyError, ValueError, TypeError, OSError) as error:
        raise PermissionError("invalid pool structure") from error


def _validate_recovery_structure(pool, native_order):
    from evals.e_planning import planning_requests

    grant = validate_recovery_bindings(
        pool["migration_grant"], pool["quarantined_predecessor"]
    )
    if (
        canonical_hash(grant) != pool["migration_grant_sha256"]
        or pool["denied_attempts"] != native_order[5:]
        or pool["quarantine_record"]
        != pool["quarantined_predecessor"]["quarantine_record"]
        or pool["recovery_plan"]["sha256"] != grant["recovery_plan_sha256"]
    ):
        raise PermissionError("recovery grant, quarantine or denied sixth slot differs")
    if set(pool["recovery_equivalence"]) != {
        "original_execution",
        "candidate_execution",
        "policy_pin",
    }:
        raise PermissionError("explicit recovery equivalence proof required")
    for index, (child, allowed) in enumerate(
        zip(pool["children"], (3, 2), strict=True)
    ):
        registration = child["registration"]
        planning = registration["planning_registration"]
        dispatch = registration["planning_dispatch_registration_receipt"]
        requests = [canonical_hash(request) for request in planning_requests(planning)]
        expected = {
            "registration_sha256": canonical_hash(planning),
            "journal_path": dispatch["journal_path"],
            "request_sha256s": requests,
            "authorized_request_sha256s": requests[:allowed],
            "denied_request_sha256s": requests[allowed:],
        }
        if grant["children"][index] != expected:
            raise PermissionError(
                "recovery grant differs from frozen native child requests"
            )


def validate_recovery_measurement_equivalence(pool):
    from evals.recovery_equivalence import validate_recovery_equivalence

    proof = pool["recovery_equivalence"]
    return validate_recovery_equivalence(
        proof["original_execution"], proof["candidate_execution"], proof["policy_pin"]
    )


def recovery_execution_identity(registration):
    """Stable native identities; future authorization hashes stay in formal binding."""
    epoch = registration["planning_registration"]["epoch_binding"]
    return {
        "source": {key: epoch[key] for key in ("source_sha256", "epoch_id")}
        | {"source_commit": registration["source_commit"]},
        "model": deepcopy(registration["core_config"]["model_identity"]),
        "controller": {"source_files": deepcopy(registration["source_files"])},
    }


def validate_recovery_equivalence_join(pool, original):
    """Join scope-only transformation review to independently verified native data."""
    proof = validate_recovery_measurement_equivalence(pool)
    old = pool["recovery_equivalence"]["original_execution"]
    new = pool["recovery_equivalence"]["candidate_execution"]
    if (
        proof.get("schema_version") != "task13-recovery-equivalence-proof-v1"
        or proof.get("scope") != "source-and-declared-conditions-only"
        or proof.get("authorization") is not False
        or proof.get("timing_credit") is not False
        or proof["original_measurement_files"] != pool["original_measurement_files"]
        or proof["candidate_measurement_files"] != pool["measurement_files"]
        or Path(new["root"]) != Path(pool["measurement_root"])
        or old["identity"] != recovery_execution_identity(original["registration"])
        or old["core_config"] != original["registration"]["core_config"]
        or old["disclosed_control_changes"] != {}
        or old["candidate_conditions"] != original["actual_conditions"]
        or new["candidate_conditions"] != original["actual_conditions"]
        or proof["declared_candidate_conditions"] != original["actual_conditions"]
        or old["measurement_constants"] != pool["measurement_constants"]
        or new["measurement_constants"] != pool["measurement_constants"]
    ):
        raise PermissionError(
            "recovery equivalence differs from actual C10 and native pool declarations"
        )
    if (
        old["measurement_files"] != pool["original_measurement_files"]
        or new["measurement_files"] != pool["measurement_files"]
        or old["native_measurement_files"] != proof["native_measurement_files"]
        or new["native_measurement_files"]
        != proof["candidate_native_measurement_files"]
    ):
        raise PermissionError("recovery equivalence raw inventories differ")
    for record, registration in [(old, original["registration"])] + [
        (new, c["registration"]) for c in pool["children"]
    ]:
        if (
            record["identity"] != recovery_execution_identity(registration)
            or record["core_config"] != registration["core_config"]
        ):
            raise PermissionError(
                "recovery identity or declared core config differs from native registration"
            )
        root = Path(record["root"])
        for relative, digest in record["native_measurement_files"].items():
            if registration["source_files"].get(str(root / relative)) != digest:
                raise PermissionError(
                    "recovery native implementation map differs from registration"
                )
    if any(
        c["disclosed_control_changes"] != new["disclosed_control_changes"]
        for c in pool["children"]
    ):
        raise PermissionError(
            "recovery declared control disclosures differ from native child"
        )
    return proof


def require_recovery_child_authority(pool, timing, authority):
    from evals.adapters.e_planning_journal import (
        LimitedEPlanningAuthority,
        parse_authority,
    )

    parsed = parse_authority(authority)
    if (
        not isinstance(parsed, LimitedEPlanningAuthority)
        or parsed.registration_sha256 != canonical_hash(timing["planning_registration"])
        or parsed.journal_path
        != timing["planning_dispatch_registration_receipt"]["journal_path"]
        or parsed.migration_grant.model_dump(mode="json") != pool["migration_grant"]
        or parsed.migration_grant_sha256 != pool["migration_grant_sha256"]
        or canonical_hash(parsed)
        != timing["planning_dispatch_registration_receipt"]["authority_sha256"]
    ):
        raise PermissionError(
            "native limited child authority differs from exact recovery grant"
        )
    return parsed


def validate_denied_native_slot(context, request, view):
    """Allow only native structural defaults, with no denied-slot activity."""
    import sqlite3

    trial = view.trials[request.trial_id]
    expected_records = {}
    structural_drift = False
    if hasattr(view, "registration"):
        registered = next(
            (
                t
                for t in view.registration["trials"]
                if t["trial_id"] == request.trial_id
            ),
            None,
        )
        if registered is None:
            raise PermissionError("denied sixth native slot is not registered")
        structural_drift = canonical_hash(trial) != canonical_hash(
            {
                "trial_id": request.trial_id,
                "source_row_id": registered["source_row_id"],
                "status": "not_started",
                "reason": None,
                "binding": None,
            }
        )
        expected_records = {
            branch["request_id"]: {
                **branch,
                "trial_id": request.trial_id,
                "status": "not_started",
                "reason": None,
            }
            for branch in registered["branches"]
        }
    actual_records = {
        key: row
        for key, row in view.records.items()
        if key in expected_records or row.get("trial_id") == request.trial_id
    }
    slot = context["reader"]._root / "slots" / request.planning_slot_id
    if (
        trial.get("status") != "not_started"
        or trial.get("binding")
        or trial.get("review_pending")
        or context["claims"][request.trial_id]["status"] != "unclaimed"
        or structural_drift
        or canonical_hash(actual_records) != canonical_hash(expected_records)
        or any(
            event["payload"].get("trial_id") == request.trial_id
            or event["payload"].get("request_id") in expected_records
            for event in getattr(view, "events", [])
        )
        or slot.exists()
        and any(slot.iterdir())
    ):
        raise PermissionError(
            "denied sixth native slot contains plan/read/decision/trial/branch activity"
        )
    path = _plain(context["planning_journal_path"])
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        claim = db.execute(
            "SELECT 1 FROM analysis_import_planning_claims WHERE planning_slot_id=?",
            (request.planning_slot_id,),
        ).fetchone()
    if claim:
        raise PermissionError("denied sixth native slot contains SQL claim")


def validate_recovery_quarantine(pool):
    from evals.timing_pool_recovery import validate_quarantine_evidence

    ref = pool["quarantine_record"]
    path = _plain(ref["path"])
    if file_sha256(path) != ref["sha256"]:
        raise PermissionError("recovery quarantine raw pin differs")
    quarantine = validate_quarantine_evidence(
        _json(path), expected_scope=pool["recovery_plan"]
    )
    predecessor = pool["quarantined_predecessor"]
    journal = quarantine["parent_journal"]
    if {"path": journal["path"], "sha256": journal["sha256"]} != predecessor[
        "pool_journal"
    ] or journal["head_sha256"] != predecessor["pool_head_sha256"]:
        raise PermissionError("quarantine predecessor journal differs")
    host_ref = quarantine["pool_host_manifest"]
    host_path = _plain(host_ref["path"])
    if (
        file_sha256(host_path) != host_ref["sha256"]
        or _json(host_path)["pool_registration"] != predecessor["pool_registration"]
    ):
        raise PermissionError("quarantine predecessor pool registration differs")
    return quarantine


def validate_pool_registration(pool):
    return _validated_registration(pool, set())[0]


def _runtime_tree(path, expected, audited):
    # Per-invocation only: no persistent timestamps cache or caller attestation.
    path = _directory(path)
    key = (str(path), expected)
    if key not in audited:
        from scripts.task13_worker_runtime import dependency_tree_hash

        for member in path.rglob("*"):
            if member.is_file() and (
                member.stat().st_nlink != 1 or not stat.S_ISREG(member.stat().st_mode)
            ):
                raise PermissionError(
                    "runtime evidence hardlink or special file forbidden"
                )
        if dependency_tree_hash(path) != expected:
            raise PermissionError("runtime tree differs")
        audited.add(key)
    return expected


def read_native_observation(
    evidence_root, trial_id, *, used_resources=None, seen=None, evidence_archives=None
):
    return _read_native_observation(
        evidence_root,
        trial_id,
        used_resources=used_resources,
        seen=seen,
        runtime_audit=set(),
        archives=_archive_context(evidence_archives or {}),
    )


def _validate_selection(expected, supplied, selected_ids):
    if (
        len(expected) != 3
        or supplied != expected
        or selected_ids != [r["trial_id"] for r in expected]
    ):
        raise PermissionError(
            "first three qualified observations required in frozen order"
        )


def _unified_max(observations, claimed):
    maximum = max(
        max(o["duration_wall_seconds"], o["duration_monotonic_seconds"])
        for o in observations
    )
    if claimed != maximum:
        raise PermissionError("unified maximum differs")
    return maximum


def _relative_host_path(path):
    normalized = str(path).replace("\\", "/")
    for part in ("evals", "scripts", "services", "docs"):
        if "/" + part + "/" in normalized:
            return part + "/" + normalized.split("/" + part + "/", 1)[1]
    raise ValueError("host manifest entry outside known source roots")


def _validate_host_coverage(files, root, original_paths):
    from evals.freeze import required_freeze_files

    root = _directory(root)
    required = set(required_freeze_files(root)) | set(original_paths)
    actual = {
        _plain(p).relative_to(root).as_posix(): digest for p, digest in files.items()
    }
    if not required <= set(actual) or len(actual) != len(files):
        raise PermissionError("host manifest omits current evaluated source or tests")
    for relative, digest in actual.items():
        if file_sha256(_plain(root / relative)) != digest:
            raise PermissionError("host manifest file bytes differ")


def _validate_source_semantics(view, trial, source):
    # This is the unchanged original semantic source/replicate validation,
    # including sealed analysis provenance, targets and retained resources.
    return view._source(trial["trial_id"], source)


def _validate_host_semantics(view, host, inputs):
    from datetime import UTC, datetime

    from evals.adapters.e_planning_journal import parse_authority
    from evals.adapters.model_identities import require_registered_model_identity
    from evals.adapters.source_epochs import require_registered_epoch
    from evals.e_planning import planning_requests
    from scripts.task13_e_trial import INPUTS

    if (
        host.get("schema_version") != "task13-e-host-controller-v1"
        or host.get("synthetic") is not False
        or set(host["inputs"]) not in (INPUTS, INPUTS | {"pool_authority"})
        or inputs["planning_registration"] != view.registration["planning_registration"]
        or inputs["timing_registration"] != view.registration
        or Path(host["output_dir"]) != view.root.parent
    ):
        raise PermissionError("native host identity or rooted output differs")
    # Authenticate the original native identities before any historical code
    # can run. SQL lookups are read-only and retain the original budget path.
    validate_registration(view.registration)
    requests = planning_requests(inputs["planning_registration"])
    request = requests[0]
    options = inputs["runtime_options"]
    budget = _plain(Path(options["budget_dir"]) / "campaign.sqlite")
    epoch = require_registered_epoch(
        budget,
        request.epoch_id,
        source_sha256=request.source_sha256,
        config_sha256=request.config_sha256,
        budget_identity=request.budget_identity,
        manifest_sha256=request.epoch_manifest_sha256,
        latest=False,
    )
    if epoch["authority"] != {
        "kind": "phase_scope_consent",
        "packet_sha256": host["inputs"]["scope_packet"]["sha256"],
        "decision_record_sha256": host["inputs"]["scope_decision"]["sha256"],
    }:
        raise PermissionError("registered native source epoch authority differs")
    if epoch["source_commit"] != request.source_commit:
        raise PermissionError("registered native source commit differs")
    roots = [_directory(p) for p in epoch["controller_state_roots"]]
    if any(
        not any(path.is_relative_to(root) for root in roots)
        for path in (
            view.root.parent,
            _directory(host["host_termination_dir"]),
            _directory(options["output_dir"]),
        )
    ):
        raise PermissionError("native evidence outside registered epoch roots")
    if "pool_authority" in inputs:
        journal = Path(inputs["pool_authority"]["execution_journal_path"])
        if not any(journal.is_relative_to(root) for root in roots):
            raise PermissionError(
                "parent pool journal outside registered source epoch roots"
            )
    # Preserve historical host identity; do not compare historical source to NEW.
    source_map = {
        _relative_host_path(p): digest
        for p, digest in view.registration["source_files"].items()
    }
    for relative in ("scripts/task13_e_trial.py", "evals/host_review.py"):
        if epoch["entrypoints"].get(relative) != source_map.get(relative):
            raise PermissionError("historical host entrypoint binding differs")
    model = request.model_identity_binding
    if model is None:
        raise PermissionError("explicit actual model epoch required")
    descriptor = require_registered_model_identity(
        budget,
        model.model_epoch_id,
        epoch_id=request.epoch_id,
        source_sha256=request.source_sha256,
        config_sha256=request.config_sha256,
        purpose=request.purpose,
        manifest_sha256=model.model_identity_sha256,
        latest=False,
    )
    if (
        descriptor["expected_model"]
        != inputs["planning_registration"]["core_config"]["model_identity"]
    ):
        raise PermissionError("registered model descriptor differs")
    authority = inputs["planning_authority"]
    if (
        authority.get("scope_packet_sha256") != host["inputs"]["scope_packet"]["sha256"]
        or authority.get("decision_record_sha256")
        != host["inputs"]["scope_decision"]["sha256"]
    ):
        raise PermissionError("original native planning scope authority differs")
    parsed_authority = parse_authority(authority)
    dispatch = view.registration["planning_dispatch_registration_receipt"]
    if (
        canonical_hash(parsed_authority) != dispatch["authority_sha256"]
        or parsed_authority.registration_sha256
        != canonical_hash(inputs["planning_registration"])
        or parsed_authority.synthetic != host["synthetic"]
        or parsed_authority.journal_path != dispatch["journal_path"]
        or parsed_authority.scope_packet_sha256
        != host["inputs"]["scope_packet"]["sha256"]
        or parsed_authority.decision_record_sha256
        != host["inputs"]["scope_decision"]["sha256"]
    ):
        raise PermissionError("original native planning authority binding differs")
    from evals.timing_pool_history import (
        historical_controller_type,
        read_historical_planning_analysis,
    )

    controller = historical_controller_type(view, host, inputs, epoch)
    # Only native read methods are called. No constructor, preflight, provider,
    # decision, product factory or dispatch is part of this evidence reader.
    reader = object.__new__(controller)
    reader._manifest = host
    reader._inputs = inputs
    reader._planning = inputs["planning_registration"]
    reader._timing = view.registration
    reader._requests = requests
    reader._root = view.root.parent
    reader._termination = _directory(host["host_termination_dir"])
    reader._agent = _directory(host["agent_dir"])
    reader._now = lambda: datetime.now(UTC)
    reader._scope()
    journal = reader._journal()
    denied = set(authority.get("denied_request_sha256s", []))
    claims = {
        t["trial_id"]: (
            {"status": "unclaimed"}
            if canonical_hash(item) in denied
            else journal.validate_request(item)
        )
        for t, item in zip(view.registration["trials"], requests, strict=True)
    }

    before = file_sha256(budget)
    imported = read_historical_planning_analysis(
        request, _directory(options["import_source_dir"]), budget
    )
    imported_values = imported.product_values()
    if file_sha256(budget) != before:
        raise PermissionError(
            "read-only original package verification observed budget drift"
        )
    return {
        "reader": reader,
        "claims": claims,
        "planning_journal_path": authority["journal_path"],
        "epoch": epoch,
        "model": descriptor,
        "budget_path": budget,
        "imported_values": imported_values,
        "imported": imported,
        "budget_sha256": before,
    }


def _archive_context(mapping):
    if not isinstance(mapping, dict):
        raise PermissionError("archive mapping must be explicit")
    targets = set()
    origins = set()
    for original, ref in mapping.items():
        path = Path(original)
        if (
            not path.is_absolute()
            or ".." in path.parts
            or set(ref) != {"path", "sha256"}
        ):
            raise PermissionError("exact absolute archive pin required")
        target = str(_plain(ref["path"])).casefold()
        origin = str(path).casefold()
        if target in targets or origin in origins or target == origin:
            raise PermissionError("duplicate or aliased archive mapping")
        targets.add(target)
        origins.add(origin)
    return {"mapping": deepcopy(mapping), "used": set()}


def _archived_json(ref, context):
    original = ref["path"]
    pin = ref
    if original in context["mapping"]:
        pin = context["mapping"][original]
        if pin["sha256"] != ref["sha256"]:
            raise PermissionError("archive cannot change original raw digest")
        context["used"].add(original)
    path = _plain(pin["path"])
    if file_sha256(path) != ref["sha256"]:
        raise PermissionError("archived raw evidence differs")
    return _json(path)


def _finish_archives(context):
    if set(context["mapping"]) != context["used"]:
        raise PermissionError("unused archive substitution forbidden")


def validate_migration_marker(marker, pool, parent_packet_pin, parent_decision_pin):
    if pool.get("schema_version") == RECOVERY_REGISTRATION_SCHEMA:
        grant = validate_recovery_bindings(
            pool["migration_grant"], pool["quarantined_predecessor"]
        )
        if (
            parent_packet_pin["sha256"] != grant["scope_packet_sha256"]
            or parent_decision_pin["sha256"] != grant["decision_record_sha256"]
        ):
            raise PermissionError(
                "actual recovery parent scope differs from limited grant"
            )
        quarantine = validate_recovery_quarantine(pool)
        if marker != quarantine:
            raise PermissionError(
                "recovery migration evidence differs from pinned independent quarantine"
            )
        return quarantine
    path = _plain(C10_EVIDENCE_ROOT / "registration.json")
    if file_sha256(path) != C10_REGISTRATION:
        raise PermissionError("migration original registration anchor differs")
    original = _json(path)
    expected = {
        "schema_version": "task13-e-timing-pool-migration-v1",
        "pool_registration_sha256": canonical_hash(pool),
        "source_registration_sha256": C10_REGISTRATION,
        "source_journal_head_sha256": C10_IMPORT_PINS["journal_head_sha256"],
        "imported_trial_id": C10_TRIAL,
        "excluded_trial_ids": [t["trial_id"] for t in original["trials"][1:]],
        "future_trial_ids": [a["trial_id"] for a in pool["attempt_order"]],
        "parent_scope_packet_sha256": parent_packet_pin["sha256"],
        "parent_scope_decision_sha256": parent_decision_pin["sha256"],
    }
    if marker != expected:
        raise PermissionError(
            "migration marker differs from exact historical and parent membership"
        )
    return deepcopy(marker)


def _validate_historical_direct_approval(context, request, source, chat, started, ref):
    """Recognize only the frozen unknown-prefix root capture, never new consent."""
    from evals.timing_pool_recovery import (
        APPROVAL_SHA256,
        FROZEN,
        PACKET_SHA256,
        PLAN_ID,
        TRIAL_ID,
    )

    authority = context["reader"]._inputs.get("pool_authority")
    if (
        not isinstance(ref, dict)
        or set(ref) != {"path", "sha256"}
        or ref != started["chat_record"]
        or ref["sha256"] != APPROVAL_SHA256
        or not isinstance(authority, dict)
        or authority.get("schema_version") != REGISTRATION_SCHEMA
        or canonical_hash(authority) != FROZEN["pool_sha256"]
        or request.trial_id != TRIAL_ID
        or canonical_hash(request)
        != "085313f34f67a5fc2690a23e9108a823f38f79fddc800be1ec80bbd5903fd259"
        or chat["packet_sha256"] != PACKET_SHA256
        or source["state"]["response_plan"]["response_plan_id"] != PLAN_ID
        or "prepared_question" in chat
        or "actual_question_reply" in chat
        or chat.get("source") != "actual_current_send_user_message_question_reply"
        or chat.get("decision") != "approved"
    ):
        raise PermissionError("historical direct approval is not the frozen original")
    replies = chat.get("actual_incoming_reply")
    if (
        not isinstance(replies, list)
        or len(replies) != 1
        or not isinstance(replies[0], dict)
        or set(replies[0]) != {"question", "answer", "questionItemId"}
    ):
        raise PermissionError("historical direct approval lacks its exact reply")
    reply = replies[0]
    try:
        item = json.loads(reply["questionItemId"])
    except (TypeError, ValueError) as error:
        raise PermissionError(
            "historical direct approval question ID is invalid"
        ) from error
    if (
        not isinstance(item, list)
        or len(item) != 3
        or item[0] != "request_user_input_async"
        or not isinstance(item[1], str)
        or not item[1].startswith("call_")
        or type(item[2]) is not int
        or item[2] != 0
        or chat["record_id"] != "actual-current-chat/" + reply["questionItemId"]
        or reply["answer"] != chat["reason"]
        or not isinstance(reply["question"], str)
        or any(
            value not in reply["question"]
            for value in (PLAN_ID, request.case_id, PACKET_SHA256)
        )
        or chat["text"] != reply["question"] + "\n" + reply["answer"]
    ):
        raise PermissionError(
            "historical direct approval question/reply binding differs"
        )


def _validate_approval_semantics(
    context,
    trial,
    source,
    chat,
    started,
    decided,
    archives,
    *,
    approved_before=None,
    historical_direct_capture=None,
):
    from evals.adapters.e_planning_review import build_review_request
    from evals.adapters.retained_workflow import build_approval_packet

    reader = context["reader"]
    request = next(r for r in reader._requests if r.trial_id == trial["trial_id"])
    reader._chat(chat, kind="plan", participation_policy=request.participation_policy)
    packet = build_approval_packet(
        {"case_id": request.case_id, "dataset": request.dataset},
        source["retained_state"],
        now=_time(chat["decided_at"]),
        participation_policy=request.participation_policy,
    )
    if (
        packet["status"] != "pending"
        or chat["packet_sha256"] != canonical_hash(packet)
        or chat["case_id"] != request.case_id
        or chat["incident_id"] != request.incident_id
        or not isinstance(chat.get("reason"), str)
        or not chat["reason"].strip()
        or started
        != {
            "operation": "decision",
            "request_sha256": canonical_hash(request),
            "packet_sha256": canonical_hash(packet),
            "chat_record": started["chat_record"],
            "decision": chat["decision"],
            "reason": chat["reason"],
        }
        or _archived_json(started["chat_record"], archives) != chat
    ):
        raise PermissionError("actual chat does not bind exact original pending plan")
    if historical_direct_capture is not None:
        _validate_historical_direct_approval(
            context, request, source, chat, started, historical_direct_capture
        )
    else:
        if "prepared_question" not in chat or "actual_incoming_reply" in chat:
            raise PermissionError("actual prepared plan question evidence required")
        question = _archived_json(chat["prepared_question"], archives)
        if (
            question.get("schema_version")
            != "task13-preloaded-specific-plan-question-v1"
            or question.get("synthetic_control_fixture") is not False
            or question.get("automatic_approval") is not False
            or question.get("record_kind") != "prepared_question_not_user_consent"
            or any(
                question.get(k) != chat[k]
                for k in ("case_id", "incident_id", "packet_sha256", "scope")
            )
            or len(chat["actual_question_reply"]) != 1
            or chat["actual_question_reply"][0].get("question") != question["question"]
            or chat["actual_question_reply"][0].get("answer")
            != question["approved_answer"]
            or chat["reason"] != question["approved_answer"]
            or not chat["actual_question_reply"][0].get("questionItemId")
            or _time(question["created_at"]) > _time(chat["decided_at"])
        ):
            raise PermissionError(
                "actual question response does not match prepared plan question"
            )
        # Preserve and verify all explicitly pinned presentation/preview bytes.
        for key in ("presentation_source", "preview"):
            if key in question:
                _archived_json(question[key], archives)
    state = source["state"]
    approval = state["approval"]
    if (
        any(
            approval.get(k) != chat[v]
            for k, v in (("decision", "decision"), ("reason", "reason"))
        )
        or approval["response_plan_id"] != state["response_plan"]["response_plan_id"]
        or not _time(chat["decided_at"])
        <= _time(approval["decided_at"])
        <= _time(approved_before or trial["started_at"])
    ):
        raise PermissionError("persisted approval differs from exact user decision")
    reader._receipt(decided["approval_receipt"], state)
    review = build_review_request(
        request,
        source["resources"],
        operation="decision",
        packet=packet,
        decision="approved",
        reason=chat["reason"],
    )
    if (
        decided["input_sha256"] != canonical_hash(review)
        or decided["request_id"] != review.request_id
        or decided["operation"] != "decision"
        or decided["planning_slot_id"] != request.planning_slot_id
        or decided["registration_sha256"] != request.registration_sha256
        or decided["model_ledger"] != []
        or decided["source_state_sha256"] != canonical_hash(state)
    ):
        raise PermissionError("actual zero-model decision protocol differs")
    terminal = _json(
        reader._root / "slots" / request.planning_slot_id / "decision-terminal.json"
    )
    _validate_runtime_capture(
        decided, terminal, reader._inputs["runtime_options"], review
    )
    expected = build_approval_packet(
        {"case_id": request.case_id, "dataset": request.dataset},
        state,
        now=_time(approval["decided_at"]),
        participation_policy=request.participation_policy,
    )
    if decided["approval_packet"] != expected:
        raise PermissionError("approved packet differs from actual retained state")


def _validate_same_source(original, current):
    old, new = original["planning_registration"], current["planning_registration"]
    for key in ("source", "source_selection_receipt", "selected_source_lineage"):
        if old[key] != new[key]:
            raise PermissionError(
                "pool migration cannot replace original development analysis or case"
            )
    before, after = old.get("recovery_lineage") or {}, new.get("recovery_lineage") or {}
    original_keys = {k for k in before if k.startswith("original_")}
    if (
        any(after.get(k) != before[k] for k in original_keys)
        or {k for k in after if k.startswith("original_")} != original_keys
    ):
        raise PermissionError("original analysis recovery lineage changed")


def _validate_runtime_capture(value, terminal, options, request):
    """Read-only counterpart of the original host's exact stdout capture checks."""
    from scripts.task13_e_trial import _decode

    isolation = value["isolation_evidence"]
    ref = isolation["raw_stdout"]
    path = _plain(ref["path"])
    raw = path.read_bytes()
    if (
        file_sha256(path) != ref["sha256"]
        or len(raw) != ref["bytes"]
        or path.name != "worker-stdout.bin"
        or not path.parent.name.endswith(".controller")
        or not path.is_relative_to(_directory(options["output_dir"]))
    ):
        raise PermissionError("original runtime stdout protocol differs")
    saved = _plain(terminal["stdout"]["path"])
    if file_sha256(saved) != terminal["stdout"]["sha256"] or saved.read_bytes() != raw:
        raise PermissionError(
            "native captured stdout differs from original worker bytes"
        )
    nonce = path.parent.name.removesuffix(".controller")
    expected = (
        Path(options["output_dir"])
        / (
            request.run_id
            if request.schema_version == "task13-e-planning-worker-v1"
            else "source_review"
        )
        / request.case_id
        / (
            request.group
            if request.schema_version == "task13-e-planning-worker-v1"
            else request.request_id
        )
        / nonce
    )
    if (
        path.parent.with_name(nonce) != expected
        or isolation["status"] != "passed"
        or isolation["source_commit"] != request.source_commit
        or isolation["probe"]["pid"] != 1
        or isolation["probe"]["nonce"] != nonce
        or len(nonce) != 32
        or not isolation["container"]["container_id"]
    ):
        raise PermissionError(
            "actual inspected runtime source/process identity differs"
        )
    original = _decode(raw)
    for key in (
        "execution_status",
        "product_status",
        "status",
        "input_sha256",
        "model_ledger",
        "verification",
        "artifact_hashes",
        "errors",
        "diagnosis_status",
        "diagnostic_snapshot",
        "resources",
        "tool_ledger",
        "source",
        "approval_packet",
        "approval_receipt",
        "operation",
        "request_id",
        "source_state_sha256",
        "planning_slot_id",
        "registration_sha256",
        "selected_source_lineage_sha256",
    ):
        if original.get(key) != value.get(key):
            raise PermissionError("native runtime result differs from original stdout")
    if request.schema_version == "task13-e-planning-worker-v1":
        from scripts.task13_worker_runtime import validate_e_planning_probe

        validate_e_planning_probe(
            isolation["probe"]["planning"],
            request,
            authority_sha256=options["planning_authority_sha256"],
        )
    return nonce
