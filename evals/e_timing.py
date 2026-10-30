"""Independent E bootstrap controller; never creates approvals or calls a model.

Registration is not authority. The caller must supply actual persisted-approval,
execution-admission and independent host-termination verifiers. Worker output
cannot prove that its own container was terminated. Synthetic execution is
explicitly marked and is not a real timing observation or F8 coverage.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import math
import re
import time
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evals.adapters.e_participation import require_participation_window
from evals.adapters.retained_workflow import build_approval_packet, resource_fields
from evals.adapters.verification_worker import VerificationWorkerRequest
from evals.contracts import canonical_hash
from evals.verification import _eligibility, _measurements
from evals.verification_v2 import (
    CAMPAIGN,
    _immutable,
    _json_bytes,
    _time,
    _validated_worker_result,
    file_sha256,
    observed_six_branch_max,
)

BOOTSTRAP = {
    "minimum_remaining_seconds": 1500,
    "per_branch_timeout_seconds": 180,
    "total_timeout_seconds": 1200,
    "clock_tolerance_seconds": 2,
}
ORDER = [
    (condition, enabled)
    for condition in ("success", "failure", "no_change")
    for enabled in (True, False)
]
TERMINAL = {"completed", "failed", "expired", "rejected", "not_applicable"}
STATUSES = TERMINAL | {"not_started", "dispatched", "unknown"}
SHA = r"[0-9a-f]{64}"
SOURCE_KEYS = (
    "source_row_id",
    "case_id",
    "dataset",
    "agent_sha256",
    "manifest_sha256",
    "request_sha256",
    "analysis_output_sha256",
    "imported_values_sha256",
)
SOURCE_DIGEST_KEYS = (
    "agent_sha256",
    "manifest_sha256",
    "request_sha256",
    "analysis_output_sha256",
    "imported_values_sha256",
)
ANALYSIS_KEYS = ("origin", "classification", "diagnosis")
IMPORTED_KEYS = ANALYSIS_KEYS + (
    "alerts",
    "evidence",
    "knowledge",
    "attack_steps",
    "claims",
)
DIAGNOSTIC_KEYS = ANALYSIS_KEYS + (
    "evidence",
    "knowledge",
    "attack_steps",
    "claims",
)


def _digest(value):
    return isinstance(value, str) and re.fullmatch(SHA, value) is not None


def _replicate_registration(
    planning_registration, source_files, f8_plan_sha256, dispatch
):
    """Derive every v2 identity from immutable planning inputs, without authority."""
    from evals.e_planning import planning_requests, validate_e_planning_registration

    planning = validate_e_planning_registration(planning_registration)
    requests = planning_requests(planning)
    source = planning["source"]
    if (
        not _digest(f8_plan_sha256)
        or planning["core_config"].get("f8_plan_sha256") != f8_plan_sha256
        or "timing_receipt_sha256" in planning["core_config"]
        or not isinstance(source_files, dict)
        or not source_files
        or any(
            not Path(path).is_absolute() or not _digest(digest)
            for path, digest in source_files.items()
        )
    ):
        raise ValueError("frozen source manifest/core config/F8 plan required")
    expected_dispatch = {
        "schema_version": "task13-e-planning-dispatch-registration-v1",
        "campaign_id": CAMPAIGN,
        "registration_sha256": canonical_hash(planning),
        "synthetic": planning["synthetic"],
        "planning_slot_ids": [q.planning_slot_id for q in requests],
    }
    if (
        not isinstance(dispatch, dict)
        or set(dispatch)
        != set(expected_dispatch) | {"authority_sha256", "journal_path"}
        or any(dispatch.get(key) != value for key, value in expected_dispatch.items())
        or type(dispatch.get("synthetic")) is not bool
        or not _digest(dispatch.get("authority_sha256"))
        or not isinstance(dispatch.get("journal_path"), str)
        or not Path(dispatch["journal_path"]).is_absolute()
    ):
        raise ValueError("actual host planning dispatch registration receipt required")
    return {
        "schema_version": "task13-e-timing-registration-v2",
        "campaign_id": CAMPAIGN,
        "synthetic": planning["synthetic"],
        "mode": planning["mode"],
        "bootstrap": deepcopy(BOOTSTRAP),
        "source_commit": planning["epoch_binding"]["source_commit"],
        "source_files": deepcopy(source_files),
        "core_config": deepcopy(planning["core_config"]),
        "f8_plan_sha256": f8_plan_sha256,
        "budget_source_receipt_sha256": planning["budget_source_receipt_sha256"],
        "source_selection_receipt": deepcopy(planning["source_selection_receipt"]),
        "source_selection_receipt_sha256": planning["source_selection_receipt_sha256"],
        "selected_source_lineage": deepcopy(planning["selected_source_lineage"]),
        "selected_source_lineage_sha256": planning["selected_source_lineage_sha256"],
        "planning_registration": planning,
        "planning_registration_sha256": canonical_hash(planning),
        "planning_dispatch_registration_receipt": deepcopy(dispatch),
        "planning_dispatch_registration_receipt_sha256": canonical_hash(dispatch),
        "qualified_source_count": planning["qualified_source_count"],
        "distinct_source_count": 1,
        "distinct_case_count": 1,
        "replicate_count": 3,
        "f8_approval_credit": 0,
        "approval_policy": planning["approval_policy"],
        "trials": [
            {
                **{
                    key: source[key]
                    for key in SOURCE_KEYS
                    + (
                        "order_index",
                        "source_identity",
                        "source_package_manifest_sha256",
                    )
                },
                **(
                    {
                        key: source[key]
                        for key in ("source_kind", "source_registration_sha256")
                    }
                    if source.get("source_kind") == "additional-development-v1"
                    else {}
                ),
                **{
                    key: getattr(q, key)
                    for key in (
                        "ordinal",
                        "trial_id",
                        "planning_slot_id",
                        "run_id",
                        "incident_id",
                    )
                },
                "planning_request": q.model_dump(mode="json"),
                "planning_request_sha256": canonical_hash(q),
                "branches": deepcopy(slot["branches"]),
            }
            for q, slot in zip(requests, planning["slots"], strict=True)
        ],
    }


def build_e_timing_registration(
    planning_registration,
    *,
    source_files,
    f8_plan_sha256,
    planning_dispatch_registration_receipt,
):
    """Build a detached E2 proposal; never register slots or confer execution scope.

    The dispatch receipt must come from the actual externally authorized host
    journal registration. Synthetic proposals must use synthetic receipts.
    """
    value = _replicate_registration(
        planning_registration,
        source_files,
        f8_plan_sha256,
        planning_dispatch_registration_receipt,
    )
    validate_registration(value)
    return value


def validate_registration(registration):
    """Verify the mechanically selected original first three, never pick sources."""
    r = registration
    if (
        isinstance(r, dict)
        and r.get("schema_version") == "task13-e-timing-registration-v2"
    ):
        try:
            expected = _replicate_registration(
                r["planning_registration"],
                r["source_files"],
                r["f8_plan_sha256"],
                r["planning_dispatch_registration_receipt"],
            )
            # Equality plus exact key sets rejects unknown fields and rebound full
            # receipts even when a caller recomputes the corresponding hashes.
            if r != expected or set(r) != set(expected):
                raise ValueError(
                    "timing registration differs from frozen planning slots"
                )
            if canonical_hash(r) != canonical_hash(expected):
                raise ValueError("strict timing registration field types differ")
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError(
                "complete immutable planning registration required"
            ) from error
        return
    if (
        not isinstance(r, dict)
        or r.get("schema_version") != "task13-e-timing-registration-v1"
        or r.get("campaign_id") != CAMPAIGN
        or r.get("mode") != "bootstrap"
        or type(r.get("synthetic")) is not bool
    ):
        raise ValueError(
            "E bootstrap registration and explicit synthetic flag required"
        )
    if "observed_max_seconds" in r or "complete_observed_trials" in r:
        raise ValueError("observed M cannot be registered or initialized to zero")
    if r.get("bootstrap", BOOTSTRAP) != BOOTSTRAP:
        raise ValueError("bootstrap constants cannot be changed")
    if (
        re.fullmatch(r"[0-9a-f]{40}", r.get("source_commit", "")) is None
        or not r.get("source_files")
        or not isinstance(r.get("core_config"), dict)
        or not _digest(r.get("f8_plan_sha256"))
        or r["core_config"].get("f8_plan_sha256") != r["f8_plan_sha256"]
        or "timing_receipt_sha256" in r["core_config"]
        or not _digest(r.get("budget_source_receipt_sha256"))
    ):
        raise ValueError("pre-frozen source/core config/F8 plan identities required")
    for path, digest in r["source_files"].items():
        if not Path(path).is_absolute() or not _digest(digest):
            raise ValueError("absolute frozen source file manifest required")
    selection = r.get("source_selection_receipt", {})
    if (
        selection.get("schema_version") != "task13-analysis-source-selection-v1"
        or selection.get("rule") != "first-three-qualified-original-36-v1"
        or selection.get("status") != "selected"
        or canonical_hash(selection) != r.get("source_selection_receipt_sha256")
    ):
        raise ValueError("successful fixed first-three source selection required")
    rows, selected = selection.get("rows", []), selection.get("selected_sources", [])
    if (
        len(rows) != 36
        or len(selected) != 3
        or len({row["source_row_id"] for row in rows}) != 36
        or [row["order_index"] for row in rows]
        != sorted({row["order_index"] for row in rows})
        or any(
            row.get("source_status") not in {"completed", "failed", "unknown"}
            or row.get("status")
            not in {"selected", "qualified_after_first_three", "rejected"}
            for row in rows
        )
    ):
        raise ValueError("all original 36 sources must have auditable terminal rows")
    qualified = [
        row
        for row in rows
        if row["status"] in {"selected", "qualified_after_first_three"}
    ]
    if any(
        not _digest(row.get(key))
        for row in qualified + selected
        for key in SOURCE_DIGEST_KEYS
    ):
        raise ValueError("verified original source digests are required")
    projection = lambda row: {key: row[key] for key in SOURCE_KEYS + ("order_index",)}
    if (
        len(qualified) < 3
        or [projection(row) for row in qualified[:3]]
        != [projection(row) for row in selected]
        or [projection(row) for row in rows if row["status"] == "selected"]
        != [projection(row) for row in selected]
    ):
        raise ValueError(
            "selection must retain exactly the original first three qualified rows"
        )
    duplicates = [
        {
            "case_id": case,
            "source_row_ids": [
                row["source_row_id"] for row in selected if row["case_id"] == case
            ],
        }
        for case, count in Counter(row["case_id"] for row in selected).items()
        if count > 1
    ]
    if selection.get("related_case_duplicates") != duplicates:
        raise ValueError("related case duplicates must be disclosed")
    trials = r.get("trials", [])
    if len(trials) != 3:
        raise ValueError("exactly three fixed trials required")
    trial_ids, requests, namespaces = set(), set(), set()
    for trial, source in zip(trials, selected, strict=True):
        if any(trial.get(key) != source[key] for key in SOURCE_KEYS):
            raise ValueError("trial differs from fixed source selection")
        if (
            re.fullmatch(r"[0-9a-f]{32}", trial.get("trial_id", "")) is None
            or trial["trial_id"] in trial_ids
        ):
            raise ValueError("independent trial identity required")
        trial_ids.add(trial["trial_id"])
        if (
            not _digest(trial.get("agent_sha256"))
            or not _digest(trial.get("manifest_sha256"))
            or trial.get("dataset") not in {"ait", "dedale"}
            or not trial["case_id"].startswith(trial["dataset"] + "-")
        ):
            raise ValueError("registered source hashes and dataset differ")
        branches = trial.get("branches", [])
        if [
            (b.get("condition"), b.get("verification_enabled")) for b in branches
        ] != ORDER:
            raise ValueError("fixed six-branch order required")
        for branch in branches:
            if type(branch["verification_enabled"]) is not bool:
                raise ValueError("branch flag must be a boolean")
            for key, used in (("request_id", requests), ("namespace", namespaces)):
                value = branch.get(key, "")
                if re.fullmatch(r"[0-9a-f]{32}", value) is None or value in used:
                    raise ValueError(
                        "all trial request/namespace identities must be independent"
                    )
                used.add(value)


def _validate_imported_state(state, selected):
    """Compare live content with digests frozen by actual source verification.

    Persisted approval verifies a live plan, not its original analysis lineage.
    Never derive the expected original digests from the live state itself.
    """
    from evidencesoc.agents.graph import _plan_hash
    from evidencesoc.agents.models import AnalysisOutput

    if not isinstance(state, dict):
        raise PermissionError("imported analysis state is required")
    provenance = state.get("analysis_import_provenance")
    if (
        not isinstance(provenance, dict)
        or provenance.get("schema_version") != "task13-analysis-import-provenance-v1"
        or provenance.get("entry") != "analysis_import"
        or provenance.get("reconstruct_executed") is not False
        or type(provenance.get("order_index")) is not int
        or any(
            provenance.get(key) != selected[key]
            for key in SOURCE_KEYS + ("order_index",)
        )
        or provenance.get("source_kind") != selected.get("source_kind")
        or provenance.get("source_registration_sha256")
        != selected.get("source_registration_sha256")
    ):
        raise PermissionError("import provenance differs from fixed source selection")
    seal = state.get("diagnostic_snapshot")
    if (
        not isinstance(seal, dict)
        or seal.get("sealed_after") != "analysis_import"
        or not seal.get("sealed_at")
        or state.get("diagnostic_snapshot_sha256") != _plan_hash(seal)
        or any(
            key not in state or key not in seal or state[key] != seal[key]
            for key in DIAGNOSTIC_KEYS
        )
    ):
        raise PermissionError("imported analysis seal or live content differs")
    try:
        output = AnalysisOutput.model_validate(
            {key: state[key] for key in ANALYSIS_KEYS}
        ).model_dump(mode="json")
        values = {key: state[key] for key in IMPORTED_KEYS}
        if (
            canonical_hash(output) != selected["analysis_output_sha256"]
            or canonical_hash(values) != selected["imported_values_sha256"]
        ):
            raise ValueError("original imported content differs")
    except (KeyError, TypeError, ValueError) as error:
        raise PermissionError(
            "imported analysis differs from verified original"
        ) from error


def _additional_source_expectation(registration, request):
    """Keep analysis provenance historical while admission uses the current epoch."""
    planning = registration["planning_registration"]
    recovery = request.get("recovery_lineage")
    registered_recovery = planning.get("recovery_lineage")
    if (recovery is None) != (registered_recovery is None) or (
        recovery is not None
        and canonical_hash(recovery) != canonical_hash(registered_recovery)
    ):
        raise ValueError("timing recovery lineage differs from its registration")
    original = None
    if recovery is not None:
        from evals.adapters.planning_recovery import (
            validate_recovery_execution,
            validate_recovery_original,
        )

        validate_recovery_original(
            recovery,
            planning["source_selection_receipt"]["additional_registration"],
            request["source_package_manifest_sha256"],
            request["original_request_sha256"],
        )
        validate_recovery_execution(recovery, request, request["core_config_sha256"])
        validate_recovery_execution(
            recovery, planning["epoch_binding"], planning["core_config_sha256"]
        )
        original = recovery["original_epoch_binding"]
    return {
        "source_kind": request["source"]["source_kind"],
        "source_registration_sha256": request["source"]["source_registration_sha256"],
        "source_core_sha256": recovery["original_core_config_sha256"]
        if original
        else request["core_config_sha256"],
        "source_epoch_id": original["epoch_id"] if original else request["epoch_id"],
        "source_epoch_manifest_sha256": original["epoch_manifest_sha256"]
        if original
        else request["epoch_manifest_sha256"],
        "source_model_identity_binding": original["model_identity_binding"]
        if original
        else request["model_identity_binding"],
        "source_synthetic": registration["synthetic"],
        "source_commit": original["source_commit"]
        if original
        else request["source_commit"],
        "source_sha256": original["source_sha256"]
        if original
        else request["source_sha256"],
    }


def _validate_replicate_source(registration, registered, source):
    """Independently join the live approval to original bytes and worker retention.

    A persisted approval proves the live plan only. The original analysis and
    bounded-input hashes come exclusively from the frozen original selection;
    slot/request/epoch/authority hashes come from the separate frozen planning
    registration and actual host journal receipt.
    """
    from evals.adapters.verification_worker import SourceResources

    request = registered["planning_request"]
    additional = request["source"].get("source_kind") == "additional-development-v1"
    package_schema = (
        "task13-additional-analysis-package-v1"
        if additional
        else "task13-analysis-artifacts-v2"
    )
    dispatch = registration["planning_dispatch_registration_receipt"]
    admission = {
        **(
            {"model_identity_binding": request["model_identity_binding"]}
            if "model_identity_binding" in request
            else {}
        ),
        "planning_slot_id": request["planning_slot_id"],
        "request_sha256": registered["planning_request_sha256"],
        "registration_sha256": registration["planning_registration_sha256"],
        "authority_sha256": dispatch["authority_sha256"],
        "source_identity": request["source_identity"],
        "analysis_output_sha256": request["analysis_output_sha256"],
        "incident_id": request["incident_id"],
        **{
            key: request[key]
            for key in (
                "source_package_manifest_sha256",
                "original_request_sha256",
                "original_manifest_sha256",
                "imported_values_sha256",
                "source_selection_receipt_sha256",
                "epoch_id",
                "epoch_manifest_sha256",
                "selected_source_lineage_sha256",
                "budget_source_receipt_sha256",
                "selected_source_lineage",
            )
        },
    }
    try:
        if (
            source.get("planning_request") != request
            or canonical_hash(source["planning_request"])
            != registered["planning_request_sha256"]
        ):
            raise ValueError("actual planning request differs from its fixed slot")
        additional_expected = (
            _additional_source_expectation(registration, request)
            if additional
            else None
        )
        state, retained, reference = (
            source["state"],
            source["retained_state"],
            source["resources"],
        )
        if not isinstance(retained, dict) or not isinstance(reference, dict):
            raise TypeError(
                "concrete retained worker state and resource receipt required"
            )
        for current in (state, retained):
            _validate_imported_state(
                current, registration["planning_registration"]["source"]
            )
            provenance = current["analysis_import_provenance"]
            if (
                current.get("incident_id") != request["incident_id"]
                or provenance.get("planning_admission") != admission
                or canonical_hash(provenance.get("planning_admission"))
                != canonical_hash(admission)
                or provenance.get("source_package_schema_version") != package_schema
                or provenance.get("source_package_manifest_sha256")
                != request["source_package_manifest_sha256"]
                or provenance.get("original_manifest_sha256")
                != request["original_manifest_sha256"]
                or current["diagnostic_snapshot"].get("analysis_import_provenance")
                != provenance
            ):
                raise ValueError("sealed original source/planning admission differs")
            if additional and (
                type(provenance.get("source_synthetic")) is not bool
                or any(
                    provenance.get(key) != value
                    for key, value in additional_expected.items()
                )
            ):
                raise ValueError(
                    "sealed additional source registration/epoch/core/model differs"
                )
            if additional and request.get("recovery_lineage") is not None:
                from evals.adapters.planning_recovery import (
                    validate_recovery_provenance,
                )

                validate_recovery_provenance(request["recovery_lineage"], provenance)
        if (
            retained.get("status") != "awaiting_approval"
            or retained.get("approval") is not None
            or retained["response_plan"] != state["response_plan"]
            or retained["diagnostic_snapshot"] != state["diagnostic_snapshot"]
            or retained["analysis_import_provenance"]
            != state["analysis_import_provenance"]
            or source.get("retained_state_sha256") != canonical_hash(retained)
            or source.get("resources_sha256") != canonical_hash(reference)
        ):
            raise ValueError(
                "actual retained pending state differs from live approved plan"
            )
        resources = SourceResources.model_validate(
            resource_fields(reference)
        ).model_dump(mode="json")
        expected = {
            "schema_version": "task13-case-resource-v1",
            **resources,
            "incident_id": request["incident_id"],
            "run_id": request["run_id"],
            "case_id": request["case_id"],
            "source_commit": request["source_commit"],
            "status": "retained_for_human_approval",
            "planning_slot_id": request["planning_slot_id"],
            "registration_sha256": request["registration_sha256"],
            "request_sha256": registered["planning_request_sha256"],
            "source_identity": request["source_identity"],
            "source_package_manifest_sha256": request["source_package_manifest_sha256"],
            # The worker writes canonical content hashes here. Product approval
            # versions use _plan_hash (different Unicode escaping); do not alias.
            "plan_sha256": canonical_hash(state["response_plan"]),
            "snapshot_sha256": state["diagnostic_snapshot_sha256"],
            "state_sha256": canonical_hash(retained),
            "input_sha256": reference.get("input_sha256"),
        }
        if (
            reference != expected
            or set(reference) != set(expected)
            or not _digest(reference.get("input_sha256"))
            or state["response_plan"].get("incident_id") != request["incident_id"]
        ):
            raise ValueError(
                "actual worker retain resource receipt differs from planning slot"
            )
    except (KeyError, TypeError, ValueError) as error:
        raise PermissionError(
            "actual planning source/retained resource binding differs"
        ) from error


async def _await(value):
    return await value if inspect.isawaitable(value) else value


def read_timing_journal(output_dir):
    """Verify current E state while the host already holds its writer lock."""
    root = Path(output_dir)
    registration = json.loads((root / "registration.json").read_text(encoding="utf-8"))
    validate_registration(registration)
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
        raise PermissionError("E journal origin is missing")
    return {"cases": deepcopy(view.trials), "records": deepcopy(view.records)}


class ETimingCampaign:
    """Single writer, append-only bootstrap. No automatic replay or renewal.

    ``run_worker`` is a request-only callable, normally a partial binding of
    ``run_verification_container`` to its inspected agent/runtime options.
    ``worker_lifecycle_verifier(request, timed_out=...)`` reads immutable trusted
    host records, independently of worker output. It establishes container/process
    termination only; it does not claim database/index reclamation.
    """

    def __init__(
        self,
        registration,
        output_dir,
        *,
        execution_admitter=None,
        approval_verifier=None,
        worker_lifecycle_verifier=None,
        now=None,
        monotonic_ns=None,
    ):
        validate_registration(registration)
        self.registration, self.root = deepcopy(registration), Path(output_dir)
        self.execution_admitter = execution_admitter
        self.approval_verifier = approval_verifier
        self.worker_lifecycle_verifier = worker_lifecycle_verifier
        self.now = now or (lambda: datetime.now(UTC))
        self.monotonic_ns = monotonic_ns or time.monotonic_ns
        self.identity = {
            "campaign_id": CAMPAIGN,
            "plan_sha256": registration["f8_plan_sha256"],
            "source_commit": registration["source_commit"],
            "source_sha256": canonical_hash(registration["source_files"]),
            "config_sha256": canonical_hash(registration["core_config"]),
        }
        self._frozen = deepcopy(self.registration)
        self._identity = deepcopy(self.identity)
        self.root.mkdir(parents=True, exist_ok=True)
        with self._lock():
            _immutable(self.root / "registration.json", self.registration)
            self._guard()
            self._load()
            if not self.events:
                self._append(
                    {
                        "kind": "campaign.registered",
                        "registration_sha256": canonical_hash(self.registration),
                    }
                )
            # A dispatch without a committed terminal event is indeterminate.
            # A saved host/output receipt can be merged explicitly, never replayed.
            for row in list(self.records.values()):
                if row["status"] == "dispatched":
                    self._append(
                        {
                            "kind": "branch.recovered_unknown",
                            "trial_id": row["trial_id"],
                            "trial_patch": {
                                "status": "unknown",
                                "reason": "dispatched_without_terminal_event",
                            },
                            "request_id": row["request_id"],
                            "branch_patch": {
                                "status": "unknown",
                                "reason": "dispatched_without_terminal_event",
                            },
                        }
                    )

    @contextmanager
    def _lock(self):
        lock = self.root / ".writer-lock"
        try:
            lock.mkdir()
        except FileExistsError:
            raise PermissionError(
                "E writer active or stale lock requires explicit reconciliation"
            ) from None
        try:
            yield
        finally:
            lock.rmdir()

    def _guard(self):
        if (
            self.registration != self._frozen
            or self.identity != self._identity
            or (self.root / "registration.json").read_bytes()
            != _json_bytes(self._frozen)
        ):
            raise PermissionError("frozen registration/configuration drift")
        for path, digest in self.registration["source_files"].items():
            if file_sha256(path) != digest:
                raise PermissionError("frozen source file drift")

    def _load(self):
        self.events, self.trials, self.records = [], {}, {}
        for trial in self.registration["trials"]:
            trial_id = trial["trial_id"]
            self.trials[trial_id] = {
                "trial_id": trial_id,
                "source_row_id": trial["source_row_id"],
                "status": "not_started",
                "reason": None,
                "binding": None,
            }
            for branch in trial["branches"]:
                self.records[branch["request_id"]] = {
                    **deepcopy(branch),
                    "trial_id": trial_id,
                    "status": "not_started",
                    "reason": None,
                }
        previous = None
        for index, path in enumerate(sorted((self.root / "events").glob("*.json"))):
            try:
                event = json.loads(path.read_text(encoding="utf-8"))
                if (
                    event["sequence"] != index
                    or event["previous_sha256"] != previous
                    or event["registration_sha256"] != canonical_hash(self.registration)
                    or path.name != f"{index:08d}-{canonical_hash(event)}.json"
                ):
                    raise ValueError("journal hash chain differs")
                payload = event["payload"]
                if index == 0 and payload != {
                    "kind": "campaign.registered",
                    "registration_sha256": canonical_hash(self.registration),
                }:
                    raise ValueError("journal registration event differs")
                self._apply(payload)
                self.events.append(event)
                previous = canonical_hash(event)
            except (ValueError, KeyError, TypeError) as error:
                raise PermissionError("E journal is invalid") from error
        for trial in self.trials.values():
            if trial["binding"]:
                self._blob("sources", trial["binding"]["source_sha256"])
                self._blob("approvals", trial["binding"]["approval_receipt_sha256"])
                self._blob("gates", trial["binding"]["execution_gate_sha256"])
        for row in self.records.values():
            for key, category in (
                ("input_sha256", "inputs"),
                ("output_sha256", "outputs"),
                ("host_receipt_sha256", "host-receipts"),
                ("receipt_sha256", "receipts"),
            ):
                if row.get(key):
                    self._blob(category, row[key])

    def _apply(self, payload):
        if "trial_patch" in payload:
            trial = self.trials[payload["trial_id"]]
            if payload["trial_patch"].get("status", trial["status"]) not in STATUSES:
                raise ValueError("unknown trial status")
            trial.update(deepcopy(payload["trial_patch"]))
        if "branch_patch" in payload:
            row = self.records[payload["request_id"]]
            if payload["branch_patch"].get("status", row["status"]) not in STATUSES:
                raise ValueError("unknown branch status")
            row.update(deepcopy(payload["branch_patch"]))

    def _append(self, payload):
        event = {
            "sequence": len(self.events),
            "previous_sha256": canonical_hash(self.events[-1]) if self.events else None,
            "registration_sha256": canonical_hash(self.registration),
            "synthetic": self.registration["synthetic"],
            "payload": deepcopy(payload),
        }
        _immutable(
            self.root
            / "events"
            / f"{len(self.events):08d}-{canonical_hash(event)}.json",
            event,
        )
        self._apply(payload)
        self.events.append(event)

    def _blob(self, category, digest):
        value = json.loads(
            (self.root / category / (digest + ".json")).read_text(encoding="utf-8")
        )
        if canonical_hash(value) != digest:
            raise PermissionError("immutable E artifact hash differs")
        return value

    def _save(self, category, value):
        digest = canonical_hash(value)
        _immutable(self.root / category / (digest + ".json"), value)
        return digest

    def _rows(self, trial_id):
        return [row for row in self.records.values() if row["trial_id"] == trial_id]

    def _progress(self):
        complete = [
            trial for trial in self.trials.values() if trial["status"] == "completed"
        ]
        progress = {
            "schema_version": "task13-e-bootstrap-progress-v1",
            "synthetic": self.registration["synthetic"],
            "mode": "bootstrap",
            "identity": deepcopy(self.identity),
            "bootstrap": deepcopy(BOOTSTRAP),
            "complete_observed_trials": len(complete),
            "observed_max_seconds": max(
                (trial["duration_monotonic_seconds"] for trial in complete),
                default=None,
            ),
            "formal_admissible": False,
            "trials": deepcopy(list(self.trials.values())),
            "records": deepcopy(list(self.records.values())),
        }
        if self.registration["schema_version"] == "task13-e-timing-registration-v2":
            progress.update(self._replicate_disclosure())
        return progress

    def _replicate_disclosure(self):
        return {
            key: deepcopy(self.registration[key])
            for key in (
                "mode",
                "distinct_source_count",
                "distinct_case_count",
                "replicate_count",
                "f8_approval_credit",
                "approval_policy",
                "planning_registration_sha256",
                "selected_source_lineage",
                "selected_source_lineage_sha256",
                "planning_dispatch_registration_receipt_sha256",
            )
        }

    def snapshot(self):
        with self._lock():
            self._guard()
            self._load()
            return self._progress()

    def _source(self, trial_id, source):
        registered = next(
            (
                trial
                for trial in self.registration["trials"]
                if trial["trial_id"] == trial_id
            ),
            None,
        )
        if registered is None:
            raise ValueError("unregistered trial")
        expected = {
            key: self.identity[key]
            for key in (
                "campaign_id",
                "source_commit",
                "source_sha256",
                "config_sha256",
            )
        }
        expected.update(
            source_row_id=registered["source_row_id"],
            case_id=registered["case_id"],
            dataset=registered["dataset"],
            analysis_manifest_sha256=registered["manifest_sha256"],
            budget_source_receipt_sha256=self.registration[
                "budget_source_receipt_sha256"
            ],
        )
        if not isinstance(source, dict) or any(
            source.get(key) != value for key, value in expected.items()
        ):
            raise PermissionError("source selection/core/config binding differs")
        if (
            self.registration["schema_version"] == "task13-e-timing-registration-v2"
            and registered["planning_request"]["source"].get("source_kind")
            == "additional-development-v1"
        ):
            selected = self.registration["planning_registration"]["source"]
        else:
            selected = next(
                row
                for row in self.registration["source_selection_receipt"][
                    "selected_sources"
                ]
                if row["source_row_id"] == registered["source_row_id"]
            )
        _validate_imported_state(source.get("state"), selected)
        if self.registration["schema_version"] == "task13-e-timing-registration-v2":
            _validate_replicate_source(self.registration, registered, source)
            reference = source["resources"]
            for other_id, other in self.trials.items():
                if other_id == trial_id or not other["binding"]:
                    continue
                prior = self._blob("sources", other["binding"]["source_sha256"])
                if any(
                    reference[key] == prior["resources"][key]
                    for key in (
                        "incident_id",
                        "run_id",
                        "planning_slot_id",
                        "database_name",
                        "index_name",
                    )
                ):
                    raise PermissionError(
                        "three planning incidents/runs/source resources must be independent"
                    )
        bound = self.trials[trial_id]["binding"]
        if bound and canonical_hash(source) != bound["source_sha256"]:
            raise PermissionError("source drift; no renewal or cross-version stitching")
        return registered

    def prepare_approval(self, trial_id, source):
        """Prepare a packet under the frozen policy; never persist a decision."""
        current = _time(self.now())
        policy = (
            self.registration.get("planning_registration", {})
            .get("core_config", {})
            .get("participation_policy")
        )
        require_participation_window(current, policy)
        with self._lock():
            self._guard()
            self._load()
            registered = self._source(trial_id, source)
            if self.trials[trial_id]["status"] != "not_started":
                raise PermissionError("trial already started or terminal")
            if any(
                trial_id != key and row.get("review_pending")
                for key, row in self.trials.items()
            ):
                raise PermissionError("only one human approval may be pending")
            packet = build_approval_packet(
                registered,
                deepcopy(source["state"]),
                now=current,
                participation_policy=policy,
            )
            digest = self._save("reviews", packet)
            self._append(
                {
                    "kind": "review.prepared",
                    "trial_id": trial_id,
                    "trial_patch": {
                        "review_pending": True,
                        "review_packet_sha256": digest,
                    },
                }
            )
            return deepcopy(packet)

    def _stop(self, trial_id, status, reason):
        self._append(
            {
                "kind": "trial.stopped",
                "trial_id": trial_id,
                "trial_patch": {
                    "status": status,
                    "reason": reason,
                    "review_pending": False,
                },
            }
        )
        return self._progress()

    def _used_resources(self, *, excluding=None):
        used = set()
        for row in self.records.values():
            if row.get("output_sha256") and row["request_id"] != excluding:
                request = VerificationWorkerRequest.model_validate(
                    self._blob("inputs", row["input_sha256"])
                )
                try:
                    _validated_worker_result(
                        self._blob("outputs", row["output_sha256"]),
                        request,
                        self.identity,
                        used,
                    )
                except (ValueError, PermissionError, TypeError, KeyError):
                    if row["status"] == "completed":
                        raise
        return used

    async def _host_receipt(self, request, *, timed_out, result=None):
        value = await _await(
            self.worker_lifecycle_verifier(request, timed_out=timed_out)
        )
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != "task13-host-worker-termination-v1"
            or value.get("status") != "verified"
            or value.get("request_sha256") != canonical_hash(request)
            or value.get("host_process_exited") is not True
            or value.get("container_absent") is not True
            or not value.get("container_id")
            or not value.get("worker_nonce")
            or not _digest(value.get("receipt_binding_sha256"))
        ):
            raise PermissionError("host container termination is unknown")
        if result is not None and (
            value["container_id"]
            != result["isolation_evidence"]["container"]["container_id"]
            or value["worker_nonce"] != result["resource_receipt"]["worker_nonce"]
        ):
            raise PermissionError(
                "host termination receipt differs from inspected worker"
            )
        return value

    async def run_trial(
        self, trial_id, approved_source, *, run_worker, approval_verifier=None
    ):
        """Run one registered trial once. Defaults never confer execution authority."""
        source = deepcopy(approved_source)
        verifier = approval_verifier or self.approval_verifier
        with self._lock():
            self._guard()
            self._load()
            registered = self._source(trial_id, source)
            trial = self.trials[trial_id]
            if trial["binding"] or trial["status"] != "not_started":
                return self._progress()
            if verifier is None:
                raise PermissionError("actual persisted approval verifier required")
            if self.execution_admitter is None:
                raise PermissionError("actual verified execution admission required")
            if self.worker_lifecycle_verifier is None:
                raise PermissionError(
                    "independent host termination verifier required; runtime integration incomplete"
                )
            current = _time(self.now())
            status, reason = _eligibility(source, current)
            if status is not None:
                return self._stop(
                    trial_id,
                    "expired"
                    if reason == "plan_expired"
                    else "not_applicable"
                    if status == "not_applicable"
                    else "rejected",
                    reason,
                )
            state = source["state"]
            created, expires = (
                _time(state["response_plan"]["created_at"]),
                _time(state["response_plan"]["expires_at"]),
            )
            if expires - created != timedelta(seconds=1800):
                return self._stop(trial_id, "rejected", "plan_ttl_must_be_1800")
            if state["approval"].get("decided_by") != "user":
                raise PermissionError("actual user approval required")
            approval_id = state["approval"]["approval_id"]
            if any(
                row["binding"] and row["binding"]["approval_id"] == approval_id
                for row in self.trials.values()
            ):
                raise PermissionError("three approval identities must be independent")
            gate = await _await(self.execution_admitter(deepcopy(self.identity)))
            if (
                not isinstance(gate, dict)
                or gate.get("schema_version") != "task13-v2-execution-gate-v1"
                or gate.get("status") != "verified"
                or any(gate.get(key) != value for key, value in self.identity.items())
            ):
                raise PermissionError("execution gate binding differs")
            approval = await _await(verifier(deepcopy(source)))
            current = _time(self.now())
            remaining = (expires - current).total_seconds()
            progress = self._progress()
            if remaining <= 1500:
                return self._stop(
                    trial_id, "rejected", "bootstrap_remaining_must_exceed_1500"
                )
            provisional = progress["observed_max_seconds"]
            if provisional is not None and remaining <= 1.5 * provisional + 300:
                return self._stop(trial_id, "rejected", "provisional_remaining")
            if current < created or _time(state["approval"]["decided_at"]) > current:
                return self._stop(trial_id, "rejected", "plan_or_approval_from_future")
            requests = []
            for branch in registered["branches"]:
                request = VerificationWorkerRequest(
                    request_id=branch["request_id"],
                    namespace=branch["namespace"],
                    case_id=registered["case_id"],
                    agent_sha256=registered["agent_sha256"],
                    source_state_sha256=canonical_hash(state),
                    approved_plan_sha256=state["approved_plan_sha256"],
                    approval_receipt=approval,
                    approval_receipt_sha256=canonical_hash(approval),
                    approved_state=state,
                    source_resources=resource_fields(source["resources"]),
                    verification_enabled=branch["verification_enabled"],
                    observations=_measurements(state, branch["condition"], current),
                )
                requests.append(request)
            binding = {
                "source_sha256": self._save("sources", source),
                "approval_id": approval_id,
                "approval_receipt_sha256": self._save("approvals", approval),
                "execution_gate_sha256": self._save("gates", gate),
                "diagnostic_snapshot_sha256": state["diagnostic_snapshot_sha256"],
                "approved_plan_sha256": state["approved_plan_sha256"],
                "expires_at": expires.isoformat(),
                "prior_complete_observed_trials": progress["complete_observed_trials"],
                "prior_observed_max_seconds": provisional,
            }
            if self.registration["schema_version"] == "task13-e-timing-registration-v2":
                binding.update(
                    planning_slot_id=registered["planning_slot_id"],
                    planning_request_sha256=registered["planning_request_sha256"],
                    planning_registration_sha256=self.registration[
                        "planning_registration_sha256"
                    ],
                    resources_sha256=source["resources_sha256"],
                    retained_state_sha256=source["retained_state_sha256"],
                    source_incident_id=source["state"]["incident_id"],
                    source_run_id=registered["run_id"],
                )
            self._append(
                {
                    "kind": "trial.started",
                    "trial_id": trial_id,
                    "trial_patch": {
                        "status": "dispatched",
                        "binding": binding,
                        "reason": None,
                        "review_pending": False,
                    },
                }
            )
            started, started_ns = _time(self.now()), self.monotonic_ns()
            deadline = min(
                started + timedelta(seconds=1200), expires - timedelta(seconds=1)
            )
            for request in requests:
                self._guard()
                now, ns = _time(self.now()), self.monotonic_ns()
                if now >= deadline or ns - started_ns >= 1200_000_000_000:
                    return self._stop(
                        trial_id,
                        "expired" if now >= expires else "failed",
                        "trial_hard_deadline",
                    )
                # Recheck the actual persisted source before each independent clone.
                if canonical_hash(
                    await _await(verifier(deepcopy(source)))
                ) != canonical_hash(approval):
                    return self._stop(trial_id, "failed", "persisted_approval_drift")
                input_hash = self._save("inputs", request.model_dump(mode="json"))
                dispatched, dispatched_ns = _time(self.now()), self.monotonic_ns()
                trial_patch = None
                if request is requests[0]:
                    # The same sample anchors both actual dispatch and duration.
                    started, started_ns = dispatched, dispatched_ns
                    deadline = min(
                        started + timedelta(seconds=1200),
                        expires - timedelta(seconds=1),
                    )
                    remaining = (expires - dispatched).total_seconds()
                    if remaining <= 1500 or (
                        provisional is not None and remaining <= 1.5 * provisional + 300
                    ):
                        return self._stop(
                            trial_id, "rejected", "remaining_changed_before_dispatch"
                        )
                    trial_patch = {
                        "started_at": started.isoformat(),
                        "started_monotonic_ns": started_ns,
                        "hard_deadline": deadline.isoformat(),
                    }
                if (
                    dispatched >= deadline
                    or dispatched_ns - started_ns >= 1200_000_000_000
                ):
                    return self._stop(
                        trial_id,
                        "expired" if dispatched >= expires else "failed",
                        "trial_hard_deadline",
                    )
                dispatch_event = {
                    "kind": "branch.dispatched",
                    "trial_id": trial_id,
                    "request_id": request.request_id,
                    "branch_patch": {
                        "status": "dispatched",
                        "input_sha256": input_hash,
                        "dispatched_at": dispatched.isoformat(),
                        "dispatched_monotonic_ns": dispatched_ns,
                    },
                }
                if trial_patch:
                    dispatch_event["trial_patch"] = trial_patch
                self._append(dispatch_event)
                timeout = min(
                    180,
                    (deadline - dispatched).total_seconds(),
                    1200 - (dispatched_ns - started_ns) / 1e9,
                )
                if timeout <= 0:
                    return self._stop(trial_id, "expired", "trial_hard_deadline")
                task = asyncio.create_task(run_worker(request))
                result_hash, host_hash, returned_at, returned_ns = (
                    None,
                    None,
                    None,
                    None,
                )
                try:
                    done, _ = await asyncio.wait({task}, timeout=timeout)
                    timed_out = not done
                    if timed_out:
                        task.cancel()
                        await asyncio.wait({task}, timeout=5)
                        if task.done() and not task.cancelled():
                            task.exception()  # Consume a late failure without exposing provider text.
                        try:
                            host = await self._host_receipt(request, timed_out=True)
                            if not task.done():
                                raise PermissionError("host task has not exited")
                            host_hash = self._save("host-receipts", host)
                            branch_status, reason = "failed", "worker_timeout"
                        except Exception:  # noqa: BLE001 - indeterminate host cleanup must stop dispatch.
                            host_hash, branch_status, reason = (
                                None,
                                "unknown",
                                "worker_timeout_termination_unknown",
                            )
                        self._append(
                            {
                                "kind": "branch.timeout",
                                "trial_id": trial_id,
                                "request_id": request.request_id,
                                "branch_patch": {
                                    "status": branch_status,
                                    "reason": reason,
                                    "host_receipt_sha256": host_hash,
                                },
                            }
                        )
                        return self._stop(trial_id, branch_status, reason)
                    result = task.result()
                    returned_at, returned_ns = _time(self.now()), self.monotonic_ns()
                    result_hash = self._save("outputs", result)
                    host = await self._host_receipt(
                        request, timed_out=False, result=result
                    )
                    host_hash = self._save("host-receipts", host)
                    self._accept(
                        request.request_id,
                        result,
                        result_hash,
                        host_hash,
                        returned_at=returned_at,
                        returned_ns=returned_ns,
                    )
                except asyncio.CancelledError:
                    task.cancel()
                    self._append(
                        {
                            "kind": "branch.interrupted",
                            "trial_id": trial_id,
                            "request_id": request.request_id,
                            "branch_patch": {
                                "status": "unknown",
                                "reason": "controller_cancelled",
                            },
                        }
                    )
                    self._stop(trial_id, "unknown", "controller_cancelled")
                    raise
                except Exception as error:  # noqa: BLE001 - preserve dispatched uncertainty, never retry.
                    patch = {
                        "status": "unknown",
                        "reason": "worker_or_termination_unknown",
                        "error_type": type(error).__name__,
                    }
                    if result_hash is not None:
                        patch.update(
                            output_sha256=result_hash,
                            worker_returned_at=returned_at.isoformat(),
                            worker_returned_monotonic_ns=returned_ns,
                        )
                    self._append(
                        {
                            "kind": "branch.unknown",
                            "trial_id": trial_id,
                            "request_id": request.request_id,
                            "branch_patch": patch,
                        }
                    )
                    return self._stop(
                        trial_id, "unknown", "worker_or_termination_unknown"
                    )
                row = self.records[request.request_id]
                if row["status"] != "completed":
                    return self._stop(trial_id, row["status"], row["reason"])
            final_row = self.records[requests[-1].request_id]
            end, end_ns = (
                _time(final_row["completed_at"]),
                final_row["completed_monotonic_ns"],
            )
            duration = (end_ns - started_ns) / 1e9
            if (
                not math.isfinite(duration)
                or duration <= 0
                or duration > 1200
                or abs((end - started).total_seconds() - duration) > 2
            ):
                return self._stop(
                    trial_id, "failed", "clock_inconsistent_or_nonpositive"
                )
            self._append(
                {
                    "kind": "trial.completed",
                    "trial_id": trial_id,
                    "trial_patch": {
                        "status": "completed",
                        "reason": None,
                        "completed_at": end.isoformat(),
                        "completed_monotonic_ns": end_ns,
                        "duration_monotonic_seconds": duration,
                    },
                }
            )
            return self._progress()

    def _accept(
        self, request_id, result, output_hash, host_hash, *, returned_at, returned_ns
    ):
        row = self.records[request_id]
        request = VerificationWorkerRequest.model_validate(
            self._blob("inputs", row["input_sha256"])
        )
        trial = self.trials[row["trial_id"]]
        patch = {
            "output_sha256": output_hash,
            "host_receipt_sha256": host_hash,
            "worker_returned_at": returned_at.isoformat(),
            "worker_returned_monotonic_ns": returned_ns,
        }
        try:
            if result.get("cost") != 0:
                raise ValueError("verification worker cost must be zero")
            outcome = _validated_worker_result(
                result,
                request,
                self.identity,
                self._used_resources(excluding=request_id),
            )
            # Disk persistence and all host/worker validation precede completion.
            receipt_hash = self._save(
                "receipts",
                {
                    "input_sha256": row["input_sha256"],
                    "output_sha256": output_hash,
                    "host_receipt_sha256": host_hash,
                    "received_at": returned_at.isoformat(),
                    "received_monotonic_ns": returned_ns,
                },
            )
            current, ns = _time(self.now()), self.monotonic_ns()
            seconds = (ns - row["dispatched_monotonic_ns"]) / 1e9
            utc_seconds = (current - _time(row["dispatched_at"])).total_seconds()
            expires = _time(request.approved_state["response_plan"]["expires_at"])
            reason, status = None, "completed"
            if current >= expires:
                status, reason = "expired", "receipt_after_plan_expiry"
            elif current >= _time(trial["hard_deadline"]) or seconds > 180:
                status, reason = "failed", "worker_or_trial_timeout"
            elif seconds < 0 or utc_seconds < 0 or abs(utc_seconds - seconds) > 2:
                status, reason = "failed", "clock_inconsistent"
            patch.update(
                status=status,
                reason=reason,
                outcome=outcome if status == "completed" else None,
                completed_at=current.isoformat(),
                completed_monotonic_ns=ns,
                receipt_sha256=receipt_hash,
                worker_latency_seconds=(returned_ns - row["dispatched_monotonic_ns"])
                / 1e9,
                host_cleanup_duration_seconds=self._blob(
                    "host-receipts", host_hash
                ).get("cleanup_duration_seconds"),
            )
        except (ValueError, PermissionError, TypeError, KeyError):
            patch.update(status="failed", reason="worker_receipt_invalid", outcome=None)
        self._append(
            {
                "kind": "branch.completed"
                if patch["status"] == "completed"
                else "branch.invalid",
                "trial_id": row["trial_id"],
                "request_id": request_id,
                "branch_patch": patch,
            }
        )

    async def merge_result(self, request_id, value):
        """Merge existing evidence without dispatch, completing no interrupted trial."""
        with self._lock():
            self._guard()
            self._load()
            row = self.records[request_id]
            if row["status"] not in {"dispatched", "unknown"} or not row.get(
                "input_sha256"
            ):
                raise PermissionError(
                    "only existing indeterminate dispatch can receive a receipt"
                )
            request = VerificationWorkerRequest.model_validate(
                self._blob("inputs", row["input_sha256"])
            )
            host = await self._host_receipt(request, timed_out=False, result=value)
            self._accept(
                request_id,
                value,
                self._save("outputs", value),
                self._save("host-receipts", host),
                returned_at=_time(self.now()),
                returned_ns=self.monotonic_ns(),
            )
            return self._progress()

    def export_timing_receipt(self):
        """Original formal schema only after three complete validated observations."""
        with self._lock():
            self._guard()
            self._load()
            if (
                len(
                    [
                        trial
                        for trial in self.trials.values()
                        if trial["status"] == "completed"
                    ]
                )
                != 3
            ):
                raise PermissionError(
                    "three complete trials required before formal timing export"
                )
            trials = []
            for trial in self.trials.values():
                branches = [
                    {
                        "request": self._blob("inputs", row["input_sha256"]),
                        "result": self._blob("outputs", row["output_sha256"]),
                        "dispatched_at": row["dispatched_at"],
                        "completed_at": row["completed_at"],
                        "dispatched_monotonic_ns": row["dispatched_monotonic_ns"],
                        "completed_monotonic_ns": row["completed_monotonic_ns"],
                        "input_sha256": row["input_sha256"],
                        "output_sha256": row["output_sha256"],
                        "receipt_sha256": row["receipt_sha256"],
                        "host_receipt_sha256": row["host_receipt_sha256"],
                    }
                    for row in self._rows(trial["trial_id"])
                ]
                trials.append({**deepcopy(trial), "branches": branches})
            receipt = {
                "schema_version": "task13-v2-six-branch-timing-v1",
                **self.identity,
                "synthetic": self.registration["synthetic"],
                "trials": trials,
                "registration_sha256": canonical_hash(self.registration),
                "budget_source_receipt_sha256": self.registration[
                    "budget_source_receipt_sha256"
                ],
                "source_files_sha256": self.identity["source_sha256"],
                "source_selection_receipt_sha256": self.registration[
                    "source_selection_receipt_sha256"
                ],
            }
            if self.registration["schema_version"] == "task13-e-timing-registration-v2":
                receipt.update(self._replicate_disclosure())
                receipt["planning_registration"] = deepcopy(
                    self.registration["planning_registration"]
                )
                receipt["planning_dispatch_registration_receipt"] = deepcopy(
                    self.registration["planning_dispatch_registration_receipt"]
                )
            receipt["observed_max_seconds"] = observed_six_branch_max(
                receipt, self.identity
            )
            self._save("timings", receipt)
            return deepcopy(receipt)
