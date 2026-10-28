"""Bound read/decision operations for E2; never renew or construct a model."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Self

from evidencesoc.agents.analysis_import import PlanningAdmission
from evidencesoc.agents.graph import _plan_hash
from pydantic import model_validator

from evals.adapters.e_planning_contracts import EPlanningRequest
from evals.adapters.e_planning_journal import EPlanningDispatchJournal
from evals.adapters.remediation_worker import (
    require_existing_budget,
    validate_exported_source,
)
from evals.adapters.source_epochs import require_registered_epoch
from evals.adapters.verification_worker import SourceReviewRequest, run_source_review
from evals.contracts import canonical_hash


def _operation_identity(planning, operation, packet):
    key = canonical_hash(
        [planning.request_id, operation, canonical_hash(packet) if packet else None]
    )
    return {"request_id": key[:32], "namespace": canonical_hash(["e-review", key])[:32]}


class EPlanningReviewRequest(SourceReviewRequest):
    schema_version: Literal["task13-e-planning-review-worker-v1"] = (
        "task13-e-planning-review-worker-v1"
    )
    operation: Literal["read_packet", "decision"]
    planning_request: EPlanningRequest
    case_resource: dict

    @model_validator(mode="after")
    def bound_planning_review(self) -> Self:
        planning = self.planning_request
        expected = {
            "case_id": planning.case_id,
            "dataset": planning.dataset,
            "agent_sha256": planning.agent_sha256,
            "source_commit": planning.source_commit,
            "incident_id": planning.incident_id,
            "model": planning.model,
            **_operation_identity(planning, self.operation, self.packet),
        }
        if any(getattr(self, key) != value for key, value in expected.items()):
            raise ValueError(
                "review operation differs from its registered planning request"
            )
        reference = {
            "schema_version": "task13-case-resource-v1",
            **self.source_resources.model_dump(mode="json"),
            "incident_id": planning.incident_id,
            "run_id": planning.run_id,
            "case_id": planning.case_id,
            "source_commit": planning.source_commit,
            "status": "retained_for_human_approval",
            "planning_slot_id": planning.planning_slot_id,
            "registration_sha256": planning.registration_sha256,
            "request_sha256": canonical_hash(planning),
            "source_identity": planning.source_identity,
            "source_package_manifest_sha256": planning.source_package_manifest_sha256,
        }
        digests = {"plan_sha256", "snapshot_sha256", "state_sha256", "input_sha256"}
        if (
            set(self.case_resource) != set(reference) | digests
            or any(
                self.case_resource.get(key) != value for key, value in reference.items()
            )
            or any(
                not isinstance(self.case_resource.get(key), str)
                or re.fullmatch(r"[0-9a-f]{64}", self.case_resource[key]) is None
                for key in digests
            )
        ):
            raise ValueError("review retained resource binding differs")
        return self

    @property
    def budget_identity(self):
        return self.planning_request.budget_identity

    def source_review_request(self):
        values = self.model_dump(mode="json")
        return SourceReviewRequest(
            **{
                key: values[key]
                for key in SourceReviewRequest.model_fields
                if key != "schema_version"
            }
        )


def build_review_request(
    planning_request,
    case_resource,
    *,
    operation,
    packet=None,
    decision=None,
    reason=None,
):
    planning = EPlanningRequest.model_validate(planning_request)
    return EPlanningReviewRequest(
        **_operation_identity(planning, operation, packet),
        planning_request=planning,
        case_resource=case_resource,
        case_id=planning.case_id,
        dataset=planning.dataset,
        agent_sha256=planning.agent_sha256,
        source_commit=planning.source_commit,
        source_resources={
            key: case_resource.get(key) for key in ("database_name", "index_name")
        },
        incident_id=planning.incident_id,
        operation=operation,
        packet=packet,
        decision=decision,
        reason=reason,
        model=planning.model,
    )


def require_review_window(now: datetime | None = None):
    current = now or datetime.now(UTC)
    if (
        current.tzinfo is None
        or current.astimezone(timezone(timedelta(hours=8))).hour < 19
    ):
        raise PermissionError("review window is 19:00-00:00 Asia/Shanghai")


def validate_review_state(request, state, imported, binding):
    """Validate live persisted state before any decision, independently of packet text."""
    admission = PlanningAdmission._from_existing_claim(binding, lambda: binding)
    provenance = admission.provenance_for(imported, request.incident_id)
    expected = imported.product_values()
    expected["analysis_import_provenance"] = provenance
    seal = state.get("diagnostic_snapshot")
    if (
        state.get("incident_id") != request.incident_id
        or any(state.get(key) != value for key, value in expected.items())
        or not isinstance(seal, dict)
        or seal.get("sealed_after") != "analysis_import"
        or _plan_hash(seal) != state.get("diagnostic_snapshot_sha256")
        or seal.get("analysis_import_provenance") != provenance
        or any(
            seal.get(key) != state.get(key)
            for key in (
                "origin",
                "classification",
                "diagnosis",
                "evidence",
                "knowledge",
                "claims",
                "attack_steps",
            )
        )
        or request.case_resource["snapshot_sha256"]
        != state.get("diagnostic_snapshot_sha256")
        or request.case_resource["plan_sha256"]
        != canonical_hash(state.get("response_plan"))
        or (
            state.get("status") == "awaiting_approval"
            and request.case_resource["state_sha256"] != canonical_hash(state)
        )
    ):
        raise PermissionError(
            "review actual original diagnosis, seal or planning claim differs"
        )


def validate_review_inputs(request, agent_dir):
    """All validation is read-only and uses no secrets."""
    from evals.adapters.analysis_package import verify_portable_analysis_package
    from evals.adapters.e_planning_worker import _claim_binding

    request = EPlanningReviewRequest.model_validate(request.model_dump(mode="json"))
    planning = request.planning_request
    validate_exported_source(planning, agent_dir, Path(os.environ["TASK13_SOURCE_DIR"]))
    budget = Path(os.environ["TASK13_BUDGET_DB"])
    require_existing_budget(budget, planning.budget_identity)
    epoch = require_registered_epoch(
        budget,
        planning.epoch_id,
        source_sha256=planning.source_sha256,
        config_sha256=planning.config_sha256,
        budget_identity=planning.budget_identity,
        manifest_sha256=planning.epoch_manifest_sha256,
        latest=True,
    )
    if planning.model_identity_binding is not None:
        from evals.adapters.model_identity_runtime import require_dispatch_identity

        require_dispatch_identity(budget, planning)
    if epoch["source_commit"] != planning.source_commit or epoch[
        "runtime_binding"
    ] != json.loads(os.environ["TASK13_RUNTIME_BINDING"]):
        raise ValueError("review registered source epoch runtime differs")
    journal = EPlanningDispatchJournal.open_existing(
        Path(os.environ["TASK13_IMPORT_DISPATCH_DB"]),
        expected_registration_sha256=planning.registration_sha256,
        expected_authority_sha256=os.environ["TASK13_IMPORT_AUTHORITY_SHA256"],
        mounted_host_journal_path=os.environ["TASK13_IMPORT_HOST_JOURNAL_PATH"],
    )

    def claim():
        return _claim_binding(planning, journal.validate_request(planning))

    binding = claim()
    if binding["status"] != "started":
        raise PermissionError(
            "review requires its actual previously claimed planning slot"
        )
    imported = verify_portable_analysis_package(
        Path(os.environ["TASK13_IMPORT_SOURCE_DIR"]),
        planning.source_package_manifest_sha256,
    )
    admission = PlanningAdmission._from_existing_claim(binding, claim)
    admission.provenance_for(imported, request.incident_id)
    return request, imported, binding, claim


async def run_e_planning_review(request, agent_dir: Path) -> dict:
    if (
        os.getpid() != 1
        or not os.environ.get("TASK13_WORKER_NONCE")
        or os.environ.get("TASK13_PHASE") != "verification"
    ):
        raise PermissionError(
            "planning review requires its inspected verification worker"
        )
    require_review_window()
    request, imported, binding, claim = validate_review_inputs(request, agent_dir)

    def validate(state):
        require_review_window()
        if claim() != binding:
            raise PermissionError("registered review planning claim changed")
        validate_review_state(request, state, imported, binding)
        approval = state.get("approval")
        if approval is not None:
            require_review_window(
                datetime.fromisoformat(approval["decided_at"].replace("Z", "+00:00"))
            )
        require_review_window()

    result = await run_source_review(
        request.source_review_request(),
        agent_dir,
        state_validator=validate,
        decision_admitter=require_review_window,
        verification_enabled=False,
    )
    if result.get("model_ledger"):
        raise PermissionError("planning reads and decisions cannot make model calls")
    return {
        **result,
        "source_review_input_sha256": result.get("input_sha256"),
        "input_sha256": canonical_hash(request),
        "planning_slot_id": request.planning_request.planning_slot_id,
        "registration_sha256": request.planning_request.registration_sha256,
        "selected_source_lineage_sha256": request.planning_request.selected_source_lineage_sha256,
    }
