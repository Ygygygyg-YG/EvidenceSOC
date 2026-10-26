"""Dedicated E2 import -> respond -> persisted approval-interrupt worker.

Admission is existing-only and precedes secrets, model construction and services.
This module never registers an epoch or slot and never approves or renews a plan.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

from evidencesoc.agents.analysis_import import PlanningAdmission
from evidencesoc.agents.capabilities import InvestigationCapabilities, capability_scope
from evidencesoc.agents.checkpoint import open_checkpointer
from evidencesoc.agents.graph import InvestigationWorkflow, _plan_hash
from evidencesoc.agents.services import PostgresWorkflowServices
from evidencesoc.domain.models import ResponsePlan
from evidencesoc.persistence.tables import IncidentTable, ResponsePlanTable
from sqlalchemy import select

from evals.adapters.e_planning_contracts import EPlanningRequest
from evals.adapters.e_planning_journal import EPlanningDispatchJournal
from evals.adapters.environment import case_environment
from evals.adapters.evidencesoc import _complete_usage
from evals.adapters.isolation_probe import run_service_probe
from evals.adapters.remediation_worker import (
    PayloadRecorder,
    _write_json,
    development_seed,
    export_tool_ledger,
    make_model,
    require_existing_budget,
    validate_exported_source,
)
from evals.adapters.source_epochs import require_registered_epoch
from evals.adapters.worker_errors import exception_category
from evals.contracts import AdapterResult, canonical_hash


class RespondOnlyModel:
    """Product retries use changing hints; one slot always has one logical call."""

    def __init__(self, model, planning_slot_id):
        self.model = model
        self.hint = "e-planning-respond-" + canonical_hash(planning_slot_id)
        self.attempts = 0

    @property
    def ledger(self):
        return self.model.ledger

    @property
    def account(self):
        return self.model.account

    async def structured(self, role, schema, state):
        if role != "respond" or self.attempts >= 3:
            raise PermissionError(
                "planning permits one respond with at most three attempts"
            )
        self.attempts += 1
        return await self.model.structured(
            role, schema, {**state, "_model_call_id": self.hint}
        )


def require_received_response(ledger):
    """Rule fallback may be retained only after an actual provider response."""
    if not any(
        record.get("http_status") == 200
        and isinstance(record.get("raw_response"), dict)
        for record in ledger
    ):
        raise ValueError(
            "planning has no received model response; resources cannot be retained"
        )


def _claim_binding(request, receipt):
    return {
        **receipt,
        **{
            key: getattr(request, key)
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
            )
        },
        "selected_source_lineage": request.selected_source_lineage.model_dump(
            mode="json"
        ),
    }


def validate_planning_inputs(request, agent_dir):
    """Read-only validation, shared with tests; no API-key or resource access."""
    if os.getpid() != 1 or not os.environ.get("TASK13_WORKER_NONCE"):
        raise PermissionError("planning requires inspected container worker PID1")
    request = EPlanningRequest.model_validate(request.model_dump(mode="json"))
    if os.environ.get("TASK13_PHASE") != "development":
        raise ValueError("planning worker phase must be development")
    source_root = Path(os.environ["TASK13_SOURCE_DIR"])
    validate_exported_source(request, agent_dir, source_root)
    budget_path = Path(os.environ["TASK13_BUDGET_DB"])
    require_existing_budget(budget_path, request.budget_identity)
    epoch = require_registered_epoch(
        budget_path,
        request.epoch_id,
        source_sha256=request.source_sha256,
        config_sha256=request.config_sha256,
        budget_identity=request.budget_identity,
        manifest_sha256=request.epoch_manifest_sha256,
        latest=True,
    )
    if epoch["source_commit"] != request.source_commit or epoch[
        "runtime_binding"
    ] != json.loads(os.environ["TASK13_RUNTIME_BINDING"]):
        raise ValueError("registered planning epoch runtime binding differs")
    receipt = json.loads(
        (source_root / "source_receipt.json").read_text(encoding="utf-8")
    )
    required = {
        "scripts/task13_worker_runtime.py",
        "evals/adapters/e_planning_worker.py",
        "evals/adapters/e_planning_contracts.py",
        "evals/adapters/e_planning_journal.py",
        "evals/adapters/analysis_package.py",
        "evals/adapters/analysis_import.py",
        "evals/e_planning.py",
    }
    entries, files = epoch["entrypoints"], receipt["files"]
    if (
        not required <= entries.keys()
        or not required <= files.keys()
        or any(files[name] != entries[name] for name in entries.keys() & files.keys())
    ):
        raise ValueError(
            "registered planning epoch entrypoint differs from source export"
        )
    journal = EPlanningDispatchJournal.open_existing(
        Path(os.environ["TASK13_IMPORT_DISPATCH_DB"]),
        expected_registration_sha256=request.registration_sha256,
        expected_authority_sha256=os.environ["TASK13_IMPORT_AUTHORITY_SHA256"],
        mounted_host_journal_path=os.environ.get("TASK13_IMPORT_HOST_JOURNAL_PATH"),
    )
    journal.validate_request(request)
    # Import locally so the portable verifier remains the one source authority.
    from evals.adapters.analysis_package import verify_portable_analysis_package

    source = verify_portable_analysis_package(
        Path(os.environ["TASK13_IMPORT_SOURCE_DIR"]),
        request.source_package_manifest_sha256,
    )
    expected = {
        "case_id": request.case_id,
        "source_row_id": request.source_row_id,
        "request_sha256": request.original_request_sha256,
        "manifest_sha256": request.original_manifest_sha256,
        "analysis_output_sha256": request.analysis_output_sha256,
        "imported_values_sha256": request.imported_values_sha256,
        "source_package_manifest_sha256": request.source_package_manifest_sha256,
    }
    if source.source_identity != request.source_identity or any(
        source.provenance.get(key) != value for key, value in expected.items()
    ):
        raise ValueError("portable original planning source lineage differs")
    source.revalidate()
    return request, source, journal, budget_path


def validate_persisted_pending(snapshot, row, incident, provenance):
    """Require checkpoint, incident and actual persisted response-plan equality."""
    state = dict(snapshot.values)
    seal = state.get("diagnostic_snapshot")
    if (
        snapshot.next != ("approval",)
        or state.get("status") != "awaiting_approval"
        or incident is None
        or incident.status != "awaiting_approval"
        or state.get("approval") is not None
        or row is None
        or state.get("analysis_import_provenance") != provenance
        or not isinstance(seal, dict)
        or seal.get("sealed_after") != "analysis_import"
        or state.get("diagnostic_snapshot_sha256") != _plan_hash(seal)
        or seal.get("analysis_import_provenance") != provenance
        or any(
            seal.get(key) != state.get(key)
            for key in (
                "diagnosis",
                "origin",
                "classification",
                "attack_steps",
                "claims",
                "evidence",
                "knowledge",
            )
        )
    ):
        raise ValueError("planning did not persist a consistent approval interrupt")
    plan = ResponsePlan.model_validate(state.get("response_plan"))
    if (
        plan.incident_id != state["incident_id"]
        or plan.expires_at is None
        or (plan.expires_at - plan.created_at).total_seconds() != 1800
        or plan.expires_at <= datetime.now(UTC)
    ):
        raise ValueError("planning requires an unexpired exact-1800-second plan")
    stored = {}
    for key in ResponsePlan.model_fields:
        value = getattr(row, key)
        # PostgreSQL returns timezone-aware values; SQLite free fixtures may not.
        if isinstance(value, datetime) and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        stored[key] = value
    if ResponsePlan.model_validate(stored) != plan:
        raise ValueError("persisted response plan differs from checkpoint")
    return state


def _persisted_pending(environment, snapshot, provenance):
    state = snapshot.values
    plan = state.get("response_plan") or {}
    with environment.sessions() as session:
        rows = session.scalars(
            select(ResponsePlanTable).where(
                ResponsePlanTable.incident_id == environment.incident_id
            )
        ).all()
        if len(rows) != 1 or rows[0].response_plan_id != plan.get("response_plan_id"):
            raise ValueError("planning requires exactly one actual response plan row")
        incident = session.get(IncidentTable, environment.incident_id)
        return validate_persisted_pending(snapshot, rows[0], incident, provenance)


async def run_e_planning(request: EPlanningRequest, agent_dir: Path) -> AdapterResult:
    request, source, journal, budget_path = validate_planning_inputs(request, agent_dir)
    # This durable one-shot claim is consumed on every later failure or crash.
    claim = journal.claim_planning_slot(request)
    binding = _claim_binding(request, claim)
    admission = PlanningAdmission._from_existing_claim(
        binding, lambda: _claim_binding(request, journal.validate_request(request))
    )
    started = time.monotonic()
    output = Path(os.environ["TASK13_OUTPUT_DIR"])
    recorder = PayloadRecorder(output)
    model = None
    probe = None
    result = AdapterResult(
        execution_status="failed", diagnosis_status="failed", product_status="failed"
    )
    seed = None
    try:
        spec = request.worker_spec()
        seed = development_seed(request, agent_dir)
        result.evidence_registry = seed["registry"]
        policy = InvestigationCapabilities(
            allowed_tools=frozenset(), rag_mode="disabled", verification_enabled=False
        )
        with case_environment(spec, seed) as environment:
            services = None
            try:
                if environment.incident_id != request.incident_id:
                    raise ValueError("fresh planning incident identity differs")
                before = canonical_hash([])
                probe = await run_service_probe(spec, environment, seed)
                probe.update(
                    model_ledger_before_sha256=before,
                    model_ledger_after_sha256=canonical_hash([]),
                )
                if probe.get("status") != "passed":
                    raise ValueError("independent service isolation probe failed")
                model = RespondOnlyModel(
                    make_model(
                        request, budget_path, "development", payload_sink=recorder
                    ),
                    request.planning_slot_id,
                )
                services = PostgresWorkflowServices(
                    environment.settings,
                    session_factory=environment.sessions,
                    capabilities=policy,
                    model_timeout=request.model.timeout_seconds,
                )
                services.planner_model = model
                provenance = admission.provenance_for(source, environment.incident_id)
                with capability_scope(policy):
                    async with open_checkpointer(
                        environment.settings.database_url
                    ) as checkpointer:
                        workflow = InvestigationWorkflow.for_analysis_import(
                            imported_analysis=source,
                            planning_admission=admission,
                            services=services,
                            settings=environment.settings,
                            checkpointer=checkpointer,
                            model=model,
                            database_url=environment.settings.database_url,
                            capabilities=policy,
                        )
                        state = await workflow.import_analysis(
                            environment.incident_id, source
                        )
                        result.errors.extend(state.get("errors", []))
                        _write_json(output / "investigation-state.json", state)
                        _write_json(output / "import-provenance.json", provenance)
                        snapshot = await workflow.graph.aget_state(
                            workflow._config(environment.incident_id)
                        )
                        state = _persisted_pending(environment, snapshot, provenance)
                        require_received_response(model.ledger)
                        result.tool_ledger = export_tool_ledger(environment)
                        # All immutable artifacts and ledger export must succeed before retention.
                        _write_json(output / "model-ledger.json", model.ledger)
                        _write_json(output / "tool-ledger.json", result.tool_ledger)
                        _write_json(output / "model-payloads.json", recorder.records)
                        reference = {
                            **environment.reference(),
                            "planning_slot_id": request.planning_slot_id,
                            "registration_sha256": request.registration_sha256,
                            "request_sha256": canonical_hash(request),
                            "source_identity": source.source_identity,
                            "source_package_manifest_sha256": request.source_package_manifest_sha256,
                            "plan_sha256": canonical_hash(state["response_plan"]),
                            "snapshot_sha256": state["diagnostic_snapshot_sha256"],
                            "state_sha256": canonical_hash(state),
                            "input_sha256": seed["input_sha256"],
                        }
                # Closing the checkpointer and service is also part of successful persistence.
                await services.aclose()
                services = None
                _write_json(output / "case-resource.json", reference)
                environment.retain()
                result.diagnostic_snapshot = state["diagnostic_snapshot"]
                result.diagnosis_status = "succeeded"
                result.execution_status = "completed"
                result.product_status = "awaiting_approval"
                result.degradation = (
                    [{"kind": "bounded_rule_fallback"}]
                    if state.get("fallback_used")
                    else []
                )
                result.verification = {
                    "status": "awaiting_human_approval",
                    "case_reference": reference,
                }
                result.artifact_hashes = {
                    "investigation_state": canonical_hash(state),
                    "import_provenance": canonical_hash(provenance),
                    "case_resource": canonical_hash(reference),
                }
            finally:
                if services is not None:
                    try:
                        result.tool_ledger = export_tool_ledger(environment)
                        if not (output / "tool-ledger.json").exists():
                            _write_json(output / "tool-ledger.json", result.tool_ledger)
                    except Exception as error:  # noqa: BLE001 - preserve export failure alongside original failure.
                        result.errors.append(
                            {
                                "stage": "tool_ledger_export",
                                "type": type(error).__name__,
                                "category": exception_category(error),
                            }
                        )
                    finally:
                        await services.aclose()
    except Exception as error:  # noqa: BLE001 - sanitized failure; resources still clean in context finally.
        result.errors.append(
            {
                "stage": "e_planning",
                "type": type(error).__name__,
                "category": exception_category(error),
            }
        )
    finally:
        ledger = model.ledger if model else []
        result.model_ledger = ledger
        if probe is not None:
            result.isolation_evidence = {"service_probe": probe}
        complete = _complete_usage(ledger)
        costs = bool(ledger) and all(
            record.get("cost_cny") is not None for record in ledger
        )
        latency = round((time.monotonic() - started) * 1000)
        probe_latency = probe.get("latency_ms", 0) if probe else 0
        result.resources = {
            "latency_ms": max(0, latency - probe_latency),
            "worker_total_latency_ms": latency,
            "isolation_probe_latency_ms": probe_latency,
            "input_tokens": sum(r["usage"]["prompt_tokens"] for r in ledger)
            if complete
            else None,
            "output_tokens": sum(r["usage"]["completion_tokens"] for r in ledger)
            if complete
            else None,
            "cost": sum(r["cost_cny"] for r in ledger) if costs else None,
            "model_logical_calls": len({r["logical_call_id"] for r in ledger}),
            "model_physical_attempts": len(ledger),
            "missing_reason": None
            if complete and costs
            else "usage_or_cost_unavailable",
            "planning_slot_id": request.planning_slot_id,
        }
        # A failed workflow still preserves every physical charge and recorded payload.
        for filename, value in (
            ("model-ledger.json", ledger),
            ("model-payloads.json", recorder.records),
        ):
            if not (output / filename).exists():
                _write_json(output / filename, value)
    return result
