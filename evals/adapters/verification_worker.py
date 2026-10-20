"""Answer-free F8 worker contract and isolated replay of the original validator."""

from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal, Self

from evidencesoc.agents.capabilities import InvestigationCapabilities
from evidencesoc.agents.checkpoint import open_checkpointer
from evidencesoc.agents.graph import (
    InvestigationWorkflow,
    _persisted_plan_version,
    _plan_hash,
)
from evidencesoc.agents.services import PostgresWorkflowServices
from evidencesoc.config import Settings
from evidencesoc.domain.models import ApprovalRecord, EvidenceItem, ResponsePlan
from evidencesoc.ingestion.normalize import calculate_content_sha256
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.event_search import create_opensearch_client
from evidencesoc.persistence.tables import (
    ApprovalTable,
    EvidenceItemTable,
    ResponsePlanTable,
    SecurityEventTable,
)
from evidencesoc.tools.ledger import Ledger
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from evals.adapters.verification_observations import (
    ControlledObservationAdapter,
    clone_approved_state,
)
from evals.contracts import SHA256, ModelConfig, canonical_hash


class SourceResources(BaseModel):
    model_config = ConfigDict(extra="forbid")
    database_name: str = Field(pattern=r"^task13_[0-9a-f]{32}$")
    index_name: str = Field(pattern=r"^security-events-task13-[0-9a-f]{32}$")

    @model_validator(mode="after")
    def same_case(self) -> Self:
        if self.database_name.removeprefix("task13_") != self.index_name.removeprefix(
            "security-events-task13-"
        ):
            raise ValueError(
                "database and index must belong to the same case namespace"
            )
        return self


class MeasuredControlState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observed_at: datetime
    network_blocked: StrictBool | None = None
    host_isolated: StrictBool | None = None
    account_enabled: StrictBool | None = None
    error_code: str | None = None

    @model_validator(mode="after")
    def aware_time(self) -> Self:
        if self.observed_at.tzinfo is None:
            raise ValueError("control observations need an aware timestamp")
        return self


class ObservationPair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    before: MeasuredControlState
    after: MeasuredControlState


class VerificationWorkerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["task13-verification-worker-v1"] = (
        "task13-verification-worker-v1"
    )
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    namespace: str = Field(pattern=r"^[0-9a-f]{32}$")
    case_id: str = Field(pattern=r"^(?:ait|dedale)-[0-9a-f]{16,24}$")
    agent_sha256: str = Field(pattern=SHA256)
    source_state_sha256: str = Field(pattern=SHA256)
    approved_plan_sha256: str = Field(pattern=SHA256)
    approval_receipt_sha256: str = Field(pattern=SHA256)
    approval_receipt: dict[str, Any]
    approved_state: dict[str, Any]
    source_resources: SourceResources
    verification_enabled: StrictBool
    observations: dict[str, ObservationPair]

    @model_validator(mode="after")
    def bound_inputs(self) -> Self:
        state = self.approved_state
        if canonical_hash(state) != self.source_state_sha256:
            raise ValueError("approved state hash differs")
        if state.get("approved_plan_sha256") != self.approved_plan_sha256:
            raise ValueError("approved plan hash differs")
        if canonical_hash(self.approval_receipt) != self.approval_receipt_sha256:
            raise ValueError("persisted approval receipt hash differs")
        expected = {
            "status": "verified",
            "source": "original_product_database",
            "state_sha256": self.source_state_sha256,
            "approval_sha256": canonical_hash(state.get("approval")),
            "plan_sha256": self.approved_plan_sha256,
            "plan_version": state.get("approved_plan_version"),
        }
        if any(
            self.approval_receipt.get(key) != value for key, value in expected.items()
        ):
            raise ValueError("persisted approval receipt is not bound to this input")
        clone_approved_state(state, self.namespace)
        return self


class SourceReviewRequest(BaseModel):
    """Original-workflow operations; a packet read never implies a decision."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["task13-source-review-worker-v1"] = (
        "task13-source-review-worker-v1"
    )
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    namespace: str = Field(pattern=r"^[0-9a-f]{32}$")
    case_id: str = Field(pattern=r"^(?:ait|dedale)-[0-9a-f]{16,24}$")
    dataset: Literal["ait", "dedale"]
    agent_sha256: str = Field(pattern=SHA256)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_resources: SourceResources
    incident_id: str = Field(min_length=1, max_length=64)
    operation: Literal["read_packet", "decision", "renew_plan"]
    reviewer: Literal["user"] = "user"
    packet: dict[str, Any] | None = None
    decision: Literal["approved", "rejected"] | None = None
    reason: str | None = None
    model: ModelConfig = Field(default_factory=ModelConfig)

    @model_validator(mode="after")
    def explicit_operation(self) -> Self:
        if not self.case_id.startswith(self.dataset + "-"):
            raise ValueError("review dataset differs from the case identity")
        if self.operation == "decision":
            if self.decision is None or not self.reason or not self.reason.strip():
                raise ValueError("an explicit user decision and reason are required")
        elif self.decision is not None or self.reason is not None:
            raise ValueError("a packet read or renewal cannot contain a decision")
        if self.operation != "read_packet":
            packet = self.packet or {}
            if any(
                packet.get(key) != value
                for key, value in (
                    ("schema_version", "task13-response-review-v1"),
                    ("incident_id", self.incident_id),
                    ("case_id", self.case_id),
                    ("dataset", self.dataset),
                    ("reviewer", self.reviewer),
                )
            ) or any(
                not isinstance(packet.get(key), str)
                or re.fullmatch(SHA256, packet[key]) is None
                for key in ("state_sha256", "diagnostic_snapshot_sha256", "plan_sha256")
            ):
                raise ValueError("the original bound review packet is required")
        elif self.packet is not None:
            raise ValueError("packet reads must inspect the live original checkpoint")
        return self


async def run_source_review(request: SourceReviewRequest, agent_dir: Path) -> dict:
    """Read, explicitly decide, or renew the retained original product workflow."""
    from evals.adapters import retained_workflow
    from evals.adapters.artifacts import write_immutable_json
    from evals.adapters.model_client import BudgetAccount, TrackedModel

    if (
        not os.environ.get("TASK13_WORKER_NONCE")
        or os.getpid() != 1
        or os.environ.get("TASK13_PHASE") != "verification"
        or os.environ.get("TASK13_SOURCE_COMMIT") != request.source_commit
    ):
        raise PermissionError("source review requires its inspected bound worker")
    if (
        sha256((Path(agent_dir) / "events.jsonl").read_bytes()).hexdigest()
        != request.agent_sha256
    ):
        raise ValueError("source review case input hash differs")
    reference = {
        **request.source_resources.model_dump(),
        "incident_id": request.incident_id,
        "source_commit": request.source_commit,
    }
    model, state, packet, receipt, tool_calls = None, None, None, None, []
    status, error_type = "completed", None
    try:
        if request.operation == "renew_plan":
            budget_path = Path(os.environ["TASK13_BUDGET_DB"])
            if not budget_path.is_file():
                raise PermissionError(
                    "the existing shared campaign account is required"
                )
            model = TrackedModel(
                request.model,
                api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
                account=BudgetAccount(budget_path, total_cny=100, dev_cny=15),
                phase="verification",
                max_calls=3,
                max_logical_calls=1,
            )
        async with retained_workflow.open_retained_workflow(
            reference, model=model
        ) as workflow:
            sessions = workflow.services._sessions
            ledger = Ledger(sessions)
            before = {
                row.call_id
                for round_no in (1, 2)
                for row in ledger.calls(request.incident_id, round_no)
            }
            try:
                if request.operation == "decision":
                    state = await retained_workflow.apply_human_decision(
                        workflow,
                        request.packet,
                        decision=request.decision,
                        reason=request.reason,
                        decided_by=request.reviewer,
                    )
                    if request.decision == "approved":
                        receipt = read_persisted_approval(state, sessions)
                elif request.operation == "renew_plan":
                    pending = await workflow.get_state(request.incident_id)
                    previous_errors = len(pending.get("errors", []))
                    state = await retained_workflow.renew_expired_plan(
                        workflow,
                        request.packet,
                        requested_by=request.reviewer,
                    )
                    successful_roles = {
                        row["role"]
                        for row in model.ledger
                        if row.get("parse_status") == "valid"
                    }
                    if "respond" not in successful_roles or any(
                        row.get("role") == "respond"
                        for row in state.get("errors", [])[previous_errors:]
                    ):
                        raise PermissionError(
                            "original renewal did not complete its tracked model stages"
                        )
                else:
                    state = await workflow.get_state(request.incident_id)
                packet = retained_workflow.build_approval_packet(
                    {"case_id": request.case_id, "dataset": request.dataset}, state
                )
            finally:
                tool_calls = [
                    asdict(row)
                    for round_no in (1, 2)
                    for row in ledger.calls(request.incident_id, round_no)
                    if row.call_id not in before
                ]
    except Exception as error:  # noqa: BLE001 -- provider/DB errors may include credentials.
        status, error_type = "failed", type(error).__name__
    output = Path(os.environ["TASK13_OUTPUT_DIR"])
    if state is not None:
        write_immutable_json(output / "source-review-state.json", state)
    if packet is not None:
        write_immutable_json(output / "approval-packet.json", packet)
    return {
        "status": status,
        "error_type": error_type,
        "operation": request.operation,
        "request_id": request.request_id,
        "input_sha256": canonical_hash(request),
        "source_state_sha256": canonical_hash(state) if state is not None else None,
        "approved_plan_sha256": (state or {}).get("approved_plan_sha256"),
        "approval_packet": packet,
        "approval_receipt": receipt,
        "source": {"state": state, "resources": reference}
        if status == "completed"
        else None,
        "model_ledger": model.ledger if model else [],
        "tool_ledger": tool_calls,
    }


def read_persisted_approval(state, session_factory) -> dict:
    """Read the actual original product rows; imported JSON alone is insufficient."""
    plan = ResponsePlan.model_validate(state["response_plan"])
    approval = ApprovalRecord.model_validate(state["approval"])
    with session_factory() as session:
        stored_plan = session.get(ResponsePlanTable, plan.response_plan_id)
        stored_approval = session.get(ApprovalTable, approval.approval_id)
        if stored_plan is None or stored_approval is None:
            raise PermissionError(
                "approval is not persisted in the original product database"
            )
        stored_values = {
            key: getattr(stored_plan, key) for key in ResponsePlan.model_fields
        }
        for key in ("created_at", "expires_at"):
            value = stored_values[key]
            if value is not None and value.tzinfo is None:
                stored_values[key] = value.replace(tzinfo=UTC)
        actual_plan = ResponsePlan.model_validate(stored_values)
        actual_approval = ApprovalRecord.model_validate(
            {key: getattr(stored_approval, key) for key in ApprovalRecord.model_fields}
        )
        # SQLite test storage drops timezone offsets; production PostgreSQL keeps them.
        if actual_approval.decided_at.tzinfo is None:
            actual_approval.decided_at = actual_approval.decided_at.replace(tzinfo=UTC)
        if (
            approval.decision != "approved"
            or approval.decided_by != "user"
            or actual_approval != approval
            or _persisted_plan_version(actual_plan.model_dump(mode="json"))
            != state.get("approved_plan_version")
            or _persisted_plan_version(plan.model_dump(mode="json"))
            != state.get("approved_plan_version")
            or state.get("approved_plan_sha256") != _plan_hash(state["response_plan"])
        ):
            raise PermissionError("persisted approval or plan version differs")
    return {
        "status": "verified",
        "source": "original_product_database",
        "state_sha256": canonical_hash(state),
        "approval_sha256": canonical_hash(state["approval"]),
        "plan_sha256": state["approved_plan_sha256"],
        "plan_version": state["approved_plan_version"],
    }


@contextmanager
def cloned_resources(request: VerificationWorkerRequest):
    """Copy the retained case resources into fresh per-branch PostgreSQL/index stores."""
    base = Settings(_env_file=None)
    url = make_url(base.database_url)
    if url.get_backend_name() != "postgresql":
        raise ValueError("verification replay requires PostgreSQL")
    source = request.source_resources
    suffix = uuid.uuid4().hex
    database_name = "task13_" + suffix
    index_name = "security-events-task13-" + suffix
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    search = create_opensearch_client(base.opensearch_url)
    engine = None
    created_database = created_index = False
    old_database, old_index = (
        os.environ.get("DATABASE_URL"),
        os.environ.get("OPENSEARCH_INDEX"),
    )
    try:
        # Both identifiers are validated fixed-prefix hex names. No source resource
        # is mutated or deleted, including on a failed clone or validation.
        with admin.connect() as connection:
            connection.exec_driver_sql(
                f'CREATE DATABASE "{database_name}" TEMPLATE "{source.database_name}"'
            )
        created_database = True
        search.indices.create(
            index=index_name,
            body={"settings": {"number_of_shards": 1, "number_of_replicas": 0}},
        )
        created_index = True
        copied = search.reindex(
            body={
                "source": {"index": source.index_name},
                "dest": {"index": index_name},
            },
            refresh=True,
            wait_for_completion=True,
        )
        if copied.get("failures") or copied.get("timed_out"):
            raise RuntimeError("verification index copy was incomplete")
        isolated_url = url.set(database=database_name).render_as_string(
            hide_password=False
        )
        settings = Settings(
            _env_file=None,
            database_url=isolated_url,
            opensearch_url=base.opensearch_url,
            opensearch_index=index_name,
            llm_mode="deepseek",
        )
        engine = create_database_engine(isolated_url)
        sessions = create_session_factory(engine)
        read_persisted_approval(request.approved_state, sessions)
        os.environ["DATABASE_URL"], os.environ["OPENSEARCH_INDEX"] = (
            isolated_url,
            index_name,
        )
        yield (
            settings,
            sessions,
            {"database_name": database_name, "index_name": index_name},
        )
    finally:
        for key, old in (
            ("DATABASE_URL", old_database),
            ("OPENSEARCH_INDEX", old_index),
        ):
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
        if engine is not None:
            engine.dispose()
        if created_index:
            search.indices.delete(index=index_name)
        if created_database:
            with admin.connect() as connection:
                connection.exec_driver_sql(
                    f'DROP DATABASE "{database_name}" WITH (FORCE)'
                )
        search.close()
        admin.dispose()


def _register_observation_evidence(sessions, incident_id, items):
    with sessions() as session, session.begin():
        for item in items:
            evidence = EvidenceItem.model_validate(item)
            raw = item["raw"]
            if calculate_content_sha256(raw) != evidence.content_sha256:
                raise ValueError("controlled observation evidence integrity differs")
            event = SecurityEventTable(
                event_id=evidence.event_id,
                source=evidence.source,
                external_id=None,
                deduplication_key=evidence.event_id,
                observed_at=evidence.observed_at,
                ingested_at=datetime.now(UTC),
                severity="info",
                event_type="simulation.control_observation",
                raw=raw,
                content_sha256=evidence.content_sha256,
                index_status="pending",
            )
            session.merge(event)
            session.flush()
            session.merge(
                EvidenceItemTable(**evidence.model_dump(), incident_id=incident_id)
            )


async def run_verification(request: VerificationWorkerRequest, agent_dir: Path) -> dict:
    if not os.environ.get("TASK13_WORKER_NONCE") or os.getpid() != 1:
        raise PermissionError("verification requires the inspected PID1 worker")
    if (
        sha256((Path(agent_dir) / "events.jsonl").read_bytes()).hexdigest()
        != request.agent_sha256
    ):
        raise ValueError("verification source case input hash differs")
    state = clone_approved_state(request.approved_state, request.namespace)
    plan = ResponsePlan.model_validate(state["response_plan"])
    if plan.expires_at is None or plan.expires_at <= datetime.now(UTC):
        raise PermissionError("expired plan requires original product renewal")
    state.update(trace_id="TRACE-" + request.namespace, status="validating", events=[])
    with cloned_resources(request) as (settings, sessions, resources):
        if plan.expires_at <= datetime.now(UTC):
            raise PermissionError(
                "plan expired while copying; original product renewal is required"
            )
        ledger = Ledger(sessions)
        copied_call_ids = {
            row.call_id for row in ledger.calls(state["incident_id"], 1, "verification")
        }

        async def register(incident_id, namespace, items):
            if namespace != request.namespace:
                raise PermissionError("observation registration namespace differs")
            await asyncio.to_thread(
                _register_observation_evidence, sessions, incident_id, items
            )

        observer = ControlledObservationAdapter(
            namespace=request.namespace,
            observations={
                key: value.model_dump(mode="json")
                for key, value in request.observations.items()
            },
            register_evidence=register,
        )
        policy = InvestigationCapabilities(
            verification_enabled=request.verification_enabled
        )
        services = PostgresWorkflowServices(
            settings,
            session_factory=sessions,
            capabilities=policy,
            verification_observer=observer,
        )
        async with open_checkpointer(settings.database_url) as saver:
            workflow = InvestigationWorkflow(
                services=services,
                settings=settings,
                checkpointer=saver,
                capabilities=policy,
                database_url=settings.database_url,
            )
            config = workflow._config(state["incident_id"])
            persisted_state = await workflow.get_state(state["incident_id"])
            if canonical_hash(persisted_state) != request.source_state_sha256:
                raise PermissionError(
                    "copied original checkpoint differs from the approved input"
                )
            await workflow.graph.aupdate_state(config, state, as_node="simulate")
            result = await workflow.graph.ainvoke(None, config)
        outcome = (
            (result.get("validation_result") or {}).get("outcome")
            if request.verification_enabled
            else "unverified"
        )
        own_calls = [
            asdict(row)
            for row in ledger.calls(state["incident_id"], 1, "verification")
            if row.call_id not in copied_call_ids
        ]
        output = Path(os.environ["TASK13_OUTPUT_DIR"]) / "verification-state.json"
        with output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True, ensure_ascii=False, default=str)
        receipt = {
            **resources,
            "checkpoint_id": canonical_hash(
                [resources["database_name"], state["incident_id"]]
            ),
            "trace_id": state["trace_id"],
            "evidence_namespace": request.namespace,
            "worker_nonce": os.environ["TASK13_WORKER_NONCE"],
        }
        return {
            "status": "completed" if outcome else "failed",
            "outcome": outcome,
            "input_sha256": canonical_hash(request),
            "source_state_sha256": request.source_state_sha256,
            "approved_plan_sha256": request.approved_plan_sha256,
            "diagnostic_snapshot_sha256": state["diagnostic_snapshot_sha256"],
            "approval_receipt_sha256": request.approval_receipt_sha256,
            "resource_receipt": receipt,
            "validation_result": result.get("validation_result"),
            "model_ledger": [],
            "tool_ledger": own_calls,
            "cost": 0.0,
            "verification_call_count": result.get("verification_call_count", 0),
            "verification_attempts": result.get("verification_attempts", 0),
            "verification_duration_ms": result.get("verification_duration_ms", 0),
        }
