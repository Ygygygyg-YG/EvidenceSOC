"""SYNTHETIC offline I/O boundaries, never real isolation or approval credit.

Public controllers, package/approval/ledger validators and native journals stay
unmodified. Only model/worker transports and product persistence backends are
test doubles. All artifacts must remain in the copied fixture namespace.
"""

import json
import os
from contextlib import asynccontextmanager, nullcontext
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from evals.contracts import canonical_hash
from evals.tests.pool_composite_fixture import _ISOLATED


def write_json(path, value):
    path = Path(path)
    if not _ISOLATED.get() or not path.resolve().is_relative_to(_ISOLATED.get()):
        raise PermissionError("synthetic artifact must remain in copied namespace")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    path.write_bytes(raw)
    return {"path": str(path), "sha256": sha256(raw).hexdigest()}


def capture(value, request, options, nonce, *, planning=False):
    out = Path(options["output_dir"])
    out = (
        out / request.run_id / request.case_id / request.group / nonce
        if planning
        else out / "source_review" / request.case_id / request.request_id / nonce
    )
    out.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    stdout = out.with_name(nonce + ".controller") / "worker-stdout.bin"
    stdout.parent.mkdir(parents=True)
    stdout.write_bytes(raw)
    probe = {"pid": 1, "nonce": nonce}
    if planning:
        probe["planning"] = {
            "source_package_manifest_sha256": request.source_package_manifest_sha256,
            "registration_sha256": request.registration_sha256,
            "request_sha256": canonical_hash(request),
            "authority_sha256": options["planning_authority_sha256"],
            "readonly_source": True,
            "writable_dispatch": True,
        }
    return {
        **value,
        "isolation_evidence": {
            "status": "passed",
            "source_commit": options["source_commit"],
            "probe": probe,
            "container": {
                "container_id": sha256(nonce.encode()).hexdigest(),
                "image_id": options["image_id"],
            },
            "raw_stdout": {
                "schema_version": "task13-worker-stdout-v1",
                "path": str(stdout),
                "sha256": sha256(raw).hexdigest(),
                "bytes": len(raw),
            },
        },
    }


def fixture_plan_chat(root, request, packet):
    """Parser-shaped synthetic chat, explicitly no actual consent or credit."""
    from datetime import UTC, datetime

    from scripts.task13_e_trial import SCOPE

    stamp = datetime.now(UTC).isoformat()
    header = "SYNTHETIC OFFLINE TEST ONLY; NO ACTUAL USER CONSENT OR TIMING CREDIT"
    question = {
        "schema_version": "task13-preloaded-specific-plan-question-v1",
        "fixture_only_header": header,
        "synthetic_control_fixture": False,
        "automatic_approval": False,
        "record_kind": "prepared_question_not_user_consent",
        "case_id": request.case_id,
        "incident_id": request.incident_id,
        "packet_sha256": canonical_hash(packet),
        "scope": SCOPE,
        "question": header + " approve fixture plan?",
        "approved_answer": header + " approved fixture",
        "created_at": stamp,
    }
    question_pin = write_json(Path(root) / "SYNTHETIC-question.json", question)
    chat = {
        "schema_version": "task13-e-user-plan-decision-v1",
        "fixture_only_header": header,
        "role": "user",
        "scope": SCOPE,
        "decision": "approved",
        "record_id": "SYNTHETIC-OFFLINE/" + request.trial_id,
        "text": header,
        "reason": question["approved_answer"],
        "decided_at": stamp,
        "prepared_question": question_pin,
        "case_id": request.case_id,
        "incident_id": request.incident_id,
        "packet_sha256": canonical_hash(packet),
        "source": "root_supplied_actual_question_reply_after_user_response",
        "synthetic_control_fixture": False,
        "actual_question_reply": [
            {
                "questionItemId": json.dumps(
                    ["request_user_input_async", "SYNTHETIC/" + request.trial_id, 0]
                ),
                "question": question["question"],
                "answer": question["approved_answer"],
            }
        ],
    }
    return write_json(Path(root) / "SYNTHETIC-chat.json", chat)


class ProductSession:
    """Read-only SQLAlchemy I/O double backed by original workflow saved rows."""

    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    @property
    def state(self):
        return self.data["services"].saved[-1]

    def get(self, table, key):
        from evidencesoc.domain.models import ApprovalRecord, ResponsePlan

        kind = table.__name__
        if kind == "IncidentTable" and key == self.state["incident_id"]:
            return SimpleNamespace(incident_id=key, status=self.state["status"])
        for name, field, model, identity in (
            ("ResponsePlanTable", "response_plan", ResponsePlan, "response_plan_id"),
            ("ApprovalTable", "approval", ApprovalRecord, "approval_id"),
        ):
            value = self.state.get(field)
            if kind == name and value and value[identity] == key:
                return SimpleNamespace(**model.model_validate(value).model_dump())
        return None

    def scalars(self, statement):
        entity = statement.column_descriptions[0].get("entity")
        rows = []
        if (
            entity is not None
            and entity.__name__ == "ApprovalTable"
            and self.state.get("approval")
        ):
            rows = [self.get(entity, self.state["approval"]["approval_id"])]
        return SimpleNamespace(all=lambda: rows)

    def execute(self, statement):
        if "current_database()" not in str(statement):
            raise AssertionError("unexpected product SQL in offline read fixture")
        return SimpleNamespace(
            one=lambda: (self.data["resources"]["database_name"], "on")
        )


class OfflineRuntime:
    def __init__(self, controller):
        self.controller = controller
        self.plans = {}
        self.io_calls = []

    async def docker(self, arguments, environment):
        if arguments[:2] != ["container", "ls"]:
            raise AssertionError(
                "fixture only allows read-only synthetic docker listing"
            )
        self.io_calls.append(("docker", list(arguments)))
        return {
            "argv": ["docker", *arguments],
            "returncode": 0,
            "stdout_sha256": sha256(b"").hexdigest(),
            "stderr_sha256": sha256(b"").hexdigest(),
        }, b""

    async def plan(self, request, agent_dir, options):
        from evals.tests.pool_composite_planning_fixture import build_offline_planning

        nonce = uuid4().hex
        output = (
            Path(options["output_dir"])
            / request.run_id
            / request.case_id
            / request.group
            / nonce
        )
        data = await build_offline_planning(
            request,
            package_root=options["import_source_dir"],
            budget_path=Path(options["budget_dir"]) / "campaign.sqlite",
            journal_path=options["import_dispatch_path"],
            authority_sha256=options["planning_authority_sha256"],
            output_root=output,
            resource_name="task13_" + request.planning_slot_id.replace("-", "_")[-24:],
        )
        self.plans[request.incident_id] = data
        from evals.adapters.remediation_worker import development_seed

        seed = development_seed(request, agent_dir)
        resource_id = uuid4().hex
        data["resources"].update(
            schema_version="task13-case-resource-v1",
            database_name="task13_" + resource_id,
            index_name="security-events-task13-" + resource_id,
            run_id=request.run_id,
            case_id=request.case_id,
            status="retained_for_human_approval",
            input_sha256=seed["input_sha256"],
        )
        data["services"]._sessions = lambda: ProductSession(data)
        for name, value in (
            ("investigation-state.json", data["state"]),
            ("case-resource.json", data["resources"]),
            ("import-provenance.json", data["provenance"]),
        ):
            write_json(output / name, value)
        value = {
            "execution_status": "completed",
            "product_status": "awaiting_approval",
            "diagnosis_status": "succeeded",
            "errors": [],
            "model_ledger": data["model"].ledger,
            "tool_ledger": [],
            "artifact_hashes": {
                "investigation_state": canonical_hash(data["state"]),
                "case_resource": canonical_hash(data["resources"]),
                "import_provenance": canonical_hash(data["provenance"]),
            },
        }
        return capture(value, request, options, nonce, planning=True)

    @asynccontextmanager
    async def retained(self, reference, **options):
        data = self.plans[reference["incident_id"]]
        assert reference["database_name"] == data["resources"]["database_name"]
        flow = data["flow"]

        class Cursor:
            def execute(self, sql):
                assert "transaction_read_only" in sql

            def fetchone(self):
                return {"database_name": reference["database_name"], "read_only": "on"}

        checkpoint = SimpleNamespace(
            conn=SimpleNamespace(
                connection=lambda: nullcontext(
                    SimpleNamespace(cursor=lambda: nullcontext(Cursor()))
                )
            )
        )

        class Facade:
            checkpointer = checkpoint

            def __getattr__(self, name):
                return getattr(flow, name)

        yield Facade()

    def engine(self, url):
        from sqlalchemy.engine import make_url

        database = make_url(url).database
        data = next(
            d
            for d in self.plans.values()
            if d["resources"]["database_name"] == database
        )
        return SimpleNamespace(data=data, dispose=lambda: None)

    async def review(self, request, agent_dir, options):
        from evals.adapters.e_planning_review import run_e_planning_review
        from evals.adapters.source_epochs import require_registered_epoch

        planning = request.planning_request
        budget = Path(options["budget_dir"]) / "campaign.sqlite"
        epoch = require_registered_epoch(
            budget,
            planning.epoch_id,
            source_sha256=planning.source_sha256,
            config_sha256=planning.config_sha256,
            manifest_sha256=planning.epoch_manifest_sha256,
            latest=True,
        )
        nonce = uuid4().hex
        output = (
            Path(options["output_dir"])
            / "source_review"
            / request.case_id
            / request.request_id
            / nonce
        )
        output.mkdir(parents=True)
        environment = {
            "TASK13_WORKER_NONCE": nonce,
            "TASK13_PHASE": "verification",
            "TASK13_SOURCE_COMMIT": options["source_commit"],
            "TASK13_SOURCE_DIR": options["source_dir"],
            "TASK13_BUDGET_DB": str(budget),
            "TASK13_RUNTIME_BINDING": json.dumps(epoch["runtime_binding"]),
            "TASK13_IMPORT_DISPATCH_DB": options["import_dispatch_path"],
            "TASK13_IMPORT_AUTHORITY_SHA256": options["planning_authority_sha256"],
            "TASK13_IMPORT_SOURCE_DIR": options["import_source_dir"],
            "TASK13_OUTPUT_DIR": str(output),
        }
        with patch.dict(os.environ, environment), patch.object(os, "getpid", lambda: 1):
            value = await run_e_planning_review(request, agent_dir)
        return capture(value, request, options, nonce)

    async def verification(self, request, agent_dir, options):
        from evals.tests.test_verification_v2 import worker_value
        from evals.worker_lifecycle import capture_worker_termination

        value = worker_value(request)
        isolation = value["isolation_evidence"]
        isolation["source_commit"] = options["source_commit"]
        isolation["container"]["container_id"] = sha256(
            request.request_id.encode()
        ).hexdigest()
        isolation["container"]["image_id"] = options["image_id"]
        nonce = isolation["probe"]["nonce"]
        await capture_worker_termination(
            process=SimpleNamespace(returncode=0),
            name="task13-worker-" + nonce,
            nonce=nonce,
            container_id=isolation["container"]["container_id"],
            request_sha256=canonical_hash(request),
            source_commit=options["source_commit"],
            environment={},
            receipt_dir=options["host_termination_dir"],
        )
        return value

    def install(self, monkeypatch):
        from evals import host_review, verification, worker_lifecycle
        from evals.adapters import retained_workflow
        from scripts import task13_timing_pool, task13_worker_runtime

        monkeypatch.setattr(
            task13_worker_runtime, "run_e_planning_container", self.plan
        )
        monkeypatch.setattr(
            task13_worker_runtime, "run_e_planning_review_container", self.review
        )
        monkeypatch.setattr(
            task13_worker_runtime, "run_verification_container", self.verification
        )
        monkeypatch.setattr(worker_lifecycle, "_docker", self.docker)
        monkeypatch.setattr(task13_timing_pool, "_docker", self.docker)
        monkeypatch.setattr(retained_workflow, "open_retained_workflow", self.retained)
        monkeypatch.setattr(host_review, "open_retained_workflow", self.retained)
        monkeypatch.setattr(verification, "create_database_engine", self.engine)
        monkeypatch.setattr(
            verification,
            "create_session_factory",
            lambda engine: lambda: ProductSession(engine.data),
        )
