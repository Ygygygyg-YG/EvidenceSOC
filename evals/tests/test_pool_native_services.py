"""Opt-in FREE native-container rehearsal, never user consent or E3/F8 credit.

Unchanged exported worker/runtime bytes execute generic reads, one SYNTHETIC
fixture decision and all six verification branches. No PID/source/admission
patch runs in a container. Formal model HTTP is deliberately outside this test.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from evals.contracts import WorkerRunSpec, canonical_hash

pytest_plugins = ["evals.tests.test_e_planning_live_services"]

CANDIDATE = Path(
    "D:/传智杯/data/task13/supplements/task13-repair-202610-v2/development/timing-v2-rebind-candidate-20261101-e5c49a24"
)
SYNTHETIC_REASON = "SYNTHETIC NATIVE CONTAINER FIXTURE ONLY; NOT AN ACTUAL USER DECISION OR EXPERIMENTAL APPROVAL"


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode()
    path.write_bytes(raw)
    return {"path": str(path.resolve()), "sha256": sha256(raw).hexdigest()}


def _read_pin(pin):
    raw = Path(pin["path"]).read_bytes()
    assert sha256(raw).hexdigest() == pin["sha256"]
    return json.loads(raw)


def _docker(*arguments):
    result = subprocess.run(
        ["docker", *arguments], capture_output=True, text=True, timeout=45, check=False
    )
    if result.returncode:
        raise RuntimeError(
            "Docker local rehearsal command failed: "
            + arguments[0]
            + " / "
            + result.stderr[:400]
        )
    return result.stdout.strip()


@contextmanager
def _internal_services(proof):
    network = "task13-native-free-" + uuid.uuid4().hex
    members = json.loads(
        _docker(
            "network",
            "inspect",
            "evidencesoc_default",
            "--format",
            "{{json .Containers}}",
        )
    )
    names = {v["Name"]: k for k, v in members.items()}
    services = [
        (names["evidencesoc-postgres-1"], "native-free-postgres"),
        (names["evidencesoc-opensearch-1"], "native-free-opensearch"),
    ]
    connected = []
    _docker(
        "network",
        "create",
        "--internal",
        "--label",
        "task13.synthetic_native_free=true",
        network,
    )
    proof.update(
        network_name=network,
        network_internal=True,
        connected_service_ids=[s[0] for s in services],
    )
    try:
        assert json.loads(_docker("network", "inspect", network))[0]["Internal"] is True
        for identifier, alias in services:
            _docker("network", "connect", "--alias", alias, network, identifier)
            connected.append(identifier)
        yield network
    finally:
        leftovers = json.loads(_docker("network", "inspect", network))[0].get(
            "Containers", {}
        )
        removed = []
        for identifier, entry in leftovers.items():
            if identifier in connected:
                continue
            name = entry["Name"]
            assert re.fullmatch("task13-worker-[0-9a-f]{32}", name), (
                "unrecognized container in owned network"
            )
            _docker("rm", "-f", identifier)
            removed.append(identifier)
        for identifier in reversed(connected):
            _docker("network", "disconnect", network, identifier)
        _docker("network", "rm", network)
        proof.update(
            forced_owned_worker_cleanup=removed,
            network_removed=True,
            service_attachments_removed=True,
        )


@contextmanager
def _container_urls(settings):
    # Only local service coordinates are transformed; credentials never printed.
    before = {key: os.environ.get(key) for key in ("DATABASE_URL", "OPENSEARCH_URL")}
    db = make_url(settings.database_url).set(host="native-free-postgres", port=5432)
    search = urlsplit(settings.opensearch_url)
    credentials = search.netloc.rsplit("@", 1)[0] + "@" if "@" in search.netloc else ""
    os.environ["DATABASE_URL"] = db.render_as_string(hide_password=False)
    os.environ["OPENSEARCH_URL"] = urlunsplit(
        (
            search.scheme,
            credentials + "native-free-opensearch:9200",
            search.path,
            search.query,
            search.fragment,
        )
    )
    try:
        assert "DEEPSEEK_API_KEY" not in os.environ
        yield
    finally:
        for key, value in before.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _absence(settings, reference):
    from evidencesoc.persistence.event_search import create_opensearch_client

    db, index = reference["database_name"], reference["index_name"]
    assert re.fullmatch(r"task13_[0-9a-f]{32}", db)
    assert re.fullmatch(r"security-events-task13-[0-9a-f]{32}", index)
    admin = create_engine(
        make_url(settings.database_url).set(database="postgres"),
        isolation_level="AUTOCOMMIT",
    )
    search = create_opensearch_client(settings.opensearch_url)
    try:
        with admin.connect() as connection:
            exists = connection.execute(
                text("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=:name)"),
                {"name": db},
            ).scalar_one()
        return {
            "database_name": db,
            "index_name": index,
            "database_absent": not exists,
            "index_absent": not search.indices.exists(index=index),
        }
    finally:
        admin.dispose()
        search.close()


async def _stage_pending(environment, seed):
    from evidencesoc.agents import fallback
    from evidencesoc.agents.capabilities import InvestigationCapabilities
    from evidencesoc.agents.checkpoint import open_checkpointer
    from evidencesoc.agents.diagnosis import Diagnosis
    from evidencesoc.agents.graph import InvestigationWorkflow, _seal_diagnosis
    from evidencesoc.agents.services import PostgresWorkflowServices

    settings, sessions, incident = environment
    state = {
        "incident_id": incident,
        "trace_id": "TRACE-native-free-" + uuid.uuid4().hex,
        "evidence": seed["evidence"],
        "knowledge": [],
        "errors": [],
        "events": [],
        "alerts": seed["alerts"],
        "status": "awaiting_approval",
    }
    for make in (fallback.analyze, fallback.reconstruct, fallback.respond):
        state.update(make(state).model_dump(mode="json"))
    now = datetime.now(UTC)
    state["response_plan"].update(
        created_at=now.isoformat(), expires_at=(now + timedelta(minutes=30)).isoformat()
    )
    state.update(
        diagnosis_execution_status="completed",
        approval=None,
        simulation=[],
        simulation_execution=None,
        validation_result=None,
        diagnosis=Diagnosis(
            verdict="attack",
            taxonomy_status="out_of_taxonomy",
            origin=state["origin"],
            evidence_ids=state["classification"]["evidence_ids"],
        ).model_dump(mode="json"),
    )
    state.update(_seal_diagnosis(state, "reconstruct"))
    policy = InvestigationCapabilities(verification_enabled=False)
    services = PostgresWorkflowServices(
        settings, session_factory=sessions, capabilities=policy
    )
    try:
        async with open_checkpointer(settings.database_url) as saver:
            workflow = InvestigationWorkflow(
                services=services,
                settings=settings,
                checkpointer=saver,
                capabilities=policy,
                database_url=settings.database_url,
            )
            await services.save_result(state)
            await workflow.graph.aupdate_state(
                workflow._config(incident), state, as_node="respond"
            )
            await workflow.graph.ainvoke(None, workflow._config(incident))
            pending = await workflow.get_state(incident)
            assert (
                pending["status"] == "awaiting_approval" and pending["approval"] is None
            )
            return pending
    finally:
        await services.aclose()


def _checked_result(result, request, options):
    assert result["status"] == "completed", {
        "status": result.get("status"),
        "error_type": result.get("error_type"),
    }
    assert result["input_sha256"] == canonical_hash(request)
    assert result["model_ledger"] == []
    evidence = result["isolation_evidence"]
    assert evidence["status"] == "passed"
    assert evidence["probe"]["pid"] == 1
    assert evidence["container"]["image_id"] == options["image_id"]
    assert (
        evidence["real_model_invocations"] == 0
        and evidence["model_physical_attempts"] == 0
    )
    assert all(
        row["readable"] is False
        for values in evidence["probe"]["boundaries"].values()
        for row in values
    )
    name = "task13-worker-" + evidence["probe"]["nonce"]
    assert not _docker(
        "ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.ID}}"
    )


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.environ.get("TASK13_NATIVE_FREE_REHEARSAL") != "1",
    reason="explicit opt-in for isolated zero-provider native containers",
)
async def test_native_generic_review_and_all_six_branches(
    tmp_path, loopback_services, monkeypatch
):
    from evals.adapters.environment import case_environment
    from evals.adapters.retained_workflow import build_approval_packet, resource_fields
    from evals.adapters.seed import load_seed
    from evals.adapters.verification_worker import (
        SourceReviewRequest,
        VerificationWorkerRequest,
    )
    from evals.verification import CONDITIONS, _measurements, verify_source_approval
    from evals.verification_v2 import _validated_worker_result
    from evals.worker_lifecycle import HostWorkerLifecycleVerifier
    from scripts import task13_worker_runtime as runtime

    settings, blocked = loopback_services
    run_root = Path(os.environ.get("TASK13_NATIVE_FREE_RUN_DIR", str(tmp_path)))
    assert run_root.is_absolute() and run_root.resolve().is_relative_to(
        Path("D:/传智杯").resolve()
    )
    run_root.mkdir(parents=True, exist_ok=True)
    proof = {
        "schema_version": "task13-native-free-rehearsal-v1",
        "synthetic_control_fixture": True,
        "actual_user_approval": False,
        "timing_credit": False,
        "f8_credit": False,
        "provider_requests": 0,
        "formal_native_model_http_tested": False,
        "native_guard_monkeypatches": [],
        "started_at": datetime.now(UTC).isoformat(),
        "results": [],
        "requests": [],
        "cleanup": {},
    }
    materialization = json.loads(
        (CANDIDATE / "activation/materialization.json").read_bytes()
    )
    original = _read_pin(materialization["runtime_options"])
    source = Path(original["source_dir"])
    receipt = json.loads((source / "source_receipt.json").read_bytes())
    assert len(receipt["files"]) == 117
    current = Path(__file__).resolve().parents[2]
    for relative, digest in receipt["files"].items():
        assert sha256((source / relative).read_bytes()).hexdigest() == digest
        assert sha256((current / relative).read_bytes()).hexdigest() == digest
    proof["source_receipt_raw_sha256"] = sha256(
        (source / "source_receipt.json").read_bytes()
    ).hexdigest()
    proof["source_files"] = 117
    proof["source_commit"] = original["source_commit"]
    proof["runtime_original_pin"] = materialization["runtime_options"]
    # Warm and verify exact native dependencies before the fresh synthetic TTL starts.
    print(
        "NATIVE FREE: verifying unchanged source and native runtime assets", flush=True
    )
    runtime._validate_source(source, original["source_commit"])
    dependencies = json.loads(
        (Path(original["dependencies_dir"]) / "task13_dependencies.json").read_bytes()
    )
    assert (
        runtime.dependency_tree_hash(Path(original["dependencies_dir"]))
        == dependencies["tree_sha256"]
    )
    assert (
        runtime.dependency_tree_hash(Path(original["knowledge_dir"]))
        == original["knowledge_sha256"]
    )
    budget = run_root / "budget"
    budget.mkdir()
    with (
        sqlite3.connect(
            (Path(original["budget_dir"]) / "campaign.sqlite").resolve().as_uri()
            + "?mode=ro",
            uri=True,
        ) as old,
        sqlite3.connect(budget / "campaign.sqlite") as copy,
    ):
        old.backup(copy)
    budget_before = sha256((budget / "campaign.sqlite").read_bytes()).hexdigest()
    options = {
        **original,
        "phase": "verification",
        "budget_dir": str(budget),
        "output_dir": str(run_root / "worker-output"),
        "temporary_root": str(run_root / "staging"),
    }
    agent = run_root / "synthetic-agent"
    agent.mkdir()
    marker = "synthetic-native-free-" + uuid.uuid4().hex
    event = {
        "source": marker,
        "observed_at": "2026-10-18T00:00:00Z",
        "event_type": "http.request",
        "source_ip": "198.51.100.10",
        "host": marker + ".example.test",
        "message": "SYNTHETIC ONLY UNION SELECT; native container free rehearsal",
    }
    (agent / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
    agent_sha = sha256((agent / "events.jsonl").read_bytes()).hexdigest()
    spec = WorkerRunSpec(
        run_id="native-free-" + uuid.uuid4().hex,
        case_id="ait-" + uuid.uuid4().hex[:24],
        group="B3",
        config_sha256="a" * 64,
    )
    seed = load_seed(spec, agent)
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", original["source_commit"])
    owned = None
    resource_receipts = []
    try:
        with _internal_services(proof["cleanup"]) as network:
            options["network"] = network
            _write(run_root / "synthetic-runtime-options.json", options)
            with case_environment(spec, seed) as environment:
                owned = environment.reference()
                proof["synthetic_retained_resources"] = owned
                print(
                    "NATIVE FREE: staging isolated synthetic pending state", flush=True
                )
                pending = await _stage_pending(environment, seed)
                _write(run_root / "synthetic-pending-state.json", pending)
                environment.sessions.kw["bind"].dispose()
                args = {
                    "case_id": spec.case_id,
                    "dataset": "ait",
                    "agent_sha256": agent_sha,
                    "source_commit": original["source_commit"],
                    "source_resources": resource_fields(owned),
                    "incident_id": environment.incident_id,
                }
                read = SourceReviewRequest(
                    **args,
                    namespace=uuid.uuid4().hex,
                    request_id=uuid.uuid4().hex,
                    operation="read_packet",
                )
                proof["requests"].append(
                    _write(run_root / "read-request.json", read.model_dump(mode="json"))
                )
                with _container_urls(environment.settings):
                    result = await runtime.run_source_review_container(
                        read, agent, options
                    )
                proof["results"].append(_write(run_root / "read-result.json", result))
                _checked_result(result, read, options)
                print("NATIVE FREE: generic read container verified", flush=True)
                assert result["source"]["state"] == pending
                policy = {
                    "schema_version": "task13-e-participation-policy-v1",
                    "dispatch_window": "anytime",
                    "user_presence_required": False,
                    "plan_approval": "individual-user-decision-v1",
                    "authorization_record_sha256": canonical_hash(
                        {"synthetic_fixture_only": True}
                    ),
                }
                packet = build_approval_packet(
                    {"case_id": spec.case_id, "dataset": "ait"},
                    pending,
                    participation_policy=policy,
                )
                assert (
                    packet["review_window"] == "anytime"
                    and packet["status"] == "pending"
                )
                _write(
                    run_root / "synthetic-approval-packet.json",
                    {
                        "synthetic_control_fixture": True,
                        "actual_user_consent": False,
                        "packet": packet,
                    },
                )
                decision = SourceReviewRequest(
                    **args,
                    namespace=uuid.uuid4().hex,
                    request_id=uuid.uuid4().hex,
                    operation="decision",
                    packet=packet,
                    decision="approved",
                    reason=SYNTHETIC_REASON,
                )
                proof["requests"].append(
                    _write(
                        run_root / "synthetic-decision-request.json",
                        decision.model_dump(mode="json"),
                    )
                )
                with _container_urls(environment.settings):
                    decided = await runtime.run_source_review_container(
                        decision, agent, options
                    )
                proof["results"].append(
                    _write(run_root / "synthetic-decision-result.json", decided)
                )
                _checked_result(decided, decision, options)
                print(
                    "NATIVE FREE: synthetic generic decision container verified",
                    flush=True,
                )
                approved = decided["source"]["state"]
                assert approved["approval"]["reason"] == SYNTHETIC_REASON
                assert approved["simulation_execution"]["status"] == "completed"
                verified = verify_source_approval(
                    {"state": approved, "resources": owned}
                )
                assert verified == decided["approval_receipt"]
                _write(
                    run_root / "synthetic-persisted-approval-verification.json",
                    {"synthetic_control_fixture": True, "receipt": verified},
                )
                outcomes = []
                used_resources = set()
                for condition in CONDITIONS:
                    observations = _measurements(approved, condition, datetime.now(UTC))
                    for enabled in (True, False):
                        request = VerificationWorkerRequest(
                            request_id=uuid.uuid4().hex,
                            namespace=uuid.uuid4().hex,
                            case_id=spec.case_id,
                            agent_sha256=agent_sha,
                            source_state_sha256=canonical_hash(approved),
                            approved_plan_sha256=approved["approved_plan_sha256"],
                            approval_receipt=verified,
                            approval_receipt_sha256=canonical_hash(verified),
                            approved_state=approved,
                            source_resources=resource_fields(owned),
                            verification_enabled=enabled,
                            observations=observations,
                        )
                        proof["requests"].append(
                            _write(
                                run_root
                                / (condition + "-" + str(enabled) + "-request.json"),
                                request.model_dump(mode="json"),
                            )
                        )
                        branch_options = {
                            **options,
                            "host_termination_dir": str(run_root / "terminations"),
                        }
                        with _container_urls(environment.settings):
                            value = await runtime.run_verification_container(
                                request, agent, branch_options
                            )
                        proof["results"].append(
                            _write(
                                run_root
                                / (condition + "-" + str(enabled) + "-result.json"),
                                value,
                            )
                        )
                        _checked_result(value, request, options)
                        assert (
                            _validated_worker_result(
                                value,
                                request,
                                {"source_commit": original["source_commit"]},
                                used_resources,
                            )
                            == value["outcome"]
                        )
                        assert len(value["tool_ledger"]) == int(enabled)
                        termination = HostWorkerLifecycleVerifier(
                            run_root / "terminations"
                        )(request, timed_out=False)
                        assert (
                            termination["status"] == "verified"
                            and termination["host_process_exited"]
                            and termination["container_absent"]
                        )
                        proof.setdefault("termination_receipts", []).append(
                            {
                                k: termination[k]
                                for k in (
                                    "receipt_path",
                                    "receipt_binding_sha256",
                                    "request_sha256",
                                    "host_process_exited",
                                    "container_absent",
                                    "process_returncode",
                                )
                            }
                        )
                        print(
                            "NATIVE FREE: branch",
                            condition,
                            enabled,
                            "verified",
                            flush=True,
                        )
                        resource_receipts.append(value["resource_receipt"])
                        outcomes.append(value["outcome"])
                        absent = _absence(settings, value["resource_receipt"])
                        assert absent["database_absent"] and absent["index_absent"]
                        proof.setdefault("branch_resource_cleanup", []).append(absent)
                assert outcomes == [
                    "success",
                    "unverified",
                    "failure",
                    "unverified",
                    "insufficient_evidence",
                    "unverified",
                ]
                assert len({r["database_name"] for r in resource_receipts}) == 6
                assert len({r["index_name"] for r in resource_receipts}) == 6
                assert owned["database_name"] not in {
                    r["database_name"] for r in resource_receipts
                }
                proof.update(
                    outcomes=outcomes,
                    completed_branches=6,
                    generic_reads=1,
                    generic_fixture_decisions=1,
                    native_worker_results=8,
                    persisted_approval_verified=True,
                )
            proof["cleanup"]["source_resources"] = _absence(settings, owned)
            assert all(
                proof["cleanup"]["source_resources"][k]
                for k in ("database_absent", "index_absent")
            )
        assert (
            sha256((budget / "campaign.sqlite").read_bytes()).hexdigest()
            == budget_before
        )
        assert not blocked and "DEEPSEEK_API_KEY" not in os.environ
        proof.update(
            status="passed", budget_copy_unchanged=True, provider_key_absent=True
        )
    finally:
        if owned is not None:
            proof["cleanup"]["source_resources_final"] = _absence(settings, owned)
        proof["finished_at"] = datetime.now(UTC).isoformat()
        _write(run_root / "native-free-rehearsal-proof.json", proof)


def audit_existing_native_branches(run_root):
    """Recover logical requests only when two original native hash bindings match.

    Recovered JSON is labelled as recovery, not as the deleted original spec-file
    bytes. This performs no service or container operation and confers no credit.
    """
    from evals.adapters.retained_workflow import resource_fields
    from evals.adapters.verification_worker import VerificationWorkerRequest
    from evals.verification import CONDITIONS, _measurements
    from evals.verification_v2 import _validated_worker_result
    from evals.worker_lifecycle import HostWorkerLifecycleVerifier

    run_root = Path(run_root)
    proof = json.loads((run_root / "native-free-rehearsal-proof.json").read_bytes())
    assert proof["status"] == "passed" and proof["synthetic_control_fixture"] is True
    assert (
        proof["actual_user_approval"] is False
        and proof["timing_credit"] is False
        and proof["f8_credit"] is False
    )
    pinned_results = {
        Path(pin["path"]).name: _read_pin(pin) for pin in proof["results"]
    }
    decided = pinned_results["synthetic-decision-result.json"]
    approved = decided["source"]["state"]
    receipt = decided["approval_receipt"]
    assert (
        receipt
        == json.loads(
            (run_root / "synthetic-persisted-approval-verification.json").read_bytes()
        )["receipt"]
    )
    used = set()
    branches = []
    for condition in CONDITIONS:
        enabled = pinned_results[condition + "-True-result.json"]
        nonce = enabled["isolation_evidence"]["probe"]["nonce"]
        files = list(
            (run_root / "worker-output" / "verification").glob(
                "*/*/" + nonce + "/verification-state.json"
            )
        )
        assert len(files) == 1
        enabled_state = json.loads(files[0].read_bytes())
        observations = [
            item["raw"]
            for item in enabled_state["evidence"]
            if item.get("source") == "simulated-control-observation"
            and item.get("query", {}).get("namespace")
            == enabled["resource_receipt"]["evidence_namespace"]
        ]
        assert observations, (
            "actual controlled observation timestamps are required for exact recovery"
        )
        before = min(
            datetime.fromisoformat(row["observed_at"].replace("Z", "+00:00"))
            for row in observations
        )
        measurement = _measurements(approved, condition, before)
        for flag in (True, False):
            value = pinned_results[condition + "-" + str(flag) + "-result.json"]
            nonce = value["isolation_evidence"]["probe"]["nonce"]
            paths = list(
                (run_root / "worker-output" / "verification").glob(
                    "*/*/" + nonce + "/verification-state.json"
                )
            )
            assert len(paths) == 1
            state_path = paths[0]
            request = VerificationWorkerRequest(
                request_id=state_path.parent.parent.name,
                namespace=value["resource_receipt"]["evidence_namespace"],
                case_id=state_path.parents[2].name,
                agent_sha256=value["isolation_evidence"]["probe"]["agent_sha256"],
                source_state_sha256=canonical_hash(approved),
                approved_plan_sha256=approved["approved_plan_sha256"],
                approval_receipt=receipt,
                approval_receipt_sha256=canonical_hash(receipt),
                approved_state=approved,
                source_resources=resource_fields(proof["synthetic_retained_resources"]),
                verification_enabled=flag,
                observations=measurement,
            )
            assert canonical_hash(request) == value["input_sha256"], (
                "recovery is forbidden unless original native input commitment matches exactly"
            )
            termination = HostWorkerLifecycleVerifier(run_root / "terminations")(
                request, timed_out=False
            )
            assert termination["request_sha256"] == value["input_sha256"]
            assert (
                termination["status"] == "verified"
                and termination["host_process_exited"]
                and termination["container_absent"]
            )
            outcome = _validated_worker_result(
                value, request, {"source_commit": proof["source_commit"]}, used
            )
            assert len(value["tool_ledger"]) == int(flag)
            pin = _write(
                run_root
                / "recovered-requests"
                / (condition + "-" + str(flag) + ".json"),
                request.model_dump(mode="json"),
            )
            branches.append(
                {
                    "condition": condition,
                    "verification_enabled": flag,
                    "outcome": outcome,
                    "recovered_request": pin,
                    "original_native_input_sha256": value["input_sha256"],
                    "termination": {
                        k: termination[k]
                        for k in (
                            "receipt_path",
                            "receipt_binding_sha256",
                            "request_sha256",
                            "process_returncode",
                            "host_process_exited",
                            "container_absent",
                        )
                    },
                }
            )
    assert len(branches) == 6 and len(used) == 36
    audit = {
        "schema_version": "task13-native-free-recovered-request-audit-v1",
        "status": "verified",
        "synthetic_control_fixture": True,
        "actual_user_approval": False,
        "timing_credit": False,
        "f8_credit": False,
        "new_container_executions": 0,
        "original_spec_file_bytes_preserved": False,
        "recovery_rule": "exact canonical request equals original native result input and original host termination request hashes",
        "generic_review_limit": "generic request namespaces were not archived; live run asserted their input hashes, but they cannot be independently reconstructed from retained outputs",
        "branches": branches,
        "original_rehearsal_proof": {
            "path": str(run_root / "native-free-rehearsal-proof.json"),
            "sha256": sha256(
                (run_root / "native-free-rehearsal-proof.json").read_bytes()
            ).hexdigest(),
        },
    }
    _write(run_root / "recovered-native-branch-audit.json", audit)
    return audit


@pytest.mark.skipif(
    not os.environ.get("TASK13_NATIVE_FREE_AUDIT_DIR"),
    reason="explicit existing rehearsal artifact directory required",
)
def test_recovered_native_branch_receipts_without_reexecution():
    result = audit_existing_native_branches(
        Path(os.environ["TASK13_NATIVE_FREE_AUDIT_DIR"])
    )
    assert result["status"] == "verified" and len(result["branches"]) == 6
