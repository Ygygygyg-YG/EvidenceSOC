"""Opt-in live stores with synthetic states/approvals, never experiment results.

The test substitutes only the PID1 guard and a worker nonce. It provides no
container-isolation receipt and cannot count as a formal execution or approval.
"""

from __future__ import annotations

import json
import os
import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import SimpleNamespace

import pytest

from evals.contracts import WorkerRunSpec, canonical_hash


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.environ.get("TASK13_LIVE_SYNTHETIC_VERIFICATION") != "1",
    reason="explicit opt-in required for synthetic live PostgreSQL/OpenSearch test",
)
async def test_synthetic_original_approval_and_live_verification_resource_copies(
    tmp_path, monkeypatch
):
    import httpx
    from evidencesoc.agents import fallback
    from evidencesoc.agents.capabilities import InvestigationCapabilities
    from evidencesoc.agents.checkpoint import open_checkpointer
    from evidencesoc.agents.graph import InvestigationWorkflow, _plan_hash
    from evidencesoc.agents.services import PostgresWorkflowServices
    from evidencesoc.config import Settings
    from evidencesoc.persistence.event_search import create_opensearch_client
    from sqlalchemy import text

    from evals import verification as controller
    from evals.adapters import model_client, retained_workflow
    from evals.adapters import verification_worker as worker
    from evals.adapters.environment import case_environment
    from evals.adapters.seed import load_seed

    configured = Settings()  # Use local service credentials, never export them.
    monkeypatch.setenv("DATABASE_URL", configured.database_url)
    monkeypatch.setenv("OPENSEARCH_URL", configured.opensearch_url)
    monkeypatch.setenv("TASK13_SOURCE_COMMIT", "a" * 40)
    monkeypatch.setenv("TASK13_PHASE", "verification")
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-test-only")
    agent = tmp_path / "agent"
    agent.mkdir()
    event = {
        "source": "synthetic-verification-test",
        "observed_at": "2026-10-18T00:00:00Z",
        "event_type": "http.request",
        "source_ip": "198.51.100.10",
        "host": "synthetic.example.test",
        "message": "UNION SELECT",
    }
    (agent / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    (knowledge / "knowledge_chunks.jsonl").write_text(
        json.dumps(
            {
                "knowledge_chunk_id": "synthetic-only",
                "source": "https://example.test",
                "content": "Synthetic fixture only",
                "chunk_metadata": {},
                "embedding": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RAG_DATA_DIRECTORY", str(knowledge))
    spec = WorkerRunSpec(
        run_id="synthetic-verification",
        case_id="ait-" + "0" * 24,
        group="B3",
        config_sha256="a" * 64,
    )
    seed = load_seed(spec, agent)
    policy = InvestigationCapabilities(verification_enabled=False)
    with case_environment(spec, seed) as environment:
        settings, sessions, incident_id = environment
        state = {
            "incident_id": incident_id,
            "trace_id": "TRACE-synthetic-only",
            "evidence": seed["evidence"],
            "knowledge": [],
            "errors": [],
            "events": [],
            "alerts": seed["alerts"],
            "status": "awaiting_approval",
        }
        for make in (fallback.analyze, fallback.reconstruct, fallback.respond):
            state.update(make(state).model_dump(mode="json"))
        state.update(
            diagnosis_execution_status="completed",
            approval=None,
            simulation=[],
            simulation_execution=None,
            validation_result=None,
            diagnostic_snapshot={
                "diagnosis": {
                    "verdict": "attack",
                    "taxonomy_status": "out_of_taxonomy",
                },
                "evidence": deepcopy(state["evidence"]),
                "sealed_after": "reconstruct",
            },
        )
        state["diagnostic_snapshot_sha256"] = _plan_hash(state["diagnostic_snapshot"])
        state["response_plan"]["created_at"] = (
            datetime.now(UTC) - timedelta(minutes=31)
        ).isoformat()
        state["response_plan"]["expires_at"] = (
            datetime.now(UTC) - timedelta(minutes=1)
        ).isoformat()
        services = PostgresWorkflowServices(
            settings, session_factory=sessions, capabilities=policy
        )
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
                workflow._config(incident_id), state, as_node="respond"
            )
            await workflow.graph.ainvoke(None, workflow._config(incident_id))
            pending = await workflow.get_state(incident_id)
            assert pending["status"] == "awaiting_approval"
        await services.aclose()
        reference = environment.reference()
        resources = controller.resource_fields(reference)
        monkeypatch.setattr(
            worker, "os", SimpleNamespace(environ=os.environ, getpid=lambda: 1)
        )
        monkeypatch.setattr(
            retained_workflow,
            "os",
            SimpleNamespace(environ=os.environ, getpid=lambda: 1),
        )
        # Original renewal calls the real TrackedModel with an HTTP mock and an
        # isolated synthetic account. No paid request or real campaign charge.
        budget_path = tmp_path / "synthetic-campaign.sqlite"
        model_client.BudgetAccount(budget_path)
        monkeypatch.setenv("TASK13_BUDGET_DB", str(budget_path))
        monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-never-sent")
        outputs = iter(
            [
                fallback.respond(pending).model_dump_json(),
            ]
        )

        def synthetic_response(http_request):
            return httpx.Response(
                200,
                json={
                    "id": "synthetic-only",
                    "model": "synthetic-local-only",
                    "choices": [
                        {"message": {"content": next(outputs)}, "finish_reason": "stop"}
                    ],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                },
            )

        real_tracked = model_client.TrackedModel
        monkeypatch.setattr(
            model_client,
            "TrackedModel",
            lambda *args, **kwargs: real_tracked(
                *args, **kwargs, transport=httpx.MockTransport(synthetic_response)
            ),
        )
        review_arguments = {
            "namespace": uuid.uuid4().hex,
            "case_id": spec.case_id,
            "dataset": "ait",
            "agent_sha256": sha256((agent / "events.jsonl").read_bytes()).hexdigest(),
            "source_commit": reference["source_commit"],
            "source_resources": resources,
            "incident_id": incident_id,
        }
        packet = None
        for operation in ("read_packet", "renew_plan", "decision"):
            output = tmp_path / uuid.uuid4().hex
            output.mkdir()
            monkeypatch.setenv("TASK13_OUTPUT_DIR", str(output))
            request = worker.SourceReviewRequest(
                **review_arguments,
                request_id=uuid.uuid4().hex,
                operation=operation,
                **({"packet": packet} if operation == "renew_plan" else {}),
                **(
                    {
                        "packet": packet,
                        "decision": "approved",
                        "reason": "SYNTHETIC TEST FIXTURE ONLY; never experimental human approval",
                    }
                    if operation == "decision"
                    else {}
                ),
            )
            result = await worker.run_source_review(request, agent)
            assert result["status"] == "completed", result
            if operation == "read_packet":
                assert result["model_ledger"] == []
                packet = result["approval_packet"]
                assert packet["state_sha256"] == canonical_hash(pending)
                assert packet["decision"] is None
                assert packet["status"] == "renewal_required"
                expired_output = tmp_path / uuid.uuid4().hex
                expired_output.mkdir()
                monkeypatch.setenv("TASK13_OUTPUT_DIR", str(expired_output))
                refused = await worker.run_source_review(
                    worker.SourceReviewRequest(
                        **review_arguments,
                        request_id=uuid.uuid4().hex,
                        operation="decision",
                        packet=packet,
                        decision="approved",
                        reason="SYNTHETIC TEST: expired plan must never be approved",
                    ),
                    agent,
                )
                assert refused["status"] == "failed"
                assert refused["error_type"] == "PermissionError"
                with sessions() as session:
                    assert (
                        session.execute(
                            text("select count(*) from approvals")
                        ).scalar_one()
                        == 0
                    )
            elif operation == "renew_plan":
                assert [row["role"] for row in result["model_ledger"]] == [
                    "respond",
                ]
                assert all(
                    row["request_id"] == "synthetic-only"
                    for row in result["model_ledger"]
                )
                packet = result["approval_packet"]
                assert packet["status"] == "pending"
                assert packet["plan_sha256"] != _plan_hash(pending["response_plan"])
                assert result["source"]["state"]["approval"] is None
            else:
                assert result["model_ledger"] == []
                source_state = result["source"]["state"]
                receipt = result["approval_receipt"]
        assert source_state["simulation_execution"]["status"] == "completed"
        # PostgreSQL TEMPLATE copying requires all source connections to close.
        sessions.kw["bind"].dispose()
        outcomes, resource_receipts = [], []
        for condition in controller.CONDITIONS:
            measurements = controller._measurements(
                source_state, condition, datetime.now(UTC)
            )
            for enabled in (True, False):
                output = tmp_path / uuid.uuid4().hex
                output.mkdir()
                monkeypatch.setenv("TASK13_OUTPUT_DIR", str(output))
                request = worker.VerificationWorkerRequest(
                    request_id=uuid.uuid4().hex,
                    namespace=uuid.uuid4().hex,
                    case_id=spec.case_id,
                    agent_sha256=sha256(
                        (agent / "events.jsonl").read_bytes()
                    ).hexdigest(),
                    source_state_sha256=canonical_hash(source_state),
                    approved_plan_sha256=source_state["approved_plan_sha256"],
                    approval_receipt=receipt,
                    approval_receipt_sha256=canonical_hash(receipt),
                    approved_state=source_state,
                    source_resources=resources,
                    verification_enabled=enabled,
                    observations=measurements,
                )
                value = await worker.run_verification(request, agent)
                outcomes.append(value["outcome"])
                resource_receipts.append(value["resource_receipt"])
                assert value["model_ledger"] == []
                assert len(value["tool_ledger"]) == int(enabled)
                stored = json.loads(
                    (output / "verification-state.json").read_text(encoding="utf-8")
                )
                assert (
                    stored["diagnostic_snapshot"] == source_state["diagnostic_snapshot"]
                )
                assert stored["response_plan"] == source_state["response_plan"]
        assert outcomes == [
            "success",
            "unverified",
            "failure",
            "unverified",
            "insufficient_evidence",
            "unverified",
        ]
        database_names = [row["database_name"] for row in resource_receipts]
        index_names = [row["index_name"] for row in resource_receipts]
        assert len(set(database_names)) == len(set(index_names)) == 6
        assert reference["database_name"] not in database_names
        assert reference["index_name"] not in index_names
        with sessions() as session:
            assert (
                session.execute(text("select count(*) from approvals")).scalar_one()
                == 1
            )
            assert not set(database_names) & set(
                session.execute(text("select datname from pg_database")).scalars()
            )
        search = create_opensearch_client(settings.opensearch_url)
        try:
            assert search.indices.exists(index=reference["index_name"])
            assert all(not search.indices.exists(index=name) for name in index_names)
        finally:
            search.close()
