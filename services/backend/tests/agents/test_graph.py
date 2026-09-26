from __future__ import annotations

import asyncio
import importlib
from typing import Any

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.errors import NodeCancelledError

from evidencesoc.config import Settings

EV = "EV-01ARZ3NDEKTSV4RRFFQ69G5FAV"
NOW = "2026-09-21T10:20:17+00:00"


def graph_module():
    try:
        return importlib.import_module("evidencesoc.agents.graph")
    except ModuleNotFoundError:
        pytest.fail("Task8 investigation graph has not been implemented")


class MemoryServices:
    def __init__(self, *, empty=False, verify_error=False, verify_empty=False):
        self.empty = empty
        self.verify_error = verify_error
        self.verify_empty = verify_empty
        self.collections = 0
        self.verifications = 0
        self.runs: list[dict[str, Any]] = []
        self.saved: list[dict[str, Any]] = []

    async def load_incident(self, incident_id):
        return {
            "alerts": [
                {
                    "alert_id": "AL-demo",
                    "title": "SQL injection alert",
                    "severity": "high",
                    "created_at": NOW,
                    "event_ids": ["SE-demo"],
                }
            ]
        }

    async def start_run(self, state, role):
        run_id = f"AR-{len(self.runs)}"
        self.runs.append({"run_id": run_id, "role": role, "status": "running"})
        return run_id

    async def finish_run(self, run_id, delta, status="completed"):
        next(run for run in self.runs if run["run_id"] == run_id)["status"] = status

    async def collect(self, state, run_id):
        self.collections += 1
        return {
            "evidence": [] if self.empty else [self.evidence()],
            "knowledge": [
                {
                    "knowledge_chunk_id": "KC-demo",
                    "technique_id": "T1190",
                    "title": "Exploit Public-Facing Application",
                    "source": "https://attack.mitre.org/techniques/T1190/",
                    "content": "Exploit a public facing application",
                    "version": "19.2",
                }
            ],
        }

    def evidence(self):
        return {
            "evidence_id": EV,
            "event_id": "SE-demo",
            "source": "nginx",
            "observed_at": NOW,
            "query": {},
            "summary": "Verified request",
            "content_sha256": "a" * 64,
            "raw": {
                "source_ip": "203.0.113.42",
                "host": "shop.example.test",
                "service": "checkout-api",
                "message": "GET /search?q=' OR 1=1-- HTTP/1.1",
                "http": {"path": "/search?q=' OR 1=1--", "status_code": 403},
            },
        }

    async def verify(self, state, run_id):
        self.verifications += 1
        if self.verify_error:
            raise RuntimeError("dependency unavailable; secret-value")
        return {"evidence": [] if self.verify_empty else [self.evidence()]}

    async def save_result(self, state):
        self.saved.append(dict(state))


def workflow(services=None, saver=None, nodes=None):
    module = graph_module()
    services = services or MemoryServices()
    settings = Settings(_env_file=None, llm_mode="fixture")
    return module.InvestigationWorkflow(
        services=services,
        settings=settings,
        checkpointer=saver or InMemorySaver(),
        nodes=nodes,
    )


async def approve(flow, incident_id="IN-demo", decision="approved"):
    state = await flow.get_state(incident_id)
    return await flow.approve(
        incident_id,
        response_plan_id=state["response_plan"]["response_plan_id"],
        decision=decision,
        reason="Reviewed demonstration",
        decided_by="reviewer",
    )


@pytest.mark.asyncio
async def test_fixture_pauses_before_actions_and_finishes_six_roles_after_approval():
    services = MemoryServices()
    flow = workflow(services)
    state = await flow.run_investigation("IN-demo")
    assert state["status"] == "awaiting_approval"
    assert state["fallback_used"] is True
    assert not state.get("simulation")
    assert services.verifications == 0
    assert state["origin"]["observed_source_ip"] == "203.0.113.42"
    assert state["classification"]["primary_type"] == "sql_injection"
    assert state["attack_steps"] and all(
        step["evidence_ids"] for step in state["attack_steps"]
    )
    assert services.saved[-1]["response_plan"] == state["response_plan"]
    final = await approve(flow)
    assert final["status"] == "completed"
    assert final["validation_result"]["outcome"] == "success"
    assert final["simulation"] and all(
        action["simulated"] for action in final["simulation"]
    )
    assert services.verifications == 1
    roles = [
        event["node"] for event in final["events"] if event["event"] == "node.completed"
    ]
    assert roles == [
        "triage",
        "collect",
        "analyze",
        "reconstruct",
        "respond",
        "validate",
    ]
    assert all(run["status"] == "completed" for run in services.runs)


@pytest.mark.asyncio
async def test_insufficient_evidence_retries_once_then_enters_manual_review():
    services = MemoryServices(empty=True)
    final = await workflow(services).run_investigation("IN-empty")
    assert services.collections == 2
    assert final["fallback_count"] == 1
    assert final["status"] == "manual_review"
    assert not final.get("response_plan") and not final.get("simulation")
    assert services.verifications == 0


@pytest.mark.asyncio
async def test_rejection_stops_and_preserves_reason_without_validation():
    services = MemoryServices()
    flow = workflow(services)
    await flow.run_investigation("IN-demo")
    result = await approve(flow, decision="rejected")
    assert result["status"] == "rejected"
    assert result["approval"]["reason"] == "Reviewed demonstration"
    assert not result.get("simulation") and services.verifications == 0


@pytest.mark.asyncio
async def test_checkpoint_resume_and_duplicate_approval_cannot_repeat_simulation():
    services = MemoryServices()
    saver = InMemorySaver()
    original = workflow(services, saver)
    paused = await original.run_investigation("IN-demo")
    recovered = workflow(services, saver)
    assert (await recovered.run_investigation("IN-demo"))["response_plan"] == paused[
        "response_plan"
    ]
    assert services.collections == 1
    final = await approve(recovered)
    assert (await recovered.run_investigation("IN-demo"))["simulation"] == final[
        "simulation"
    ]
    with pytest.raises(ValueError):
        await approve(recovered)
    assert services.verifications == 1


@pytest.mark.asyncio
async def test_approval_is_bound_to_pending_plan_and_requires_a_reason():
    services = MemoryServices()
    flow = workflow(services)
    await flow.run_investigation("IN-demo")
    with pytest.raises(ValueError):
        await flow.approve(
            "IN-demo",
            response_plan_id="RP-other",
            decision="approved",
            reason="reviewed",
            decided_by="reviewer",
        )
    state = await flow.get_state("IN-demo")
    with pytest.raises(ValueError):
        await flow.approve(
            "IN-demo",
            response_plan_id=state["response_plan"]["response_plan_id"],
            decision="approved",
            reason="   ",
            decided_by="reviewer",
        )
    assert not (await flow.get_state("IN-demo")).get("simulation")


@pytest.mark.asyncio
async def test_verification_dependency_failure_is_not_success_and_is_redacted():
    flow = workflow(MemoryServices(verify_error=True))
    await flow.run_investigation("IN-demo")
    final = await approve(flow)
    assert final["status"] == "failed"
    assert "secret-value" not in str(final)
    assert any(error["node"] == "validate" for error in final["errors"])


@pytest.mark.asyncio
async def test_no_verification_evidence_returns_insufficient_evidence():
    flow = workflow(MemoryServices(verify_empty=True))
    await flow.run_investigation("IN-demo")
    final = await approve(flow)
    assert final["validation_result"]["outcome"] == "insufficient_evidence"
    assert final["status"] == "manual_review"


def test_manual_review_and_rejected_are_valid_persistable_domain_states():
    from evidencesoc.domain.models import IncidentStatus
    from evidencesoc.persistence.tables import IncidentTable

    assert "manual_review" in {status.value for status in IncidentStatus}
    assert "rejected" in {status.value for status in IncidentStatus}
    constraint = next(
        c
        for c in IncidentTable.__table__.constraints
        if c.name == "ck_incidents_status"
    )
    assert "manual_review" in str(constraint.sqltext)
    assert "rejected" in str(constraint.sqltext)


class AlteredNodes:
    def __init__(self, services, *, role, change):
        from evidencesoc.agents.nodes import NodeHandlers

        self.real = NodeHandlers(services, Settings(_env_file=None, llm_mode="fixture"))
        self.role = role
        self.change = change

    def __getattr__(self, name):
        original = getattr(self.real, name)
        if name != self.role:
            return original

        async def changed(state):
            delta = await original(state)
            self.change(delta)
            return delta

        return changed


@pytest.mark.asyncio
async def test_forged_current_node_citation_cannot_reach_approval():
    services = MemoryServices()
    nodes = AlteredNodes(
        services,
        role="analyze",
        change=lambda delta: delta["classification"].update(
            evidence_ids=["EV-other-incident"]
        ),
    )
    result = await workflow(services, nodes=nodes).run_investigation("IN-forged")
    assert result["status"] == "manual_review"
    assert any(error["code"] == "UNSUPPORTED_CITATION" for error in result["errors"])
    assert not result["response_plan"] and not result["simulation"]


@pytest.mark.asyncio
async def test_real_action_cannot_be_persisted_or_reach_approval():
    services = MemoryServices()
    nodes = AlteredNodes(
        services,
        role="respond",
        change=lambda delta: delta["response_plan"]["actions"][0].update(
            action="run_shell"
        ),
    )
    result = await workflow(services, nodes=nodes).run_investigation("IN-unsafe")
    assert result["status"] == "failed"
    assert not result["response_plan"] and not result["simulation"]


@pytest.mark.asyncio
async def test_simulation_tampering_returns_validation_failure():
    services = MemoryServices()
    nodes = AlteredNodes(services, role="validate", change=lambda delta: None)
    real = nodes.real.validate

    async def validation(state):
        state["simulation"][0]["status"] = "failed"
        return await real(state)

    nodes.validate = validation
    flow = workflow(services, nodes=nodes)
    await flow.run_investigation("IN-demo")
    result = await approve(flow)
    assert result["status"] == "failed"
    assert result["validation_result"]["outcome"] == "failure"


@pytest.mark.asyncio
async def test_two_concurrent_approvals_execute_one_simulation_and_validation():
    services = MemoryServices()
    saver = InMemorySaver()
    flow = workflow(services, saver)
    other = workflow(services, saver)
    await flow.run_investigation("IN-demo")
    results = await asyncio.gather(
        approve(flow), approve(other), return_exceptions=True
    )
    assert sum(isinstance(result, ValueError) for result in results) == 1
    assert (
        sum(
            isinstance(result, dict) and result["status"] == "completed"
            for result in results
        )
        == 1
    )
    assert services.verifications == 1


@pytest.mark.asyncio
async def test_restart_after_simulation_resumes_validation_without_resimulation():
    class InterruptedServices(MemoryServices):
        async def verify(self, state, run_id):
            raise asyncio.CancelledError()

    saver = InMemorySaver()
    crashed = workflow(InterruptedServices(), saver)
    await crashed.run_investigation("IN-demo")
    with pytest.raises(NodeCancelledError):
        await approve(crashed)
    intermediate = await crashed.get_state("IN-demo")
    assert intermediate["status"] == "validating"
    recovered = workflow(MemoryServices(), saver)
    result = await recovered.run_investigation("IN-demo")
    assert result["status"] == "completed"
    assert result["simulation"] == intermediate["simulation"]
    assert (
        sum(event["event"] == "simulation.completed" for event in result["events"]) == 1
    )


@pytest.mark.asyncio
async def test_events_are_ordered_and_can_be_replayed_after_a_cursor():
    flow = workflow()
    first = [event async for event in flow.stream_events("IN-demo")]
    assert first and [event["event_id"] for event in first] == list(
        range(1, len(first) + 1)
    )
    again = [
        event
        async for event in flow.stream_events(
            "IN-demo", after_event_id=first[-2]["event_id"]
        )
    ]
    assert again == first[-1:]


@pytest.mark.asyncio
async def test_node_started_is_observable_before_slow_collection_finishes():
    class SlowServices(MemoryServices):
        async def collect(self, state, run_id):
            await asyncio.Event().wait()

    flow = workflow(SlowServices())
    stream = flow.stream_events("IN-live")
    try:
        first = await asyncio.wait_for(anext(stream), timeout=1)
        assert first["event"] == "node.started" and first["node"] == "triage"
    finally:
        await stream.aclose()


@pytest.mark.asyncio
async def test_approval_stream_exposes_validate_start_before_slow_requery():
    class SlowVerification(MemoryServices):
        async def verify(self, state, run_id):
            await asyncio.Event().wait()

    flow = workflow(SlowVerification())
    before = await flow.run_investigation("IN-demo")
    stream = flow.stream_approval(
        "IN-demo",
        response_plan_id=before["response_plan"]["response_plan_id"],
        decision="approved",
        reason="reviewed",
        decided_by="reviewer",
        after_event_id=before["events"][-1]["event_id"],
    )
    try:
        async with asyncio.timeout(1):
            async for event in stream:
                if event["node"] == "validate" and event["event"] == "node.started":
                    break
            else:
                pytest.fail("validation start event was not observable")
    finally:
        await stream.aclose()


@pytest.mark.asyncio
async def test_restart_during_approval_record_save_recovers_submitted_decision():
    class InterruptedApproval(MemoryServices):
        async def save_result(self, state):
            await super().save_result(state)
            if state.get("approval"):
                raise asyncio.CancelledError()

    saver = InMemorySaver()
    crashed = workflow(InterruptedApproval(), saver)
    await crashed.run_investigation("IN-demo")
    with pytest.raises(NodeCancelledError):
        await approve(crashed)
    recovered = workflow(MemoryServices(), saver)
    result = await recovered.run_investigation("IN-demo")
    assert result["status"] == "completed"
    assert result["approval"]["reason"] == "Reviewed demonstration"
    assert (
        sum(event["event"] == "simulation.completed" for event in result["events"]) == 1
    )
