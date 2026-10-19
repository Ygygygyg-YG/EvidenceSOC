from __future__ import annotations

from importlib import import_module

import pytest
from pydantic import ValidationError


def test_diagnosis_represents_benign_and_unmapped_attack_explicitly():
    module = import_module("evidencesoc.agents.models")
    assert hasattr(module, "Diagnosis"), (
        "analysis needs an explicit three-state diagnosis"
    )
    diagnosis = module.Diagnosis
    assert (
        diagnosis(verdict="benign", taxonomy_status="not_applicable").attack_types == []
    )
    assert (
        diagnosis(verdict="attack", taxonomy_status="out_of_taxonomy").verdict
        == "attack"
    )
    with pytest.raises(ValidationError):
        diagnosis(
            verdict="benign",
            taxonomy_status="mapped",
            attack_types=["credential_attack"],
        )
    with pytest.raises(ValidationError):
        diagnosis(
            verdict="attack", taxonomy_status="mapped", attack_types=["sql_injection"]
        )
    with pytest.raises(ValidationError):
        diagnosis(
            verdict="attack",
            taxonomy_status="mapped",
            attack_types=["credential_attack", "credential_attack"],
        )


def test_explicit_verdict_controls_original_graph_route():
    route = import_module("evidencesoc.agents.graph")._analysis_route
    assert route({"diagnosis": {"verdict": "benign"}}) == "__end__"
    assert (
        route(
            {"diagnosis": {"verdict": "attack", "taxonomy_status": "out_of_taxonomy"}}
        )
        == "reconstruct"
    )
    assert route({"diagnosis": {"verdict": "unknown"}, "fallback_count": 0}) == "retry"
    assert route({"diagnosis": {"verdict": "unknown"}, "fallback_count": 1}) == "review"


@pytest.mark.parametrize(
    ("action", "field", "before", "after"),
    [
        ("block_ip_simulated", "network_blocked", False, True),
        ("isolate_host_simulated", "host_isolated", False, True),
        ("disable_account_simulated", "account_enabled", True, False),
    ],
)
def test_simulation_effect_uses_observations_and_never_same_target_alone(
    action, field, before, after
):
    module = import_module("evidencesoc.agents.verification")
    common = {
        "namespace": "opaque-1",
        "action_id": "ACT-1",
        "target": "target",
        "evidence_ids": ["EV-1"],
    }
    earlier = {**common, "observed_at": "2026-10-18T00:00:00Z", field: before}
    later = {**common, "observed_at": "2026-10-18T00:00:01Z", field: after}
    evaluate = module.evaluate_simulated_effect
    assert evaluate(action, earlier, later) == "success"
    assert (
        evaluate(action, earlier, {**later, field: before}) == "insufficient_evidence"
    )
    assert (
        evaluate(
            action, earlier, {**later, field: before, "error_code": "ACTION_REJECTED"}
        )
        == "failure"
    )
    assert (
        evaluate(action, earlier, {**later, "namespace": "opaque-2"})
        == "insufficient_evidence"
    )
    assert (
        evaluate(action, earlier, {**later, "evidence_ids": []})
        == "insufficient_evidence"
    )
    with pytest.raises(ValidationError):
        module.EffectObservation.model_validate({**later, "condition": "success"})


def test_semantic_only_does_not_take_exact_technique_shortcut():
    module = import_module("evidencesoc.rag.retriever")

    class Repository:
        def exact(self, *_):
            pytest.fail("exact channel must be unavailable")

        def keyword(self, *_):
            pytest.fail("keyword channel must be unavailable")

        def semantic(self, vector, limit):
            return [{"knowledge_chunk_id": "KC-1"}]

    class Embedder:
        def embed_query(self, query):
            assert query == "T1190"
            return [1.0]

    retriever = module.HybridRetriever(Repository(), Embedder(), mode="semantic_only")
    assert retriever.retrieve_knowledge("T1190") == [{"knowledge_chunk_id": "KC-1"}]


def test_disabled_retrieval_never_opens_dependencies():
    module = import_module("evidencesoc.rag.retriever")

    class Unavailable:
        def __getattr__(self, _):
            pytest.fail("disabled retrieval accessed a dependency")

    with pytest.raises(PermissionError):
        module.HybridRetriever(
            Unavailable(), Unavailable(), mode="disabled"
        ).retrieve_knowledge("T1190")


@pytest.mark.parametrize("value", [0, 1, "true", "false"])
def test_effect_observation_flags_require_actual_booleans(value):
    from evidencesoc.agents.verification import EffectObservation

    with pytest.raises(ValidationError):
        EffectObservation(
            namespace="opaque",
            action_id="ACT-1",
            target="target",
            observed_at="2026-10-18T00:00:00Z",
            network_blocked=value,
        )


def test_repository_channels_cannot_bypass_capability_scope():
    from evidencesoc.agents.capabilities import (
        InvestigationCapabilities,
        capability_scope,
    )
    from evidencesoc.rag.retriever import PostgresKnowledgeRepository

    class Unavailable:
        def __getattr__(self, name):
            pytest.fail("disabled repository channel touched its session")

    repository = PostgresKnowledgeRepository(Unavailable(), embedding_model="test")
    with capability_scope(InvestigationCapabilities(rag_mode="semantic_only")):
        with pytest.raises(PermissionError):
            repository.exact("T1190", 1)
        with pytest.raises(PermissionError):
            repository.keyword("query", 1)
    with (
        capability_scope(InvestigationCapabilities(rag_mode="disabled")),
        pytest.raises(PermissionError),
    ):
        repository.semantic([1.0], 1)


@pytest.mark.asyncio
async def test_benign_original_graph_seals_seed_diagnosis_without_response():
    from evidencesoc.agents.graph import InvestigationWorkflow
    from evidencesoc.config import Settings
    from langgraph.checkpoint.memory import InMemorySaver

    class Services:
        async def start_run(self, state, role):
            return role

        async def finish_run(self, *args):
            pass

        async def save_result(self, state):
            pass

    class Nodes:
        async def triage(self, state):
            return {"status": "triaged"}

        async def collect(self, state):
            assert state["evidence"] == [{"evidence_id": "seed"}]
            return {"status": "collecting"}

        async def analyze(self, state):
            return {
                "diagnosis": {"verdict": "benign", "taxonomy_status": "not_applicable"},
                "status": "completed",
            }

        async def respond(self, state):
            pytest.fail("benign diagnosis must not propose a response")

    workflow = InvestigationWorkflow(
        services=Services(),
        settings=Settings(_env_file=None),
        checkpointer=InMemorySaver(),
        nodes=Nodes(),
        initial_state={"evidence": [{"evidence_id": "seed"}]},
    )
    result = await workflow.run_investigation("neutral-1")
    assert result["diagnostic_snapshot"]["diagnosis"]["verdict"] == "benign"
    assert result["diagnostic_snapshot"]["evidence"] == [{"evidence_id": "seed"}]
    assert result["diagnosis_execution_status"] == "completed"


@pytest.mark.asyncio
async def test_disabled_validation_does_not_invoke_observer():
    from evidencesoc.agents.nodes import NodeHandlers
    from evidencesoc.config import Settings

    policy = import_module("evidencesoc.agents.capabilities").InvestigationCapabilities(
        verification_enabled=False
    )

    class Services:
        async def verify(self, *args):
            pytest.fail("disabled validation must not execute a verifier")

    result = await NodeHandlers(
        Services(), Settings(_env_file=None), capabilities=policy
    ).validate({"_run_id": "run"})
    assert result["verification_status"] == "unverified"
    assert result["validation_result"] is None


def test_capability_context_cannot_be_overridden_by_retriever_argument():
    module = import_module("evidencesoc.agents.capabilities")
    with (
        module.capability_scope(module.InvestigationCapabilities(rag_mode="disabled")),
        pytest.raises(PermissionError),
    ):
        import_module("evidencesoc.rag.retriever").retrieve_knowledge(
            "query", mode="hybrid"
        )


@pytest.mark.asyncio
async def test_original_graph_seals_unmapped_attack_before_response_and_keeps_snapshot():
    from evidencesoc.agents.graph import InvestigationWorkflow
    from evidencesoc.config import Settings
    from langgraph.checkpoint.memory import InMemorySaver

    visited = []

    class Services:
        async def start_run(self, state, role):
            visited.append(role)
            return role

        async def finish_run(self, *args):
            pass

        async def save_result(self, state):
            pass

    class Nodes:
        async def triage(self, state):
            return {"status": "triaged"}

        async def collect(self, state):
            return {"status": "collecting"}

        async def analyze(self, state):
            return {
                "diagnosis": {
                    "verdict": "attack",
                    "taxonomy_status": "out_of_taxonomy",
                },
                "status": "analyzing",
            }

        async def reconstruct(self, state):
            return {"attack_steps": [], "status": "reconstructing"}

        async def respond(self, state):
            assert state["diagnostic_snapshot"]["diagnosis"]["verdict"] == "attack"
            return {
                "status": "manual_review",
                "evidence": [{"evidence_id": "post-action"}],
                "diagnosis": {"verdict": "benign", "taxonomy_status": "not_applicable"},
            }

    flow = InvestigationWorkflow(
        services=Services(),
        settings=Settings(_env_file=None),
        checkpointer=InMemorySaver(),
        nodes=Nodes(),
        initial_state={"evidence": [{"evidence_id": "seed"}]},
    )
    result = await flow.run_investigation("neutral-attack")
    assert visited == ["triage", "collect", "analyze", "reconstruct", "respond"]
    assert result["diagnostic_snapshot"]["diagnosis"]["verdict"] == "attack"
    assert result["diagnostic_snapshot"]["evidence"] == [{"evidence_id": "seed"}]


def test_canonical_diagnosis_cannot_invent_origin_or_unretrieved_techniques():
    from evidencesoc.agents.diagnosis import Diagnosis
    from evidencesoc.agents.nodes import validate_output_citations
    from evidencesoc.domain.models import AttackOrigin

    ev = "EV-01ARZ3NDEKTSV4RRFFQ69G5FAV"
    state = {
        "evidence": [
            {
                "evidence_id": ev,
                "event_id": "event",
                "source": "log",
                "observed_at": "2026-10-18T00:00:00Z",
                "query": {},
                "summary": "observed",
                "content_sha256": "a" * 64,
                "raw": {"source_ip": "192.0.2.1"},
            }
        ],
        "knowledge": [],
    }
    origin = AttackOrigin(
        observed_source_ip="192.0.2.2",
        entry_host=None,
        entry_service=None,
        first_seen_at=None,
        source_scope="unknown",
        confidence=1,
        evidence_ids=[ev],
    )
    with pytest.raises(ValueError, match="source IP"):
        validate_output_citations(
            Diagnosis(
                verdict="attack",
                taxonomy_status="out_of_taxonomy",
                origin=origin,
                evidence_ids=[ev],
            ),
            state,
        )
    with pytest.raises(ValueError, match="retrieved knowledge"):
        validate_output_citations(
            Diagnosis(
                verdict="attack",
                taxonomy_status="out_of_taxonomy",
                technique_ids=["T1190"],
                evidence_ids=[ev],
            ),
            state,
        )
