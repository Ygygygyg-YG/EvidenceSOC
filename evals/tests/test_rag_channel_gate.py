"""The gate observes the real HTTP boundary; fixtures never count as R1 evidence."""

import hashlib
import json

import pytest

from evals.contracts import ModelConfig, canonical_hash


def test_gate_engineering_seed_is_one_valid_json_record_per_line(tmp_path):
    from evals.adapters.seed import load_seed
    from evals.contracts import WorkerRunSpec
    from evals.rag_gates import write_engineering_seed

    agent = write_engineering_seed(tmp_path)
    lines = (agent / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["message"] == "password guessing"
    seed = load_seed(
        WorkerRunSpec(
            run_id="gate", case_id="gate", group="B3", config_sha256="a" * 64
        ),
        agent,
    )
    assert len(seed["evidence"]) == 1


@pytest.mark.asyncio
async def test_gate_records_final_http_messages_after_five_chunk_projection(tmp_path):
    from evals.rag_gates import capture_model_input

    state = {
        "incident_id": "IN-fixed",
        "evidence": [],
        "knowledge": [
            {
                "knowledge_chunk_id": f"KC-{i}",
                "technique_id": "T1110.001",
                "source_uri": "https://attack.mitre.org/techniques/T1110/001/",
                "summary": "password guessing " + "x" * 3000,
            }
            for i in range(8)
        ],
    }
    record = await capture_model_input(state, ModelConfig(), tmp_path, "bounded")
    payload = json.loads(
        (tmp_path / record["payload_path"]).read_text(encoding="utf-8")
    )
    context = json.loads(payload["messages"][-1]["content"])
    assert [item["knowledge_chunk_id"] for item in context["knowledge"]] == [
        f"KC-{i}" for i in range(5)
    ]
    assert all(len(item["summary"].encode()) <= 2048 for item in context["knowledge"])
    assert record["messages_sha256"] == canonical_hash(payload["messages"])
    assert record["request_sha256"] == canonical_hash(payload)
    body = (tmp_path / record["http_body_path"]).read_bytes()
    assert record["http_body_sha256"] == hashlib.sha256(body).hexdigest()
    assert json.loads(body) == payload
    assert record["knowledge_ids"] == [f"KC-{i}" for i in range(5)]
    assert record["paid_model_requests"] == 0
    assert record["mock_transport_requests"] == 1
    assert (
        record["recorded_response"]["choices"][0]["message"]["content"]
        == '{"observed":true}'
    )
    assert record["ledger"][0]["context_projection"]["knowledge_total"] == 8


@pytest.mark.asyncio
async def test_gate_observes_byte_budget_dropping_real_final_payload_chunks(tmp_path):
    from evals.rag_gates import capture_model_input

    state = {
        "knowledge": [
            {"knowledge_chunk_id": str(i), "summary": "x" * 3000} for i in range(8)
        ]
    }
    record = await capture_model_input(
        state, ModelConfig(max_context_bytes=4096), tmp_path, "bytes"
    )
    assert 0 < len(record["knowledge_ids"]) < 5
    assert record["context_bytes"] <= 4096
    assert record["ledger"][0]["context_projection"]["truncated"] is True


def test_channel_gate_rejects_a_name_without_real_channel_calls():
    from evals.rag_gates import assert_channels

    with pytest.raises(AssertionError, match="semantic"):
        assert_channels("semantic_only", [], exact_query=False)


@pytest.mark.parametrize(
    "mode,events,exact",
    [
        ("hybrid", [{"channel": "exact"}], True),
        (
            "hybrid",
            [
                {"channel": "keyword"},
                {"channel": "embedding"},
                {"channel": "semantic"},
                {"channel": "rrf"},
            ],
            False,
        ),
        (
            "semantic_only",
            [{"channel": "embedding"}, {"channel": "semantic"}, {"channel": "rrf"}],
            False,
        ),
        ("disabled", [], False),
    ],
)
def test_expected_actual_channels_are_counted(mode, events, exact):
    from evals.rag_gates import assert_channels

    counts = assert_channels(mode, events, exact_query=exact)
    assert counts["exact"] == (1 if exact else 0)


def test_public_result_validation_rejects_manual_or_changed_content():
    from evals.rag_gates import assert_public_results

    official = {
        "KC-official": {
            "source": "https://attack.mitre.org/techniques/T1110/001/",
            "content": "official text",
            "chunk_metadata": {
                "technique_id": "T1110.001",
                "title": "Password Guessing",
                "version": "19.2",
            },
        }
    }
    item = {
        "knowledge_chunk_id": "KC-official",
        "technique_id": "T1110.001",
        "summary": "official text",
        "title": "Password Guessing",
        "version": "19.2",
        "source_uri": "https://attack.mitre.org/techniques/T1110/001/",
    }
    assert_public_results([item], official)
    with pytest.raises(AssertionError):
        assert_public_results([{**item, "summary": "changed"}], official)
    with pytest.raises(AssertionError):
        assert_public_results([{**item, "knowledge_chunk_id": "manual"}], official)
