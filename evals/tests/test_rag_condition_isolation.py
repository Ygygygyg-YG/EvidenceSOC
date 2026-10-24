"""Negative controls for R2; synthetic tests do not count as real service runs."""

import socket

import pytest

from evals.contracts import ModelConfig


def test_escaped_transport_cannot_even_resolve_a_nonlocal_model_host(monkeypatch):
    from evals.rag_gates import local_network_only

    # Avoid actual DNS if the guard is broken: this stub makes the red run safe.
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])
    with (
        local_network_only() as blocked,
        pytest.raises(PermissionError, match="loopback"),
    ):
        socket.getaddrinfo("api.deepseek.com", 443)
    assert blocked == ["api.deepseek.com"]


@pytest.mark.parametrize(
    "mode,channel",
    [
        ("disabled", "semantic"),
        ("disabled", "keyword"),
        ("disabled", "exact"),
        ("semantic_only", "exact"),
        ("semantic_only", "keyword"),
        ("semantic_only", "legacy_keyword"),
    ],
)
def test_forbidden_channel_calls_fail_even_if_final_results_look_correct(mode, channel):
    from evals.rag_gates import assert_channels

    with pytest.raises(AssertionError, match="forbidden"):
        assert_channels(mode, [{"channel": channel}], exact_query=False)


@pytest.mark.asyncio
async def test_empty_condition_has_no_stale_knowledge_in_final_request(tmp_path):
    from evals.rag_gates import capture_model_input, fresh_condition_state

    seed = {
        "alerts": [{"alert_id": "AL-fixed"}],
        "evidence": [{"evidence_id": "EV-fixed", "summary": "same evidence"}],
        "knowledge": [{"knowledge_chunk_id": "KC-stale"}],
    }
    first = fresh_condition_state(seed, "IN-fixed")
    first["knowledge"].append({"knowledge_chunk_id": "KC-prior"})
    second = fresh_condition_state(seed, "IN-fixed")
    record = await capture_model_input(second, ModelConfig(), tmp_path, "empty")
    assert record["knowledge_ids"] == []
    assert "KC-stale" not in (tmp_path / record["payload_path"]).read_text(
        encoding="utf-8"
    )
    assert "KC-prior" not in (tmp_path / record["payload_path"]).read_text(
        encoding="utf-8"
    )
    assert second["evidence"] == seed["evidence"]
    second["evidence"][0]["summary"] = "mutation"
    assert seed["evidence"][0]["summary"] == "same evidence"


def test_conditions_must_use_distinct_state_cache_and_mcp_process():
    from evals.rag_gates import assert_condition_isolation

    records = [
        {
            "mode": mode,
            "state_id": str(i),
            "result_cache_id": str(i),
            "mcp_pid": i + 100,
            "fixed_input_sha256": "same",
            "query": "password guessing",
            "model_config_sha256": "fixed",
        }
        for i, mode in enumerate(("disabled", "semantic_only", "hybrid"))
    ]
    assert_condition_isolation(records)
    records[1]["result_cache_id"] = records[0]["result_cache_id"]
    with pytest.raises(AssertionError, match="result_cache_id"):
        assert_condition_isolation(records)
