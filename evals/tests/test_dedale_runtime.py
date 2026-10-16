"""The actual MCP child must demonstrate its filesystem boundary."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def runtime():
    path = Path(__file__).resolve().parents[2] / "scripts/dedale_task12_runtime.py"
    assert path.is_file(), "isolated runtime bootstrap is missing"
    return importlib.import_module("scripts.dedale_task12_runtime")


def test_probe_reads_agent_and_actually_attempts_unmounted_score_file(tmp_path):
    module = runtime()
    agent = tmp_path / "agent"
    agent.mkdir()
    (agent / "events.jsonl").write_bytes(b'{"message":"observation"}\n')
    result = module.filesystem_probe(
        agent / "events.jsonl", [tmp_path / "unmounted" / "canary.json"], "nonce"
    )
    assert result["agent_readable"] is True
    assert result["forbidden_reads"] == [
        {"readable": False, "error_type": "FileNotFoundError"}
    ]
    assert result["nonce"] == "nonce"
    assert len(result["agent_sha256"]) == 64


def test_probe_fails_if_score_file_can_be_read(tmp_path):
    module = runtime()
    agent, score = tmp_path / "events.jsonl", tmp_path / "score.json"
    agent.write_bytes(b"{}\n")
    score.write_bytes(b"secret")
    with pytest.raises(ValueError, match="scoring"):
        module.filesystem_probe(agent, [score], "nonce")


def inspection(mounts):
    return {
        "Id": "a" * 64,
        "Image": "sha256:" + "b" * 64,
        "Config": {"Hostname": "a" * 12, "User": "65532:65532"},
        "State": {"Running": True},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidMode": "",
            "NetworkMode": "evidencesoc_default",
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=64m"},
        },
        "Mounts": mounts,
    }


def test_inspect_rejects_unexpected_scoring_mount_or_writable_source():
    module = runtime()
    expected = {"/app/agent": "D:/project/neutral-agent"}
    mounts = [
        {
            "Type": "bind",
            "Source": "D:/project/neutral-agent",
            "Destination": "/app/agent",
            "RW": False,
        }
    ]
    valid = inspection(mounts)
    assert (
        module.validate_container_inspection(valid, expected, "evidencesoc_default")[
            "root_read_only"
        ]
        is True
    )
    for replacement in (
        [{**mounts[0], "RW": True}],
        [
            *mounts,
            {
                "Type": "bind",
                "Source": "D:/project/scoring",
                "Destination": "/scoring",
                "RW": False,
            },
        ],
        [{**mounts[0], "Source": "D:/project"}],
    ):
        with pytest.raises(ValueError):
            module.validate_container_inspection(
                inspection(replacement), expected, "evidencesoc_default"
            )


def test_probe_is_bound_to_same_running_container_and_input():
    module = runtime()
    probe = {
        "nonce": "n",
        "hostname": "a" * 12,
        "agent_sha256": "d" * 64,
        "agent_readable": True,
        "forbidden_reads": [{"readable": False, "error_type": "FileNotFoundError"}],
    }
    inspect = inspection([])
    module.validate_probe_binding(probe, inspect, nonce="n", agent_sha256="d" * 64)
    for change in (
        {"nonce": "wrong"},
        {"hostname": "other-container"},
        {"agent_sha256": "e" * 64},
    ):
        with pytest.raises(ValueError):
            module.validate_probe_binding(
                {**probe, **change}, inspect, nonce="n", agent_sha256="d" * 64
            )


def test_docker_launch_passes_environment_names_and_exact_read_only_mounts():
    module = runtime()
    mounts = {
        "/app/agent": "D:/project/neutral-agent",
        "/opt/dedale-deps": "D:/project/deps",
        "/app/backend/src": "D:/project/backend/src",
        "/app/runtime.py": "D:/project/runtime.py",
    }
    arguments = module.docker_run_arguments(
        name="dedale-mcp-0123",
        image_id="sha256:" + "b" * 64,
        network="evidencesoc_default",
        mounts=mounts,
        environment={"DATABASE_URL": "secret"},
    )
    assert "secret" not in " ".join(arguments)
    assert "--pull=never" in arguments
    assert "--read-only" in arguments
    assert "--tty" not in arguments
    assert arguments.count("--mount") == 4
    assert "DATABASE_URL" in arguments
    with pytest.raises(ValueError):
        module.docker_run_arguments(
            name="dedale-mcp-0123",
            image_id="strix:latest",
            network="host",
            mounts=mounts,
            environment={},
        )
