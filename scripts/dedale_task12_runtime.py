"""Same-process isolation probes and model-free MCP bootstrap for Docker.

This file is mounted individually, with backend/src, Linux dependencies and a
neutral agent input directory. Neither the repository nor scoring data is
mounted. The evaluator validates this process's nonce/hostname against Docker
inspection while its real MCP stdio session is active.
"""

from __future__ import annotations

import json
import os
import re
import socket
import sys
from hashlib import sha256
from pathlib import Path

PROBE_PREFIX = "DEDALE_RUNTIME_PROBE:"


def docker_run_arguments(
    *,
    name: str,
    image_id: str,
    network: str,
    mounts: dict[str, str],
    environment: dict[str, str],
) -> list[str]:
    if (
        not re.fullmatch(r"dedale-mcp-[a-z0-9]+", name)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
        or not network
        or network == "host"
        or set(mounts)
        != {"/app/agent", "/app/runtime.py", "/app/backend/src", "/opt/dedale-deps"}
    ):
        raise ValueError("unexpected Docker runtime boundary")
    arguments = [
        "run",
        "--rm",
        "--pull=never",
        "-i",
        "--name",
        name,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "512m",
        "--cpus",
        "2",
        "--network",
        network,
        "--workdir",
        "/app/agent",
    ]
    for target, source in sorted(mounts.items()):
        if "," in source:
            raise ValueError("mount paths must not contain Docker option separators")
        arguments.extend(
            ["--mount", f"type=bind,source={source},target={target},readonly"]
        )
    for key in sorted(environment):
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError("invalid explicit environment name")
        arguments.extend(["--env", key])
    arguments.extend(["--entrypoint", "python3", image_id, "-B", "/app/runtime.py"])
    return arguments


def filesystem_probe(agent_events: Path, forbidden: list[Path], nonce: str) -> dict:
    payload = agent_events.read_bytes()
    attempts = []
    for path in forbidden:
        try:
            path.read_bytes()
        except (FileNotFoundError, PermissionError) as error:
            attempts.append({"readable": False, "error_type": type(error).__name__})
        else:
            raise ValueError("scoring filesystem canary is readable by MCP runtime")
    if not attempts or not nonce:
        raise ValueError("isolation requires a nonce and scoring canary read probes")
    return {
        "nonce": nonce,
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "agent_readable": True,
        "agent_sha256": sha256(payload).hexdigest(),
        "forbidden_reads": attempts,
    }


def _host_source(path: str) -> str:
    normalized = path.replace("\\", "/").rstrip("/")
    drive = re.match(r"^([a-zA-Z]):/(.*)$", normalized)
    if drive:
        return f"/run/desktop/mnt/host/{drive[1].lower()}/{drive[2]}".lower()
    return normalized.replace("/host_mnt/", "/run/desktop/mnt/host/").lower()


def validate_container_inspection(
    info: dict, expected_mounts: dict[str, str], network: str
) -> dict:
    host = info["HostConfig"]
    if (
        info["State"].get("Running") is not True
        or host.get("ReadonlyRootfs") is not True
        or host.get("Privileged") is not False
        or "ALL" not in host.get("CapDrop", [])
        or not any(
            option.startswith("no-new-privileges")
            for option in host.get("SecurityOpt", [])
        )
        or host.get("PidMode", "") not in {"", "private"}
        or network == "host"
        or host.get("NetworkMode") != network
        or info["Config"].get("User") != "65532:65532"
        or set(host.get("Tmpfs", {})) != {"/tmp"}
    ):
        raise ValueError("container isolation flags are not the declared boundary")
    actual = info.get("Mounts", [])
    if len(actual) != len(expected_mounts):
        raise ValueError("unexpected container mount count")
    destinations = set()
    sanitized = []
    for mount in actual:
        target = mount["Destination"]
        if (
            target not in expected_mounts
            or target in destinations
            or mount.get("RW") is not False
            or mount.get("Type") != "bind"
            or _host_source(mount["Source"]) != _host_source(expected_mounts[target])
        ):
            raise ValueError("container mount differs from exact read-only allowlist")
        destinations.add(target)
        sanitized.append(
            {"source": mount["Source"], "target": target, "read_only": True}
        )
    return {
        "container_id": info["Id"],
        "image_id": info["Image"],
        "hostname": info["Config"]["Hostname"],
        "user": info["Config"]["User"],
        "root_read_only": True,
        "privileged": False,
        "capabilities_dropped": ["ALL"],
        "no_new_privileges": True,
        "private_pid_namespace": True,
        "network": network,
        "mounts": sorted(sanitized, key=lambda row: row["target"]),
    }


def validate_probe_binding(
    probe: dict, inspection: dict, *, nonce: str, agent_sha256: str
) -> None:
    if (
        probe.get("nonce") != nonce
        or probe.get("hostname") != inspection["Config"]["Hostname"]
        or not inspection["Id"].startswith(probe["hostname"])
        or inspection["State"].get("Running") is not True
        or probe.get("agent_sha256") != agent_sha256
        or probe.get("agent_readable") is not True
        or not probe.get("forbidden_reads")
        or any(row.get("readable") is not False for row in probe["forbidden_reads"])
    ):
        raise ValueError("runtime probe is not bound to this MCP container and input")


def main() -> None:
    from evidencesoc.config import Settings
    from evidencesoc.mcp_server.context import load_run_context
    from evidencesoc.mcp_server.main import build_server
    from evidencesoc.persistence.database import (
        create_database_engine,
        create_session_factory,
    )
    from evidencesoc.rag.embeddings import LocalEmbeddingProvider

    def deny_model(*_args, **_kwargs):
        raise RuntimeError("model execution forbidden in DEDALE acceptance")

    LocalEmbeddingProvider.embed_query = deny_model
    LocalEmbeddingProvider.embed_documents = deny_model
    settings = Settings(
        _env_file=None,
        llm_mode="fixture",
        deepseek_api_key=None,
        rag_data_directory=Path("/no-model-artifacts"),
    )
    engine = create_database_engine(
        settings.database_url, bounded_tool_connections=True
    )
    try:
        server = build_server(
            context=load_run_context(os.environ),
            settings=settings,
            session_factory=create_session_factory(engine),
            max_attempts=1,
        )
        probe = filesystem_probe(
            Path("/app/agent/events.jsonl"),
            [Path(value) for value in json.loads(os.environ["DEDALE_FORBIDDEN_PATHS"])],
            os.environ["DEDALE_ISOLATION_NONCE"],
        )
        sys.stderr.write(PROBE_PREFIX + json.dumps(probe, sort_keys=True) + "\n")
        sys.stderr.flush()
        server.run(transport="stdio")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
