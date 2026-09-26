from __future__ import annotations

import importlib
import os
import sqlite3
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import anyio
import pytest

from evidencesoc.config import Settings
from evidencesoc.mcp_server.context import RunContext

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _settings(database_url: str) -> Settings:
    return Settings(
        _env_file=None,
        database_url=database_url,
        opensearch_url="http://127.0.0.1:9",
        opensearch_index="test-security-events",
    )


def test_stdio_parameters_bind_context_and_local_dependencies() -> None:
    client = importlib.import_module("evidencesoc.mcp_server.client")
    context = RunContext("AR-42", "IN-42", "TRACE-42")
    settings = _settings("sqlite+pysqlite:///example.db")

    parameters = client.build_stdio_parameters(
        context,
        settings=settings,
        backend_dir=BACKEND_DIR,
        python_executable=sys.executable,
    )

    assert parameters.command == sys.executable
    assert parameters.args == ["-m", "evidencesoc.mcp_server.main"]
    assert Path(parameters.cwd) == BACKEND_DIR
    assert parameters.env == {
        "EVIDENCESOC_RUN_ID": "AR-42",
        "EVIDENCESOC_INCIDENT_ID": "IN-42",
        "EVIDENCESOC_TRACE_ID": "TRACE-42",
        "DATABASE_URL": settings.database_url,
        "OPENSEARCH_URL": settings.opensearch_url,
        "OPENSEARCH_INDEX": settings.opensearch_index,
    }


def _database_with_agent_run(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE agent_runs ("
            "run_id VARCHAR(64) PRIMARY KEY, "
            "incident_id VARCHAR(64) NOT NULL)"
        )
        connection.execute(
            "INSERT INTO agent_runs (run_id, incident_id) VALUES (?, ?)",
            ("AR-42", "IN-42"),
        )
        connection.execute(
            "CREATE TABLE tool_calls ("
            "tool_call_id VARCHAR(64) PRIMARY KEY, "
            "run_id VARCHAR(64) NOT NULL, "
            "tool_name VARCHAR(128) NOT NULL, "
            "arguments JSON NOT NULL, "
            "result JSON, "
            "started_at DATETIME NOT NULL, "
            "finished_at DATETIME, "
            "success BOOLEAN NOT NULL, "
            "error_code VARCHAR(64)"
            ")"
        )
        connection.commit()
    finally:
        connection.close()


@pytest.fixture
def agent_run_database() -> Iterator[Path]:
    descriptor, name = tempfile.mkstemp(
        prefix="mcp-stdio-",
        suffix=".db",
        dir=BACKEND_DIR / "tests",
    )
    os.close(descriptor)
    path = Path(name)
    try:
        _database_with_agent_run(path)
        yield path
    finally:
        path.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_stdio_process_initializes_and_discovers_exactly_three_tools(
    agent_run_database: Path,
) -> None:
    client = importlib.import_module("evidencesoc.mcp_server.client")
    settings = _settings(f"sqlite+pysqlite:///{agent_run_database.as_posix()}")

    with anyio.fail_after(20):
        async with client.open_stdio_session(
            RunContext("AR-42", "IN-42", "TRACE-42"),
            settings=settings,
            backend_dir=BACKEND_DIR,
            python_executable=sys.executable,
        ) as session:
            first = await session.list_tools()
            second = await session.list_tools()
            denial = await session.call_tool("run_shell", {})

    assert {tool.name for tool in first.tools} == {
        "search_security_events",
        "get_alert_context",
        "lookup_attack_technique",
    }
    assert {tool.name for tool in second.tools} == {
        "search_security_events",
        "get_alert_context",
        "lookup_attack_technique",
    }
    assert len(first.tools) == len(second.tools) == 3
    assert denial.isError is True
    assert denial.structuredContent["error"]["code"] == "POLICY_DENIED"
    assert denial.structuredContent["error"]["trace_id"] == "TRACE-42"
    assert all(
        not ({"run_id", "incident_id", "trace_id"} & set(tool.inputSchema["properties"]))
        for tool in first.tools
    )

    connection = sqlite3.connect(agent_run_database)
    try:
        row = connection.execute(
            "SELECT tool_name, success, error_code FROM tool_calls"
        ).fetchone()
    finally:
        connection.close()
    assert row == ("run_shell", 0, "POLICY_DENIED")


@pytest.mark.asyncio
async def test_stdio_process_rejects_mismatched_incident_before_tools(
    agent_run_database: Path,
) -> None:
    client = importlib.import_module("evidencesoc.mcp_server.client")
    settings = _settings(f"sqlite+pysqlite:///{agent_run_database.as_posix()}")

    with tempfile.TemporaryFile(
        mode="w+", encoding="utf-8", errors="replace", dir=BACKEND_DIR / "tests"
    ) as errlog:
        with pytest.raises(Exception) as error, anyio.fail_after(20):
            async with client.open_stdio_session(
                RunContext("AR-42", "IN-wrong", "TRACE-42"),
                settings=settings,
                backend_dir=BACKEND_DIR,
                python_executable=sys.executable,
                errlog=errlog,
            ):
                pytest.fail("mismatched run context must not initialize")

        errlog.seek(0)
        assert "PermissionError: invalid run context" in errlog.read()
        assert not isinstance(error.value, (OSError, TimeoutError))
