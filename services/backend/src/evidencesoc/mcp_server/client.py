from __future__ import annotations

import json
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TextIO

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from evidencesoc.config import Settings
from evidencesoc.mcp_server.context import RunContext


def build_stdio_parameters(
    context: RunContext,
    *,
    settings: Settings,
    backend_dir: Path,
    python_executable: str = sys.executable,
    managed_attempts: bool = False,
) -> StdioServerParameters:
    """Bind one local MCP child process to an existing AgentRun."""
    environment = {
        "EVIDENCESOC_RUN_ID": context.run_id,
        "EVIDENCESOC_INCIDENT_ID": context.incident_id,
        "EVIDENCESOC_TRACE_ID": context.trace_id,
        "DATABASE_URL": settings.database_url,
        "OPENSEARCH_URL": settings.opensearch_url,
        "OPENSEARCH_INDEX": settings.opensearch_index,
        "RAG_DATA_DIRECTORY": str(settings.rag_data_directory),
    }
    # MCP's default child environment omits PYTHONPATH. Exported workers load
    # both backend source and locked dependencies through this explicit path.
    if "PYTHONPATH" in os.environ:
        environment["PYTHONPATH"] = os.environ["PYTHONPATH"]
    if managed_attempts:
        environment["EVIDENCESOC_MAX_TOOL_ATTEMPTS"] = "1"
    from evidencesoc.agents.capabilities import current_capabilities

    policy = current_capabilities()
    if policy is not None:
        environment["EVIDENCESOC_RAG_MODE"] = policy.rag_mode
        environment["EVIDENCESOC_ALLOWED_TOOLS"] = json.dumps(
            sorted(policy.allowed_tools)
        )
    return StdioServerParameters(
        command=python_executable,
        args=["-m", "evidencesoc.mcp_server.main"],
        cwd=backend_dir,
        env=environment,
    )


@asynccontextmanager
async def open_stdio_session(
    context: RunContext,
    *,
    settings: Settings,
    backend_dir: Path,
    python_executable: str = sys.executable,
    errlog: TextIO | None = None,
    managed_attempts: bool = False,
) -> AsyncIterator[ClientSession]:
    """Keep one session open for the entire AgentRun; tools expire on exit."""
    parameters = build_stdio_parameters(
        context,
        settings=settings,
        backend_dir=backend_dir,
        python_executable=python_executable,
        managed_attempts=managed_attempts,
    )
    async with (
        stdio_client(parameters, errlog=errlog or sys.stderr) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session
