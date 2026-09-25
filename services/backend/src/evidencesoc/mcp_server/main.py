from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime

from mcp.server.fastmcp import FastMCP
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from evidencesoc.config import Settings
from evidencesoc.domain.models import EvidenceItem
from evidencesoc.mcp_server.context import RunContext, load_run_context
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.tables import AgentRunTable
from evidencesoc.tools.audit_sql import SqlAuditWriter
from evidencesoc.tools.event_work import build_event_search_work
from evidencesoc.tools.security_events import SecurityEventTools


def validate_run_context(
    session_factory: Callable[[], Session],
    context: RunContext,
) -> None:
    """Reject a missing AgentRun or a run bound to a different incident."""
    with session_factory() as session:
        incident_id = session.execute(
            select(AgentRunTable.incident_id).where(
                AgentRunTable.run_id == context.run_id
            )
        ).scalar_one_or_none()
    if incident_id != context.incident_id:
        raise PermissionError("invalid run context")


def create_server(event_tools: SecurityEventTools) -> FastMCP:
    server = FastMCP("EvidenceSOC read-only investigation tools")

    @server.tool()
    async def search_security_events(
        time_from: datetime,
        time_to: datetime,
        filters: dict[str, str],
        limit: int = 100,
    ) -> list[EvidenceItem]:
        """Search bounded security events and persist verified evidence."""
        return await event_tools.search_security_events(
            time_from=time_from,
            time_to=time_to,
            filters=filters,
            limit=limit,
        )

    return server


def build_server(
    *,
    context: RunContext,
    settings: Settings,
    session_factory: sessionmaker[Session],
) -> FastMCP:
    validate_run_context(session_factory, context)
    work = build_event_search_work(
        opensearch_url=settings.opensearch_url,
        index_name=settings.opensearch_index,
        session_factory=session_factory,
    )
    event_tools = SecurityEventTools(
        context=context,
        work=work,
        audit=SqlAuditWriter(session_factory=session_factory),
    )
    return create_server(event_tools)


def main() -> None:
    context = load_run_context(os.environ)
    settings = Settings()
    engine = create_database_engine(settings.database_url)
    try:
        server = build_server(
            context=context,
            settings=settings,
            session_factory=create_session_factory(engine),
        )
        server.run(transport="stdio")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
