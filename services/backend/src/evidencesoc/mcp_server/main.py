from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from evidencesoc.config import Settings
from evidencesoc.domain.models import EvidenceItem
from evidencesoc.mcp_server.context import (
    RunContext,
    load_run_context,
    tool_attempt_limit,
)
from evidencesoc.mcp_server.restricted import RestrictedFastMCP
from evidencesoc.persistence.database import (
    create_database_engine,
    create_session_factory,
)
from evidencesoc.persistence.tables import AgentRunTable
from evidencesoc.tools.alert_context import AlertContextTools
from evidencesoc.tools.alert_work import build_alert_context_work
from evidencesoc.tools.attack import AttackTools
from evidencesoc.tools.attack_work import build_attack_lookup_work
from evidencesoc.tools.audit import AuditWriter
from evidencesoc.tools.audit_sql import SqlAuditWriter
from evidencesoc.tools.event_work import build_event_search_work
from evidencesoc.tools.incident_scope import load_incident_scope
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


def create_server(
    *,
    context: RunContext,
    boundary_audit: AuditWriter,
    event_tools: SecurityEventTools,
    alert_tools: AlertContextTools,
    attack_tools: AttackTools,
) -> RestrictedFastMCP:
    server = RestrictedFastMCP(
        context=context,
        boundary_audit=boundary_audit,
    )

    @server.tool()
    async def search_security_events(
        time_from: datetime,
        time_to: datetime,
        filters: dict[str, str],
        limit: int = 100,
    ) -> list[EvidenceItem]:
        """Search bounded security events and persist verified evidence."""
        _require_capability("search_security_events")
        server.mark_business_invoked()
        return await event_tools.search_security_events(
            time_from=time_from,
            time_to=time_to,
            filters=filters,
            limit=limit,
        )

    @server.tool()
    async def get_alert_context(
        alert_id: str,
        before_seconds: int = 900,
        after_seconds: int = 900,
    ) -> list[EvidenceItem]:
        """Return verified events scoped to the current incident alert."""
        _require_capability("get_alert_context")
        server.mark_business_invoked()
        return await alert_tools.get_alert_context(
            alert_id=alert_id,
            before_seconds=before_seconds,
            after_seconds=after_seconds,
        )

    @server.tool()
    async def lookup_attack_technique(
        query: str,
        limit: int = 10,
    ) -> list[dict[str, str]]:
        """Look up local ATT&CK knowledge without network access."""
        _require_capability("lookup_attack_technique")
        server.mark_business_invoked()
        return await attack_tools.lookup_attack_technique(query=query, limit=limit)

    return server


def _require_capability(name: str) -> None:
    from evidencesoc.agents.capabilities import current_capabilities

    policy = current_capabilities()
    if policy is not None:
        policy.require_tool(name)


def build_server(
    *,
    context: RunContext,
    settings: Settings,
    session_factory: sessionmaker[Session],
    max_attempts: int = 3,
) -> RestrictedFastMCP:
    validate_run_context(session_factory, context)
    audit = SqlAuditWriter(session_factory=session_factory)
    event_work = build_event_search_work(
        opensearch_url=settings.opensearch_url,
        index_name=settings.opensearch_index,
        session_factory=session_factory,
        max_attempts=max_attempts,
    )
    event_tools = SecurityEventTools(
        context=context,
        work=event_work,
        audit=audit,
        incident_scope=lambda: load_incident_scope(
            session_factory, context.incident_id
        ),
    )
    alert_tools = AlertContextTools(
        context=context,
        work=build_alert_context_work(
            opensearch_url=settings.opensearch_url,
            index_name=settings.opensearch_index,
            session_factory=session_factory,
            max_attempts=max_attempts,
        ),
        audit=audit,
    )
    attack_tools = AttackTools(
        context=context,
        work=build_attack_lookup_work(
            session_factory=session_factory,
            model_path=settings.rag_data_directory / "model",
            max_attempts=max_attempts,
        ),
        audit=audit,
    )
    return create_server(
        context=context,
        boundary_audit=audit,
        event_tools=event_tools,
        alert_tools=alert_tools,
        attack_tools=attack_tools,
    )


def main() -> None:
    from evidencesoc.agents.capabilities import (
        InvestigationCapabilities,
        capability_scope,
    )
    from evidencesoc.tools.policy import ALLOWED_TOOLS

    context = load_run_context(os.environ)
    settings = Settings(_env_file=None)
    engine = create_database_engine(
        settings.database_url, bounded_tool_connections=True
    )
    try:
        policy = InvestigationCapabilities(
            allowed_tools=frozenset(
                json.loads(
                    os.environ.get(
                        "EVIDENCESOC_ALLOWED_TOOLS", json.dumps(sorted(ALLOWED_TOOLS))
                    )
                )
            ),
            rag_mode=os.environ.get("EVIDENCESOC_RAG_MODE", "hybrid"),
        )
        with capability_scope(policy):
            server = build_server(
                context=context,
                settings=settings,
                session_factory=create_session_factory(engine),
                max_attempts=tool_attempt_limit(os.environ),
            )
            server.run(transport="stdio")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
