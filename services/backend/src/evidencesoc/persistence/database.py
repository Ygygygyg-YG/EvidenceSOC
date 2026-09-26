from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from evidencesoc.execution import check_execution


def create_database_engine(url: str, *, bounded_tool_connections: bool = False) -> Engine:
    """Create a database engine without opening a connection."""
    if not url.strip():
        raise ValueError("database URL must not be blank")

    options: dict[str, Any] = {}
    if bounded_tool_connections and url.startswith("postgresql"):
        options = {"pool_timeout": 1, "connect_args": {"connect_timeout": 1}}
    engine = create_engine(url, pool_pre_ping=True, **options)

    @event.listens_for(engine, "before_cursor_execute")
    def bound_statement(
        connection: Any, cursor: Any, statement: Any,
        parameters: Any, context: Any, executemany: Any,
    ) -> None:
        remaining = check_execution()
        if remaining is not None and connection.dialect.name == "postgresql":
            milliseconds = max(1, int(remaining * 1000))
            cursor.execute("SELECT set_config('statement_timeout', %s, true)", (f"{milliseconds}ms",))

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create independent request/job sessions for an existing engine."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
