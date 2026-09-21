from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def create_database_engine(url: str) -> Engine:
    """Create a database engine without opening a connection."""
    if not url.strip():
        raise ValueError("database URL must not be blank")

    return create_engine(url, pool_pre_ping=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create independent request/job sessions for an existing engine."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
