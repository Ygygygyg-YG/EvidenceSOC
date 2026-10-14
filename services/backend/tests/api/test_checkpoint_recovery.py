import asyncio
import os

import pytest
from evidencesoc.agents.checkpoint import open_checkpointer, psycopg_url
from evidencesoc.config import Settings
from evidencesoc.ids import new_ulid
from langgraph.graph import END, START, StateGraph
from psycopg import Connection


@pytest.mark.skipif(
    os.getenv("EVIDENCESOC_TEST_POSTGRES") != "1",
    reason="requires opt-in local PostgreSQL connectivity",
)
@pytest.mark.asyncio
async def test_checkpoint_survives_loss_of_its_own_postgres_connection():
    settings = Settings()
    identity = "IN-api-checkpoint-" + new_ulid()
    config = {"configurable": {"thread_id": identity}}
    try:
        async with open_checkpointer(settings.database_url) as saver:
            builder = StateGraph(dict)
            builder.add_node("increment", lambda state: {"value": state["value"] + 1})
            builder.add_edge(START, "increment")
            builder.add_edge("increment", END)
            graph = builder.compile(checkpointer=saver)
            assert await graph.ainvoke({"value": 1}, config) == {"value": 2}

            def terminate_owned_connection():
                if isinstance(saver.conn, Connection):
                    pid = saver.conn.info.backend_pid
                else:
                    with saver.conn.connection() as connection:
                        pid = connection.info.backend_pid
                with Connection.connect(
                    psycopg_url(settings.database_url),
                    autocommit=True,
                    connect_timeout=3,
                ) as terminator:
                    assert terminator.execute(
                        "SELECT pg_terminate_backend(%s)", (pid,)
                    ).fetchone() == (True,)

            await asyncio.to_thread(terminate_owned_connection)
            recovered = await asyncio.wait_for(graph.aget_state(config), timeout=5)
            assert recovered.values == {"value": 2}
            assert await graph.ainvoke({"value": 2}, config) == {"value": 3}
    finally:
        async with open_checkpointer(settings.database_url) as cleaner:
            await cleaner.adelete_thread(identity)
