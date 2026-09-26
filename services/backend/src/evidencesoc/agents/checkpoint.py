from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from langgraph.checkpoint.postgres import PostgresSaver
from psycopg import Connection
from psycopg.rows import dict_row


class ThreadedPostgresSaver(PostgresSaver):
    """Keep psycopg's sync driver off the Windows subprocess event loop."""

    async def aget_tuple(self, config):
        return await asyncio.to_thread(self.get_tuple, config)

    async def alist(self, config, *, filter=None, before=None, limit=None):
        values = await asyncio.to_thread(
            lambda: list(self.list(config, filter=filter, before=before, limit=limit))
        )
        for value in values:
            yield value

    async def aput(self, config, checkpoint, metadata, new_versions):
        return await asyncio.to_thread(
            self.put, config, checkpoint, metadata, new_versions
        )

    async def aput_writes(self, config, writes, task_id, task_path=""):
        await asyncio.to_thread(self.put_writes, config, writes, task_id, task_path)

    async def adelete_thread(self, thread_id):
        await asyncio.to_thread(self.delete_thread, thread_id)


def psycopg_url(database_url: str) -> str:
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


@asynccontextmanager
async def open_checkpointer(database_url: str):
    connection = await asyncio.to_thread(
        Connection.connect,
        psycopg_url(database_url),
        autocommit=True,
        prepare_threshold=0,
        row_factory=dict_row,
    )
    try:
        saver = ThreadedPostgresSaver(connection)
        await asyncio.to_thread(saver.setup)
        yield saver
    finally:
        await asyncio.to_thread(connection.close)
