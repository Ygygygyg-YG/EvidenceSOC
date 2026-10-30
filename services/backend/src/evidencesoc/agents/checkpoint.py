from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from langgraph.checkpoint.postgres import PostgresSaver
from psycopg import Connection
from psycopg.rows import DictRow, dict_row
from psycopg_pool import ConnectionPool


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
async def open_checkpointer(database_url: str, *, readonly: bool = False):
    """Open existing checkpoints read-only when requested; default still sets up."""
    pool: ConnectionPool[Connection[DictRow]] = ConnectionPool(
        psycopg_url(database_url),
        kwargs={
            "autocommit": True,
            "connect_timeout": 3,
            "prepare_threshold": 0,
            "row_factory": dict_row,
            "options": "-c statement_timeout=3000"
            + (" -c default_transaction_read_only=on" if readonly else ""),
        },
        min_size=1,
        max_size=2,
        timeout=3,
        check=ConnectionPool.check_connection,
        open=False,
    )
    try:
        await asyncio.to_thread(pool.open, wait=True, timeout=3)
        saver = ThreadedPostgresSaver(pool)
        if not readonly:
            await asyncio.to_thread(saver.setup)
        yield saver
    finally:
        await asyncio.to_thread(pool.close)
