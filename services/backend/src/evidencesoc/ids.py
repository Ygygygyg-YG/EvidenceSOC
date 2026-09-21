from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Final

_CROCKFORD_BASE32: Final[str] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_MAX_TIMESTAMP: Final[int] = (1 << 48) - 1


def _encode_ulid(value: int) -> str:
    characters = ["0"] * 26

    for index in range(25, -1, -1):
        characters[index] = _CROCKFORD_BASE32[value & 31]
        value >>= 5

    return "".join(characters)


def new_ulid(timestamp: datetime | None = None) -> str:
    if timestamp is None:
        timestamp = datetime.now(UTC)

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("ULID timestamp must be timezone-aware")

    timestamp_ms = int(timestamp.timestamp() * 1000)

    if not 0 <= timestamp_ms <= _MAX_TIMESTAMP:
        raise ValueError("ULID timestamp is out of range")

    randomness = int.from_bytes(
        secrets.token_bytes(10),
        byteorder="big",
    )
    value = (timestamp_ms << 80) | randomness

    return _encode_ulid(value)


def new_event_id() -> str:
    return f"SE-{new_ulid()}"


def new_evidence_id() -> str:
    return f"EV-{new_ulid()}"
