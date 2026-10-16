"""Fixed-version DEDALE observation adapters; labels stay in scoring code."""

from .parse import (
    ARCHIVE_SOURCES,
    DATASET_ID,
    event_fingerprint,
    iter_archive_events,
    iter_archive_lines,
    parse_event,
    read_archive_manifest,
)

__all__ = [
    "ARCHIVE_SOURCES",
    "DATASET_ID",
    "event_fingerprint",
    "iter_archive_events",
    "iter_archive_lines",
    "parse_event",
    "read_archive_manifest",
]
