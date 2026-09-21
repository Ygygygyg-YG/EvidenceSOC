from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from evidencesoc.domain.models import SecurityEvent, Severity
from evidencesoc.ingestion.jsonl import ParsedLogRecord


class NormalizationError(ValueError):
    def __init__(
        self,
        *,
        code: str,
        record: ParsedLogRecord,
        message: str,
    ) -> None:
        self.code = code
        self.source_path = record.source_path
        self.line_number = record.line_number

        super().__init__(
            f"{message} [{code}] ({record.source_path}:{record.line_number})"
        )


def canonical_json(
    value: Mapping[str, Any],
) -> bytes:
    try:
        serialized = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("事件内容不是有效的规范 JSON") from exc

    return serialized.encode("utf-8")


def calculate_content_sha256(
    value: Mapping[str, Any],
) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def build_deduplication_key(
    external_id: str | None,
    content_sha256: str,
) -> str:
    if external_id is not None:
        return f"id:{external_id}"

    return f"sha256:{content_sha256}"


def _required_text(
    record: ParsedLogRecord,
    field_name: str,
    error_code: str,
) -> str:
    value = record.raw.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise NormalizationError(
            code=error_code,
            record=record,
            message=f"{field_name} 必须是非空字符串",
        )

    return value.strip()


def _optional_external_id(
    record: ParsedLogRecord,
) -> str | None:
    value = record.raw.get("external_id")

    if value is None:
        return None

    if not isinstance(value, str):
        raise NormalizationError(
            code="INVALID_EXTERNAL_ID",
            record=record,
            message="external_id 必须是字符串",
        )

    cleaned = value.strip()
    return cleaned or None


def _aware_utc(
    value: datetime,
    *,
    record: ParsedLogRecord,
    error_code: str,
    field_name: str,
) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise NormalizationError(
            code=error_code,
            record=record,
            message=f"{field_name} 必须包含时区",
        )

    return value.astimezone(UTC)


def _observed_at(
    record: ParsedLogRecord,
) -> datetime:
    value = record.raw.get("observed_at")

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise NormalizationError(
                code="INVALID_OBSERVED_AT",
                record=record,
                message="observed_at 不是合法 ISO-8601 时间",
            ) from exc
    else:
        raise NormalizationError(
            code="INVALID_OBSERVED_AT",
            record=record,
            message="observed_at 缺失或类型错误",
        )

    return _aware_utc(
        parsed,
        record=record,
        error_code="INVALID_OBSERVED_AT",
        field_name="observed_at",
    )


def _severity(record: ParsedLogRecord) -> Severity:
    value = record.raw.get("severity", Severity.INFO.value)

    if not isinstance(value, str):
        raise NormalizationError(
            code="INVALID_SEVERITY",
            record=record,
            message="severity 必须是字符串",
        )

    try:
        return Severity(value.strip().casefold())
    except ValueError as exc:
        raise NormalizationError(
            code="INVALID_SEVERITY",
            record=record,
            message=f"未知 severity：{value}",
        ) from exc


def normalize_record(
    record: ParsedLogRecord,
    *,
    event_id: str,
    ingested_at: datetime,
) -> SecurityEvent:
    if not isinstance(event_id, str) or not event_id.strip():
        raise NormalizationError(
            code="INVALID_EVENT_ID",
            record=record,
            message="event_id 必须是非空字符串",
        )

    source = _required_text(
        record,
        "source",
        "INVALID_SOURCE",
    ).casefold()
    event_type = _required_text(
        record,
        "event_type",
        "INVALID_EVENT_TYPE",
    ).casefold()
    external_id = _optional_external_id(record)
    observed_at = _observed_at(record)
    normalized_ingested_at = _aware_utc(
        ingested_at,
        record=record,
        error_code="INVALID_INGESTED_AT",
        field_name="ingested_at",
    )

    raw = deepcopy(record.raw)
    content_sha256 = calculate_content_sha256(raw)
    deduplication_key = build_deduplication_key(
        external_id,
        content_sha256,
    )

    return SecurityEvent(
        event_id=event_id.strip(),
        source=source,
        external_id=external_id,
        deduplication_key=deduplication_key,
        observed_at=observed_at,
        ingested_at=normalized_ingested_at,
        severity=_severity(record),
        event_type=event_type,
        raw=raw,
        content_sha256=content_sha256,
    )
