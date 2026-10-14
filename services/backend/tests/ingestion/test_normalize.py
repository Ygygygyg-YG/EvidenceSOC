from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest
from evidencesoc.ingestion.jsonl import ParsedLogRecord

INGESTED_AT = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)


def normalize_module():
    return import_module("evidencesoc.ingestion.normalize")


def parsed_record(raw: dict[str, Any]) -> ParsedLogRecord:
    return ParsedLogRecord(
        raw=raw,
        source_path="events.jsonl",
        line_number=7,
    )


def normalize(
    raw: dict[str, Any],
    *,
    event_id: str = "SE-01K5N8B8Y00000000000000000",
    ingested_at: datetime = INGESTED_AT,
):
    module = normalize_module()
    normalize_record = getattr(
        module,
        "normalize_record",
        None,
    )

    assert callable(normalize_record), "normalize_record 尚未实现"

    return normalize_record(
        parsed_record(raw),
        event_id=event_id,
        ingested_at=ingested_at,
    )


def assert_normalization_error(
    error: ValueError,
    *,
    code: str,
) -> None:
    assert getattr(error, "code", None) == code
    assert getattr(error, "source_path", None) == "events.jsonl"
    assert getattr(error, "line_number", None) == 7


def valid_raw() -> dict[str, Any]:
    return {
        "source": " NGINX ",
        "external_id": " request-001 ",
        "observed_at": "2026-09-21T10:20:30+08:00",
        "severity": " HIGH ",
        "event_type": " WEB.Request ",
        "message": "GET /health",
    }


def test_canonical_hash_is_stable_for_key_order() -> None:
    module = normalize_module()

    calculate_hash = getattr(
        module,
        "calculate_content_sha256",
        None,
    )
    assert callable(calculate_hash)

    first = {
        "source": "nginx",
        "message": "request",
    }
    second = {
        "message": "request",
        "source": "nginx",
    }

    assert calculate_hash(first) == calculate_hash(second)


def test_content_change_changes_hash() -> None:
    module = normalize_module()
    calculate_hash = module.calculate_content_sha256

    first = {
        "source": "nginx",
        "status": 200,
    }
    second = {
        "source": "nginx",
        "status": 500,
    }

    assert calculate_hash(first) != calculate_hash(second)


def test_normalize_record_returns_security_event() -> None:
    raw = valid_raw()

    event = normalize(raw)

    assert event.event_id == "SE-01K5N8B8Y00000000000000000"
    assert event.source == "nginx"
    assert event.external_id == "request-001"
    assert event.deduplication_key == "id:request-001"
    assert event.observed_at == datetime(
        2026,
        9,
        21,
        2,
        20,
        30,
        tzinfo=UTC,
    )
    assert event.ingested_at == INGESTED_AT
    assert event.severity.value == "high"
    assert event.event_type == "web.request"
    assert event.raw == raw
    assert event.index_status.value == "pending"
    assert len(event.content_sha256) == 64


def test_normalize_accepts_utc_z_suffix() -> None:
    raw = valid_raw()
    raw["observed_at"] = "2026-09-21T12:00:00Z"

    event = normalize(raw)

    assert event.observed_at == datetime(2026, 9, 21, 12, 0, tzinfo=UTC)


def test_missing_external_id_uses_content_hash() -> None:
    raw = valid_raw()
    raw.pop("external_id")

    event = normalize(raw)

    assert event.external_id is None
    assert event.deduplication_key == (f"sha256:{event.content_sha256}")


@pytest.mark.parametrize(
    "source",
    [None, "", "   ", 123],
)
def test_normalize_record_rejects_invalid_source(
    source: object,
) -> None:
    raw = valid_raw()
    raw["source"] = source

    with pytest.raises(ValueError) as exc_info:
        normalize(raw)

    assert_normalization_error(
        exc_info.value,
        code="INVALID_SOURCE",
    )


@pytest.mark.parametrize(
    "observed_at",
    [
        None,
        "",
        "not-a-time",
        "2026-09-21T10:20:30",
    ],
)
def test_normalize_record_rejects_invalid_time(
    observed_at: object,
) -> None:
    raw = valid_raw()
    raw["observed_at"] = observed_at

    with pytest.raises(ValueError) as exc_info:
        normalize(raw)

    assert_normalization_error(
        exc_info.value,
        code="INVALID_OBSERVED_AT",
    )


def test_normalize_record_rejects_invalid_severity() -> None:
    raw = valid_raw()
    raw["severity"] = "emergency"

    with pytest.raises(ValueError) as exc_info:
        normalize(raw)

    assert_normalization_error(
        exc_info.value,
        code="INVALID_SEVERITY",
    )


@pytest.mark.parametrize(
    "event_type",
    [None, "", "   ", 123],
)
def test_normalize_record_rejects_invalid_event_type(
    event_type: object,
) -> None:
    raw = valid_raw()
    raw["event_type"] = event_type

    with pytest.raises(ValueError) as exc_info:
        normalize(raw)

    assert_normalization_error(
        exc_info.value,
        code="INVALID_EVENT_TYPE",
    )


def test_normalize_record_rejects_naive_ingestion_time() -> None:
    with pytest.raises(ValueError) as exc_info:
        normalize(
            valid_raw(),
            ingested_at=datetime(2026, 9, 21, 12, 0),  # noqa: DTZ001
        )

    assert_normalization_error(
        exc_info.value,
        code="INVALID_INGESTED_AT",
    )


def test_hash_does_not_depend_on_ingestion_metadata() -> None:
    raw = valid_raw()

    first = normalize(
        raw,
        event_id="SE-01K5N8B8Y00000000000000000",
        ingested_at=datetime(
            2026,
            9,
            21,
            12,
            0,
            tzinfo=UTC,
        ),
    )
    second = normalize(
        raw,
        event_id="SE-01K5N8B8Y00000000000000001",
        ingested_at=datetime(
            2026,
            9,
            22,
            12,
            0,
            tzinfo=UTC,
        ),
    )

    assert first.content_sha256 == second.content_sha256


def test_canonical_json_rejects_non_finite_number() -> None:
    module = normalize_module()

    with pytest.raises(ValueError):
        module.calculate_content_sha256({"score": float("nan")})


def test_error_retains_source_location() -> None:
    record = ParsedLogRecord(
        raw={"event_type": "web.request"},
        source_path=str(Path("samples") / "events.jsonl"),
        line_number=19,
    )

    module = normalize_module()

    with pytest.raises(ValueError) as exc_info:
        module.normalize_record(
            record,
            event_id="SE-01K5N8B8Y00000000000000000",
            ingested_at=INGESTED_AT,
        )

    assert exc_info.value.source_path == record.source_path
    assert exc_info.value.line_number == 19
