import re
from datetime import UTC, datetime
from importlib import import_module


def ids_module():
    return import_module("evidencesoc.ids")


def test_generated_ids_match_required_formats() -> None:
    module = ids_module()

    assert hasattr(module, "new_ulid")
    assert hasattr(module, "new_event_id")
    assert hasattr(module, "new_evidence_id")

    ulid = module.new_ulid()
    event_id = module.new_event_id()
    evidence_id = module.new_evidence_id()

    assert re.fullmatch(
        r"[0-9A-HJKMNP-TV-Z]{26}",
        ulid,
    )
    assert re.fullmatch(
        r"SE-[0-9A-HJKMNP-TV-Z]{26}",
        event_id,
    )
    assert re.fullmatch(
        r"EV-[0-9A-HJKMNP-TV-Z]{26}",
        evidence_id,
    )


def test_generated_ulids_are_unique() -> None:
    module = ids_module()

    values = {module.new_ulid() for _ in range(100)}

    assert len(values) == 100


def test_ulids_sort_by_timestamp() -> None:
    module = ids_module()

    earlier = module.new_ulid(datetime(2026, 9, 21, 10, 0, tzinfo=UTC))
    later = module.new_ulid(datetime(2026, 9, 21, 10, 1, tzinfo=UTC))

    assert earlier < later


def test_ulid_rejects_naive_timestamp() -> None:
    module = ids_module()

    try:
        module.new_ulid(datetime(2026, 9, 21, 10, 0))  # noqa: DTZ001
    except ValueError as exc:
        assert "timezone-aware" in str(exc)
    else:
        raise AssertionError("naive datetime 应被拒绝")
