import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "datasets/ait_v2/audit_parse.py"
LOG = "internal/logs/audit/audit.log"
LINE = "type=USER_AUTH msg=audit(1642492924.071:42): opaque payload  "


@pytest.fixture
def parser():
    if not SCRIPT.exists():

        class Missing:
            def __getattr__(self, name):
                pytest.fail("Audit parser is not implemented")

        return Missing()
    spec = importlib.util.spec_from_file_location("audit_parser_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def line(parser, text=LINE, **kwargs):
    return parser.parse_audit_line(
        text,
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG,
        line_number=kwargs.pop("line_number", 1),
        **kwargs,
    )


def file(parser, tmp_path, data, **kwargs):
    root = tmp_path / "raw"
    source = root / "gather" / LOG
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(data)
    options = {
        "dataset_root": root,
        "dataset_id": "ait-v2.1:fox",
        "relative_log_path": LOG,
        "output": tmp_path / "events.jsonl",
        "errors": tmp_path / "errors.jsonl",
    }
    options.update(kwargs)
    return parser.parse_audit_file(**options)


def rows(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


def test_observation_preserves_payload_and_physical_origin(parser):
    raw = "\ufeff" + LINE + "\r\n"
    record = line(parser, raw)
    assert record["timestamp"] == record["observed_at"] == "2022-01-18T08:02:04.071000Z"
    assert record["audit_payload"] == "opaque payload  "
    assert record["audit_epoch"] == "1642492924.071"
    assert record["audit_sequence"] == 42
    assert record["audit_event_id"] == "1642492924.071:42"
    assert record["audit_record_type"] == "USER_AUTH"
    assert record["source"] == "auditd" and record["event_type"] == "audit.record"
    assert record["raw_line"] == raw
    assert record["raw_line_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    key = json.dumps(["ait-v2.1:fox", LOG, 1], separators=(",", ":")).encode()
    assert record["external_id"] == "ait:" + hashlib.sha256(key).hexdigest()
    assert line(parser, raw, line_number=2)["external_id"] != record["external_id"]
    assert (
        not {"labels", "rules", "source_ip", "is_attack", "attack_types"}
        & record.keys()
    )


@pytest.mark.parametrize(
    "epoch,expected",
    [
        ("0", "1970-01-01T00:00:00Z"),
        ("0.000001", "1970-01-01T00:00:00.000001Z"),
        ("253402300799.999999", "9999-12-31T23:59:59.999999Z"),
    ],
)
def test_exact_epoch(parser, epoch, expected):
    assert line(parser, f"type=A1_ msg=audit({epoch}:0): ")["timestamp"] == expected


@pytest.mark.parametrize(
    "text,code",
    [
        ("type=x msg=audit(0:0): secret", "INVALID_AUDIT_FORMAT"),
        ("type=A msg=audit(-1:0): secret", "INVALID_AUDIT_FORMAT"),
        ("type=A msg=audit(0.1234567:0): secret", "INVALID_AUDIT_FORMAT"),
        ("type=A msg=audit(253402300800:0): secret", "INVALID_AUDIT_TIMESTAMP"),
    ],
)
def test_invalid_header(parser, text, code):
    with pytest.raises(ValueError, match=code):
        line(parser, text)


def test_stream_errors_blank_and_counts(parser, tmp_path):
    data = (
        (LINE + "\r\n").encode()
        + b"\n\xffsecret\nbad secret\n"
        + (LINE + "\n").encode()
    )
    summary = file(parser, tmp_path, data)
    assert (
        summary["read_lines"],
        summary["written_records"],
        summary["blank_lines"],
        summary["parse_errors"],
    ) == (5, 2, 1, 2)
    assert summary["record_type_counts"] == {"USER_AUTH": 2}
    assert not summary["truncated"]
    records = rows(tmp_path / "events.jsonl")
    assert [r["line_number"] for r in records] == [1, 5]
    assert (
        records[0]["raw_line_sha256"]
        == hashlib.sha256((LINE + "\r\n").encode()).hexdigest()
    )
    errors = rows(tmp_path / "errors.jsonl")
    assert [r["error_code"] for r in errors] == ["INVALID_UTF8", "INVALID_AUDIT_FORMAT"]
    assert set(errors[0]) == {
        "dataset_id",
        "relative_log_path",
        "line_number",
        "raw_line_sha256",
        "error_code",
    }
    assert "secret" not in (tmp_path / "errors.jsonl").read_text()


@pytest.mark.parametrize("limit", [True, 0, -1, 1.5, "2"])
def test_strict_limit(parser, tmp_path, limit):
    with pytest.raises(ValueError, match="max_lines"):
        file(parser, tmp_path, LINE.encode(), max_lines=limit)


@pytest.mark.parametrize("extra,truncated", [(b"", False), (b"\n", True)])
def test_limit_actual_remaining_bytes(parser, tmp_path, extra, truncated):
    assert (
        file(parser, tmp_path, (LINE + "\n").encode() + extra, max_lines=1)["truncated"]
        is truncated
    )


def test_time_interval_counts_only_written(parser, tmp_path):
    data = b"type=A msg=audit(0:1): a\ntype=B msg=audit(1:2): b\ntype=C msg=audit(2:3): c\n"
    summary = file(
        parser,
        tmp_path,
        data,
        time_from=datetime.fromtimestamp(1, UTC),
        time_to=datetime.fromtimestamp(2, UTC),
    )
    assert summary["record_type_counts"] == {"B": 1}
    assert summary["time_filtered"] == 2


@pytest.mark.parametrize(
    "bounds",
    [
        {"time_from": datetime.now(UTC)},
        {"time_from": datetime(2022, 1, 1), "time_to": datetime(2022, 1, 2)},  # noqa: DTZ001 -- intentionally invalid naive bounds
        {
            "time_from": datetime(2022, 1, 2, tzinfo=UTC),
            "time_to": datetime(2022, 1, 1, tzinfo=UTC),
        },
    ],
)
def test_invalid_bounds(parser, tmp_path, bounds):
    with pytest.raises(ValueError):
        file(parser, tmp_path, LINE.encode(), **bounds)


@pytest.mark.parametrize(
    "path",
    [
        "attacker/logs/audit.log",
        "../internal/logs/audit.log",
        "internal/logs/attacks.log",
    ],
)
def test_source_rejected(parser, path):
    with pytest.raises(ValueError):
        parser.parse_audit_line(
            LINE, dataset_id="ait-v2.1:fox", relative_log_path=path, line_number=1
        )


def test_existing_output_preserved(parser, tmp_path):
    output = tmp_path / "events.jsonl"
    output.write_text("keep")
    with pytest.raises(FileExistsError):
        file(parser, tmp_path, LINE.encode())
    assert output.read_text() == "keep"
    assert not (tmp_path / "errors.jsonl").exists()


def test_cli_error_two(parser):
    with pytest.raises(SystemExit) as exc:
        parser.main(
            [
                "--dataset-root",
                ".",
                "--dataset-id",
                "invalid",
                "--log-path",
                LOG,
                "--output",
                "x",
                "--errors",
                "y",
            ]
        )
    assert exc.value.code == 2


@pytest.mark.parametrize("mode", ["same", "raw"])
def test_output_boundaries(parser, tmp_path, mode):
    output = (
        tmp_path / "events.jsonl" if mode == "same" else tmp_path / "raw" / "out.jsonl"
    )
    errors = output if mode == "same" else tmp_path / "errors.jsonl"
    with pytest.raises(ValueError, match="outside the raw"):
        file(parser, tmp_path, LINE.encode(), output=output, errors=errors)
    assert not output.exists()


def test_failure_removes_only_created_file(parser, tmp_path, monkeypatch):
    original = Path.open
    errors = tmp_path / "errors.jsonl"

    def fail_second(path, *args, **kwargs):
        if path == errors and args and args[0] == "x":
            raise OSError("fixture write failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_second)
    with pytest.raises(OSError, match="fixture write failure"):
        file(parser, tmp_path, LINE.encode())
    assert not (tmp_path / "events.jsonl").exists()
    assert not errors.exists()
    assert (tmp_path / "raw" / "gather" / LOG).read_bytes() == LINE.encode()


def test_normalize_and_sparse_fixture_join(parser, tmp_path):
    from evidencesoc.ingestion.jsonl import ParsedLogRecord
    from evidencesoc.ingestion.normalize import normalize_record

    file(
        parser,
        tmp_path,
        ((LINE + "\n") * 2).encode(),
        output=tmp_path / "agent" / "events.jsonl",
    )
    record = rows(tmp_path / "agent" / "events.jsonl")[0]
    normalized = normalize_record(
        ParsedLogRecord(raw=record, source_path="events.jsonl", line_number=1),
        event_id="SE-01K5N8B8Y00000000000000000",
        ingested_at=datetime.now(UTC),
    )
    assert normalized.source == "auditd"
    assert normalized.external_id == record["external_id"]
    label = tmp_path / "raw" / "labels" / LOG
    label.parent.mkdir(parents=True)
    label.write_text(
        json.dumps(
            {"line": 1, "labels": ["fixture"], "rules": {"fixture": ["fixture-rule"]}}
        )
        + "\n",
        encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location(
        "audit_fixture_join", SCRIPT.with_name("join_labels.py")
    )
    joiner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(joiner)
    summary = joiner.join_labels(
        dataset_root=tmp_path / "raw",
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG,
        events=tmp_path / "agent" / "events.jsonl",
        output=tmp_path / "gold.jsonl",
        report=tmp_path / "join.json",
    )
    assert summary["labeled_events"] == 1
    assert summary["unlabeled_unknown_events"] == 1
    assert [r["annotation_status"] for r in rows(tmp_path / "gold.jsonl")] == [
        "labeled",
        "unlabeled_unknown",
    ]


def test_windows_source_case_is_canonical(parser, tmp_path):
    import os

    if os.name != "nt":
        pytest.skip("Windows source casing")
    summary = file(parser, tmp_path, LINE.encode(), relative_log_path=LOG.upper())
    assert summary["relative_log_path"] == LOG


def test_reparse_point_rejected(parser, tmp_path, monkeypatch):
    import os
    import stat
    from types import SimpleNamespace

    root = tmp_path / "raw"
    original = os.lstat

    def metadata(path, *args, **kwargs):
        if Path(path) == root:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR,
                st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
            )
        return original(path, *args, **kwargs)

    monkeypatch.setattr(parser._helpers.os, "lstat", metadata)
    with pytest.raises(ValueError, match="filesystem links"):
        file(parser, tmp_path, LINE.encode())
