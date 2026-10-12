import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "datasets/ait_v2/dnsmasq_parse.py"
LOG = "inet-firewall/logs/dnsmasq.log"
LINE = "Jan 18 08:02:04 dnsmasq[42]: query[A] example.test from 192.0.2.1  "


@pytest.fixture
def parser():
    if not SCRIPT.exists():

        class Missing:
            def __getattr__(self, name):
                pytest.fail("DNS parser is not implemented")

        return Missing()
    spec = importlib.util.spec_from_file_location("dnsmasq_parser_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def line(parser, text=LINE, **kwargs):
    return parser.parse_dnsmasq_line(
        text,
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG,
        line_number=kwargs.pop("line_number", 1),
        year=kwargs.pop("year", 2022),
        utc_offset=kwargs.pop("utc_offset", "+00:00"),
        **kwargs,
    )


def file(parser, tmp_path, data, **kwargs):
    root = tmp_path / "raw"
    source = root / "gather" / LOG
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(data)
    options = {
        "year": 2022,
        "utc_offset": "+00:00",
        "dataset_root": root,
        "dataset_id": "ait-v2.1:fox",
        "relative_log_path": LOG,
        "output": tmp_path / "events.jsonl",
        "errors": tmp_path / "errors.jsonl",
    }
    options.update(kwargs)
    return parser.parse_dnsmasq_file(**options)


def rows(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


def test_observation_preserves_payload_and_physical_origin(parser):
    raw = "\ufeff" + LINE + "\r\n"
    r = line(parser, raw)
    assert r["timestamp"] == r["observed_at"] == "2022-01-18T08:02:04Z"
    assert r["dns_payload"] == "query[A] example.test from 192.0.2.1  "
    assert r["dnsmasq_pid"] == 42
    assert (r["syslog_month"], r["syslog_day"], r["syslog_time"]) == (
        "Jan",
        18,
        "08:02:04",
    )
    assert (r["timestamp_year"], r["timestamp_utc_offset"], r["timestamp_basis"]) == (
        2022,
        "+00:00",
        "explicit_year_and_utc_offset",
    )
    assert r["raw_line"] == raw
    assert r["raw_line_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    key = json.dumps(["ait-v2.1:fox", LOG, 1], separators=(",", ":")).encode()
    assert r["external_id"] == "ait:" + hashlib.sha256(key).hexdigest()
    assert line(parser, line_number=2)["external_id"] != r["external_id"]
    assert r["source"] == "dnsmasq" and r["event_type"] == "dns.log"
    assert r["source_ip"] == r["dns_query_client"] == "192.0.2.1"
    assert r["dns_query_type"] == "A" and r["dns_question_name"] == "example.test"
    assert not {"labels", "rules", "is_attack", "attack_types"} & r.keys()


@pytest.mark.parametrize("year", [True, 0, 10000, 2022.0, "2022", None])
def test_year_strict(parser, year):
    with pytest.raises(ValueError, match="year"):
        line(parser, year=year)


@pytest.mark.parametrize(
    "offset", [True, None, "+0000", "+24:00", "-00:60", "00:00", "+０0:00"]
)
def test_offset_strict(parser, offset):
    with pytest.raises(ValueError, match="utc_offset"):
        line(parser, utc_offset=offset)


@pytest.mark.parametrize(
    "text,year,offset,expected",
    [
        ("Feb 29 00:00:00 dnsmasq[0]: ", 2024, "+00:00", "2024-02-29T00:00:00Z"),
        ("Jan  1 00:00:00 dnsmasq[1]: x", 2022, "+08:30", "2021-12-31T15:30:00Z"),
        ("Dec 31 23:00:00 dnsmasq[1]: x", 2022, "-02:00", "2023-01-01T01:00:00Z"),
    ],
)
def test_calendar_offsets(parser, text, year, offset, expected):
    assert line(parser, text, year=year, utc_offset=offset)["timestamp"] == expected


@pytest.mark.parametrize(
    "text,year,offset,code",
    [
        ("Feb 29 00:00:00 dnsmasq[1]: x", 2022, "+00:00", "TIMESTAMP"),
        ("Jan 1 00:00:00 dnsmasq[1]: x", 1, "+00:01", "TIMESTAMP"),
        ("Dec 31 23:59:59 dnsmasq[1]: x", 9999, "-00:01", "TIMESTAMP"),
        ("Jan 32 00:00:00 dnsmasq[1]: x", 2022, "+00:00", "TIMESTAMP"),
        ("Jan 1 24:00:00 dnsmasq[1]: x", 2022, "+00:00", "TIMESTAMP"),
        ("Jan 1 00:00:00 host dnsmasq[1]: x", 2022, "+00:00", "FORMAT"),
        ("Jan １ 00:00:00 dnsmasq[1]: x", 2022, "+00:00", "FORMAT"),
        ("Jan 1 00:00:00 dnsmasq[-1]: x", 2022, "+00:00", "FORMAT"),
        ("Jan 1 00:00:00 dnsmasq[1]:x", 2022, "+00:00", "FORMAT"),
    ],
)
def test_invalid_header(parser, text, year, offset, code):
    with pytest.raises(ValueError, match="INVALID_DNSMASQ_" + code):
        line(parser, text, year=year, utc_offset=offset)


@pytest.mark.parametrize(
    "payload,kind,client,ip",
    [
        (
            "query[AAAA] example.test from 2001:DB8::1",
            "query",
            "2001:DB8::1",
            "2001:DB8::1",
        ),
        ("query[A] x from invalid", "query", "invalid", None),
        ("query[A] x from 192.0.2.1 extra", "query", None, None),
        ("query[bad", "query", None, None),
        ("forwarded x to 192.0.2.1", "forwarded", None, None),
        ("reply x is 192.0.2.1", "reply", None, None),
        ("cached x is 192.0.2.1", "cached", None, None),
        ("other $(opaque) text  ", "other", None, None),
    ],
)
def test_payload_observations(parser, payload, kind, client, ip):
    r = line(parser, "Jan 18 08:02:04 dnsmasq[42]: " + payload)
    assert r["dns_payload"] == payload and r["dns_record_kind"] == kind
    assert r["dns_query_client"] == client and r["source_ip"] == ip
    if client is None:
        assert r["dns_query_type"] is None and r["dns_question_name"] is None


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
    assert summary["record_kind_counts"] == {"query": 2}
    assert not summary["truncated"]
    records = rows(tmp_path / "events.jsonl")
    assert [r["line_number"] for r in records] == [1, 5]
    assert (
        records[0]["raw_line_sha256"]
        == hashlib.sha256((LINE + "\r\n").encode()).hexdigest()
    )
    errors = rows(tmp_path / "errors.jsonl")
    assert [r["error_code"] for r in errors] == [
        "INVALID_UTF8",
        "INVALID_DNSMASQ_FORMAT",
    ]
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
    data = b"Jan 1 00:00:00 dnsmasq[1]: query[bad\nJan 1 00:00:01 dnsmasq[1]: reply x\nJan 1 00:00:02 dnsmasq[1]: query[bad\n"
    summary = file(
        parser,
        tmp_path,
        data,
        time_from=datetime(2022, 1, 1, 0, 0, 1, tzinfo=UTC),
        time_to=datetime(2022, 1, 1, 0, 0, 2, tzinfo=UTC),
    )
    assert summary["record_kind_counts"] == {"reply": 1}
    assert summary["unparsed_query_records"] == 0
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
        parser.parse_dnsmasq_line(
            LINE,
            dataset_id="ait-v2.1:fox",
            relative_log_path=path,
            line_number=1,
            year=2022,
            utc_offset="+00:00",
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
    assert normalized.source == "dnsmasq"
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


def test_unparsed_query_is_observation(parser, tmp_path):
    summary = file(parser, tmp_path, b"Jan 1 00:00:00 dnsmasq[1]: query[bad\n")
    assert summary["unparsed_query_records"] == summary["written_records"] == 1
    assert summary["parse_errors"] == 0


@pytest.mark.parametrize("number", [True, 0, -1, "1"])
def test_line_number_strict(parser, number):
    with pytest.raises(ValueError, match="line_number"):
        line(parser, line_number=number)


def test_invalid_dataset_id(parser):
    with pytest.raises(ValueError, match="dataset_id"):
        parser.parse_dnsmasq_line(
            LINE,
            dataset_id="invalid",
            relative_log_path=LOG,
            line_number=1,
            year=2022,
            utc_offset="+00:00",
        )


def test_standalone_carriage_return_is_not_line_ending(parser):
    with pytest.raises(ValueError, match="INVALID_DNSMASQ_FORMAT"):
        line(parser, LINE + "\r")


def test_second_open_race_preserves_preexisting_file(parser, tmp_path, monkeypatch):
    original = Path.open
    errors = tmp_path / "errors.jsonl"

    def race(path, *args, **kwargs):
        if path == errors and args and args[0] == "x":
            with original(path, "w", encoding="utf-8") as handle:
                handle.write("keep race file")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", race)
    with pytest.raises(FileExistsError):
        file(parser, tmp_path, LINE.encode())
    assert errors.read_text() == "keep race file"
    assert not (tmp_path / "events.jsonl").exists()


@pytest.mark.parametrize("target", ["source", "output", "errors"])
def test_link_components_rejected(parser, tmp_path, monkeypatch, target):
    import os
    import stat
    from types import SimpleNamespace

    paths = {
        "source": tmp_path / "raw" / "gather" / LOG,
        "output": tmp_path / "events.jsonl",
        "errors": tmp_path / "errors.jsonl",
    }
    original = os.lstat

    def metadata(path, *args, **kwargs):
        if Path(path) == paths[target]:
            return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(parser._helpers.os, "lstat", metadata)
    with pytest.raises(ValueError, match="filesystem links"):
        file(parser, tmp_path, LINE.encode())
