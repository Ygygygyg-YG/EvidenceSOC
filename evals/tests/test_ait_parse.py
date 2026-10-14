from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

PARSER_PATH = Path(__file__).resolve().parents[1] / "datasets/ait_v2/parse.py"
LOG_PATH = "web/logs/apache2/access.log"
LINE = (
    "192.0.2.10 - - [18/Jan/2022:08:02:04 +0000] "
    '"GET / HTTP/1.1" 200 12 "-" "Example/1.0"'
)


@pytest.fixture
def parser():
    if not PARSER_PATH.is_file():

        class MissingParser:
            def __getattr__(self, name):
                pytest.fail("AIT Apache parser has not been implemented")

        return MissingParser()
    spec = importlib.util.spec_from_file_location("ait_apache_parser", PARSER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def make_source(tmp_path: Path, content: bytes) -> Path:
    root = tmp_path / "raw"
    source = root / "gather" / LOG_PATH
    source.parent.mkdir(parents=True)
    source.write_bytes(content)
    return root


def parse_file(parser, tmp_path: Path, root: Path, **kwargs):
    return parser.parse_apache_file(
        dataset_root=root,
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG_PATH,
        output=tmp_path / "agent.jsonl",
        errors=tmp_path / "errors.jsonl",
        **kwargs,
    )


def test_parses_observable_fields_without_ground_truth(parser):
    record = parser.parse_apache_line(
        LINE + "\n",
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG_PATH,
        line_number=886,
    )
    assert record["source"] == "apache"
    assert record["event_type"] == "web.request"
    assert record["severity"] == "info"
    assert record["source_ip"] == "192.0.2.10"
    assert record["host"] == "web"
    assert record["http_method"] == "GET"
    assert record["request_target"] == "/"
    assert record["http_version"] == "HTTP/1.1"
    assert record["http_status"] == 200
    assert record["response_bytes"] == 12
    assert record["observed_at"] == "2022-01-18T08:02:04Z"
    assert record["timestamp"] == record["observed_at"]
    assert record["line_number"] == 886
    assert record["dataset_id"] == "ait-v2.1:fox"
    assert record["relative_log_path"] == LOG_PATH
    assert record["raw_line"] == LINE + "\n"
    assert (
        not {"labels", "rules", "dataset_labels", "is_attack", "attack_types"}
        & record.keys()
    )


def test_converts_explicit_offset_to_utc(parser):
    record = parser.parse_apache_line(
        LINE.replace("+0000", "+0200"),
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG_PATH,
        line_number=1,
    )
    assert record["observed_at"] == "2022-01-18T06:02:04Z"


def test_missing_request_and_byte_count_are_retained(parser):
    record = parser.parse_apache_line(
        LINE.replace('"GET / HTTP/1.1" 200 12', '"-" 400 -'),
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG_PATH,
        line_number=1,
    )
    assert record["http_status"] == 400
    assert record["http_method"] is None
    assert record["request_target"] is None
    assert record["http_version"] is None
    assert record["response_bytes"] is None


def test_escaped_quote_does_not_break_combined_fields(parser):
    record = parser.parse_apache_line(
        LINE.replace('"Example/1.0"', '"Example \\"quoted\\""'),
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG_PATH,
        line_number=1,
    )
    assert record["user_agent"] == 'Example \\"quoted\\"'


def test_origin_key_is_stable_and_separates_scenarios_files_and_lines(parser):
    def external_id(dataset_id="ait-v2.1:fox", path=LOG_PATH, number=1):
        return parser.parse_apache_line(
            LINE, dataset_id=dataset_id, relative_log_path=path, line_number=number
        )["external_id"]

    reference = external_id()
    assert reference == external_id()
    assert (
        len(
            {
                reference,
                external_id("ait-v2.1:shaw"),
                external_id(path="web/logs/other.log"),
                external_id(number=2),
            }
        )
        == 4
    )


def test_blank_invalid_and_bad_encoding_lines_keep_physical_numbers(parser, tmp_path):
    content = b"\nnot an apache record\n\xff\n" + (LINE + "\r\n").encode()
    root = make_source(tmp_path, content)
    summary = parse_file(parser, tmp_path, root)
    records = read_jsonl(tmp_path / "agent.jsonl")
    failures = read_jsonl(tmp_path / "errors.jsonl")
    assert [record["line_number"] for record in records] == [4]
    assert (
        records[0]["raw_line_sha256"]
        == hashlib.sha256((LINE + "\r\n").encode()).hexdigest()
    )
    assert records[0]["raw_line"].endswith("\r\n")
    assert [error["line_number"] for error in failures] == [2, 3]
    assert [error["error_code"] for error in failures] == [
        "INVALID_APACHE_FORMAT",
        "INVALID_UTF8",
    ]
    assert summary["read_lines"] == 4
    assert summary["written_records"] == 1
    assert summary["parse_errors"] == 2
    assert summary["blank_lines"] == 1
    assert summary["truncated"] is False


def test_time_filter_does_not_assume_sorted_logs(parser, tmp_path):
    lines = [
        LINE.replace("08:02:04", "08:02:06"),
        LINE,
        LINE.replace("08:02:04", "08:02:05"),
        LINE,
    ]
    root = make_source(tmp_path, ("\n".join(lines) + "\n").encode())
    summary = parse_file(
        parser,
        tmp_path,
        root,
        time_from=datetime(2022, 1, 18, 8, 2, 4, tzinfo=UTC),
        time_to=datetime(2022, 1, 18, 8, 2, 5, tzinfo=UTC),
    )
    assert [
        record["line_number"] for record in read_jsonl(tmp_path / "agent.jsonl")
    ] == [2, 4]
    assert summary["time_filtered"] == 2


def test_limit_counts_physical_lines_and_reports_truncation(parser, tmp_path):
    root = make_source(
        tmp_path, ("\nbad record\n" + LINE + "\n" + LINE + "\n").encode()
    )
    summary = parse_file(parser, tmp_path, root, max_lines=3)
    assert summary["read_lines"] == 3
    assert summary["written_records"] == 1
    assert summary["truncated"] is True
    assert read_jsonl(tmp_path / "agent.jsonl")[0]["line_number"] == 3


def test_limit_equal_to_file_length_is_not_truncated(parser, tmp_path):
    root = make_source(tmp_path, (LINE + "\n").encode())
    assert parse_file(parser, tmp_path, root, max_lines=1)["truncated"] is False


@pytest.mark.parametrize(
    "path",
    [
        "../labels/web/logs/access.log",
        "/web/logs/access.log",
        "C:/logs/access.log",
        "attacker_0/logs/access.log",
        "web/configs/access.log",
        "web/logs/attacks.log",
        "web/logs/../../labels/access.log",
    ],
)
def test_rejects_ground_truth_and_out_of_scope_paths(parser, tmp_path, path):
    root = make_source(tmp_path, (LINE + "\n").encode())
    with pytest.raises(ValueError):
        parser.parse_apache_file(
            dataset_root=root,
            dataset_id="ait-v2.1:fox",
            relative_log_path=path,
            output=tmp_path / "agent.jsonl",
            errors=tmp_path / "errors.jsonl",
        )
    assert not (tmp_path / "agent.jsonl").exists()


def test_does_not_overwrite_source_or_existing_output(parser, tmp_path):
    root = make_source(tmp_path, (LINE + "\n").encode())
    source = root / "gather" / LOG_PATH
    before = source.read_bytes()
    with pytest.raises(ValueError):
        parser.parse_apache_file(
            dataset_root=root,
            dataset_id="ait-v2.1:fox",
            relative_log_path=LOG_PATH,
            output=source,
            errors=tmp_path / "errors.jsonl",
        )
    assert source.read_bytes() == before
    (tmp_path / "agent.jsonl").write_text("keep this", encoding="utf-8")
    with pytest.raises(FileExistsError):
        parse_file(parser, tmp_path, root)
    assert (tmp_path / "agent.jsonl").read_text() == "keep this"


def test_requires_distinct_output_files(parser, tmp_path):
    root = make_source(tmp_path, (LINE + "\n").encode())
    with pytest.raises(ValueError):
        parser.parse_apache_file(
            dataset_root=root,
            dataset_id="ait-v2.1:fox",
            relative_log_path=LOG_PATH,
            output=tmp_path / "same.jsonl",
            errors=tmp_path / "same.jsonl",
        )


def test_gather_directory_link_cannot_redirect_to_labels(parser, tmp_path, monkeypatch):
    root = tmp_path / "raw"
    labels = root / "labels"
    fake_log = labels / LOG_PATH
    fake_log.parent.mkdir(parents=True)
    fake_log.write_text(LINE + "\n", encoding="utf-8")
    gather = root / "gather"
    original_resolve = Path.resolve

    def resolve_directory_link(path, *args, **kwargs):
        # Simulate the OS resolving a junction, without requiring link privileges.
        target = labels if path == gather else path
        return original_resolve(target, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve_directory_link)
    with pytest.raises(ValueError):
        parse_file(parser, tmp_path, root)
    assert not (tmp_path / "agent.jsonl").exists()


@pytest.mark.parametrize("linked_path", ["gather", "gather/web", "gather/" + LOG_PATH])
def test_rejects_links_when_resolve_cannot_follow_them(
    parser, tmp_path, monkeypatch, linked_path
):
    root = make_source(tmp_path, (LINE + "\n").encode())
    link = root / linked_path
    original_lstat = os.lstat

    def report_link(path, *args, **kwargs):
        metadata = original_lstat(path, *args, **kwargs)
        if Path(path) == link:
            return SimpleNamespace(
                st_mode=stat.S_IFLNK,
                st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
            )
        return metadata

    # Path.resolve may preserve a path when OS link resolution is denied.
    monkeypatch.setattr(Path, "resolve", lambda path, **kwargs: path.absolute())
    monkeypatch.setattr(os, "lstat", report_link)
    with pytest.raises(ValueError):
        parse_file(parser, tmp_path, root)
    assert not (tmp_path / "agent.jsonl").exists()


def test_output_parent_reparse_point_cannot_redirect_writes(
    parser, tmp_path, monkeypatch
):
    root = make_source(tmp_path, (LINE + "\n").encode())
    output_parent = tmp_path / "agent"
    output_parent.mkdir()
    original_lstat = os.lstat

    def report_junction(path, *args, **kwargs):
        metadata = original_lstat(path, *args, **kwargs)
        if Path(path) == output_parent:
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
            )
        return metadata

    monkeypatch.setattr(Path, "resolve", lambda path, **kwargs: path.absolute())
    monkeypatch.setattr(os, "lstat", report_junction)
    with pytest.raises(ValueError):
        parser.parse_apache_file(
            dataset_root=root,
            dataset_id="ait-v2.1:fox",
            relative_log_path=LOG_PATH,
            output=output_parent / "events.jsonl",
            errors=tmp_path / "errors.jsonl",
        )
    assert not (output_parent / "events.jsonl").exists()


@pytest.mark.parametrize(
    "timestamp",
    ["01/Jan/0001:00:00:00 +0100", "31/Dec/9999:23:59:59 -0100"],
)
def test_timestamp_overflow_is_reported_without_losing_later_lines(
    parser, tmp_path, timestamp
):
    invalid = LINE.replace("18/Jan/2022:08:02:04 +0000", timestamp)
    root = make_source(tmp_path, (invalid + "\n" + LINE + "\n").encode())
    summary = parse_file(parser, tmp_path, root)
    assert summary["parse_errors"] == 1
    assert summary["written_records"] == 1
    assert read_jsonl(tmp_path / "agent.jsonl")[0]["line_number"] == 2
    assert read_jsonl(tmp_path / "errors.jsonl")[0]["error_code"] == (
        "INVALID_APACHE_TIMESTAMP"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows paths are case insensitive")
def test_windows_path_alias_keeps_the_same_origin_key(parser, tmp_path):
    root = make_source(tmp_path, (LINE + "\n").encode())
    parse_file(parser, tmp_path, root)
    parser.parse_apache_file(
        dataset_root=root,
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG_PATH.upper(),
        output=tmp_path / "alias.jsonl",
        errors=tmp_path / "alias-errors.jsonl",
    )
    original = read_jsonl(tmp_path / "agent.jsonl")[0]
    alias = read_jsonl(tmp_path / "alias.jsonl")[0]
    assert alias["relative_log_path"] == original["relative_log_path"] == LOG_PATH
    assert alias["external_id"] == original["external_id"]


def test_cli_reports_time_bound_overflow_as_an_argument_error(parser, tmp_path):
    root = make_source(tmp_path, (LINE + "\n").encode())
    result = subprocess.run(
        [
            sys.executable,
            str(PARSER_PATH),
            "--dataset-root",
            str(root),
            "--dataset-id",
            "ait-v2.1:fox",
            "--log-path",
            LOG_PATH,
            "--output",
            str(tmp_path / "agent.jsonl"),
            "--errors",
            str(tmp_path / "errors.jsonl"),
            "--time-from",
            "0001-01-01T00:00:00+01:00",
            "--time-to",
            "2022-01-19T00:00:00Z",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert not (tmp_path / "agent.jsonl").exists()


@pytest.mark.parametrize("dataset_id", ["", "fox", "ait-v2.1:"])
def test_requires_version_and_scenario_identifier(parser, tmp_path, dataset_id):
    root = make_source(tmp_path, (LINE + "\n").encode())
    with pytest.raises(ValueError):
        parser.parse_apache_file(
            dataset_root=root,
            dataset_id=dataset_id,
            relative_log_path=LOG_PATH,
            output=tmp_path / "agent.jsonl",
            errors=tmp_path / "errors.jsonl",
        )


def test_time_range_must_have_timezone(parser, tmp_path):
    root = make_source(tmp_path, (LINE + "\n").encode())
    with pytest.raises(ValueError):
        parse_file(
            parser,
            tmp_path,
            root,
            time_from=datetime(2022, 1, 18),  # noqa: DTZ001 -- invalid input under test
            time_to=datetime(2022, 1, 19),  # noqa: DTZ001 -- invalid input under test
        )


def test_cli_produces_machine_readable_summary(parser, tmp_path):
    root = make_source(tmp_path, (LINE + "\n" + LINE + "\n").encode())
    result = subprocess.run(
        [
            sys.executable,
            str(PARSER_PATH),
            "--dataset-root",
            str(root),
            "--dataset-id",
            "ait-v2.1:fox",
            "--log-path",
            LOG_PATH,
            "--output",
            str(tmp_path / "agent.jsonl"),
            "--errors",
            str(tmp_path / "errors.jsonl"),
            "--max-lines",
            "1",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["written_records"] == 1
    assert json.loads(result.stdout)["truncated"] is True
