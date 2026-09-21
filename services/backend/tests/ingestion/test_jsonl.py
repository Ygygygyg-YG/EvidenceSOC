from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def parser_module() -> ModuleType:
    return import_module("evidencesoc.ingestion.jsonl")


def parse(path: Path) -> list[Any]:
    parse_log_file = getattr(
        parser_module(),
        "parse_log_file",
        None,
    )
    assert callable(parse_log_file), "parse_log_file 尚未实现"
    return parse_log_file(path)


def write_log(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def assert_parse_error(
    error: ValueError,
    *,
    path: Path,
    code: str,
    line_number: int | None,
) -> None:
    assert getattr(error, "code", None) == code
    assert getattr(error, "source_path", None) == str(path)
    assert getattr(error, "line_number", None) == line_number
    assert path.name in str(error)


def test_parse_log_file_reads_jsonl_and_preserves_lines(
    tmp_path: Path,
) -> None:
    path = write_log(
        tmp_path / "events.jsonl",
        '{"source":"nginx","event_type":"web.request"}\n'
        "   \n"
        '{"source":"waf","event_type":"alert"}\n',
    )

    records = parse(path)

    assert [record.raw for record in records] == [
        {
            "source": "nginx",
            "event_type": "web.request",
        },
        {
            "source": "waf",
            "event_type": "alert",
        },
    ]
    assert [record.source_path for record in records] == [
        str(path),
        str(path),
    ]
    assert [record.line_number for record in records] == [1, 3]


@pytest.mark.parametrize(
    ("suffix", "content"),
    [
        pytest.param(".jsonl", "", id="empty-jsonl"),
        pytest.param(".jsonl", " \n\t\n", id="whitespace-jsonl"),
        pytest.param(".json", "", id="empty-json"),
        pytest.param(".json", " \n\t\n", id="whitespace-json"),
    ],
)
def test_parse_log_file_rejects_empty_files(
    tmp_path: Path,
    suffix: str,
    content: str,
) -> None:
    path = write_log(tmp_path / f"empty{suffix}", content)

    with pytest.raises(ValueError) as exc_info:
        parse(path)

    assert_parse_error(
        exc_info.value,
        path=path,
        code="EMPTY_FILE",
        line_number=None,
    )
    assert "日志文件为空" in str(exc_info.value)


def test_parse_log_file_rejects_empty_json_array(
    tmp_path: Path,
) -> None:
    path = write_log(tmp_path / "events.json", "[]\n")

    with pytest.raises(ValueError) as exc_info:
        parse(path)

    assert_parse_error(
        exc_info.value,
        path=path,
        code="EMPTY_FILE",
        line_number=None,
    )


def test_parse_log_file_reports_invalid_json_line(
    tmp_path: Path,
) -> None:
    path = write_log(
        tmp_path / "events.jsonl",
        '{"source":"nginx"}\n{"source":}\n',
    )

    with pytest.raises(ValueError) as exc_info:
        parse(path)

    assert_parse_error(
        exc_info.value,
        path=path,
        code="INVALID_JSON",
        line_number=2,
    )


@pytest.mark.parametrize(
    "document",
    ["[]", "42", '"text"', "null", "true"],
)
def test_parse_log_file_rejects_non_object_jsonl_records(
    tmp_path: Path,
    document: str,
) -> None:
    path = write_log(
        tmp_path / "events.jsonl",
        f"{document}\n",
    )

    with pytest.raises(ValueError) as exc_info:
        parse(path)

    assert_parse_error(
        exc_info.value,
        path=path,
        code="RECORD_NOT_OBJECT",
        line_number=1,
    )


def test_parse_log_file_rejects_duplicate_keys(
    tmp_path: Path,
) -> None:
    path = write_log(
        tmp_path / "events.jsonl",
        '{"source":"nginx","source":"waf"}\n',
    )

    with pytest.raises(ValueError) as exc_info:
        parse(path)

    assert_parse_error(
        exc_info.value,
        path=path,
        code="DUPLICATE_KEY",
        line_number=1,
    )


@pytest.mark.parametrize(
    "constant",
    ["NaN", "Infinity", "-Infinity"],
)
def test_parse_log_file_rejects_non_finite_numbers(
    tmp_path: Path,
    constant: str,
) -> None:
    path = write_log(
        tmp_path / "events.jsonl",
        f'{{"score":{constant}}}\n',
    )

    with pytest.raises(ValueError) as exc_info:
        parse(path)

    assert_parse_error(
        exc_info.value,
        path=path,
        code="NON_FINITE_NUMBER",
        line_number=1,
    )


def test_parse_log_file_reads_json_root_object(
    tmp_path: Path,
) -> None:
    path = write_log(
        tmp_path / "event.json",
        '{\n  "source": "nginx",\n  "event_type": "web.request"\n}\n',
    )

    records = parse(path)

    assert [record.raw for record in records] == [
        {
            "source": "nginx",
            "event_type": "web.request",
        }
    ]
    assert records[0].line_number == 1


def test_parse_log_file_reads_json_root_array(
    tmp_path: Path,
) -> None:
    path = write_log(
        tmp_path / "events.json",
        '[\n  {"source":"nginx"},\n  {"source":"waf"}\n]\n',
    )

    records = parse(path)

    assert [record.raw for record in records] == [
        {"source": "nginx"},
        {"source": "waf"},
    ]
    assert all(record.source_path == str(path) for record in records)


def test_parse_log_file_rejects_non_object_json_root(
    tmp_path: Path,
) -> None:
    path = write_log(tmp_path / "event.json", "42\n")

    with pytest.raises(ValueError) as exc_info:
        parse(path)

    assert_parse_error(
        exc_info.value,
        path=path,
        code="RECORD_NOT_OBJECT",
        line_number=1,
    )


def test_parse_log_file_rejects_non_object_array_item(
    tmp_path: Path,
) -> None:
    path = write_log(
        tmp_path / "events.json",
        '[{"source":"nginx"}, 42]\n',
    )

    with pytest.raises(ValueError) as exc_info:
        parse(path)

    assert_parse_error(
        exc_info.value,
        path=path,
        code="RECORD_NOT_OBJECT",
        line_number=1,
    )
    assert "第 2 项" in str(exc_info.value)


def test_parse_log_file_rejects_unsupported_extension(
    tmp_path: Path,
) -> None:
    path = write_log(
        tmp_path / "events.txt",
        '{"source":"nginx"}\n',
    )

    with pytest.raises(ValueError) as exc_info:
        parse(path)

    assert_parse_error(
        exc_info.value,
        path=path,
        code="UNSUPPORTED_FORMAT",
        line_number=None,
    )


def test_parse_log_file_accepts_utf8_bom(
    tmp_path: Path,
) -> None:
    path = write_log(
        tmp_path / "events.jsonl",
        '\ufeff{"source":"nginx"}\n',
    )

    records = parse(path)

    assert records[0].raw == {"source": "nginx"}


def test_parse_log_file_rejects_invalid_utf8(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"\xff\xfe\x00")

    with pytest.raises(ValueError) as exc_info:
        parse(path)

    assert_parse_error(
        exc_info.value,
        path=path,
        code="INVALID_ENCODING",
        line_number=None,
    )
