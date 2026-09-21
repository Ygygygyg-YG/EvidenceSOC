from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, cast


@dataclass(frozen=True, slots=True)
class ParsedLogRecord:
    raw: dict[str, Any]
    source_path: str
    line_number: int


class LogParseError(ValueError):
    def __init__(
        self,
        *,
        code: str,
        source_path: Path,
        line_number: int | None,
        message: str,
    ) -> None:
        self.code = code
        self.source_path = str(source_path)
        self.line_number = line_number

        location = self.source_path
        if line_number is not None:
            location = f"{location}:{line_number}"

        super().__init__(f"{message} [{code}] ({location})")


class EmptyLogFileError(LogParseError):
    def __init__(self, source_path: Path) -> None:
        super().__init__(
            code="EMPTY_FILE",
            source_path=source_path,
            line_number=None,
            message="日志文件为空",
        )


class _DuplicateKeyError(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(key)


class _NonFiniteNumberError(ValueError):
    def __init__(self, value: str) -> None:
        self.value = value
        super().__init__(value)


def _object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value

    return result


def _reject_non_finite_number(value: str) -> NoReturn:
    raise _NonFiniteNumberError(value)


def _decode_json(
    text: str,
    *,
    source_path: Path,
    start_line: int,
) -> object:
    try:
        value: object = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_non_finite_number,
        )
        return value
    except _DuplicateKeyError as exc:
        raise LogParseError(
            code="DUPLICATE_KEY",
            source_path=source_path,
            line_number=start_line,
            message=f"JSON 包含重复字段：{exc.key}",
        ) from exc
    except _NonFiniteNumberError as exc:
        raise LogParseError(
            code="NON_FINITE_NUMBER",
            source_path=source_path,
            line_number=start_line,
            message=f"JSON 包含非有限数值：{exc.value}",
        ) from exc
    except json.JSONDecodeError as exc:
        actual_line = start_line + exc.lineno - 1
        raise LogParseError(
            code="INVALID_JSON",
            source_path=source_path,
            line_number=actual_line,
            message=f"非法 JSON：{exc.msg}",
        ) from exc


def _require_object(
    value: object,
    *,
    source_path: Path,
    line_number: int,
    message: str = "日志记录必须是 JSON 对象",
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LogParseError(
            code="RECORD_NOT_OBJECT",
            source_path=source_path,
            line_number=line_number,
            message=message,
        )

    return cast(dict[str, Any], value)


def _parse_jsonl(
    text: str,
    path: Path,
) -> list[ParsedLogRecord]:
    records: list[ParsedLogRecord] = []

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        value = _decode_json(
            line,
            source_path=path,
            start_line=line_number,
        )
        raw = _require_object(
            value,
            source_path=path,
            line_number=line_number,
        )
        records.append(
            ParsedLogRecord(
                raw=raw,
                source_path=str(path),
                line_number=line_number,
            )
        )

    if not records:
        raise EmptyLogFileError(path)

    return records


def _parse_json_document(
    text: str,
    path: Path,
) -> list[ParsedLogRecord]:
    value = _decode_json(
        text,
        source_path=path,
        start_line=1,
    )

    if isinstance(value, dict):
        return [
            ParsedLogRecord(
                raw=cast(dict[str, Any], value),
                source_path=str(path),
                line_number=1,
            )
        ]

    if isinstance(value, list):
        if not value:
            raise EmptyLogFileError(path)

        records: list[ParsedLogRecord] = []

        for index, item in enumerate(value, start=1):
            raw = _require_object(
                item,
                source_path=path,
                line_number=1,
                message=(f"JSON 数组第 {index} 项必须是对象"),
            )
            records.append(
                ParsedLogRecord(
                    raw=raw,
                    source_path=str(path),
                    line_number=1,
                )
            )

        return records

    _require_object(
        value,
        source_path=path,
        line_number=1,
    )
    raise AssertionError("unreachable")


def parse_log_file(path: Path) -> list[ParsedLogRecord]:
    suffix = path.suffix.casefold()

    if suffix not in {".json", ".jsonl"}:
        raise LogParseError(
            code="UNSUPPORTED_FORMAT",
            source_path=path,
            line_number=None,
            message="只支持 .json 和 .jsonl 文件",
        )

    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise LogParseError(
            code="INVALID_ENCODING",
            source_path=path,
            line_number=None,
            message="日志文件不是有效的 UTF-8",
        ) from exc

    if not text.strip():
        raise EmptyLogFileError(path)

    if suffix == ".json":
        return _parse_json_document(text, path)

    return _parse_jsonl(text, path)
