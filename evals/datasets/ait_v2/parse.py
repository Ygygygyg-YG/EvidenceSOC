"""Stream AIT Apache Combined logs into observable events, without reading labels.

Paths are relative to gather/. Line hashes cover the original bytes, including
line endings. Output is compatible with evidencesoc's JSONL normalization input.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import itertools
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

_COMBINED = re.compile(
    r"^(?P<client>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+'
    r"(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+"
    r'"(?P<referer>(?:[^"\\]|\\.)*)"\s+'
    r'"(?P<user_agent>(?:[^"\\]|\\.)*)"$'
)
_REQUEST = re.compile(r"^(\S+) (.+) (HTTP/\d+(?:\.\d+)?)$")
_DATASET_ID = re.compile(r"ait-v\d+(?:\.\d+)*:[a-z][a-z0-9_-]*")


def _validate_dataset_id(dataset_id: str) -> None:
    if not _DATASET_ID.fullmatch(dataset_id):
        raise ValueError(
            "dataset_id must include version and scenario, e.g. ait-v2.1:fox"
        )


def _log_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or PureWindowsPath(normalized).drive:
        raise ValueError("log path must be relative to gather/")
    if ".." in normalized.split("/") or ":" in normalized:
        raise ValueError("log path cannot contain traversal or alternate streams")
    if len(path.parts) < 3 or path.parts[1].casefold() != "logs":
        raise ValueError("log path must have the form <host>/logs/<file>")
    if path.parts[0].casefold().startswith("attacker"):
        raise ValueError("attacker logs are ground truth and cannot be parsed as input")
    if path.name.casefold() == "attacks.log":
        raise ValueError("attacks.log cannot be parsed as input")
    return path.as_posix()


def _utc_time(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("time bounds must contain an explicit timezone")
    try:
        return value.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ValueError("time bound is outside the supported UTC range") from exc


def _reject_path_links(path: Path) -> None:
    # Non-strict resolve can preserve a link when Windows denies its resolution.
    # Check every existing component directly, including output parent directories.
    absolute = path.absolute()
    for component in (*reversed(absolute.parents), absolute):
        try:
            metadata = os.lstat(component)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or (
            getattr(metadata, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ValueError("input and output paths cannot contain filesystem links")


def _windows_canonical_source(gather: Path, relative_log_path: str) -> Path:
    source = gather
    for part in PurePosixPath(relative_log_path).parts:
        names = [entry.name for entry in source.iterdir()]
        if part in names:
            name = part
        else:
            matches = [name for name in names if name.casefold() == part.casefold()]
            if not matches:
                raise FileNotFoundError(source / part)
            if len(matches) != 1:
                raise ValueError("log path has ambiguous case variants")
            name = matches[0]
        source /= name
    return source


def parse_apache_line(
    text: str,
    *,
    dataset_id: str,
    relative_log_path: str,
    line_number: int,
    raw_line_sha256: str | None = None,
) -> dict[str, Any]:
    """Parse observable fields; missing HTTP request details remain unknown."""
    _validate_dataset_id(dataset_id)
    relative_log_path = _log_path(relative_log_path)
    if line_number < 1:
        raise ValueError("line_number must start at 1")
    match = _COMBINED.fullmatch(text.rstrip("\r\n").removeprefix("\ufeff"))
    if match is None:
        raise ValueError("INVALID_APACHE_FORMAT")
    fields = match.groupdict()
    try:
        observed = datetime.strptime(fields["time"], "%d/%b/%Y:%H:%M:%S %z")
        timestamp = observed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError) as exc:
        raise ValueError("INVALID_APACHE_TIMESTAMP") from exc
    request_match = _REQUEST.fullmatch(fields["request"])
    request = request_match.groups() if request_match else (None, None, None)
    try:
        source_ip = str(ipaddress.ip_address(fields["client"]))
    except ValueError:
        source_ip = None  # Apache %h may be a hostname; do not invent an IP.
    origin_key = json.dumps(
        [dataset_id, relative_log_path, line_number],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "source": "apache",
        "event_type": "web.request",
        "severity": "info",
        "external_id": "ait:" + hashlib.sha256(origin_key).hexdigest(),
        "dataset_id": dataset_id,
        "relative_log_path": relative_log_path,
        "line_number": line_number,
        "host": PurePosixPath(relative_log_path).parts[0],
        "timestamp": timestamp,
        "observed_at": timestamp,
        "client": fields["client"],
        "source_ip": source_ip,
        "http_method": request[0],
        "request_target": request[1],
        "http_version": request[2],
        "http_status": int(fields["status"]),
        "response_bytes": None if fields["bytes"] == "-" else int(fields["bytes"]),
        "referer": None if fields["referer"] == "-" else fields["referer"],
        "user_agent": None if fields["user_agent"] == "-" else fields["user_agent"],
        "message": text.rstrip("\r\n").removeprefix("\ufeff"),
        "raw_line": text,
        "raw_line_sha256": raw_line_sha256
        or hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def parse_apache_file(
    *,
    dataset_root: Path,
    dataset_id: str,
    relative_log_path: str,
    output: Path,
    errors: Path,
    max_lines: int | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
) -> dict[str, Any]:
    """Write events and per-line errors; never infer labels or overwrite files."""
    _validate_dataset_id(dataset_id)
    relative_log_path = _log_path(relative_log_path)
    if max_lines is not None and max_lines < 1:
        raise ValueError("max_lines must be positive")
    if (time_from is None) != (time_to is None):
        raise ValueError("time_from and time_to must be provided together")
    if time_from is not None and time_to is not None:
        time_from, time_to = _utc_time(time_from), _utc_time(time_to)
        if time_from >= time_to:
            raise ValueError("time_from must be earlier than time_to")
    _reject_path_links(Path(dataset_root))
    root = Path(dataset_root).resolve()
    approved_gather = root / "gather"
    gather = approved_gather.resolve()
    source = (gather / relative_log_path).resolve()
    if gather != approved_gather or not source.is_relative_to(gather):
        raise ValueError("resolved log path is outside the dataset gather directory")
    _reject_path_links(approved_gather / relative_log_path)
    if os.name == "nt":
        source = _windows_canonical_source(gather, relative_log_path)
    relative_log_path = _log_path(source.relative_to(gather).as_posix())
    if not source.is_file():
        raise FileNotFoundError(source)
    _reject_path_links(Path(output))
    _reject_path_links(Path(errors))
    output, errors = Path(output).resolve(), Path(errors).resolve()
    if output == errors or output.is_relative_to(root) or errors.is_relative_to(root):
        raise ValueError(
            "distinct output files must be outside the raw dataset directory"
        )
    for destination in (output, errors):
        if destination.exists():
            raise FileExistsError(
                f"Output already exists; choose a new filename: {destination}"
            )
    summary = {
        "dataset_id": dataset_id,
        "relative_log_path": relative_log_path,
        "read_lines": 0,
        "written_records": 0,
        "blank_lines": 0,
        "parse_errors": 0,
        "time_filtered": 0,
        "unknown_request_records": 0,
        "truncated": False,
        "output": str(output),
        "errors": str(errors),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    errors.parent.mkdir(parents=True, exist_ok=True)
    with (
        source.open("rb") as input_file,
        output.open("x", encoding="utf-8", newline="\n") as output_file,
        errors.open("x", encoding="utf-8", newline="\n") as error_file,
    ):
        lines = (
            input_file if max_lines is None else itertools.islice(input_file, max_lines)
        )
        for line_number, raw_bytes in enumerate(lines, start=1):
            summary["read_lines"] = line_number
            raw_hash = hashlib.sha256(raw_bytes).hexdigest()
            try:
                text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                error_code = "INVALID_UTF8"
            else:
                if not text.strip().removeprefix("\ufeff"):
                    summary["blank_lines"] += 1
                    continue
                try:
                    record = parse_apache_line(
                        text,
                        dataset_id=dataset_id,
                        relative_log_path=relative_log_path,
                        line_number=line_number,
                        raw_line_sha256=raw_hash,
                    )
                except ValueError as exc:
                    error_code = str(exc)
                else:
                    observed = datetime.fromisoformat(record["observed_at"])
                    if (
                        time_from is not None
                        and time_to is not None
                        and not time_from <= observed < time_to
                    ):
                        summary["time_filtered"] += 1
                        continue
                    output_file.write(json.dumps(record, ensure_ascii=False) + "\n")
                    summary["written_records"] += 1
                    summary["unknown_request_records"] += record["http_method"] is None
                    continue
            error_file.write(
                json.dumps(
                    {
                        "dataset_id": dataset_id,
                        "relative_log_path": relative_log_path,
                        "line_number": line_number,
                        "raw_line_sha256": raw_hash,
                        "error_code": error_code,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            summary["parse_errors"] += 1
        summary["truncated"] = input_file.tell() < os.fstat(input_file.fileno()).st_size
    return summary


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--dataset-root", type=Path, required=True)
    cli.add_argument("--dataset-id", required=True)
    cli.add_argument("--log-path", required=True, help="Path relative to gather/")
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--errors", type=Path, required=True)
    cli.add_argument("--max-lines", type=int)
    cli.add_argument("--time-from", help="Inclusive ISO-8601 time with timezone")
    cli.add_argument("--time-to", help="Exclusive ISO-8601 time with timezone")
    args = cli.parse_args(argv)
    try:
        summary = parse_apache_file(
            dataset_root=args.dataset_root,
            dataset_id=args.dataset_id,
            relative_log_path=args.log_path,
            output=args.output,
            errors=args.errors,
            max_lines=args.max_lines,
            time_from=datetime.fromisoformat(args.time_from)
            if args.time_from
            else None,
            time_to=datetime.fromisoformat(args.time_to) if args.time_to else None,
        )
    except (OSError, ValueError) as exc:
        cli.error(str(exc))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
