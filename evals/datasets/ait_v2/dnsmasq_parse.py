"""Stream observable hostless dnsmasq records with explicit year and UTC offset."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import itertools
import json
import os
import re
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

_spec = importlib.util.spec_from_file_location(
    "_ait_dnsmasq_source_helpers", Path(__file__).with_name("parse.py")
)
assert _spec is not None and _spec.loader is not None
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)
_validate_dataset_id = _helpers._validate_dataset_id
_log_path = _helpers._log_path
_utc_time = _helpers._utc_time
_reject_path_links = _helpers._reject_path_links
_windows_canonical_source = _helpers._windows_canonical_source

_MONTHS = {
    name: number
    for number, name in enumerate(
        (
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ),
        1,
    )
}
_DNSMASQ = re.compile(
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +(?P<day>[0-9]{1,2}) "
    r"(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}) dnsmasq\[(?P<pid>[0-9]+)\]: (?P<payload>[^\r\n]*)"
)
_OFFSET = re.compile(r"([+-])([0-9]{2}):([0-9]{2})")
_QUERY = re.compile(r"query\[(?P<type>[^\]\s]+)\] (?P<name>\S+) from (?P<client>\S+) *")


def _timezone(year: int, utc_offset: str) -> timezone:
    if type(year) is not int or not 1 <= year <= 9999:
        raise ValueError("year must be an integer in 1..9999")
    match = _OFFSET.fullmatch(utc_offset) if type(utc_offset) is str else None
    if match is None or int(match[2]) > 23 or int(match[3]) > 59:
        raise ValueError("utc_offset must be +HH:MM or -HH:MM")
    minutes = int(match[2]) * 60 + int(match[3])
    return timezone(timedelta(minutes=minutes if match[1] == "+" else -minutes))


def parse_dnsmasq_line(
    text: str,
    *,
    dataset_id: str,
    relative_log_path: str,
    line_number: int,
    year: int,
    utc_offset: str,
    raw_line_sha256: str | None = None,
) -> dict[str, Any]:
    """Preserve physical origin and opaque payload without inferring outcomes."""
    zone = _timezone(year, utc_offset)
    _validate_dataset_id(dataset_id)
    relative_log_path = _log_path(relative_log_path)
    if type(line_number) is not int or line_number < 1:
        raise ValueError("line_number must start at 1")
    message = text
    if message.endswith("\n"):
        message = message[:-1].removesuffix("\r")
    message = message.removeprefix("\ufeff")
    match = _DNSMASQ.fullmatch(message)
    if match is None:
        raise ValueError("INVALID_DNSMASQ_FORMAT")
    try:
        hour, minute, second = map(int, match["time"].split(":"))
        observed = datetime(
            year,
            _MONTHS[match["month"]],
            int(match["day"]),
            hour,
            minute,
            second,
            tzinfo=zone,
        ).astimezone(UTC)
        pid = int(match["pid"])
    except (ValueError, OverflowError) as exc:
        raise ValueError("INVALID_DNSMASQ_TIMESTAMP") from exc
    timestamp = observed.isoformat().replace("+00:00", "Z")
    payload = match["payload"]
    kind = "other"
    for prefix, candidate in (
        ("query[", "query"),
        ("forwarded ", "forwarded"),
        ("reply ", "reply"),
        ("cached ", "cached"),
    ):
        if payload.startswith(prefix):
            kind = candidate
            break
    query = _QUERY.fullmatch(payload) if kind == "query" else None
    client = query["client"] if query else None
    source_ip = None
    if client is not None:
        try:
            ipaddress.ip_address(client)
        except ValueError:
            pass
        else:
            source_ip = client
    origin = json.dumps(
        [dataset_id, relative_log_path, line_number],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "source": "dnsmasq",
        "event_type": "dns.log",
        "severity": "info",
        "external_id": "ait:" + hashlib.sha256(origin).hexdigest(),
        "dataset_id": dataset_id,
        "relative_log_path": relative_log_path,
        "line_number": line_number,
        "host": PurePosixPath(relative_log_path).parts[0],
        "timestamp": timestamp,
        "observed_at": timestamp,
        "message": message,
        "raw_line": text,
        "raw_line_sha256": raw_line_sha256
        or hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "dnsmasq_pid": pid,
        "dns_payload": payload,
        "syslog_month": match["month"],
        "syslog_day": int(match["day"]),
        "syslog_time": match["time"],
        "timestamp_year": year,
        "timestamp_utc_offset": utc_offset,
        "timestamp_basis": "explicit_year_and_utc_offset",
        "dns_record_kind": kind,
        "dns_query_type": query["type"] if query else None,
        "dns_question_name": query["name"] if query else None,
        "dns_query_client": client,
        "source_ip": source_ip,
    }


def parse_dnsmasq_file(
    *,
    dataset_root: Path,
    dataset_id: str,
    relative_log_path: str,
    output: Path,
    errors: Path,
    year: int,
    utc_offset: str,
    max_lines: int | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
) -> dict[str, Any]:
    """Write events and per-line errors; never infer labels or overwrite files."""
    _timezone(year, utc_offset)
    _validate_dataset_id(dataset_id)
    relative_log_path = _log_path(relative_log_path)
    if max_lines is not None and (type(max_lines) is not int or max_lines < 1):
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
        "record_kind_counts": {},
        "unparsed_query_records": 0,
        "year": year,
        "utc_offset": utc_offset,
        "truncated": False,
        "output": str(output),
        "errors": str(errors),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    errors.parent.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        with ExitStack() as stack:
            input_file = stack.enter_context(source.open("rb"))
            output_file = stack.enter_context(
                output.open("x", encoding="utf-8", newline="\n")
            )
            created.append(output)
            error_file = stack.enter_context(
                errors.open("x", encoding="utf-8", newline="\n")
            )
            created.append(errors)
            lines = (
                input_file
                if max_lines is None
                else itertools.islice(input_file, max_lines)
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
                        record = parse_dnsmasq_line(
                            text,
                            dataset_id=dataset_id,
                            relative_log_path=relative_log_path,
                            line_number=line_number,
                            raw_line_sha256=raw_hash,
                            year=year,
                            utc_offset=utc_offset,
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
                        counts = summary["record_kind_counts"]
                        kind = record["dns_record_kind"]
                        counts[kind] = counts.get(kind, 0) + 1
                        if kind == "query" and record["dns_query_type"] is None:
                            summary["unparsed_query_records"] += 1
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
            summary["truncated"] = (
                input_file.tell() < os.fstat(input_file.fileno()).st_size
            )
    except BaseException:
        for destination in reversed(created):
            destination.unlink(missing_ok=True)
        raise
    return summary


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--dataset-root", type=Path, required=True)
    cli.add_argument("--dataset-id", required=True)
    cli.add_argument("--log-path", required=True, help="Path relative to gather/")
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--errors", type=Path, required=True)
    cli.add_argument("--year", type=int, required=True)
    cli.add_argument("--utc-offset", required=True)
    cli.add_argument("--max-lines", type=int)
    cli.add_argument("--time-from", help="Inclusive ISO-8601 time with timezone")
    cli.add_argument("--time-to", help="Exclusive ISO-8601 time with timezone")
    args = cli.parse_args(argv)
    try:
        summary = parse_dnsmasq_file(
            dataset_root=args.dataset_root,
            dataset_id=args.dataset_id,
            relative_log_path=args.log_path,
            output=args.output,
            errors=args.errors,
            year=args.year,
            utc_offset=args.utc_offset,
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
