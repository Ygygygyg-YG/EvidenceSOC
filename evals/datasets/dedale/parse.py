"""Stream fixed-version DEDALE system logs into allowlisted observations.

No labels are loaded here. Canonical source-event hashes are retained for a
separate scoring join; raw-line hashes include original line endings. ZIP/BZ2
streams are read without extracting archives or buffering complete members.
"""

import bz2
import hashlib
import ipaddress
import json
import math
import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from zipfile import ZipFile, ZipInfo

# Malformed external JSON consistently raises ValueError at this boundary.
# ruff: noqa: TRY004

DATASET_ID = "dedale-v2.1"
ARCHIVE_SOURCES = {
    "system_logs_auditbeat.zip": "auditbeat",
    "system_logs_winlogbeat.zip": "winlogbeat",
}
MAX_MESSAGE_CHARS = 8192
MAX_STRING_CHARS = 4096
MAX_ARGS = 64
MAX_ARG_CHARS = 1024
MAX_TRUNCATED_FIELDS = 64
_BOUNDED_FIELDS = (
    "process", "parent", "command_line", "user", "username", "network", "original_severity",
)
_TIMESTAMP = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})T(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d+)?(?P<zone>Z|[+-]\d{2}:\d{2})"
)
_SURROGATE_ESCAPE = re.compile(rb"\\u[dD][89aAbBcCdDeEfF]")
_PROCESS_FIELDS = frozenset(
    {
        "pid",
        "ppid",
        "name",
        "executable",
        "command_line",
        "title",
        "working_directory",
        "entity_id",
        "args_count",
    }
)
_USER_FIELDS = frozenset({"id", "name", "domain"})
_NETWORK_FIELDS = frozenset(
    {
        "transport",
        "protocol",
        "direction",
        "type",
        "bytes",
        "packets",
        "community_id",
        "application",
    }
)
_WINLOG_FIELDS = frozenset(
    {
        "event_id",
        "record_id",
        "channel",
        "provider_name",
        "computer_name",
        "task",
        "opcode",
        "api",
    }
)
_SEVERITIES = {
    "trace": "info",
    "verbose": "info",
    "debug": "info",
    "info": "info",
    "information": "info",
    "informational": "info",
    "notice": "low",
    "low": "low",
    "warn": "medium",
    "warning": "medium",
    "medium": "medium",
    "error": "high",
    "err": "high",
    "high": "high",
    "critical": "critical",
    "fatal": "critical",
    "alert": "critical",
    "emergency": "critical",
}


def _source(archive: str) -> str:
    if not isinstance(archive, str) or archive not in ARCHIVE_SOURCES:
        raise ValueError("archive must be an approved DEDALE system log ZIP")
    return ARCHIVE_SOURCES[archive]


def _member_path(archive: str, value: str) -> str:
    source = _source(archive)
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("member path must be a canonical relative POSIX path")
    if len(value) > MAX_STRING_CHARS:
        raise ValueError("INVALID_MEMBER_PATH_LENGTH")
    parts = value.split("/")
    if (
        PurePosixPath(value).is_absolute()
        or PureWindowsPath(value).drive
        or any(part in {"", ".", ".."} for part in parts)
        or ":" in value
        or len(parts) != 2
        or parts[0] != f"daily_{source}"
        or not parts[1].endswith(".jsonl.bz2")
        or parts[1] == ".jsonl.bz2"
    ):
        raise ValueError("member must be daily_<archive source>/<file>.jsonl.bz2")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("INVALID_JSON_DUPLICATE_KEY")
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("INVALID_JSON_NONFINITE")


def event_fingerprint(event: dict[str, Any]) -> str:
    """Hash the canonical original event, never its normalized projection.

    An Elasticsearch wrapper's ``_source`` must be passed by the caller; this
    function hashes exactly the supplied dictionary with no field removal.
    """
    if not isinstance(event, dict):
        raise ValueError("event fingerprint requires a source event object")
    try:
        serialized = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
        raise ValueError("INVALID_JSON_CANONICAL_EVENT") from exc
    return hashlib.sha256(serialized).hexdigest()


def _utc_timestamp(value: Any) -> str:
    if isinstance(value, str) and len(value) > MAX_STRING_CHARS:
        raise ValueError("INVALID_TIMESTAMP_LENGTH")
    match = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("INVALID_TIMESTAMP_EXPLICIT_TIMEZONE_REQUIRED")
    try:
        zone = match["zone"]
        if zone != "Z" and (int(zone[1:3]) > 23 or int(zone[4:6]) > 59):
            raise ValueError("invalid UTC offset")
        # datetime truncates sub-microsecond digits. Convert whole seconds and
        # carry the original fraction verbatim so nanoseconds are not lost.
        whole = datetime.fromisoformat(f"{match['date']}T{match['time']}{zone}")
        utc = whole.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ValueError("INVALID_TIMESTAMP") from exc
    return utc.isoformat().removesuffix("+00:00") + (match["fraction"] or "") + "Z"


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) and value is not None


def _project(value: Any, fields: frozenset[str]) -> dict[str, Any]:
    return {
        key: item
        for key, item in _mapping(value).items()
        if key in fields and _scalar(item)
    }


def _process(value: Any) -> dict[str, Any]:
    original = _mapping(value)
    result = _project(original, _PROCESS_FIELDS)
    args = original.get("args")
    if isinstance(args, list) and all(isinstance(arg, str) for arg in args):
        result["args"] = list(args)
    return result


def _source_event_id(wrapper: dict, event: dict) -> str | None:
    candidates = (
        wrapper.get("_id"),
        _mapping(event.get("event")).get("id"),
        _mapping(event.get("winlog")).get("record_id"),
        _mapping(event.get("auditd")).get("sequence"),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate
        if isinstance(candidate, int) and not isinstance(candidate, bool):
            return str(candidate)
    return None


def _event_type(event: dict, source: str) -> str:
    details = _mapping(event.get("event"))
    action = _text(details.get("action"))
    if action:
        return action
    category, event_type = details.get("category"), details.get("type")
    category = category[0] if isinstance(category, list) and category else category
    event_type = (
        event_type[0] if isinstance(event_type, list) and event_type else event_type
    )
    if _text(category) and _text(event_type):
        return f"{category}.{event_type}"
    event_id = _mapping(event.get("winlog")).get("event_id")
    if source == "winlogbeat" and isinstance(event_id, (str, int)):
        return f"winlog.{event_id}"
    return _text(category) or _text(event_type) or f"{source}.event"


def _bounded(value: Any, path: str, truncated: set[str]) -> Any:
    """Bound only projected observables; metadata records fixed field names."""
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            truncated.add(path)
            return value[:MAX_STRING_CHARS]
        return value
    if isinstance(value, dict):
        return {key: _bounded(item, f"{path}.{key}", truncated) for key, item in value.items()}
    if isinstance(value, list) and path in {"process.args", "parent.args"}:
        if len(value) > MAX_ARGS or any(len(arg) > MAX_ARG_CHARS for arg in value[:MAX_ARGS]):
            truncated.add(path)
        return [arg[:MAX_ARG_CHARS] for arg in value[:MAX_ARGS]]
    return value


def _message(process: dict, parent: dict, original: Any, truncated: set[str]) -> str:
    pairs = [
        (f"{prefix}.{key}", fields[key])
        for prefix, fields in (("process", process), ("parent", parent))
        for key in sorted(fields)
    ]

    def render(value):
        return json.dumps(value, ensure_ascii=False) if isinstance(value, list) else str(value)

    process_parts = [f"{field}={render(value)}" for field, value in pairs]
    process_message = "\n".join(process_parts)
    if len(process_message) > MAX_MESSAGE_CHARS:
        # Large argv/paths must not consume the summary before either command
        # appears. Both original commands remain separately available as bounded
        # structured fields; this is a concise, explicit message projection.
        priority = {name: index for index, name in enumerate(("command_line", "title", "name", "executable", "pid", "ppid", "entity_id"))}
        pairs.sort(key=lambda row: (priority.get(row[0].split(".")[1], 99), row[0]))
        process_message = "\n".join(f"{field}={render(value)[:MAX_ARG_CHARS]}" for field, value in pairs)
        truncated.add("message")
    parts = [process_message] if process_message else []
    if _text(original):
        if len(original) > MAX_MESSAGE_CHARS:
            truncated.add("message")
        parts.append(original[:MAX_MESSAGE_CHARS])
    message = "\n".join(parts)
    if len(message) > MAX_MESSAGE_CHARS:
        truncated.add("message")
    return message[:MAX_MESSAGE_CHARS]


@dataclass(slots=True)
class DecodedEvent:
    """Validated source object whose hashes and observable projection are lazy."""

    raw_line: bytes
    archive: str
    relative_log_path: str
    line_number: int
    source: str
    wrapper: dict[str, Any]
    event: dict[str, Any]
    original_timestamp: str
    timestamp: str
    host: str
    source_event_id: str | None
    event_type: str
    _fingerprint: str | None = dataclass_field(default=None, repr=False)
    _external_id: str | None = dataclass_field(default=None, repr=False)

    @property
    def fingerprint(self) -> str:
        if self._fingerprint is None:
            self._fingerprint = event_fingerprint(self.event)
        return self._fingerprint

    @property
    def external_id(self) -> str:
        if self._external_id is None:
            origin = json.dumps(
                [DATASET_ID, self.archive, self.relative_log_path, self.line_number],
                ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
            self._external_id = "dedale:" + hashlib.sha256(origin).hexdigest()
        return self._external_id

    def project(self) -> dict[str, Any]:
        return _project_decoded(self)


def decode_event(
    raw_line: bytes,
    *,
    archive: str,
    relative_log_path: str,
    line_number: int,
) -> DecodedEvent:
    """Decode once and validate every row before any projection can be skipped.

    Missing hosts, invalid timestamps, duplicate JSON keys and non-finite JSON
    numbers fail closed. No host, network address or timezone is guessed.
    """
    source = _source(archive)
    relative_log_path = _member_path(archive, relative_log_path)
    if (
        not isinstance(line_number, int)
        or isinstance(line_number, bool)
        or line_number < 1
    ):
        raise ValueError("line_number must be a positive integer starting at 1")
    if not isinstance(raw_line, bytes):
        raise ValueError("raw_line must be original UTF-8 bytes")
    nonfinite = False

    def checked_float(value: str) -> float:
        nonlocal nonfinite
        result = float(value)
        nonfinite |= not math.isfinite(result)
        return result

    try:
        wrapper = json.loads(
            raw_line.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=checked_float,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("INVALID_JSON_EVENT: " + str(exc)) from exc
    if not isinstance(wrapper, dict):
        raise ValueError("INVALID_JSON_EVENT_OBJECT_REQUIRED")
    event = wrapper.get("_source", wrapper)
    if not isinstance(event, dict):
        raise ValueError("INVALID_JSON_SOURCE_OBJECT_REQUIRED")
    if nonfinite:
        raise ValueError("INVALID_JSON_CANONICAL_EVENT")
    fingerprint = None
    # Strict UTF-8 cannot contain surrogate code points. Only a JSON UTF-16
    # escape can introduce one; retain the original canonical/encode validator
    # for these uncommon rows, including unknown fields outside an ES _source.
    # Deep trees also retain canonical validation rather than changing its
    # recursion boundary. JSON primitives otherwise serialize without failure.
    if (_SURROGATE_ESCAPE.search(raw_line)
            or raw_line.count(b"{") + raw_line.count(b"[") >= 256):
        fingerprint = event_fingerprint(event)
        if event is not wrapper:
            event_fingerprint(wrapper)
    original_timestamp = event.get("@timestamp")
    timestamp = _utc_timestamp(original_timestamp)
    host, agent = _mapping(event.get("host")), _mapping(event.get("agent"))
    hostname = next(
        (
            name
            for value in (
                host.get("name"),
                host.get("hostname"),
                agent.get("hostname"),
                agent.get("name"),
            )
            if (name := _text(value)) is not None
        ),
        None,
    )
    if hostname is None:
        raise ValueError("MISSING_HOST")
    if len(hostname) > MAX_STRING_CHARS:
        raise ValueError("INVALID_HOST_LENGTH")
    source_event_id = _source_event_id(wrapper, event)
    if source_event_id is not None and len(source_event_id) > MAX_STRING_CHARS:
        raise ValueError("INVALID_SOURCE_EVENT_ID_LENGTH")
    event_type = _event_type(event, source)
    if len(event_type) > 128:
        raise ValueError("INVALID_EVENT_TYPE_LENGTH")
    winlog = _project(event.get("winlog"), _WINLOG_FIELDS)
    if any(isinstance(value, str) and len(value) > MAX_STRING_CHARS for value in winlog.values()):
        raise ValueError("INVALID_WINLOG_IDENTITY_LENGTH")
    return DecodedEvent(raw_line, archive, relative_log_path, line_number, source,
                        wrapper, event, original_timestamp, timestamp, hostname,
                        source_event_id, event_type, fingerprint)


def parse_event(raw_line: bytes, *, archive: str, relative_log_path: str,
                line_number: int) -> dict[str, Any]:
    """Return exactly the full allowlisted projection of a validated row."""
    return decode_event(raw_line, archive=archive, relative_log_path=relative_log_path,
                        line_number=line_number).project()


def _project_decoded(decoded: DecodedEvent) -> dict[str, Any]:
    event = decoded.event
    record: dict[str, Any] = {
        "dataset_id": DATASET_ID,
        "source": decoded.source,
        "event_type": decoded.event_type,
        "external_id": decoded.external_id,
        "archive": decoded.archive,
        "relative_log_path": decoded.relative_log_path,
        "line_number": decoded.line_number,
        "host": decoded.host,
        "timestamp": decoded.timestamp,
        "observed_at": decoded.timestamp,
        "@timestamp": decoded.timestamp,
        "original_timestamp": decoded.original_timestamp,
        "raw_line_sha256": hashlib.sha256(decoded.raw_line).hexdigest(),
        "event_fingerprint": decoded.fingerprint,
        "source_event_id": decoded.source_event_id,
    }
    severity = _text(event.get("severity")) or _text(
        _mapping(event.get("log")).get("level")
    )
    record["severity"] = (
        _SEVERITIES.get(severity.strip().casefold(), "info") if severity else "info"
    )
    if severity:
        record["original_severity"] = severity
    process = _process(event.get("process"))
    parent = _process(_mapping(event.get("process")).get("parent"))
    if not parent and "ppid" in process:
        parent = {"pid": process["ppid"]}
    if process:
        record["process"] = process
    if parent:
        record["parent"] = parent
    command_line = _text(process.get("command_line")) or _text(process.get("title"))
    if command_line:
        record["command_line"] = command_line
    user = _project(event.get("user"), _USER_FIELDS)
    if user:
        record["user"] = user
        if _text(user.get("name")):
            record["username"] = user["name"]
    elif _text(event.get("user")):
        record["user"] = event["user"]
    network = _project(event.get("network"), _NETWORK_FIELDS)
    if network:
        record["network"] = network
    winlog = _project(event.get("winlog"), _WINLOG_FIELDS)
    if any(isinstance(value, str) and len(value) > MAX_STRING_CHARS for value in winlog.values()):
        raise ValueError("INVALID_WINLOG_IDENTITY_LENGTH")
    if winlog:
        record["winlog"] = winlog
    for endpoint in ("source", "destination"):
        fields = _mapping(event.get(endpoint))
        address = fields.get("ip")
        if isinstance(address, str):
            try:
                record[f"{endpoint}_ip"] = str(ipaddress.ip_address(address))
            except ValueError:
                pass
        port = fields.get("port")
        if isinstance(port, int) and not isinstance(port, bool) and 0 <= port <= 65535:
            record[f"{endpoint}_port"] = port
    truncated: set[str] = set()
    for field in _BOUNDED_FIELDS:
        if field in record:
            record[field] = _bounded(record[field], field, truncated)
    record["message"] = _message(
        record.get("process", {}), record.get("parent", {}), event.get("message"), truncated,
    )
    if truncated:
        record["projection_truncated"] = True
        record["projection_truncated_fields"] = sorted(truncated)[:MAX_TRUNCATED_FIELDS]
    return record


def iter_archive_lines(
    archive_path: Path,
    *,
    member_names: set[str] | None = None,
) -> Iterator[tuple[str, int, bytes]]:
    """Yield ``(member, local line number, original bytes)`` for line auditing.

    Every ZIP member is validated, including unselected members. Callers may
    catch ``parse_event`` errors per line to record failures and keep scanning.
    An empty selection reads no data; a missing requested member is an error.
    """
    archive_path = Path(archive_path)
    archive = archive_path.name
    _source(archive)
    if member_names is not None:
        for member in member_names:
            _member_path(archive, member)
    with ZipFile(archive_path) as zipped:
        files, manifest_info = _archive_members(zipped, archive)
        manifest = _read_manifest(zipped, archive, files, manifest_info)
        selected = set(files) if member_names is None else set(member_names)
        if selected - files.keys():
            raise ValueError("requested member is absent from archive")
        for member in sorted(selected):
            digest = hashlib.md5(usedforsecurity=False)
            with (
                zipped.open(files[member]) as compressed,
                bz2.BZ2File(compressed, "rb") as decompressed,
            ):
                for line_number, raw_line in enumerate(decompressed, start=1):
                    digest.update(raw_line)
                    yield member, line_number, raw_line
            if (
                manifest is not None
                and digest.hexdigest() != manifest["checksums"][member]
            ):
                raise ValueError(f"manifest MD5 mismatch for {member}")


def _archive_members(
    zipped: ZipFile, archive: str
) -> tuple[dict[str, ZipInfo], ZipInfo | None]:
    source = _source(archive)
    files: dict[str, ZipInfo] = {}
    manifest = None
    seen = set()
    for info in zipped.infolist():
        member = info.filename
        if member in seen:
            raise ValueError("Duplicate ZIP member name")
        seen.add(member)
        if stat.S_ISLNK(info.external_attr >> 16):
            raise ValueError("ZIP member cannot be a symbolic link")
        if info.is_dir():
            if member != f"daily_{source}/":
                raise ValueError("unapproved ZIP directory member")
        elif member == f"daily_{source}/{source}_md5sum.sig":
            manifest = info
        else:
            _member_path(archive, member)
            files[member] = info
    return files, manifest


def _read_manifest(
    zipped: ZipFile,
    archive: str,
    files: dict[str, ZipInfo],
    manifest: ZipInfo | None,
) -> dict[str, Any] | None:
    if manifest is None:
        return None
    # The official manifests are < 204 KiB. Bound this metadata read while log
    # members remain streamed; never interpret manifest paths as filesystem paths.
    if manifest.file_size > 2 * 1024 * 1024:
        raise ValueError("manifest exceeds supported metadata size")
    try:
        lines = zipped.read(manifest).decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ValueError("manifest must be UTF-8 md5sum text") from exc
    checksums: dict[str, str] = {}
    duplicates = 0
    source = _source(archive)
    for line in lines:
        match = re.fullmatch(r"([0-9a-fA-F]{32}) [ *]\./([^/\\]+\.jsonl)", line)
        if match is None:
            raise ValueError("manifest has invalid md5sum format or path")
        digest, name = match.groups()
        member = f"daily_{source}/{name}.bz2"
        try:
            _member_path(archive, member)
        except ValueError as exc:
            raise ValueError("manifest has invalid member path") from exc
        if member not in files:
            raise ValueError("manifest references an unknown member")
        digest = digest.lower()
        if member in checksums:
            if checksums[member] != digest:
                raise ValueError("manifest contains conflicting hashes for one member")
            duplicates += 1
        else:
            checksums[member] = digest
    if checksums.keys() != files.keys():
        raise ValueError("manifest does not cover every log member")
    return {
        "member": manifest.filename,
        "unique_members": len(checksums),
        "duplicate_entries": duplicates,
        "checksums": checksums,
    }


def read_archive_manifest(archive_path: Path) -> dict[str, Any] | None:
    """Validate optional official JSONL MD5 metadata and count duplicate rows.

    Equal repeated hashes are allowed and counted. Conflicting hashes fail.
    Actual selected-member hashes are verified as ``iter_archive_lines`` is
    exhausted; this metadata-only function does not read the log members.
    """
    archive_path = Path(archive_path)
    archive = archive_path.name
    _source(archive)
    with ZipFile(archive_path) as zipped:
        files, manifest = _archive_members(zipped, archive)
        return _read_manifest(zipped, archive, files, manifest)


def iter_archive_events(
    archive_path: Path,
    *,
    member_names: set[str] | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield observations in sorted member order, failing on any invalid row."""
    archive_path = Path(archive_path)
    for member, line_number, raw_line in iter_archive_lines(
        archive_path, member_names=member_names
    ):
        yield parse_event(
            raw_line,
            archive=archive_path.name,
            relative_log_path=member,
            line_number=line_number,
        )
