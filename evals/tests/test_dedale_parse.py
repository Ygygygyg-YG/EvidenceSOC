from __future__ import annotations

import bz2
import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

PARSER_PATH = Path(__file__).resolve().parents[1] / "datasets/dedale/parse.py"
ARCHIVE = "system_logs_auditbeat.zip"
MEMBER = "daily_auditbeat/2020-01-01.jsonl.bz2"


@pytest.fixture
def parser():
    if not PARSER_PATH.is_file():

        class MissingParser:
            def __getattr__(self, name):
                pytest.fail("DEDALE observable event parser has not been implemented")

        return MissingParser()
    spec = importlib.util.spec_from_file_location("dedale_parser", PARSER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def benign_event(**updates):
    event = {
        "@timestamp": "2020-01-01T01:02:03.123456789+02:00",
        "agent": {"type": "auditbeat", "hostname": "agent-fallback"},
        "host": {"name": "workstation-example", "ip": ["192.0.2.77"]},
        "event": {"id": "example-event-42", "action": "process_started"},
        "message": "A scheduled inventory command started.",
        "process": {
            "pid": 123,
            "name": "inventory",
            "executable": "/opt/example/inventory",
            "command_line": "/opt/example/inventory --list",
            "args": ["/opt/example/inventory", "--list"],
            "parent": {
                "pid": 1,
                "name": "scheduler",
                "command_line": "scheduler --daily",
            },
        },
        "user": {"name": "example-user", "id": "1000", "domain": "EXAMPLE"},
        "source": {"ip": "192.0.2.10", "port": 4242},
        "destination": {"ip": "198.51.100.5", "port": 443},
        "network": {"transport": "tcp", "protocol": "https", "direction": "outbound"},
    }
    event.update(updates)
    return event


def raw_line(event=None, *, newline=b"\n"):
    return (
        json.dumps(
            benign_event() if event is None else event, ensure_ascii=False
        ).encode("utf-8")
        + newline
    )


def parse(parser, event=None, **kwargs):
    return parser.parse_event(
        raw_line(event),
        archive=kwargs.pop("archive", ARCHIVE),
        relative_log_path=kwargs.pop("relative_log_path", MEMBER),
        line_number=kwargs.pop("line_number", 7),
        **kwargs,
    )


def make_archive(tmp_path, members, *, name=ARCHIVE):
    archive = tmp_path / name
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as output:
        for member, lines in members.items():
            output.writestr(member, bz2.compress(lines))
    return archive


def test_normalizes_raw_ecs_fields_and_retains_exact_provenance(parser):
    raw = raw_line(newline=b"\r\n")
    record = parser.parse_event(
        raw, archive=ARCHIVE, relative_log_path=MEMBER, line_number=7
    )
    assert record["dataset_id"] == "dedale-v2.1"
    assert record["source"] == "auditbeat"
    assert record["event_type"] == "process_started"
    assert record["host"] == "workstation-example"
    assert record["archive"] == ARCHIVE
    assert record["relative_log_path"] == MEMBER
    assert record["line_number"] == 7
    assert record["raw_line_sha256"] == hashlib.sha256(raw).hexdigest()
    assert record["source_event_id"] == "example-event-42"
    assert record["observed_at"] == "2019-12-31T23:02:03.123456789Z"
    assert record["@timestamp"] == record["observed_at"] == record["timestamp"]
    assert record["original_timestamp"] == "2020-01-01T01:02:03.123456789+02:00"
    assert record["process"]["name"] == "inventory"
    assert record["parent"]["name"] == "scheduler"
    assert record["command_line"] == "/opt/example/inventory --list"
    assert record["user"]["name"] == "example-user"
    assert record["source_ip"] == "192.0.2.10"
    assert record["destination_ip"] == "198.51.100.5"
    assert record["source_port"] == 4242
    assert record["destination_port"] == 443
    assert record["network"]["transport"] == "tcp"


def test_message_keeps_process_evidence_visible_to_agent_projection(parser):
    record = parse(parser)
    assert "A scheduled inventory command started." in record["message"]
    assert "inventory" in record["message"]
    assert "/opt/example/inventory --list" in record["message"]
    assert "scheduler --daily" in record["message"]


def test_projects_only_observables_including_nested_objects(parser):
    event = benign_event(
        labels={"example_class": "hidden"}, answer="hidden", attack_steps=["hidden"]
    )
    event["process"]["labels"] = {"hidden": True}
    event["process"]["parent"]["answer"] = "hidden"
    event["user"]["label"] = "hidden"
    event["network"]["scoring"] = "hidden"
    record = parse(parser, event)
    assert (
        not {
            "raw",
            "raw_line",
            "labels",
            "answer",
            "attack_steps",
            "agent",
            "ecs",
            "event",
        }
        & record.keys()
    )
    assert "hidden" not in json.dumps(record)
    assert "labels" not in record["process"]
    assert "answer" not in record["parent"]


def test_fingerprint_matches_canonical_raw_json_and_not_normalized_record(parser):
    event = benign_event()
    expected = hashlib.sha256(
        json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    assert parser.event_fingerprint(event) == expected
    assert parser.event_fingerprint(dict(reversed(list(event.items())))) == expected
    assert parse(parser, event)["event_fingerprint"] == expected


def test_external_identity_depends_on_fixed_version_origin_not_absolute_path_or_bytes(
    parser,
):
    first = parse(parser)
    changed = parse(parser, benign_event(message="Updated inventory result."))
    assert first["external_id"] == changed["external_id"]
    assert first["external_id"].startswith("dedale:")
    assert first["external_id"] != parse(parser, line_number=8)["external_id"]
    assert (
        first["external_id"]
        != parse(parser, relative_log_path="daily_auditbeat/2020-01-02.jsonl.bz2")[
            "external_id"
        ]
    )


def test_accepts_optional_elasticsearch_wrapper_and_prefers_document_id(parser):
    event = benign_event()
    wrapped = {"_id": "example-document", "_source": event, "_index": "example-index"}
    record = parse(parser, wrapped)
    assert record["source_event_id"] == "example-document"
    assert record["event_fingerprint"] == parser.event_fingerprint(event)
    assert record["host"] == "workstation-example"
    assert "_index" not in record


def test_retains_native_audit_sequence_when_event_id_is_absent(parser):
    record = parse(
        parser, benign_event(event={"category": "process"}, auditd={"sequence": 12345})
    )
    assert record["source_event_id"] == "12345"


@pytest.mark.parametrize(
    "host,agent,expected",
    [
        (
            {"hostname": "host-fallback"},
            {"hostname": "agent-host", "name": "agent-name"},
            "host-fallback",
        ),
        ({}, {"hostname": "agent-host", "name": "agent-name"}, "agent-host"),
        ({}, {"name": "agent-name"}, "agent-name"),
    ],
)
def test_host_fallback_order(parser, host, agent, expected):
    assert parse(parser, benign_event(host=host, agent=agent))["host"] == expected


@pytest.mark.parametrize(
    "event",
    [
        benign_event(host={}, agent={}),
        benign_event(host={"name": []}, agent={"name": " "}),
        benign_event(host="unexpected", agent={}),
    ],
)
def test_rejects_missing_host_instead_of_inventing_one(parser, event):
    with pytest.raises(ValueError, match="HOST"):
        parse(parser, event)


def test_omits_absent_ips_and_does_not_infer_them_from_host_or_addresses(parser):
    event = benign_event(
        source={"address": "inventory.example", "domain": "inventory.example"},
        destination={"address": "198.51.100.6"},
    )
    record = parse(parser, event)
    assert "source_ip" not in record and "destination_ip" not in record
    assert "source_port" not in record and "destination_port" not in record


def test_winlogbeat_origin_and_observable_identity(parser):
    event = benign_event(
        agent={"type": "winlogbeat"},
        event={"code": 101},
        winlog={
            "event_id": 101,
            "record_id": 42,
            "channel": "Application",
            "computer_name": "example-win",
        },
    )
    record = parse(
        parser,
        event,
        archive="system_logs_winlogbeat.zip",
        relative_log_path="daily_winlogbeat/2020-01-01.jsonl.bz2",
    )
    assert record["source"] == "winlogbeat"
    assert record["source_event_id"] == "42"
    assert record["event_type"] == "winlog.101"
    assert record["winlog"]["channel"] == "Application"


@pytest.mark.parametrize(
    "original,expected",
    [
        ("information", "info"),
        ("informational", "info"),
        ("notice", "low"),
        ("WARNING", "medium"),
        ("warn", "medium"),
        ("error", "high"),
        ("err", "high"),
        ("fatal", "critical"),
        ("alert", "critical"),
        ("emergency", "critical"),
        ("trace", "info"),
        ("verbose", "info"),
        ("debug", "info"),
        ("low", "low"),
        ("medium", "medium"),
        ("high", "high"),
        ("unknown-example", "info"),
    ],
)
def test_normalizes_backend_severity_and_preserves_original_level(
    parser, original, expected
):
    from evidencesoc.ingestion.jsonl import ParsedLogRecord
    from evidencesoc.ingestion.normalize import normalize_record

    record = parse(parser, benign_event(log={"level": original}))
    normalized = normalize_record(
        ParsedLogRecord(raw=record, source_path=MEMBER, line_number=7),
        event_id="example-normalization-id",
        ingested_at=datetime(2020, 1, 1, tzinfo=UTC),
    )
    assert record["severity"] == expected
    assert record["original_severity"] == original
    assert normalized.severity.value == expected


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
def test_preserves_explicit_source_severity_for_backend_normalization(parser, severity):
    from evidencesoc.ingestion.jsonl import ParsedLogRecord
    from evidencesoc.ingestion.normalize import normalize_record

    record = parse(parser, benign_event(severity=severity))
    normalized = normalize_record(
        ParsedLogRecord(raw=record, source_path=MEMBER, line_number=7),
        event_id="example-normalization-id",
        ingested_at=datetime(2020, 1, 1, tzinfo=UTC),
    )
    assert normalized.severity.value == severity


@pytest.mark.parametrize(
    "timestamp,expected",
    [
        ("2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z"),
        ("2020-01-01T00:00:00.000000001Z", "2020-01-01T00:00:00.000000001Z"),
        ("2020-01-01T00:00:00.1200-01:30", "2020-01-01T01:30:00.1200Z"),
    ],
)
def test_utc_conversion_preserves_original_fractional_precision(
    parser, timestamp, expected
):
    assert (
        parse(parser, benign_event(**{"@timestamp": timestamp}))["observed_at"]
        == expected
    )


@pytest.mark.parametrize(
    "timestamp",
    [
        None,
        "",
        "2020-01-01",
        "2020-01-01T00:00:00",
        "2020-02-30T01:02:03Z",
        "2020-01-01T00:00:00+25:00",
    ],
)
def test_rejects_missing_naive_or_invalid_timestamps(parser, timestamp):
    with pytest.raises(ValueError, match="TIMESTAMP"):
        parse(parser, benign_event(**{"@timestamp": timestamp}))


@pytest.mark.parametrize(
    "raw",
    [
        b'{"host":{"name":"first","name":"second"}}\n',
        b'{"@timestamp":"2020-01-01T00:00:00Z","x":NaN}\n',
        b'{"@timestamp":"2020-01-01T00:00:00Z","x":Infinity}\n',
        b'{"@timestamp":"2020-01-01T00:00:00Z","x":1e999}\n',
        b"[]\n",
        b"null\n",
        b"\xff\n",
        b"\n",
        b"{}{}\n",
    ],
)
def test_rejects_noncanonical_or_nonobject_json(parser, raw):
    with pytest.raises(ValueError):
        parser.parse_event(
            raw, archive=ARCHIVE, relative_log_path=MEMBER, line_number=1
        )


@pytest.mark.parametrize(
    "archive,member",
    [
        ("system_logs_labels.zip", MEMBER),
        ("system_logs_auditbeat.zip.part", MEMBER),
        ("../system_logs_auditbeat.zip", MEMBER),
        (ARCHIVE, "daily_winlogbeat/2020-01-01.jsonl.bz2"),
        (ARCHIVE, "daily_auditbeat/../2020-01-01.jsonl.bz2"),
        (ARCHIVE, "/daily_auditbeat/2020-01-01.jsonl.bz2"),
        (ARCHIVE, "C:/daily_auditbeat/2020-01-01.jsonl.bz2"),
        (ARCHIVE, "daily_auditbeat\\2020-01-01.jsonl.bz2"),
        (ARCHIVE, "daily_auditbeat/2020-01-01.jsonl.bz2:stream"),
        (ARCHIVE, "daily_auditbeat/2020-01-01.jsonl"),
    ],
)
def test_rejects_unapproved_archive_and_member_paths(parser, archive, member):
    with pytest.raises(ValueError):
        parse(parser, archive=archive, relative_log_path=member)


@pytest.mark.parametrize("line_number", [0, -1, True, 1.5])
def test_line_number_must_be_a_positive_integer(parser, line_number):
    with pytest.raises(ValueError, match="line_number"):
        parse(parser, line_number=line_number)


def test_streams_zip_bz2_lines_preserving_newlines_and_local_line_numbers(
    parser, tmp_path
):
    first, second = raw_line(newline=b"\r\n"), raw_line(newline=b"")
    archive = make_archive(tmp_path, {MEMBER: first + second})
    rows = list(parser.iter_archive_lines(archive))
    assert rows == [(MEMBER, 1, first), (MEMBER, 2, second)]
    records = list(parser.iter_archive_events(archive))
    assert [r["line_number"] for r in records] == [1, 2]
    assert [r["raw_line_sha256"] for r in records] == [
        hashlib.sha256(first).hexdigest(),
        hashlib.sha256(second).hexdigest(),
    ]


def test_archive_selection_can_skip_unselected_bz2_content(parser, tmp_path):
    other = "daily_auditbeat/2020-01-02.jsonl.bz2"
    archive = tmp_path / ARCHIVE
    with ZipFile(archive, "w") as output:
        output.writestr(other, b"not bz2")
        output.writestr(MEMBER, bz2.compress(raw_line()))
    records = list(parser.iter_archive_events(archive, member_names={MEMBER}))
    assert len(records) == 1
    assert records[0]["relative_log_path"] == MEMBER
    assert list(parser.iter_archive_lines(archive, member_names=set())) == []


def test_raw_line_iterator_supports_auditing_invalid_rows_without_aborting(
    parser, tmp_path
):
    bad = raw_line(benign_event(host={}, agent={}))
    archive = make_archive(tmp_path, {MEMBER: bad + raw_line()})
    valid, errors = [], []
    for member, line_number, raw in parser.iter_archive_lines(archive):
        try:
            valid.append(
                parser.parse_event(
                    raw,
                    archive=archive.name,
                    relative_log_path=member,
                    line_number=line_number,
                )
            )
        except ValueError as error:
            errors.append((line_number, hashlib.sha256(raw).hexdigest(), str(error)))
    assert len(valid) == len(errors) == 1
    assert errors[0][0] == 1 and "HOST" in errors[0][2]
    assert valid[0]["line_number"] == 2


@pytest.mark.parametrize(
    "member",
    [
        "daily_auditbeat/../bad.jsonl.bz2",
        "system_labels/example.jsonl.bz2",
        "daily_winlogbeat/example.jsonl.bz2",
    ],
)
def test_rejects_unsafe_members_even_when_not_selected(parser, tmp_path, member):
    archive = make_archive(tmp_path, {MEMBER: raw_line(), member: raw_line()})
    with pytest.raises(ValueError):
        list(parser.iter_archive_events(archive, member_names={MEMBER}))


def test_rejects_missing_requested_member(parser, tmp_path):
    archive = make_archive(tmp_path, {MEMBER: raw_line()})
    with pytest.raises(ValueError, match="member"):
        list(
            parser.iter_archive_events(
                archive, member_names={"daily_auditbeat/missing.jsonl.bz2"}
            )
        )


def test_rejects_zip_duplicate_names_and_symlink_members(parser, tmp_path):
    archive = tmp_path / ARCHIVE
    with ZipFile(archive, "w") as output:
        output.writestr(MEMBER, bz2.compress(raw_line()))
        with pytest.warns(UserWarning, match="Duplicate"):
            output.writestr(MEMBER, bz2.compress(raw_line()))
    with pytest.raises(ValueError, match="[Dd]uplicate"):
        list(parser.iter_archive_lines(archive))
    with ZipFile(archive, "w") as output:
        info = ZipInfo(MEMBER)
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        output.writestr(info, bz2.compress(raw_line()))
    with pytest.raises(ValueError, match="link"):
        list(parser.iter_archive_lines(archive))


def test_archive_results_are_deterministic_across_absolute_roots(parser, tmp_path):
    first_root, second_root = tmp_path / "first", tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    payload = {MEMBER: raw_line()}
    first = make_archive(first_root, payload)
    second = make_archive(second_root, payload)
    assert list(parser.iter_archive_events(first)) == list(
        parser.iter_archive_events(second)
    )


def test_accepts_official_md5_manifest_and_counts_identical_duplicate_rows(
    parser, tmp_path
):
    raw = raw_line()
    checksum = hashlib.md5(raw, usedforsecurity=False).hexdigest()
    entry = f"{checksum}  ./2020-01-01.jsonl\n"
    archive = tmp_path / ARCHIVE
    with ZipFile(archive, "w") as output:
        output.writestr("daily_auditbeat/", b"")
        output.writestr(MEMBER, bz2.compress(raw))
        output.writestr(
            "daily_auditbeat/auditbeat_md5sum.sig", (entry * 2).encode("ascii")
        )
    records = list(parser.iter_archive_events(archive))
    assert len(records) == 1
    manifest = parser.read_archive_manifest(archive)
    assert manifest["unique_members"] == 1
    assert manifest["duplicate_entries"] == 1
    assert manifest["checksums"] == {MEMBER: checksum}


@pytest.mark.parametrize(
    "manifest",
    [
        "0" * 32 + "  ./2020-01-01.jsonl\n" + "1" * 32 + "  ./2020-01-01.jsonl\n",
        "0" * 32 + "  ./../2020-01-01.jsonl\n",
        "0" * 32 + "  ./absent.jsonl\n",
        "invalid-checksum  ./2020-01-01.jsonl\n",
        "",
    ],
)
def test_rejects_manifest_conflicts_unsafe_paths_unknown_files_or_invalid_format(
    parser, tmp_path, manifest
):
    archive = tmp_path / ARCHIVE
    with ZipFile(archive, "w") as output:
        output.writestr(MEMBER, bz2.compress(raw_line()))
        output.writestr(
            "daily_auditbeat/auditbeat_md5sum.sig", manifest.encode("ascii")
        )
    with pytest.raises(ValueError, match="[Mm]anifest"):
        list(parser.iter_archive_lines(archive))


def test_manifest_hashes_decompressed_jsonl_and_mismatch_is_a_stream_failure(
    parser, tmp_path
):
    archive = tmp_path / ARCHIVE
    with ZipFile(archive, "w") as output:
        output.writestr(MEMBER, bz2.compress(raw_line()))
        output.writestr(
            "daily_auditbeat/auditbeat_md5sum.sig",
            ("0" * 32 + "  ./2020-01-01.jsonl\n").encode("ascii"),
        )
    with pytest.raises(ValueError, match="MD5"):
        list(parser.iter_archive_events(archive))


def test_winlogbeat_manifest_has_its_own_fixed_name(parser, tmp_path):
    raw = raw_line(benign_event(agent={"type": "winlogbeat"}))
    checksum = hashlib.md5(raw, usedforsecurity=False).hexdigest()
    archive = tmp_path / "system_logs_winlogbeat.zip"
    with ZipFile(archive, "w") as output:
        output.writestr("daily_winlogbeat/2020-01-01.jsonl.bz2", bz2.compress(raw))
        output.writestr(
            "daily_winlogbeat/winlogbeat_md5sum.sig",
            f"{checksum}  ./2020-01-01.jsonl\n".encode("ascii"),
        )
    assert len(list(parser.iter_archive_events(archive))) == 1


def test_caps_message_after_prioritizing_process_and_parent_commands(parser):
    event = benign_event(message="Original inventory details: " + "x" * 20000)
    record = parse(parser, event)
    assert len(record["message"]) <= 8192
    assert record["message"].index("process.command_line=") < record["message"].index("Original inventory details:")
    assert record["message"].index("parent.command_line=") < record["message"].index("Original inventory details:")
    assert record["projection_truncated"] is True
    assert "message" in record["projection_truncated_fields"]
    assert record["event_fingerprint"] == parser.event_fingerprint(event)
    assert record["raw_line_sha256"] == hashlib.sha256(raw_line(event)).hexdigest()


def test_caps_observable_scalars_and_args_with_bounded_neutral_metadata(parser):
    event = benign_event()
    event["process"]["name"] = "n" * 5000
    event["process"]["command_line"] = "inventory " + "a" * 5000
    event["process"]["args"] = ["b" * 1100 for _ in range(80)]
    event["user"]["name"] = "u" * 5000
    event["network"]["protocol"] = "p" * 5000
    record = parse(parser, event)
    assert len(record["process"]["name"]) == 4096
    assert len(record["process"]["command_line"]) == 4096
    assert len(record["command_line"]) == 4096
    assert len(record["user"]["name"]) == len(record["username"]) == 4096
    assert len(record["network"]["protocol"]) == 4096
    assert len(record["process"]["args"]) == 64
    assert all(len(arg) == 1024 for arg in record["process"]["args"])
    assert len(record["message"]) <= 8192
    assert "parent.command_line=scheduler --daily" in record["message"]
    fields = record["projection_truncated_fields"]
    assert fields == sorted(set(fields))
    assert len(fields) <= 64
    assert {"process.name", "process.command_line", "process.args", "user.name", "network.protocol", "message"} <= set(fields)
    assert all(isinstance(field, str) and len(field) < 80 for field in fields)
    assert not {"is_attack", "source_label", "stage"} & record.keys()


def test_exact_scalar_and_argument_boundaries_are_not_marked_truncated(parser):
    event = benign_event()
    event["process"]["name"] = "n" * 4096
    event["process"]["args"] = ["a" * 1024 for _ in range(64)]
    record = parse(parser, event)
    assert len(record["process"]["name"]) == 4096
    assert len(record["process"]["args"]) == 64
    assert "process.name" not in record["projection_truncated_fields"]
    assert "process.args" not in record["projection_truncated_fields"]


def test_normal_observations_keep_optional_truncation_metadata_absent(parser):
    record = parse(parser)
    assert "projection_truncated" not in record
    assert "projection_truncated_fields" not in record


@pytest.mark.parametrize("field", ["host", "source_event_id", "event_type", "timestamp"])
def test_oversized_identity_fields_are_rejected_instead_of_truncated(parser, field):
    event = benign_event()
    if field == "host":
        event["host"]["name"] = "h" * 4097
    elif field == "source_event_id":
        event["event"]["id"] = "i" * 4097
    elif field == "event_type":
        event["event"]["action"] = "a" * 129
    else:
        event["@timestamp"] = "2020-01-01T00:00:00." + "1" * 4097 + "Z"
    with pytest.raises(ValueError, match="LENGTH"):
        parse(parser, event)
