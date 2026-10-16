"""Small synthetic fixtures for the scoring-only DEDALE label join."""

import hashlib
import importlib.util
import json
import sys
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "datasets/dedale/join_labels.py"
CLIENT_PREFIX = "system_labels/clients_1_and_2/"
SERVER_PREFIX = "system_labels/internal_server/"


@pytest.fixture
def joiner():
    if not SCRIPT.exists():

        class MissingJoiner:
            def __getattr__(self, name):
                pytest.fail("DEDALE scoring-only label join implementation is missing")

        return MissingJoiner()
    spec = importlib.util.spec_from_file_location("dedale_join", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def event(source="winlogbeat", number=1, *, host=None):
    host = host or (
        "CLIENT1.breach.local" if source == "winlogbeat" else "internalserver"
    )
    row = {
        "@timestamp": "2025-01-07T12:00:00.000Z",
        "agent": {"type": source, "id": "synthetic-agent"},
        "host": {"name": host},
        "message": "synthetic observable é",
    }
    if source == "winlogbeat":
        row["winlog"] = {"channel": "synthetic-channel", "record_id": number}
    else:
        row["auditd"] = {"sequence": number}
    return row


def write_archive(path, *, clients=None, servers=None, omit=None):
    clients = clients or ([event()], [event(), event(number=2)])
    servers = servers or (
        [event("auditbeat")],
        [event("auditbeat"), event("auditbeat", 2)],
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for prefix, groups in [(CLIENT_PREFIX, clients), (SERVER_PREFIX, servers)]:
            for suffix, rows in zip(
                [
                    "malicious_events_class_1.jsonl",
                    "malicious_events_class_1_and_2.jsonl",
                ],
                groups,
                strict=True,
            ):
                member = prefix + suffix
                if member == omit:
                    continue
                payload = "".join(
                    json.dumps(row, ensure_ascii=False) + "\n" for row in rows
                )
                archive.writestr(member, payload)
    return path


@pytest.fixture
def archive_path(tmp_path):
    return write_archive(tmp_path / "labels.zip")


def trust_fixture(joiner, monkeypatch, path):
    monkeypatch.setattr(joiner, "OFFICIAL_ARCHIVE_SIZE", path.stat().st_size)
    monkeypatch.setattr(
        joiner, "OFFICIAL_ARCHIVE_MD5", hashlib.md5(path.read_bytes()).hexdigest()
    )


def test_fingerprint_ignores_object_order_and_rejects_nonfinite(joiner):
    original = event()
    reordered = dict(reversed(list(original.items())))
    expected = hashlib.sha256(
        json.dumps(
            original, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    assert joiner.canonical_event_fingerprint(original) == expected
    assert joiner.canonical_event_fingerprint(reordered) == expected
    with pytest.raises(ValueError):
        joiner.canonical_event_fingerprint({"bad": float("nan")})


def test_class_membership_preserves_related_and_unknown(joiner, archive_path):
    index = joiner.load_label_index(archive_path)
    for source in ["winlogbeat", "auditbeat"]:
        assert (
            index.classify(source, joiner.canonical_event_fingerprint(event(source)))
            == "malicious"
        )
        assert (
            index.classify(source, joiner.canonical_event_fingerprint(event(source, 2)))
            == "malicious-related"
        )
        assert (
            index.classify(source, joiner.canonical_event_fingerprint(event(source, 3)))
            == "unscorable"
        )
    assert index.summary["sources"]["winlogbeat"]["malicious"] == 1
    assert index.summary["sources"]["auditbeat"]["malicious-related"] == 1
    assert not index.official_verified


def test_benign_requires_official_integrity_explicit_policy_and_known_host(
    joiner, archive_path, monkeypatch
):
    trust_fixture(joiner, monkeypatch, archive_path)
    fingerprint = joiner.canonical_event_fingerprint(event(number=3))
    index = joiner.load_label_index(archive_path, exhaustive=True)
    assert index.official_verified
    assert (
        index.classify("winlogbeat", fingerprint, host="CLIENT1.breach.local")
        == "benign"
    )
    assert index.classify("winlogbeat", fingerprint) == "unscorable"
    assert index.classify("winlogbeat", fingerprint, host="OTHER") == "unscorable"
    assert (
        index.classify("auditbeat", fingerprint, host="CLIENT1.breach.local")
        == "unscorable"
    )
    assert index.classify("syslog", fingerprint, host="internalserver") == "unscorable"
    conservative = joiner.load_label_index(archive_path)
    assert (
        conservative.classify("winlogbeat", fingerprint, host="CLIENT1.breach.local")
        == "unscorable"
    )


def test_unverified_archive_cannot_produce_benign(joiner, archive_path):
    index = joiner.load_label_index(archive_path, exhaustive=True)
    assert index.classify("auditbeat", "0" * 64, host="internalserver") == "unscorable"
    assert index.summary["negative_policy"] == "unknown"


def test_known_fingerprint_cannot_be_scored_under_different_host(joiner, archive_path):
    index = joiner.load_label_index(archive_path)
    fingerprint = joiner.canonical_event_fingerprint(event())
    assert index.classify("winlogbeat", fingerprint, host="OTHER") == "unscorable"


def test_class1_must_be_subset_of_union(joiner, tmp_path):
    path = write_archive(tmp_path / "bad.zip", clients=([event()], [event(number=2)]))
    with pytest.raises(ValueError, match="subset"):
        joiner.load_label_index(path)


@pytest.mark.parametrize(
    "source,host", [("auditbeat", "CLIENT1.breach.local"), ("winlogbeat", "OTHER")]
)
def test_label_member_source_and_host_are_validated(joiner, tmp_path, source, host):
    bad = event(source, host=host)
    path = write_archive(tmp_path / "bad.zip", clients=([bad], [bad]))
    with pytest.raises(ValueError, match="source|host"):
        joiner.load_label_index(path)


def test_duplicate_rows_are_counted_without_changing_class(joiner, tmp_path):
    path = write_archive(
        tmp_path / "duplicates.zip",
        clients=([event(), event()], [event(), event(), event(number=2)]),
    )
    index = joiner.load_label_index(path)
    assert index.summary["duplicate_rows"] == 2
    assert index.summary["sources"]["winlogbeat"]["malicious"] == 1


def test_same_event_identity_with_different_content_is_conflict(joiner, tmp_path):
    changed = deepcopy(event())
    changed["message"] = "different synthetic content"
    path = write_archive(
        tmp_path / "conflict.zip", clients=([event()], [event(), changed])
    )
    with pytest.raises(ValueError, match="conflict"):
        joiner.load_label_index(path)


def test_missing_label_member_is_not_an_empty_benign_set(joiner, tmp_path):
    path = write_archive(
        tmp_path / "missing.zip", omit=SERVER_PREFIX + "malicious_events_class_1.jsonl"
    )
    with pytest.raises(ValueError, match="member|missing"):
        joiner.load_label_index(path)


def test_crc_failure_is_rejected(joiner, archive_path):
    payload = archive_path.read_bytes()
    position = payload.index(b"synthetic observable")
    archive_path.write_bytes(payload[:position] + b"X" + payload[position + 1 :])
    with pytest.raises(ValueError, match="CRC|integrity|corrupt"):
        joiner.load_label_index(archive_path)


@pytest.mark.parametrize(
    "payload", [b'{"@timestamp":1,"@timestamp":2}\n', b'{"bad":NaN}\n', b"not json\n"]
)
def test_invalid_label_json_is_rejected(joiner, archive_path, payload):
    with zipfile.ZipFile(archive_path) as source:
        contents = {info.filename: source.read(info) for info in source.infolist()}
    contents[CLIENT_PREFIX + "malicious_events_class_1.jsonl"] = payload
    with zipfile.ZipFile(archive_path, "w") as destination:
        for name, value in contents.items():
            destination.writestr(name, value)
    with pytest.raises(ValueError):
        joiner.load_label_index(archive_path)


def test_join_is_scoring_only_and_preserves_raw_input(joiner, archive_path):
    index = joiner.load_label_index(archive_path)
    original = event(number=2)
    before = deepcopy(original)
    row = joiner.join_event(
        original, index, source_file="daily/file.json.bz2", line_number=12
    )
    assert row["label"] == "malicious-related"
    assert row["source"] == "winlogbeat"
    assert row["host"] == "CLIENT1.breach.local"
    assert row["source_file"] == "daily/file.json.bz2"
    assert row["line_number"] == 12
    assert row["fingerprint"] == joiner.canonical_event_fingerprint(original)
    assert (
        not {"message", "process", "raw", "raw_event", "tactic", "technique"}
        & row.keys()
    )
    assert original == before


def test_join_rejects_invalid_location(joiner, archive_path):
    index = joiner.load_label_index(archive_path)
    with pytest.raises(ValueError, match="line_number"):
        joiner.join_event(event(), index, line_number=True)


def test_index_exposes_all_minimal_labeled_entries_with_original_locations(
    joiner, archive_path
):
    index = joiner.load_label_index(archive_path)
    fingerprint = joiner.canonical_event_fingerprint(event())
    entry = index.entries[("winlogbeat", fingerprint)]
    assert entry["timestamp"] == event()["@timestamp"]
    assert entry["host"] == "CLIENT1.breach.local"
    assert entry["label"] == "malicious"
    assert len(entry["locations"]) == 2
    assert len(index.entries) == 4
    assert all(
        set(value)
        == {"source", "fingerprint", "host", "timestamp", "label", "locations"}
        for value in index.iter_labeled_events()
    )
    values = list(index.iter_labeled_events())
    assert [(value["source"], value["fingerprint"]) for value in values] == sorted(
        index.entries
    )
    values[0]["locations"].append("must not mutate the index")
    assert not any(
        "must not mutate the index" in value["locations"]
        for value in index.entries.values()
    )


def test_bad_source_and_host_types_remain_unscorable(joiner, archive_path, monkeypatch):
    trust_fixture(joiner, monkeypatch, archive_path)
    index = joiner.load_label_index(archive_path, exhaustive=True)
    assert index.classify({}, "0" * 64, host="internalserver") == "unscorable"
    assert index.classify("auditbeat", "0" * 64, host={}) == "unscorable"


@pytest.mark.parametrize(
    "field,value", [("host", []), ("timestamp", []), ("agent_id", []), ("record", True)]
)
def test_invalid_native_identity_is_a_data_validation_failure(
    joiner, tmp_path, field, value
):
    bad = event()
    if field == "host":
        bad["host"]["name"] = value
    elif field == "timestamp":
        bad["@timestamp"] = value
    elif field == "agent_id":
        bad["agent"]["id"] = value
    else:
        bad["winlog"]["record_id"] = value
    path = write_archive(tmp_path / "bad.zip", clients=([bad], [bad]))
    with pytest.raises(ValueError):
        joiner.load_label_index(path)


def test_join_accepts_storage_source_wrapper(joiner, archive_path):
    index = joiner.load_label_index(archive_path)
    assert joiner.join_event({"_source": event()}, index)["label"] == "malicious"
