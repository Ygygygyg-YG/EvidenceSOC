"""Late projection must preserve the complete audit and every selected byte."""

import inspect
import json
from pathlib import Path

import pytest

from evals.datasets.dedale import parse, scan
from evals.datasets.dedale.build_manifests import WindowCollector, emit_cases
from evals.datasets.dedale.common import read_json
from evals.datasets.dedale.join_labels import EXHAUSTIVE_HOSTS, LabelIndex
from evals.tests.test_dedale_scan import inputs as input_fixture
from evals.tests.test_dedale_scan import line, raw_archive, raw_event


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    return input_fixture.__wrapped__(tmp_path, monkeypatch)


def labels_for(positives=(), related=()):
    entries, hosts = {}, {source: {} for source in EXHAUSTIVE_HOSTS}
    direct = {source: set() for source in EXHAUSTIVE_HOSTS}
    combined = {source: set() for source in EXHAUSTIVE_HOSTS}
    for rows, label in ((positives, "malicious"), (related, "malicious-related")):
        for event in rows:
            source = event["agent"]["type"]
            fingerprint = parse.event_fingerprint(event)
            host = event["host"]["name"]
            combined[source].add(fingerprint)
            if label == "malicious":
                direct[source].add(fingerprint)
            hosts[source][fingerprint] = host
            entries[source, fingerprint] = {"source": source, "host": host,
                "timestamp": event["@timestamp"], "label": label}
    return LabelIndex(
        {key: frozenset(value) for key, value in direct.items()},
        {key: frozenset(value) for key, value in combined.items()},
        hosts, entries, True, True, {"fixture": True},
    )


def config():
    root = Path(__file__).resolve().parents[2]
    return {**read_json(root / "data/manifests/dedale-splits.json"), "max_records": 3}


def require_late_api():
    assert callable(getattr(parse, "decode_event", None)), "validated lazy decoding is missing"
    assert "late_projection" in inspect.signature(scan.scan_member).parameters, "late scan is missing"


def test_full_and_late_preserve_duplicate_counts_candidates_and_every_artifact(tmp_path):
    require_late_api()
    attack = raw_event(number=1, timestamp="2025-01-07T12:00:00.000Z")
    related = raw_event(number=2, timestamp="2025-01-07T12:00:01.000Z")
    ordinary = [raw_event(number=n, timestamp=f"2025-01-07T12:{n // 60:02d}:{n % 60:02d}.000Z")
                for n in range(3, 140)]
    # Repeated early fingerprints occur after the projection fills. The final
    # duplicate also uses different JSON whitespace and retains the same hash.
    rows = [attack, related, *ordinary, attack, related]
    payload = b"".join(map(line, rows))
    payload += (json.dumps(attack, ensure_ascii=False, separators=(",", ": ")) + "\n").encode()
    payload += line(raw_event(number=200, timestamp="2025-01-07T13:00:00Z"))
    payload += line(raw_event(number=201, timestamp="2025-01-05T12:00:00Z"))
    payload += line(raw_event(number=202, host="OTHER"))
    path = tmp_path / "system_logs_winlogbeat.zip"
    raw_archive(path, "winlogbeat", {"sample": payload})
    labels, splits = labels_for([attack], [related]), config()
    states = [scan.scan_member(path, "daily_winlogbeat/sample.jsonl.bz2", labels=labels,
                              splits=splits, late_projection=enabled) for enabled in (False, True)]
    assert states[0] == states[1]
    assert sum(row["duplicate_retained_rows"] for row in states[0]["windows"].values()) >= 3
    selections, inventories = [], []
    for name, state in zip(("full", "late"), states, strict=True):
        collector = WindowCollector(labels=labels, splits=splits)
        scan.merge_collector_state(collector, state)
        root = tmp_path / name
        selections.append(emit_cases(collector, output_root=root, input_hashes={}))
        inventories.append({path.relative_to(root).as_posix(): path.read_bytes()
                            for path in root.rglob("*") if path.is_file()})
    assert selections[0] == selections[1]
    assert inventories[0] == inventories[1]


@pytest.mark.parametrize("extra", [
    b',"unknown":{"n":1e999}',
    b',"unknown":{"n":NaN}',
    b',"unknown":{"x":"\\ud800"}',
    b',"unknown":{"\\udfff":"value"}',
    b',"unknown":{"x":[["\\ud800"]]}',
    b',"unknown":{"x":1,"x":2}',
    b',"winlog":{"record_id":"' + b'x' * 4097 + b'"}',
    b',"event":{"action":"' + b'x' * 129 + b'"}',
    b',"_id":"' + b'x' * 4097 + b'"',
])
def test_discarded_rows_still_validate_every_field(tmp_path, extra):
    require_late_api()
    valid = raw_event(timestamp="2025-01-05T12:00:00Z")
    invalid = line(valid).rstrip()[:-1] + extra + b'}\n'
    path = tmp_path / "system_logs_winlogbeat.zip"
    raw_archive(path, "winlogbeat", {"sample": line(valid) + invalid})
    states = [scan.scan_member(path, "daily_winlogbeat/sample.jsonl.bz2", labels=labels_for(),
                              splits=config(), late_projection=enabled) for enabled in (False, True)]
    assert states[0] == states[1]
    assert states[0]["stats"]["invalid_rows"] == 1


def test_wrapper_unknown_fields_and_surrogate_pairs_are_checked_before_late_discard(tmp_path):
    require_late_api()
    event = raw_event(timestamp="2025-01-05T12:00:00Z")
    wrapped = b'{"_source":' + line(event).strip() + b',"unknown":1e999}\n'
    good = line(event).replace(b"synthetic observable", b"\\ud83d\\ude00")
    path = tmp_path / "system_logs_winlogbeat.zip"
    raw_archive(path, "winlogbeat", {"sample": good + wrapped})
    states = [scan.scan_member(path, "daily_winlogbeat/sample.jsonl.bz2", labels=labels_for(),
                              splits=config(), late_projection=enabled) for enabled in (False, True)]
    assert states[0] == states[1]
    assert states[0]["stats"]["invalid_rows"] == 1
    assert states[0]["stats"]["parsed_rows"] == 1


def test_late_clock_prefilter_never_misses_different_events_at_a_labeled_timestamp(tmp_path):
    require_late_api()
    attack = raw_event(number=1)
    ordinary = raw_event(number=2)
    path = tmp_path / "system_logs_winlogbeat.zip"
    raw_archive(path, "winlogbeat", {"sample": line(ordinary) + line(attack)})
    labels = labels_for([attack])
    states = [scan.scan_member(path, "daily_winlogbeat/sample.jsonl.bz2", labels=labels,
                              splits=config(), late_projection=enabled) for enabled in (False, True)]
    assert states[0] == states[1]
    assert states[0]["original_labels"] == {"benign": 1, "malicious": 1}
    assert states[0]["matched_labels"] == set(labels.entries)


def test_late_never_materializes_normal_calibration_rows(tmp_path, monkeypatch):
    require_late_api()
    path = tmp_path / "system_logs_winlogbeat.zip"
    raw_archive(path, "winlogbeat", {"sample": line(raw_event(timestamp="2025-01-05T12:00:00Z"))})
    def forbidden(*args, **kwargs):
        pytest.fail("calibration negative should not need a fingerprint or projection")
    monkeypatch.setattr(parse, "event_fingerprint", forbidden)
    state = scan.scan_member(path, "daily_winlogbeat/sample.jsonl.bz2", labels=labels_for(),
                             splits=config(), late_projection=True)
    assert state["stats"]["parsed_rows"] == 1
    assert not state["windows"]


def test_complete_verified_prepare_outputs_have_identical_bytes(inputs):
    full = scan.prepare_dataset(**inputs, workers=1)
    other = {**inputs, "output_root": inputs["output_root"].with_name("prepared-late")}
    late = scan.prepare_dataset(**other, workers=1, late_projection=True)
    assert full == late
    inventories = [{path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*") if path.is_file()}
                   for root in (inputs["output_root"], other["output_root"])]
    assert inventories[0] == inventories[1]


def test_initialized_worker_uses_late_mode_without_changing_transport_state(inputs):
    splits = read_json(inputs["splits"])
    label_path = str(inputs["data_root"] / "system_logs_labels.zip")
    task = str(inputs["data_root"] / "system_logs_winlogbeat.zip"), "daily_winlogbeat/D1_H0.jsonl.bz2"
    scan.initialize_worker(label_path, splits)
    full = scan.worker_scan_member(task)
    scan.initialize_worker(label_path, splits, late_projection=True)
    late = scan.worker_scan_member(task)
    assert full == late
