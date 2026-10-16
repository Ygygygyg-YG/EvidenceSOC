"""Synthetic, checksummed archives exercise full scan orchestration safely."""

import bz2
import hashlib
import importlib.util
import sys
import zipfile
from collections import Counter
from pathlib import Path

import pytest

from evals.datasets.dedale import common, join_labels
from evals.datasets.dedale.build_manifests import WindowCollector
from evals.datasets.dedale.parse import parse_event

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "evals/datasets/dedale/scan.py"


@pytest.fixture
def scanner():
    if not SCRIPT.exists():

        class MissingScanner:
            def __getattr__(self, name):
                pytest.fail("DEDALE complete-archive scan implementation is missing")

        return MissingScanner()
    spec = importlib.util.spec_from_file_location("evals.datasets.dedale.scan", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def raw_event(source="winlogbeat", number=1, *, host=None, timestamp=None):
    value = {
        "@timestamp": timestamp or "2025-01-07T12:00:00.000Z",
        "agent": {"id": "synthetic-agent", "type": source},
        "host": {
            "name": host
            or ("CLIENT1.breach.local" if source == "winlogbeat" else "internalserver")
        },
        "message": "synthetic observable",
    }
    value["winlog" if source == "winlogbeat" else "auditd"] = (
        {"channel": "synthetic-channel", "record_id": number}
        if source == "winlogbeat"
        else {"sequence": number}
    )
    return value


def line(value):
    return (common.canonical(value) + "\n").encode()


def raw_archive(path, source, members, *, manifest=True, corrupt_md5=False):
    hashes = []
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"daily_{source}/", b"")
        for name, payload in members.items():
            archive.writestr(f"daily_{source}/{name}.jsonl.bz2", bz2.compress(payload))
            digest = "0" * 32 if corrupt_md5 else hashlib.md5(payload).hexdigest()
            hashes.append(f"{digest}  ./{name}.jsonl\n")
        if manifest:
            archive.writestr(f"daily_{source}/{source}_md5sum.sig", "".join(hashes))


def label_archive(path):
    with zipfile.ZipFile(path, "w") as archive:
        for source, directory in [
            ("winlogbeat", "clients_1_and_2"),
            ("auditbeat", "internal_server"),
        ]:
            for suffix, numbers in [("class_1", [1]), ("class_1_and_2", [1, 2])]:
                archive.writestr(
                    f"system_labels/{directory}/malicious_events_{suffix}.jsonl",
                    b"".join(line(raw_event(source, number)) for number in numbers),
                )


def pin_fixture(inputs, monkeypatch):
    official = {}
    rows, metadata = [], []
    original_ids = {
        "system_logs_auditbeat.zip": 717881,
        "system_logs_winlogbeat.zip": 717892,
        "system_logs_labels.zip": 717882,
    }
    for name in sorted(original_ids):
        path = inputs["data_root"] / name
        digest = hashlib.md5(path.read_bytes()).hexdigest()
        size = path.stat().st_size
        official[name] = (original_ids[name], size, digest)
        rows.append(
            {
                "path": name,
                "bytes": size,
                "md5": digest,
                "datafile_id": original_ids[name],
                "url": f"https://entrepot.recherche.data.gouv.fr/api/access/datafile/{original_ids[name]}",
            }
        )
        metadata.append(
            {
                "dataFile": {
                    "filename": name,
                    "id": original_ids[name],
                    "filesize": size,
                    "checksum": {"value": digest},
                }
            }
        )
    snapshot = inputs["data_root"] / "metadata.json"
    snapshot.write_text(
        common.canonical(
            {"data": {"versionNumber": 2, "versionMinorNumber": 1, "files": metadata}}
        )
    )
    inputs["sources"].write_text(
        common.canonical(
            {
                "version": "2.1",
                "doi": "10.57745/Y5JLDG",
                "license": "CC-BY-4.0",
                "archives": rows,
                "metadata_snapshot": {
                    "path": "metadata.json",
                    "sha256": common.sha256(snapshot),
                },
            }
        )
    )
    monkeypatch.setattr(common, "OFFICIAL", official)
    monkeypatch.setattr(
        join_labels, "OFFICIAL_ARCHIVE_SIZE", official["system_logs_labels.zip"][1]
    )
    monkeypatch.setattr(
        join_labels, "OFFICIAL_ARCHIVE_MD5", official["system_logs_labels.zip"][2]
    )


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    root = tmp_path / "raw"
    root.mkdir()
    paths = {
        "sources": tmp_path / "sources.json",
        "splits": tmp_path / "splits.json",
        "label_policy": tmp_path / "label-policy.json",
        "data_root": root,
        "output_root": tmp_path / "prepared",
    }
    paths["splits"].write_bytes(
        (ROOT / "data/manifests/dedale-splits.json").read_bytes()
    )
    paths["label_policy"].write_bytes(
        (ROOT / "data/manifests/dedale-label-policy.json").read_bytes()
    )
    label_archive(root / "system_logs_labels.zip")
    for source in ["winlogbeat", "auditbeat"]:
        raw_archive(
            root / f"system_logs_{source}.zip",
            source,
            {
                "D1_H0": line(raw_event(source, 1)) + line(raw_event(source, 2)),
                "D1_H1": line(
                    raw_event(source, 3, timestamp="2025-01-07T13:00:00.000Z")
                ),
            },
        )
    pin_fixture(paths, monkeypatch)
    return paths


def labels_and_splits(inputs):
    return (
        join_labels.load_label_index(
            inputs["data_root"] / "system_logs_labels.zip", exhaustive=True
        ),
        common.read_json(inputs["splits"]),
    )


def normalized(number, *, timestamp=None, member="D1_H0", source="winlogbeat"):
    return parse_event(
        line(raw_event(source, number, timestamp=timestamp)),
        archive=f"system_logs_{source}.zip",
        relative_log_path=f"daily_{source}/{member}.jsonl.bz2",
        line_number=number,
    )


def test_prepare_scans_every_member_and_persists_identical_selection(scanner, inputs):
    result = scanner.prepare_dataset(**inputs, workers=1)
    assert common.read_json(inputs["output_root"] / "selection.json") == result
    scan = result["scan"]
    assert scan["full_archive_scan"]
    assert scan["members_expected"] == scan["members_completed"] == 4
    assert scan["counts"]["raw_rows"] == scan["counts"]["parsed_rows"] == 6
    assert scan["invalid_rows"] == 0
    assert (
        scan["label_fingerprints_expected"] == scan["label_fingerprints_matched"] == 4
    )
    assert scan["label_fingerprints_unmatched"] == 0
    assert scan["freeze_eligible"]
    assert result["source_verification"]["verified"]
    assert all(row["crc_checked"] for row in result["source_verification"]["archives"])
    assert all(row["jsonl_md5_verified"] for row in scan["member_summaries"])
    assert result["N_D"] == result["M_D"] == 4
    assert str(inputs["data_root"]) not in common.canonical(result)


def test_invalid_rows_are_counted_with_only_location_and_safe_error_code(
    scanner, inputs, monkeypatch
):
    path = inputs["data_root"] / "system_logs_winlogbeat.zip"
    raw_archive(
        path,
        "winlogbeat",
        {"D1_H0": b"secret-raw-command-invalid\n" + line(raw_event())},
    )
    pin_fixture(inputs, monkeypatch)
    result = scanner.prepare_dataset(**inputs, workers=1)
    assert result["scan"]["invalid_rows"] == 1
    assert result["scan"]["counts"]["raw_rows"] == 5
    assert not result["scan"]["freeze_eligible"]
    example = result["scan"]["invalid_examples"][0]
    assert example["line_number"] == 1
    assert example["archive"] == path.name
    assert set(example) == {"archive", "relative_log_path", "line_number", "error_code"}
    assert "secret-raw-command" not in common.canonical(result)
    assert common.read_json(inputs["output_root"] / "selection.json") == result


def test_unmatched_labels_are_real_set_difference(scanner, inputs, monkeypatch):
    raw_archive(
        inputs["data_root"] / "system_logs_winlogbeat.zip",
        "winlogbeat",
        {"D1_H0": line(raw_event())},
    )
    pin_fixture(inputs, monkeypatch)
    result = scanner.prepare_dataset(**inputs, workers=1)
    assert result["scan"]["label_fingerprints_matched"] == 3
    assert result["scan"]["label_fingerprints_unmatched"] == 1
    assert not result["scan"]["freeze_eligible"]
    assert (
        result["scan"]["label_coverage"]["winlogbeat"]["malicious-related"]["unmatched"]
        == 1
    )


def test_missing_official_archive_fails_before_any_output(scanner, inputs):
    (inputs["data_root"] / "system_logs_auditbeat.zip").unlink()
    with pytest.raises((FileNotFoundError, ValueError)):
        scanner.prepare_dataset(**inputs, workers=1)
    assert not inputs["output_root"].exists()


@pytest.mark.parametrize("manifest,corrupt_md5", [(False, False), (True, True)])
def test_complete_scan_requires_manifest_and_actual_member_md5(
    scanner, inputs, monkeypatch, manifest, corrupt_md5
):
    raw_archive(
        inputs["data_root"] / "system_logs_winlogbeat.zip",
        "winlogbeat",
        {"D1_H0": line(raw_event())},
        manifest=manifest,
        corrupt_md5=corrupt_md5,
    )
    pin_fixture(inputs, monkeypatch)
    with pytest.raises(ValueError, match="manifest|MD5"):
        scanner.prepare_dataset(**inputs, workers=1)
    assert not inputs["output_root"].exists()


@pytest.mark.parametrize("change", ["host", "related", "decision", "taxonomy"])
def test_policy_cannot_silently_change_label_semantics(scanner, inputs, change):
    policy = common.read_json(inputs["label_policy"])
    if change == "host":
        policy["scorable_hosts"]["auditbeat"].append("other")
    elif change == "related":
        policy["class_1_and_2_minus_class_1"] = "benign"
    elif change == "decision":
        policy["attack_decision"]["malicious-related"] = False
    else:
        policy["attack_types"] = ["inferred-category"]
    inputs["label_policy"].write_text(common.canonical(policy))
    with pytest.raises(ValueError, match="policy|label|scope|taxonomy"):
        scanner.prepare_dataset(**inputs, workers=1)
    assert not inputs["output_root"].exists()


def test_split_boundaries_are_fixed(scanner, inputs):
    config = common.read_json(inputs["splits"])
    config["periods"][0]["start"] = "2024-12-22T00:00:00Z"
    inputs["splits"].write_text(common.canonical(config))
    with pytest.raises(ValueError):
        scanner.prepare_dataset(**inputs, workers=1)
    assert not inputs["output_root"].exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_records", 99),
        ("event_sort", ["external_id"]),
        ("dedup_key", "external_id"),
        ("recent_months", 12),
        ("attack_window_rule", "UTC half-hour"),
    ],
)
def test_split_machine_policy_cannot_diverge_from_preregistration(
    scanner, inputs, field, value
):
    config = common.read_json(inputs["splits"])
    config[field] = value
    inputs["splits"].write_text(common.canonical(config))
    with pytest.raises(ValueError, match="split|policy|100"):
        scanner.prepare_dataset(**inputs, workers=1)
    assert not inputs["output_root"].exists()


def test_complete_scan_requires_registered_attack_window_rule(scanner, inputs):
    config = common.read_json(inputs["splits"])
    config.pop("attack_window_rule", None)
    inputs["splits"].write_text(common.canonical(config))
    with pytest.raises(ValueError, match="split policy.*attack_window_rule"):
        scanner.prepare_dataset(**inputs, workers=1)
    assert not inputs["output_root"].exists()


def test_parallel_executor_receives_only_sorted_member_tasks_and_initializer(
    scanner, inputs, monkeypatch
):
    observed = {}

    class InlineExecutor:
        def __init__(self, *, max_workers, initializer, initargs):
            observed["workers"] = max_workers
            observed["initializer"] = initializer
            observed["tasks"] = []
            initializer(*initargs)

        def submit(self, function, task):
            observed["tasks"].append(task)

            class Result:
                def result(self):
                    return function(task)

            return Result()

        def shutdown(self, *, wait, cancel_futures):
            observed["shutdown"] = (wait, cancel_futures)

    monkeypatch.setattr(scanner, "ProcessPoolExecutor", InlineExecutor)
    result = scanner.prepare_dataset(**inputs, workers=4)
    assert observed["workers"] == 4
    assert observed["initializer"] is scanner.initialize_worker
    assert observed["tasks"] == sorted(observed["tasks"])
    assert all(
        isinstance(path, str) and isinstance(member, str)
        for path, member in observed["tasks"]
    )
    assert observed["shutdown"] == (True, True)
    assert result["scan"]["members_completed"] == 4


@pytest.mark.parametrize("failure", ["exception", "incomplete"])
def test_parallel_task_failure_never_emits_partial_cases(
    scanner, inputs, monkeypatch, failure
):
    observed = {}

    class FailedExecutor:
        def __init__(self, **kwargs):
            self.submitted = 0
            kwargs["initializer"](*kwargs["initargs"])

        def submit(self, function, task):
            number = self.submitted
            self.submitted += 1

            class Result:
                def result(self):
                    if number == 1 and failure == "exception":
                        raise ValueError("synthetic worker failure")
                    state = function(task)
                    if number == 1:
                        state["completed"] = False
                    return state

            return Result()

        def shutdown(self, *, wait, cancel_futures):
            observed["shutdown"] = (wait, cancel_futures)

    monkeypatch.setattr(scanner, "ProcessPoolExecutor", FailedExecutor)
    with pytest.raises(ValueError):
        scanner.prepare_dataset(**inputs, workers=4)
    assert observed["shutdown"] == (True, True)
    assert not inputs["output_root"].exists()


def test_parallel_queue_is_bounded_and_results_remain_canonical(
    scanner, inputs, monkeypatch
):
    for source in ["auditbeat", "winlogbeat"]:
        raw_archive(
            inputs["data_root"] / f"system_logs_{source}.zip",
            source,
            {f"D1_H{hour}": line(raw_event(source)) for hour in range(10)},
        )
    pin_fixture(inputs, monkeypatch)
    observed = {"active": 0, "maximum": 0, "submitted": [], "resolved": []}

    class BoundedExecutor:
        def __init__(self, *, max_workers, initializer, initargs):
            assert max_workers == 2
            initializer(*initargs)

        def map(self, *args, **kwargs):
            pytest.fail("unbounded executor.map must not eagerly queue the archive")

        def submit(self, function, task):
            observed["active"] += 1
            observed["maximum"] = max(observed["maximum"], observed["active"])
            observed["submitted"].append(task)

            class Result:
                def result(self):
                    state = function(task)
                    observed["resolved"].append(task)
                    observed["active"] -= 1
                    return state

            return Result()

        def shutdown(self, *, wait, cancel_futures):
            assert wait and cancel_futures

    monkeypatch.setattr(scanner, "ProcessPoolExecutor", BoundedExecutor)
    result = scanner.prepare_dataset(**inputs, workers=2)
    assert len(observed["submitted"]) == 20
    assert observed["maximum"] == 4
    assert observed["active"] == 0
    assert (
        observed["resolved"] == observed["submitted"] == sorted(observed["submitted"])
    )
    assert result["scan"]["members_completed"] == 20
    sequential = scanner.prepare_dataset(
        **{**inputs, "output_root": inputs["output_root"].parent / "sequential"},
        workers=1,
    )
    assert result == sequential


def test_unverified_label_index_is_rejected_even_after_source_check(
    scanner, inputs, monkeypatch
):
    monkeypatch.setattr(join_labels, "OFFICIAL_ARCHIVE_MD5", "0" * 32)
    with pytest.raises(ValueError, match="official|label"):
        scanner.prepare_dataset(**inputs, workers=1)
    assert not inputs["output_root"].exists()


@pytest.mark.parametrize("workers", [0, -1, True, 1.5])
def test_invalid_worker_count_is_rejected(scanner, inputs, workers):
    with pytest.raises(ValueError, match="workers"):
        scanner.prepare_dataset(**inputs, workers=workers)


def test_scan_state_excludes_large_labels_and_splits_and_tracks_other_hosts(
    scanner, inputs
):
    labels, splits = labels_and_splits(inputs)
    raw_archive(
        inputs["data_root"] / "system_logs_winlogbeat.zip",
        "winlogbeat",
        {"D1_H0": line(raw_event()) + line(raw_event(number=3, host="OTHER"))},
    )
    state = scanner.scan_member(
        inputs["data_root"] / "system_logs_winlogbeat.zip",
        "daily_winlogbeat/D1_H0.jsonl.bz2",
        labels=labels,
        splits=splits,
    )
    assert not {"labels", "splits"} & state.keys()
    assert state["stats"]["raw_rows"] == 2
    assert state["hosts"]["winlogbeat:OTHER"] == 1
    assert state["days"] == Counter({"2025-01-07": 2})
    assert all(key[1] != "OTHER" for key in state["windows"])


def test_merge_preserves_global_earliest_unique_records_and_full_counters(
    scanner, inputs
):
    labels, splits = labels_and_splits(inputs)
    splits["max_records"] = 3
    first, second = (
        WindowCollector(labels=labels, splits=splits),
        WindowCollector(labels=labels, splits=splits),
    )
    for number in [1, 2, 3, 4]:
        first.add(normalized(number, timestamp=f"2025-01-07T12:00:0{number}.000Z"))
    for number in [2, 5, 6]:
        second.add(
            normalized(
                number, timestamp=f"2025-01-07T12:00:0{number}.000Z", member="D1_H1"
            )
        )
    states = [scanner.collector_state(first), scanner.collector_state(second)]
    merged = WindowCollector(labels=labels, splits=splits)
    for state in states:
        scanner.merge_collector_state(merged, state)
    window = next(iter(merged.windows.values()))
    assert window["raw_count"] == 7
    assert len(window["records"]) == 3
    assert len(window["kept"]) == 3
    assert [record[1]["original_timestamp"] for record in window["records"]] == [
        "2025-01-07T12:00:01.000Z",
        "2025-01-07T12:00:02.000Z",
        "2025-01-07T12:00:03.000Z",
    ]
    assert merged.stats["parsed_rows"] == 7
    assert merged.hosts["winlogbeat:CLIENT1.breach.local"] == 7
    assert merged.days["2025-01-07"] == 7
    assert merged.minimum == first.minimum
    assert merged.maximum == second.maximum
    assert len({row[1]["event_fingerprint"] for row in window["records"]}) == 3
    duplicate_representatives = [
        row
        for state in states
        for value in state["windows"].values()
        for row in value["records"]
        if row[1]["original_timestamp"] == "2025-01-07T12:00:02.000Z"
    ]
    assert (
        window["records"][1][1]["external_id"]
        == min(duplicate_representatives, key=lambda row: row[0])[1]["external_id"]
    )
    reverse = WindowCollector(labels=labels, splits=splits)
    for state in reversed(states):
        scanner.merge_collector_state(reverse, state)
    assert reverse.windows == merged.windows


def test_invalid_error_examples_are_bounded_without_losing_row_counts(
    scanner, inputs, monkeypatch
):
    raw_archive(
        inputs["data_root"] / "system_logs_winlogbeat.zip",
        "winlogbeat",
        {f"D1_H{hour}": b"invalid-secret\n" * 50 for hour in range(10)},
    )
    pin_fixture(inputs, monkeypatch)
    result = scanner.prepare_dataset(**inputs, workers=1)
    assert result["scan"]["invalid_rows"] == 500
    assert (
        len(result["scan"]["invalid_examples"])
        == result["scan"]["invalid_example_limit"]
        == 100
    )
    assert "invalid-secret" not in common.canonical(result)
    assert not result["scan"]["freeze_eligible"]


def test_changed_configuration_during_scan_aborts_before_emission(
    scanner, inputs, monkeypatch
):
    original = scanner.scan_member

    def scan(*args, **kwargs):
        state = original(*args, **kwargs)
        with inputs["splits"].open("a", encoding="utf-8") as handle:
            handle.write(" ")
        return state

    monkeypatch.setattr(scanner, "scan_member", scan)
    with pytest.raises(ValueError, match="configuration changed"):
        scanner.prepare_dataset(**inputs, workers=1)
    assert not inputs["output_root"].exists()


def test_worker_initializer_loads_labels_once_for_multiple_member_tasks(
    scanner, inputs, monkeypatch
):
    calls = []
    original = scanner.load_label_index

    def load(path, **kwargs):
        calls.append(path)
        return original(path, **kwargs)

    monkeypatch.setattr(scanner, "load_label_index", load)
    scanner.initialize_worker(
        str(inputs["data_root"] / "system_logs_labels.zip"),
        common.read_json(inputs["splits"]),
    )
    for member in ["D1_H0", "D1_H1"]:
        state = scanner.worker_scan_member(
            (
                str(inputs["data_root"] / "system_logs_winlogbeat.zip"),
                f"daily_winlogbeat/{member}.jsonl.bz2",
            )
        )
        assert state["completed"]
    assert len(calls) == 1


def test_output_root_is_preserved_if_nonempty(scanner, inputs):
    inputs["output_root"].mkdir()
    existing = inputs["output_root"] / "keep.txt"
    existing.write_text("preserve")
    with pytest.raises(FileExistsError):
        scanner.prepare_dataset(**inputs, workers=1)
    assert existing.read_text() == "preserve"


def test_scan_result_is_path_independent(scanner, inputs, tmp_path, monkeypatch):
    first = scanner.prepare_dataset(**inputs, workers=1)
    other = tmp_path / "other-location"
    other.mkdir()
    moved = {**inputs, "data_root": other / "raw", "output_root": other / "prepared"}
    moved["data_root"].mkdir()
    for path in inputs["data_root"].iterdir():
        (moved["data_root"] / path.name).write_bytes(path.read_bytes())
    for key in ["sources", "splits", "label_policy"]:
        moved[key] = other / inputs[key].name
        moved[key].write_bytes(inputs[key].read_bytes())
    second = scanner.prepare_dataset(**moved, workers=1)
    assert first == second
