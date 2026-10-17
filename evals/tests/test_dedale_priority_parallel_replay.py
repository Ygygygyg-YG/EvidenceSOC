"""Real spawn replay must retain the serial oracle and transport failures."""
import bz2
import hashlib
import json
import struct
from copy import deepcopy
from zipfile import BadZipFile, ZipFile

import pytest

from evals.datasets.dedale.common import canonical
from evals.datasets.dedale.join_labels import LabelIndex
from evals.datasets.dedale.neutralize import neutral_case_id, shift_seconds
from evals.datasets.dedale.parse import event_fingerprint
from evals.datasets.dedale.priority_audit import replay_windows
from evals.tests.test_dedale_neutralize import raw


def replay_inputs(tmp_path, *, corruption=None):
    starts = ["2025-01-07T00:00:00Z", "2025-01-07T00:30:00Z", "2025-01-07T02:00:00Z",
              "2025-01-07T01:00:00Z"]
    windows = [{"case_id": neutral_case_id("auditbeat", "internalserver", start),
                "source": "auditbeat", "host": "internalserver", "time_from": start,
                "time_to": shift_seconds(start, 1800), "candidate_kind": "attack"} for start in starts]
    first = [{**raw(shift_seconds(starts[0], number), number),
              "event": {"action": "process.start" if number % 2 else "ordinary"}}
             for number in range(114)]
    values = {"a": [*first, raw(starts[1], 200)],
              "b": [raw(starts[2], 300), raw(shift_seconds(starts[2], 1), 301)],
              "y": [raw(starts[1], 400), raw(starts[3], 401)],
              "z": [first[0], first[-1], first[0]]}
    index, signatures = [], []
    archive = tmp_path / "system_logs_auditbeat.zip"
    with ZipFile(archive, "w") as target:
        for name, rows in values.items():
            payload = b"".join((canonical(row) + "\n").encode() for row in rows)
            checksum = "0" * 32 if corruption == "md5" and name == "b" else hashlib.md5(payload).hexdigest()
            member = f"daily_auditbeat/{name}.jsonl.bz2"
            target.writestr(member, bz2.compress(payload))
            signatures.append(f"{checksum}  ./{name}.jsonl\n")
            index.append({"archive": archive.name, "member": member, "source": "auditbeat",
                          "minimum": rows[0]["@timestamp"], "maximum": rows[-1]["@timestamp"],
                          "hosts": {"auditbeat:internalserver": len(rows)}, "raw_rows": len(rows),
                          "jsonl_md5": checksum, "jsonl_md5_verified": True})
        target.writestr("daily_auditbeat/auditbeat_md5sum.sig", "".join(signatures))
    if corruption == "crc":
        data = bytearray(archive.read_bytes())
        offset = 0
        while (offset := data.find(b"PK\x01\x02", offset)) != -1:
            length = struct.unpack_from("<H", data, offset + 28)[0]
            if data[offset + 46:offset + 46 + length] == b"daily_auditbeat/b.jsonl.bz2":
                data[offset + 16] ^= 1
                break
            offset += 4
        else:
            raise AssertionError("fixture central directory member missing")
        archive.write_bytes(data)
    if corruption == "rows":
        index[1]["raw_rows"] += 1
    malicious, related = event_fingerprint(first[-1]), event_fingerprint(values["b"][0])
    labels = LabelIndex(
        class_1={"auditbeat": frozenset({malicious}), "winlogbeat": frozenset()},
        class_1_and_2={"auditbeat": frozenset({malicious, related}), "winlogbeat": frozenset()},
        fingerprint_hosts={"auditbeat": {malicious: "internalserver", related: "internalserver"}, "winlogbeat": {}},
        entries={}, official_verified=True, exhaustive=True, summary={})
    # Geometry order differs from component order and member order from ZIP order.
    return [windows[2], windows[0], windows[1], windows[3]], list(reversed(index)), labels


def test_spawn_replay_matches_complete_serial_output_with_shared_members(tmp_path, monkeypatch):
    windows, index, labels = replay_inputs(tmp_path)
    serial = replay_windows(windows, data_root=tmp_path, index=index, labels=labels)
    # Child-only profiling observes the unchanged real decoder, without replacing it.
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "sitecustomize.py").write_text(
        "import json, os, sys\n"
        f"trace_root = {str(profile)!r}\n"
        "def record(frame, event, arg):\n"
        "    if event == 'return' and frame.f_code.co_name == 'decode_event' and arg is not None:\n"
        "        with open(os.path.join(trace_root, str(os.getpid()) + '.jsonl'), 'a', encoding='utf-8') as out:\n"
        "            out.write(json.dumps([arg.archive, arg.relative_log_path, arg.line_number]) + '\\n')\n"
        "sys.setprofile(record)\n", encoding="utf-8")
    import os
    monkeypatch.setenv("PYTHONPATH", str(profile) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    parallel = replay_windows(windows, data_root=tmp_path, index=index, labels=labels, workers=2)
    assert canonical(parallel) == canonical(serial)
    decoded = [tuple(json.loads(line)) for path in profile.glob("*.jsonl") for line in path.read_text().splitlines()]
    expected = {(row["archive"], row["member"], line) for row in index for line in range(1, row["raw_rows"] + 1)}
    assert len(decoded) == len(expected)
    assert set(decoded) == expected
    assert list(parallel) == [window["case_id"] for window in windows]
    shared = parallel[windows[1]["case_id"]]
    assert shared["projected_count"] == 100
    assert shared["duplicate_retained_rows"] > 0
    assert shared["projected_labels"]["malicious"] == 1
    assert [row["member"] for row in shared["priority_pass"]] == [
        "daily_auditbeat/z.jsonl.bz2", "daily_auditbeat/y.jsonl.bz2", "daily_auditbeat/a.jsonl.bz2"]


def test_transitive_shared_members_form_one_component(tmp_path):
    from evals.datasets.dedale.priority_audit import _replay_components

    windows, index, _ = replay_inputs(tmp_path)
    components = _replay_components(windows, index)
    assert components == [[windows[0]], windows[1:]]


@pytest.mark.parametrize(("corruption", "error", "message"), [
    ("md5", ValueError, "MD5"), ("crc", BadZipFile, "CRC"), ("rows", ValueError, "row count")])
def test_spawn_replay_propagates_transport_failure(tmp_path, corruption, error, message):
    windows, index, labels = replay_inputs(tmp_path, corruption=corruption)
    with pytest.raises(error, match=message):
        replay_windows(windows, data_root=tmp_path, index=index, labels=labels, workers=2)


@pytest.mark.parametrize("workers", [True, False, 0, -1, 9, 1.0, "2", None])
def test_replay_worker_count_rejects_invalid_values(tmp_path, workers):
    with pytest.raises(ValueError, match="workers"):
        replay_windows([], data_root=tmp_path, index=[], labels=None, workers=workers)


@pytest.mark.parametrize("workers", [1, 2])
def test_replay_rejects_duplicate_window_before_raw_io(tmp_path, workers):
    windows, index, labels = replay_inputs(tmp_path)
    windows.append(deepcopy(windows[0]))
    with pytest.raises(ValueError, match="duplicate neutral window"):
        replay_windows(windows, data_root=tmp_path / "missing", index=index, labels=labels, workers=workers)


@pytest.mark.parametrize("workers", [1, 2])
def test_replay_rejects_conflicting_inventory_before_raw_io(tmp_path, workers):
    windows, index, labels = replay_inputs(tmp_path)
    index.append({**index[-1], "raw_rows": index[-1]["raw_rows"] + 1})
    with pytest.raises(ValueError, match="conflicting raw member"):
        replay_windows(windows, data_root=tmp_path / "missing", index=index, labels=labels, workers=workers)


def test_priority_dispatch_propagates_replay_workers(tmp_path, monkeypatch):
    from evals.datasets.dedale import priority_audit
    from evals.datasets.dedale.audit import audit_prepared

    received = {}

    def capture(selection, cases_root, **kwargs):
        received.update(kwargs)
        return {"accepted": False}

    monkeypatch.setattr(priority_audit, "audit_priority_prepared", capture)
    audit_prepared({"protocol": "dedale-public-priority-v4"}, tmp_path, replay_workers=8)
    assert received["replay_workers"] == 8


@pytest.mark.parametrize("workers", [None, 2, 8])
def test_final_audit_cli_propagates_replay_workers(tmp_path, monkeypatch, workers):
    from scripts import dedale_task12_final_audit as cli

    (tmp_path / "selection.json").write_text(canonical({"protocol": "dedale-public-priority-v4"}))
    received = {}

    def capture(selection, cases_root, **kwargs):
        received.update(kwargs)
        return {"accepted": False, "failed_gates": ["fixture"]}

    monkeypatch.setattr(cli, "audit_prepared", capture)
    argv = [item for name in ("sources", "scan-splits", "splits", "label-policy", "data-root", "cases-root",
                             "prepared-root", "preparation-checkpoints") for item in ("--" + name, str(tmp_path))]
    argv.extend(["--output", str(tmp_path / "audit.json")])
    if workers is not None:
        argv.extend(["--replay-workers", str(workers)])
    assert cli.main(argv) == 1
    assert received["replay_workers"] == (1 if workers is None else workers)
