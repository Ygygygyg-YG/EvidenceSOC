"""Complete-member checkpoints remain subordinate to fresh source checks."""

import hashlib
import threading
from concurrent.futures import Future
from pathlib import Path

import pytest

from evals.datasets.dedale import common
from evals.tests.test_dedale_scan import labels_and_splits

pytest_plugins = ("evals.tests.test_dedale_scan",)


def inventory(root):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def make_store(inputs, root):
    from evals.datasets.dedale.checkpoint import MemberCheckpoints
    from evals.datasets.dedale.parse import ARCHIVE_SOURCES, read_archive_manifest

    labels, splits = labels_and_splits(inputs)
    hashes = {key: common.sha256(inputs[key]) for key in ("sources", "splits", "label_policy")}
    hashes.update({f"archive:{path.name}": common.sha256(path)
                   for path in inputs["data_root"].glob("*.zip")})
    md5 = {(archive, member): digest for archive in ARCHIVE_SOURCES
           for member, digest in read_archive_manifest(inputs["data_root"] / archive)["checksums"].items()}
    return MemberCheckpoints(root, data_root=inputs["data_root"], output_root=inputs["output_root"],
                             input_hashes=hashes, member_md5=md5, labels=labels, splits=splits)


def interrupt_after_one(scanner, inputs, monkeypatch, checkpoint_root):
    original = scanner.scan_member
    calls = []

    def interrupted(path, member, **kwargs):
        calls.append((Path(path).name, member))
        if len(calls) == 2:
            raise RuntimeError("synthetic interruption before member completes")
        return original(path, member, **kwargs)

    monkeypatch.setattr(scanner, "scan_member", interrupted)
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        scanner.prepare_dataset(**inputs, workers=1, checkpoint_root=checkpoint_root)
    monkeypatch.setattr(scanner, "scan_member", original)
    return calls


def test_resume_reuses_only_complete_members_and_reverifies_all_sources(
    scanner, inputs, tmp_path, monkeypatch
):
    checkpoint_root = tmp_path / "checkpoint"
    checks = []
    verify = scanner.verify_sources

    def verify_fresh(*args, **kwargs):
        checks.append(kwargs)
        return verify(*args, **kwargs)

    monkeypatch.setattr(scanner, "verify_sources", verify_fresh)
    interrupted_calls = interrupt_after_one(scanner, inputs, monkeypatch, checkpoint_root)
    original, resumed_calls = scanner.scan_member, []

    def resumed(path, member, **kwargs):
        resumed_calls.append((Path(path).name, member))
        return original(path, member, **kwargs)

    monkeypatch.setattr(scanner, "scan_member", resumed)
    result = scanner.prepare_dataset(**inputs, workers=1, checkpoint_root=checkpoint_root)
    assert checks == [{"check_crc": True}, {"check_crc": True}]
    assert interrupted_calls[0] not in resumed_calls
    assert interrupted_calls[1] in resumed_calls
    assert len(resumed_calls) == 3
    assert result["scan"]["members_completed"] == 4
    fresh = {**inputs, "output_root": tmp_path / "without-checkpoints"}
    assert result == scanner.prepare_dataset(**fresh, workers=1)
    assert inventory(inputs["output_root"]) == inventory(fresh["output_root"])


def test_resume_cannot_skip_source_verification(scanner, inputs, tmp_path, monkeypatch):
    checkpoint_root = tmp_path / "checkpoint"
    interrupt_after_one(scanner, inputs, monkeypatch, checkpoint_root)
    archive = inputs["data_root"] / "system_logs_auditbeat.zip"
    with archive.open("r+b") as stream:
        stream.write(b"tampered")
    with pytest.raises(ValueError, match="checksum|MD5|archive"):
        scanner.prepare_dataset(**inputs, workers=1, checkpoint_root=checkpoint_root)
    assert not inputs["output_root"].exists()


@pytest.mark.parametrize("change", ["corrupt", "configuration", "code"])
def test_resume_rejects_corrupt_or_stale_checkpoints(
    scanner, inputs, tmp_path, monkeypatch, change
):
    checkpoint_root = tmp_path / "checkpoint"
    interrupt_after_one(scanner, inputs, monkeypatch, checkpoint_root)
    if change == "corrupt":
        member = next(checkpoint_root.glob("member-*.json"))
        member.write_text("{\"broken\":true}", encoding="utf-8")
    elif change == "configuration":
        with inputs["splits"].open("a", encoding="utf-8") as handle:
            handle.write(" ")
    else:
        from evals.datasets.dedale import checkpoint

        original = checkpoint.code_hashes

        def changed():
            return {**original(), "parse.py": hashlib.sha256(b"changed code").hexdigest()}

        monkeypatch.setattr(checkpoint, "code_hashes", changed)
    with pytest.raises(ValueError, match="checkpoint"):
        scanner.prepare_dataset(**inputs, workers=1, checkpoint_root=checkpoint_root)
    assert not inputs["output_root"].exists()


def test_checkpoint_directory_cannot_be_shared_by_crosspath_build(
    scanner, inputs, tmp_path, monkeypatch
):
    checkpoint_root = tmp_path / "checkpoint"
    interrupt_after_one(scanner, inputs, monkeypatch, checkpoint_root)
    other = {**inputs, "output_root": tmp_path / "other-output"}
    with pytest.raises(ValueError, match="checkpoint.*(owner|build|root)"):
        scanner.prepare_dataset(**other, workers=1, checkpoint_root=checkpoint_root)


def test_checkpointed_late_projection_and_parallel_resume_match_all_frozen_bytes(
    scanner, inputs, tmp_path, monkeypatch
):
    baseline = scanner.prepare_dataset(**inputs, workers=1)
    paths = {**inputs, "output_root": tmp_path / "resumed"}
    checkpoint_root = tmp_path / "checkpoint"
    interrupt_after_one(scanner, paths, monkeypatch, checkpoint_root)

    class InlineExecutor:
        def __init__(self, *, initializer, initargs, **kwargs):
            initializer(*initargs)

        def submit(self, function, task):
            result = Future()
            result.set_result(function(task))
            return result

        def shutdown(self, **kwargs):
            pass

    monkeypatch.setattr(scanner, "ProcessPoolExecutor", InlineExecutor)
    resumed = scanner.prepare_dataset(
        **paths, workers=3, late_projection=True, checkpoint_root=checkpoint_root
    )
    assert baseline == resumed
    assert inventory(inputs["output_root"]) == inventory(paths["output_root"])


def test_checkpoint_cli_forwarded_by_both_entrypoints(scanner, monkeypatch, tmp_path):
    from evals.datasets.dedale import build_manifests

    seen = []

    def prepare(**kwargs):
        seen.append(kwargs)
        return {"status": "test", "N_D": 0, "M_D": 0}

    monkeypatch.setattr(scanner, "prepare_dataset", prepare)
    arguments = [
        value
        for name in ("sources", "splits", "label-policy", "data-root", "output-root")
        for value in ("--" + name, str(tmp_path / name))
    ] + ["--checkpoint-root", str(tmp_path / "checkpoint")]
    assert scanner.main(arguments) == build_manifests.main(arguments) == 0
    assert [row["checkpoint_root"] for row in seen] == [tmp_path / "checkpoint"] * 2


def test_finished_parallel_members_checkpoint_before_canonical_head_completes(
    scanner, inputs, tmp_path, monkeypatch
):
    from evals.datasets.dedale import checkpoint

    waiting, saved_later, released = threading.Event(), threading.Event(), threading.Event()
    first = []
    saved = []
    original_save = checkpoint.MemberCheckpoints.save

    def save(self, state):
        original_save(self, state)
        saved.append((state["archive"], state["member"]))
        if not released.is_set():
            saved_later.set()

    class DelayedExecutor:
        def __init__(self, *, initializer, initargs, **kwargs):
            initializer(*initargs)

        def submit(self, function, task):
            result = Future()
            state = function(task)
            if not first:
                first.append((result, state))
                waiting.set()
            else:
                result.set_result(state)
            return result

        def shutdown(self, **kwargs):
            pass

    monkeypatch.setattr(checkpoint.MemberCheckpoints, "save", save)
    monkeypatch.setattr(scanner, "ProcessPoolExecutor", DelayedExecutor)
    errors = []

    def prepare():
        try:
            scanner.prepare_dataset(**inputs, workers=2, checkpoint_root=tmp_path / "checkpoint")
        except BaseException as exc:  # noqa: BLE001 - propagate background failures to this test
            errors.append(exc)

    thread = threading.Thread(target=prepare)
    thread.start()
    try:
        assert waiting.wait(5)
        assert saved_later.wait(5), "completed later member was held behind unfinished first member"
        assert saved[0] != (first[0][1]["archive"], first[0][1]["member"])
    finally:
        released.set()
        if first:
            first[0][0].set_result(first[0][1])
        thread.join(timeout=10)
    assert not thread.is_alive()
    assert not errors


def test_checkpoint_build_lock_rejects_duplicate_run_and_releases_after_close(inputs, tmp_path):
    root = tmp_path / "checkpoint"
    first = make_store(inputs, root)
    try:
        with pytest.raises(ValueError, match="checkpoint.*(active|lock|running)"):
            make_store(inputs, root)
    finally:
        if hasattr(first, "close"):
            first.close()
    second = make_store(inputs, root)
    second.close()


@pytest.mark.parametrize("change", [
    "incomplete", "unverified", "bool_count", "counter_conservation", "unknown_counter",
    "bad_window_count", "window_time", "too_many_records", "record_provenance", "record_time",
    "record_label", "extra_record_field", "invalid_nested_shape", "unknown_matched_label",
    "wrong_member_md5", "extra_state_field", "bad_sort_key", "unscoped_window", "projection_flag",
    "bool_schema",
])
def test_strict_checkpoint_rejects_inconsistent_schema_even_with_recomputed_selfhash(
    scanner, inputs, tmp_path, monkeypatch, change
):
    root = tmp_path / "checkpoint"
    interrupt_after_one(scanner, inputs, monkeypatch, root)
    path = next(root.glob("member-*.json"))
    envelope = common.read_json(path)
    state = envelope["state"]
    window = state["windows"][0]
    record = window["records"][0]
    if change == "incomplete":
        state["completed"] = False
    elif change == "unverified":
        state["jsonl_md5_verified"] = False
    elif change == "bool_count":
        state["stats"]["raw_rows"] = True
    elif change == "counter_conservation":
        state["stats"]["parsed_rows"] += 1
    elif change == "unknown_counter":
        state["stats"]["invented"] = 1
    elif change == "bad_window_count":
        window["raw_count"] += 1
    elif change == "window_time":
        window["key"][2] = "2024-01-01T00:00:00Z"
    elif change == "too_many_records":
        window["records"] *= 101
    elif change == "record_provenance":
        record["event"]["line_number"] += 1
    elif change == "record_time":
        record["event"]["observed_at"] = "2025-01-08T00:00:00Z"
    elif change == "record_label":
        record["label"] = "benign"
    elif change == "extra_record_field":
        record["event"]["is_attack"] = True
    elif change == "invalid_nested_shape":
        record["event"]["process"] = None
    elif change == "unknown_matched_label":
        state["matched_labels"].append(["auditbeat", "0" * 64])
    elif change == "wrong_member_md5":
        envelope["jsonl_md5"] = "0" * 32
    elif change == "extra_state_field":
        state["made_up"] = 1
    elif change == "bad_sort_key":
        record["order"][1] = "different"
    elif change == "unscoped_window":
        window["key"][1] = "other-host"
    elif change == "projection_flag":
        record["event"]["projection_truncated"] = False
    elif change == "bool_schema":
        envelope["schema_version"] = True
    payload = {key: value for key, value in envelope.items() if key != "payload_sha256"}
    envelope["payload_sha256"] = hashlib.sha256(common.canonical(payload).encode()).hexdigest()
    path.write_text(common.canonical(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="checkpoint"):
        scanner.prepare_dataset(**inputs, workers=1, checkpoint_root=root)
    assert not inputs["output_root"].exists()


@pytest.mark.parametrize("payload", [
    '{"duplicate":1,"duplicate":2}', '{"nonfinite":NaN}', '{"overflow":1e9999}',
    '{"surrogate":"\\ud800"}', '[', '{"schema_version":true}',
])
def test_checkpoint_reader_rejects_non_strict_json(scanner, inputs, tmp_path, monkeypatch, payload):
    root = tmp_path / "checkpoint"
    interrupt_after_one(scanner, inputs, monkeypatch, root)
    next(root.glob("member-*.json")).write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError, match="checkpoint"):
        scanner.prepare_dataset(**inputs, workers=1, checkpoint_root=root)


def test_unfinished_pending_member_is_reread(scanner, inputs, tmp_path, monkeypatch):
    root = tmp_path / "checkpoint"
    calls = interrupt_after_one(scanner, inputs, monkeypatch, root)
    original = scanner.scan_member
    store = make_store(inputs, root)
    try:
        pending = root / (store._name(*calls[1]) + ".pending")
        pending.write_text('{"completed":true}', encoding="utf-8")
    finally:
        store.close()
    read = []

    def record(path, member, **kwargs):
        read.append((Path(path).name, member))
        return original(path, member, **kwargs)

    monkeypatch.setattr(scanner, "scan_member", record)
    scanner.prepare_dataset(**inputs, workers=1, checkpoint_root=root)
    assert calls[0] not in read and calls[1] in read
    assert not pending.exists()


def test_failed_member_md5_never_creates_a_completed_checkpoint(scanner, inputs, tmp_path, monkeypatch):
    from evals.tests.test_dedale_scan import line, pin_fixture, raw_archive, raw_event

    raw_archive(inputs["data_root"] / "system_logs_auditbeat.zip", "auditbeat",
                {"D1_H0": line(raw_event("auditbeat"))}, corrupt_md5=True)
    pin_fixture(inputs, monkeypatch)
    root = tmp_path / "checkpoint"
    with pytest.raises(ValueError, match="MD5"):
        scanner.prepare_dataset(**inputs, workers=1, checkpoint_root=root)
    assert not list(root.glob("member-*.json"))
    assert not inputs["output_root"].exists()


def test_parallel_checkpoint_write_failure_propagates_before_cases_emit(
    scanner, inputs, tmp_path, monkeypatch
):
    from evals.datasets.dedale import checkpoint

    def failed(*args):
        raise ValueError("checkpoint synthetic persistence error")

    class InlineExecutor:
        def __init__(self, *, initializer, initargs, **kwargs):
            initializer(*initargs)

        def submit(self, function, task):
            result = Future()
            result.set_result(function(task))
            return result

        def shutdown(self, **kwargs):
            pass

    monkeypatch.setattr(checkpoint.MemberCheckpoints, "save", failed)
    monkeypatch.setattr(scanner, "ProcessPoolExecutor", InlineExecutor)
    with pytest.raises(ValueError, match="persistence error"):
        scanner.prepare_dataset(**inputs, workers=2, checkpoint_root=tmp_path / "checkpoint")
    assert not inputs["output_root"].exists()
