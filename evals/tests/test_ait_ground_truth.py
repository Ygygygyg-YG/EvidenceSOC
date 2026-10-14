import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "datasets/ait_v2/join_labels.py"
LOG = "web/logs/apache2/access.log"


@pytest.fixture
def joiner():
    if not SCRIPT.exists():

        class MissingJoiner:
            def __getattr__(self, name):
                pytest.fail("AIT label join implementation is missing")

        return MissingJoiner()
    spec = importlib.util.spec_from_file_location("ait_join", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def inputs(tmp_path):
    root = tmp_path / "raw"
    source = root / "gather" / LOG
    label = root / "labels" / LOG
    source.parent.mkdir(parents=True)
    label.parent.mkdir(parents=True)
    source.write_bytes(b"one\r\n\ntwo\n")
    label.write_text(
        json.dumps({"line": 2, "labels": ["scan"], "rules": {"scan": ["r"]}}) + "\n",
        encoding="utf-8",
    )
    events = tmp_path / "agent" / "events.jsonl"
    events.parent.mkdir()
    records = []
    for n, raw in enumerate(source.read_bytes().splitlines(keepends=True), 1):
        key = json.dumps(["ait-v2.1:fox", LOG, n], separators=(",", ":")).encode()
        records.append(
            {
                "dataset_id": "ait-v2.1:fox",
                "relative_log_path": LOG,
                "line_number": n,
                "external_id": "ait:" + hashlib.sha256(key).hexdigest(),
                "raw_line_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    events.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return {
        "dataset_root": root,
        "dataset_id": "ait-v2.1:fox",
        "relative_log_path": LOG,
        "events": events,
        "output": tmp_path / "gold" / "gold.jsonl",
        "report": tmp_path / "reports" / "join.json",
    }


def test_sparse_join_preserves_unknown_and_input(joiner, inputs):
    before = inputs["events"].read_bytes()
    summary = joiner.join_labels(**inputs)
    rows = [json.loads(x) for x in inputs["output"].read_text().splitlines()]
    assert [x["annotation_status"] for x in rows] == [
        "unlabeled_unknown",
        "labeled",
        "unlabeled_unknown",
    ]
    assert rows[1]["rules"] == {"scan": ["r"]}
    assert not {"is_attack", "attack_types", "raw_line", "message"} & rows[0].keys()
    assert inputs["events"].read_bytes() == before
    assert summary["labeled_events"] == 1
    assert summary["unlabeled_unknown_events"] == 2
    assert summary["raw_line_count"] == 3
    assert summary["labels_complete_read"] and summary["label_bounds_verified"]
    assert summary["labels_hash_scope"] == "complete"


@pytest.mark.parametrize(
    "field,value",
    [
        ("dataset_id", "ait-v2.1:other"),
        ("relative_log_path", "else/logs/access"),
        ("external_id", "bad"),
        ("raw_line_sha256", "0" * 64),
        ("line_number", True),
        ("labels", []),
    ],
)
def test_rejects_event_corruption_and_cleans_outputs(joiner, inputs, field, value):
    rows = [json.loads(x) for x in inputs["events"].read_text().splitlines()]
    rows[1][field] = value
    inputs["events"].write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises(ValueError):
        joiner.join_labels(**inputs)
    assert not inputs["output"].exists()
    assert not inputs["report"].exists()


@pytest.mark.parametrize(
    "annotations",
    [
        [{"line": 4, "labels": [], "rules": {}}],
        [{"line": 2, "labels": []}],
        [{"line": 2, "labels": "bad", "rules": {}}],
        [
            {"line": 2, "labels": [], "rules": {}},
            {"line": 2, "labels": [], "rules": {}},
        ],
        [
            {"line": 2, "labels": [], "rules": {}},
            {"line": 1, "labels": [], "rules": {}},
        ],
    ],
)
def test_rejects_invalid_annotations(joiner, inputs, annotations):
    (inputs["dataset_root"] / "labels" / LOG).write_text(
        "".join(json.dumps(r) + "\n" for r in annotations)
    )
    with pytest.raises(ValueError):
        joiner.join_labels(**inputs)
    assert not inputs["output"].exists()


def test_empty_label_remains_unknown(joiner, inputs):
    (inputs["dataset_root"] / "labels" / LOG).write_text(
        '{"line":2,"labels":[],"rules":{}}\n'
    )
    summary = joiner.join_labels(**inputs)
    assert summary["matched_annotation_lines"] == 1
    assert summary["labeled_events"] == 0


def test_preview_does_not_validate_unread_tail(joiner, inputs):
    label = inputs["dataset_root"] / "labels" / LOG
    label.write_bytes(b'{"line":2,"labels":[],"rules":{}}\ninvalid tail\n')
    summary = joiner.join_labels(**inputs, max_events=1)
    assert summary["truncated"]
    assert not summary["labels_complete_read"]
    assert not summary["label_bounds_verified"]
    assert summary["labels_hash_scope"] == "prefix"
    assert summary["unmatched_annotation_lines"] == 0


@pytest.mark.parametrize(
    "annotation",
    [
        {"line": 2, "labels": [], "rules": {"scan": ["r"]}},
        {"line": 2, "labels": ["scan"], "rules": {}},
    ],
)
def test_annotation_labels_and_rules_agree(joiner, inputs, annotation):
    (inputs["dataset_root"] / "labels" / LOG).write_text(json.dumps(annotation) + "\n")
    with pytest.raises(ValueError):
        joiner.join_labels(**inputs)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_json_is_rejected(joiner, inputs, constant):
    (inputs["dataset_root"] / "labels" / LOG).write_text(
        '{"line":2,"labels":[],"rules":{},"extra":' + constant + "}\n"
    )
    with pytest.raises(ValueError):
        joiner.join_labels(**inputs)


@pytest.mark.parametrize("destination", ["raw", "agent", "same", "existing"])
def test_output_protection(joiner, inputs, destination):
    if destination == "raw":
        inputs["output"] = inputs["dataset_root"] / "gold.jsonl"
    elif destination == "agent":
        inputs["output"] = inputs["events"].parent / "gold.jsonl"
    elif destination == "same":
        inputs["report"] = inputs["output"]
    else:
        inputs["output"].parent.mkdir()
        inputs["output"].write_bytes(b"keep")
    with pytest.raises((ValueError, FileExistsError)):
        joiner.join_labels(**inputs)
    if destination == "existing":
        assert inputs["output"].read_bytes() == b"keep"


def test_direct_cli(joiner, inputs):
    args = [sys.executable, str(SCRIPT)]
    for flag, key in [
        ("dataset-root", "dataset_root"),
        ("dataset-id", "dataset_id"),
        ("log-path", "relative_log_path"),
        ("events", "events"),
        ("output", "output"),
        ("report", "report"),
    ]:
        args.extend(["--" + flag, str(inputs[key])])
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["read_events"] == 3


def test_missing_label_file(joiner, inputs):
    (inputs["dataset_root"] / "labels" / LOG).unlink()
    with pytest.raises(FileNotFoundError):
        joiner.join_labels(**inputs)
    assert not inputs["output"].exists()


@pytest.mark.parametrize("order", [[1, 1], [2, 1]])
def test_event_order_is_strict(joiner, inputs, order):
    rows = [json.loads(x) for x in inputs["events"].read_text().splitlines()]
    inputs["events"].write_text("".join(json.dumps(rows[n - 1]) + "\n" for n in order))
    with pytest.raises(ValueError, match="strictly increasing"):
        joiner.join_labels(**inputs)
    assert not inputs["output"].exists()


@pytest.mark.parametrize(
    "payload",
    [b"not json\n", b"\xff\n", b'{"line":1,"line":2,"labels":[],"rules":{}}\n'],
)
def test_bad_label_json(joiner, inputs, payload):
    (inputs["dataset_root"] / "labels" / LOG).write_bytes(payload)
    with pytest.raises(ValueError):
        joiner.join_labels(**inputs)
    assert not inputs["output"].exists()


def test_report_in_agent_directory(joiner, inputs):
    inputs["report"] = inputs["events"].parent / "report.json"
    with pytest.raises(ValueError):
        joiner.join_labels(**inputs)


@pytest.mark.parametrize("path_key", ["events", "output"])
def test_reparse_input_and_output_rejected(joiner, inputs, monkeypatch, path_key):
    import os
    import stat
    from types import SimpleNamespace

    original = os.lstat
    blocked = inputs[path_key].absolute()

    def lstat(path, *args, **kwargs):
        if Path(path).absolute() == blocked:
            return SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
            )
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    with pytest.raises(ValueError, match="filesystem links"):
        joiner.join_labels(**inputs)
    assert not inputs["output"].exists()
