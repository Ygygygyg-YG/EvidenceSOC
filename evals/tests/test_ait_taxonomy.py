import hashlib
import importlib.util
import json
import zipfile
from datetime import datetime
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "datasets/ait_v2/taxonomy.py"
LOG = "intranet_server/logs/apache2/intranet.price.fox.org-access.log.2"


@pytest.fixture
def taxonomy():
    if not SCRIPT.exists():

        class Missing:
            def __getattr__(self, name):
                pytest.fail("taxonomy implementation missing")

        return Missing()
    spec = importlib.util.spec_from_file_location("taxonomy_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "label,rule,expected",
    [
        ("service_scan", "attacker.service_scan", "reconnaissance"),
        ("wpscan", "attacker.wpscan.time", "reconnaissance"),
        ("dirb", "attacker.dirb.time", "reconnaissance"),
        ("webshell_upload", "attacker.webshell.upload.seq", "webshell_upload"),
        (
            "webshell_cmd",
            "attacker.escalate.webshell.cmd.http",
            "remote_command_execution",
        ),
        (
            "webshell_cmd",
            "attacker.escalate.webshell.cmd.http_prepare_crack",
            "remote_command_execution",
        ),
        ("escalate", "attacker.escalate", None),
        ("foothold", "attacker.webshell.upload.seq", None),
        ("attacker_http", "attacker.service_scan", None),
        ("service_scan", "attacker.service_scan.new", None),
    ],
)
def test_exact_pairs(taxonomy, label, rule, expected):
    result = taxonomy.classify_record({"labels": [label], "rules": {label: [rule]}})
    assert result["is_attack"] is True
    assert result["attack_types"] == ([expected] if expected else [])
    assert result["unmapped_labels"] == ([] if expected else [label])


def test_empty_and_multilabel(taxonomy):
    empty = {"labels": [], "rules": {}, "annotation_status": "unlabeled_unknown"}
    assert taxonomy.classify_record(empty)["is_attack"] is None
    assert (
        taxonomy.classify_record(empty, completeness_verified=True)["is_attack"]
        is False
    )
    result = taxonomy.classify_record(
        {
            "labels": ["dirb", "webshell_upload"],
            "rules": {
                "dirb": ["attacker.dirb.time"],
                "webshell_upload": ["attacker.webshell.upload.seq"],
            },
        }
    )
    assert result["attack_types"] == ["reconnaissance", "webshell_upload"]
    assert len(result["mapping_evidence"]) == 2


@pytest.fixture
def bundle(taxonomy, tmp_path, monkeypatch):
    root = tmp_path / "raw"
    source = root / "gather" / LOG
    labels = root / "labels" / LOG
    source.parent.mkdir(parents=True)
    labels.parent.mkdir(parents=True)
    source.write_bytes(
        (
            b'10.0.0.1 - - [18/Jan/2022:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "test"\n'
        )
        * 2
    )
    labels.write_text(
        json.dumps(
            {"line": 1, "labels": ["dirb"], "rules": {"dirb": ["attacker.dirb.time"]}}
        )
        + "\n",
        encoding="utf-8",
    )
    events = tmp_path / "agent" / "events.jsonl"
    taxonomy._parser.parse_apache_file(
        dataset_root=root,
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG,
        output=events,
        errors=tmp_path / "errors.jsonl",
    )
    gold, report = tmp_path / "gold.jsonl", tmp_path / "join.json"
    taxonomy._join.join_labels(
        dataset_root=root,
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG,
        events=events,
        output=gold,
        report=report,
    )
    archive = tmp_path / "fox_no-pcaps.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.write(source, "fox/gather/" + LOG)
        z.write(labels, "fox/labels/" + LOG)
    monkeypatch.setattr(
        taxonomy, "_OFFICIAL_MD5", hashlib.md5(archive.read_bytes()).hexdigest()
    )
    return {
        "dataset_root": root,
        "events": events,
        "gold": gold,
        "join_report": report,
        "archive": archive,
        "time_from": datetime.fromisoformat("2022-01-18T00:00:00+00:00"),
        "time_to": datetime.fromisoformat("2022-01-19T00:00:00+00:00"),
        "output": tmp_path / "proof.json",
    }


def test_verify_and_map(taxonomy, bundle, tmp_path):
    proof = taxonomy.verify(**bundle)
    assert proof["counts"]["read_events"] == 2
    summary = taxonomy.map_gold(
        gold=bundle["gold"],
        proof=bundle["output"],
        output=tmp_path / "mapped.jsonl",
        report=tmp_path / "mapped.json",
    )
    assert (summary["attack_events"], summary["normal_events"]) == (1, 1)
    assert summary["type_event_counts"]["reconnaissance"] == 1


@pytest.mark.parametrize(
    "target,change",
    [
        ("join_report", lambda r: r.update(truncated=True)),
        ("join_report", lambda r: r.update(read_events=9)),
        ("gold", lambda r: r.update(labels=[])),
        ("events", lambda r: r.update(observed_at="2022-01-18T13:00:00Z")),
        ("events", lambda r: r.update(line_number=2)),
        ("gold", lambda r: r.update(raw_line_sha256="0" * 64)),
    ],
)
def test_verify_rejects_corruption(taxonomy, bundle, target, change):
    path = bundle[target]
    lines = path.read_text(encoding="utf-8").splitlines()
    if target == "join_report":
        row = json.loads(path.read_text(encoding="utf-8"))
        change(row)
        path.write_text(json.dumps(row), encoding="utf-8")
    else:
        row = json.loads(lines[0])
        change(row)
        lines[0] = json.dumps(row)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        taxonomy.verify(**bundle)
    assert not bundle["output"].exists()


@pytest.mark.parametrize(
    "target", ["gold", "events", "join_report", "archive", "raw", "labels"]
)
def test_map_rejects_stale_inputs(taxonomy, bundle, tmp_path, target):
    taxonomy.verify(**bundle)
    path = (
        bundle[target]
        if target not in ("raw", "labels")
        else bundle["dataset_root"] / ("gather" if target == "raw" else "labels") / LOG
    )
    with path.open("ab") as f:
        f.write(b" ")
    with pytest.raises(ValueError):
        taxonomy.map_gold(
            gold=bundle["gold"],
            proof=bundle["output"],
            output=tmp_path / "mapped.jsonl",
            report=tmp_path / "mapped.json",
        )


def test_preview_and_output_guards(taxonomy, bundle, tmp_path):
    taxonomy.verify(**bundle)
    summary = taxonomy.map_gold(
        gold=bundle["gold"],
        proof=bundle["output"],
        output=tmp_path / "preview.jsonl",
        report=tmp_path / "preview.json",
        max_events=1,
    )
    assert summary["truncated"] is True
    with pytest.raises((ValueError, FileExistsError)):
        taxonomy.map_gold(
            gold=bundle["gold"],
            proof=bundle["output"],
            output=bundle["events"],
            report=tmp_path / "bad.json",
        )


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p.update(verified=False),
        lambda p: p.update(dataset_id="ait-v2.1:other"),
        lambda p: p.update(schema_version=True),
        lambda p: p.update(archive_md5="0" * 32),
        lambda p: p["counts"].update(read_events=3),
        lambda p: p["counts"].update(parse_errors=1),
        lambda p: p["inputs"].pop("labels"),
        lambda p: p.update(time_from="2022-01-18T00:00:00"),
    ],
)
def test_map_rejects_invalid_proof(taxonomy, bundle, tmp_path, change):
    proof = taxonomy.verify(**bundle)
    change(proof)
    bundle["output"].write_text(json.dumps(proof), encoding="utf-8")
    output = tmp_path / "mapped.jsonl"
    with pytest.raises(ValueError):
        taxonomy.map_gold(
            gold=bundle["gold"],
            proof=bundle["output"],
            output=output,
            report=tmp_path / "mapped.json",
        )
    assert not output.exists()


@pytest.mark.parametrize("field", ["inputs", "counts"])
def test_cli_rejects_list_proof_sections(taxonomy, bundle, tmp_path, capsys, field):
    proof = taxonomy.verify(**bundle)
    proof[field] = list(proof[field])
    bundle["output"].write_text(json.dumps(proof), encoding="utf-8")
    output, report = tmp_path / "mapped.jsonl", tmp_path / "mapped.json"
    with pytest.raises(SystemExit) as exc:
        taxonomy.main(
            [
                "map",
                "--gold",
                str(bundle["gold"]),
                "--proof",
                str(bundle["output"]),
                "--output",
                str(output),
                "--report",
                str(report),
            ]
        )
    assert exc.value.code == 2
    assert "error:" in capsys.readouterr().err
    assert not output.exists()
    assert not report.exists()


@pytest.mark.parametrize(
    "failure",
    [
        "naive",
        "outside",
        "missing_label",
        "archive_mismatch",
        "short_events",
        "extra_gold",
        "label_bounds",
        "wrong_source",
    ],
)
def test_verify_rejects_incomplete_streams(taxonomy, bundle, failure):
    labels = bundle["dataset_root"] / "labels" / LOG
    if failure == "naive":
        bundle["time_from"] = datetime(2022, 1, 18)  # noqa: DTZ001 intentional invalid input
    elif failure == "outside":
        bundle["time_to"] = datetime.fromisoformat("2022-01-18T12:00:00+00:00")
    elif failure == "missing_label":
        labels.unlink()
    elif failure == "archive_mismatch":
        labels.write_bytes(b"")
    elif failure == "short_events":
        bundle["events"].write_text(
            bundle["events"].read_text(encoding="utf-8").splitlines()[0] + "\n",
            encoding="utf-8",
        )
    elif failure == "extra_gold":
        with bundle["gold"].open("ab") as stream:
            stream.write(b"{}\n")
    elif failure == "wrong_source":
        row = json.loads(bundle["join_report"].read_text(encoding="utf-8"))
        row["relative_log_path"] = "web/logs/apache2/other.log"
        bundle["join_report"].write_text(json.dumps(row), encoding="utf-8")
    elif failure == "label_bounds":
        row = json.loads(labels.read_text(encoding="utf-8"))
        row["line"] = 3
        labels.write_text(json.dumps(row) + "\n", encoding="utf-8")
        with zipfile.ZipFile(bundle["archive"], "w") as archive:
            archive.write(bundle["dataset_root"] / "gather" / LOG, "fox/gather/" + LOG)
            archive.write(labels, "fox/labels/" + LOG)
        taxonomy._OFFICIAL_MD5 = hashlib.md5(bundle["archive"].read_bytes()).hexdigest()
    with pytest.raises((ValueError, FileNotFoundError)):
        taxonomy.verify(**bundle)
    assert not bundle["output"].exists()
