import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "datasets/ait_v2/taxonomy.py"
LOG = "intranet_server/logs/audit/audit.log"
VERSION = "fox-intranet-audit-taxonomy-v1"
START = "attacker.escalate.audit.sudo.command.start"
EVENTS = "attacker.escalate.audit.sudo.command.events"


@pytest.fixture
def taxonomy():
    spec = importlib.util.spec_from_file_location("audit_taxonomy_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "label,rules,expected",
    [
        ("escalated_sudo_command", [START], ["privilege_escalation"]),
        ("escalated_sudo_command", [EVENTS], ["privilege_escalation"]),
        ("escalated_sudo_command", [START, EVENTS], ["privilege_escalation"]),
        ("escalate", [START], []),
        ("escalated_command", [EVENTS], []),
        ("escalated_sudo_command", [EVENTS + ".new"], []),
        ("escalated_su_command", ["attacker.escalate.audit.su.login"], []),
        ("escalated_sudo_command", ["attacker.escalate.audit.systemd.session"], []),
        ("service_scan", ["attacker.service_scan"], []),
    ],
)
def test_exact_audit_pairs(taxonomy, label, rules, expected):
    result = taxonomy.classify_record(
        {"relative_log_path": LOG, "labels": [label], "rules": {label: rules}}
    )
    assert result["attack_types"] == expected
    assert result["is_attack"] is True
    assert result["taxonomy_version"] == VERSION
    assert len(result["mapping_evidence"]) == (len(rules) if expected else 0)
    assert result["unmapped_labels"] == ([] if expected else [label])


@pytest.mark.parametrize("path", ["internal_share/logs/audit/audit.log", "", None, []])
def test_unsupported_scope(taxonomy, path):
    with pytest.raises(ValueError):
        taxonomy.classify_record({"relative_log_path": path, "labels": [], "rules": {}})


def test_pure_normal_and_apache_compatibility(taxonomy):
    row = {
        "relative_log_path": LOG,
        "labels": [],
        "rules": {},
        "annotation_status": "unlabeled_unknown",
    }
    assert taxonomy.classify_record(row)["is_attack"] is None
    assert (
        taxonomy.classify_record(row, completeness_verified=True)["is_attack"] is False
    )
    legacy = taxonomy.classify_record(
        {
            "labels": ["escalated_sudo_command"],
            "rules": {"escalated_sudo_command": [START]},
        }
    )
    assert legacy["attack_types"] == []
    assert legacy["taxonomy_version"] == "fox-apache-taxonomy-v1"


@pytest.fixture
def bundle(taxonomy, tmp_path, monkeypatch):
    root = tmp_path / "raw"
    source, labels = root / "gather" / LOG, root / "labels" / LOG
    source.parent.mkdir(parents=True)
    labels.parent.mkdir(parents=True)
    source.write_bytes(b"type=USER_CMD msg=audit(1642492924.071:42): fixture\n" * 3)
    labels.write_text(
        "\n".join(
            json.dumps(row)
            for row in [
                {
                    "line": 1,
                    "labels": ["escalated_sudo_command"],
                    "rules": {"escalated_sudo_command": [START, EVENTS]},
                },
                {
                    "line": 2,
                    "labels": ["escalated_su_command"],
                    "rules": {
                        "escalated_su_command": ["attacker.escalate.audit.su.login"]
                    },
                },
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location(
        "fixture_audit_parser", SCRIPT.with_name("audit_parse.py")
    )
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    events = tmp_path / "agent" / "events.jsonl"
    parser.parse_audit_file(
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
    archive = tmp_path / "fox.zip"
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
        "time_from": "2022-01-18T00:00:00Z",
        "time_to": "2022-01-19T00:00:00Z",
        "output": tmp_path / "proof.json",
    }


def map_args(bundle, tmp_path):
    return {
        "gold": bundle["gold"],
        "proof": bundle["output"],
        "output": tmp_path / "mapped.jsonl",
        "report": tmp_path / "mapped.json",
    }


def mutate(path, **changes):
    lines = path.read_text(encoding="utf-8").splitlines()
    if path.suffix == ".jsonl":
        row = json.loads(lines[0])
        row.update(changes)
        lines[0] = json.dumps(row)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        row = json.loads(path.read_text(encoding="utf-8"))
        row.update(changes)
        path.write_text(json.dumps(row), encoding="utf-8")


@pytest.mark.parametrize("limit", [None, 2])
def test_verify_map_and_preview(taxonomy, bundle, tmp_path, limit):
    proof = taxonomy.verify(**bundle)
    assert proof["generator_version"] == VERSION
    assert proof["relative_log_path"] == LOG
    assert proof["counts"]["parse_errors"] == 0
    assert set(proof["inputs"]) == {
        "raw",
        "labels",
        "events",
        "gold",
        "join_report",
        "archive",
    }
    args = map_args(bundle, tmp_path)
    summary = taxonomy.map_gold(**args, max_events=limit)
    assert summary["attack_events"] == 2
    assert summary["normal_events"] == (1 if limit is None else 0)
    assert summary["unknown_events"] == 0
    assert summary["unmapped_attack_events"] == 1
    assert summary["type_event_counts"]["privilege_escalation"] == 1
    assert summary["truncated"] is (limit is not None)
    rows = [
        json.loads(x) for x in args["output"].read_text(encoding="utf-8").splitlines()
    ]
    assert all(row["taxonomy_version"] == VERSION for row in rows)
    assert rows[1]["is_attack"] is True and rows[1]["attack_types"] == []
    if limit is None:
        assert rows[2]["normal_basis"] == "complete_official_annotation_absence"


@pytest.mark.parametrize(
    "target,change",
    [
        ("join_report", {"truncated": True}),
        ("join_report", {"labels_complete_read": False}),
        ("join_report", {"label_bounds_verified": False}),
        ("join_report", {"labels_hash_scope": "preview"}),
        ("join_report", {"read_events": 2}),
        ("join_report", {"unmatched_annotation_lines": 1}),
        ("join_report", {"relative_log_path": "unknown"}),
        ("join_report", {"dataset_id": "ait-v2.1:other"}),
        ("events", {"raw_line_sha256": "0" * 64}),
        ("events", {"line_number": 9}),
        ("events", {"timestamp": "2022-01-18T13:00:00Z"}),
        ("gold", {"relative_log_path": "unknown"}),
        ("gold", {"labels": [], "rules": {}, "annotation_status": "unlabeled_unknown"}),
    ],
)
def test_verify_rejects_bad_inputs(taxonomy, bundle, target, change):
    mutate(bundle[target], **change)
    with pytest.raises(ValueError):
        taxonomy.verify(**bundle)
    assert not bundle["output"].exists()


@pytest.mark.parametrize(
    "target", ["raw", "labels", "events", "gold", "join_report", "archive"]
)
def test_all_six_inputs_bound(taxonomy, bundle, tmp_path, target):
    proof = taxonomy.verify(**bundle)
    path = Path(proof["inputs"][target]["path"])
    with path.open("ab") as stream:
        stream.write(b" ")
    args = map_args(bundle, tmp_path)
    with pytest.raises(ValueError):
        taxonomy.map_gold(**args)
    assert not args["output"].exists() and not args["report"].exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"generator_version": "fox-apache-taxonomy-v1"},
        {
            "relative_log_path": "intranet_server/logs/apache2/intranet.price.fox.org-access.log.2"
        },
        {"relative_log_path": "unknown"},
        {"dataset_id": "ait-v2.1:other"},
    ],
)
def test_profile_proof_cannot_be_swapped(taxonomy, bundle, tmp_path, changes):
    taxonomy.verify(**bundle)
    mutate(bundle["output"], **changes)
    args = map_args(bundle, tmp_path)
    with pytest.raises(ValueError):
        taxonomy.map_gold(**args)
    assert not args["output"].exists()


@pytest.mark.parametrize(
    "start,end",
    [
        ("2022-01-19T00:00:00Z", "2022-01-20T00:00:00Z"),
        ("2022-01-18T00:00:00", "2022-01-19T00:00:00Z"),
    ],
)
def test_explicit_aware_time_window(taxonomy, bundle, start, end):
    bundle.update(time_from=start, time_to=end)
    with pytest.raises(ValueError):
        taxonomy.verify(**bundle)
    assert not bundle["output"].exists()


def test_archive_profile_members(taxonomy, bundle, monkeypatch):
    with zipfile.ZipFile(bundle["archive"], "w") as z:
        z.write(bundle["dataset_root"] / "gather" / LOG, "fox/gather/wrong")
        z.write(bundle["dataset_root"] / "labels" / LOG, "fox/labels/" + LOG)
    monkeypatch.setattr(
        taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5(bundle["archive"].read_bytes()).hexdigest(),
    )
    with pytest.raises(ValueError, match="archive member"):
        taxonomy.verify(**bundle)
    assert not bundle["output"].exists()


@pytest.mark.parametrize("destination", ["raw", "agent", "input", "existing"])
def test_output_protection(taxonomy, bundle, tmp_path, destination):
    taxonomy.verify(**bundle)
    args = map_args(bundle, tmp_path)
    paths = {
        "raw": bundle["dataset_root"] / "mapped",
        "agent": bundle["events"].parent / "mapped",
        "input": bundle["gold"],
        "existing": tmp_path / "existing",
    }
    paths["existing"].write_bytes(b"keep")
    args["output"] = paths[destination]
    with pytest.raises((ValueError, FileExistsError)):
        taxonomy.map_gold(**args)
    assert paths["existing"].read_bytes() == b"keep"
    assert not args["report"].exists()


@pytest.mark.parametrize("scope", [None, [], {}])
def test_cli_rejects_nonstring_report_scope(taxonomy, bundle, scope):
    mutate(bundle["join_report"], relative_log_path=scope)
    args = ["verify"]
    for key, value in bundle.items():
        args.extend(["--" + key.replace("_", "-"), str(value)])
    with pytest.raises(SystemExit) as error:
        taxonomy.main(args)
    assert error.value.code == 2
    assert not bundle["output"].exists()


@pytest.mark.parametrize("scope", [None, [], {}])
def test_cli_rejects_nonstring_proof_scope(taxonomy, bundle, tmp_path, scope):
    taxonomy.verify(**bundle)
    mutate(bundle["output"], relative_log_path=scope)
    mapped = map_args(bundle, tmp_path)
    args = ["map"]
    for key, value in mapped.items():
        args.extend(["--" + key.replace("_", "-"), str(value)])
    with pytest.raises(SystemExit) as error:
        taxonomy.main(args)
    assert error.value.code == 2
    assert not mapped["output"].exists()
