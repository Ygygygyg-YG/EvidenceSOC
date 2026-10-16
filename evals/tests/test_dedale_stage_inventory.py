"""Synthetic evidence only; no campaign answers belong in these fixtures."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path

import pytest

from evals.datasets.dedale.build_manifests import _gold, project_observations
from evals.datasets.dedale.common import canonical, sha256, write_new
from evals.datasets.dedale.join_labels import LABEL_MEMBERS
from evals.datasets.dedale.parse import parse_event

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/dedale_task12_stage_inventory.py"
STAGES = {
    "initial_access", "execution", "persistence", "command_and_control",
    "discovery", "lateral_movement", "collection", "exfiltration",
}


@pytest.fixture
def inventory():
    if not SCRIPT.is_file():
        class MissingInventory:
            def __getattr__(self, name):
                pytest.fail("DEDALE stage review inventory is not implemented")
        return MissingInventory()
    spec = importlib.util.spec_from_file_location("dedale_stage_inventory", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def raw_event(number=1):
    return {
        "@timestamp": "2025-01-07T12:00:01Z",
        "agent": {"type": "winlogbeat", "id": "synthetic-agent"},
        "host": {"name": "CLIENT1.breach.local"},
        "winlog": {"channel": "synthetic-channel", "record_id": number},
        "process": {"pid": 100, "entity_id": "synthetic-entity", "name": "sample.exe"},
        "message": "Synthetic observable action without a tactic assertion.",
    }


def fixture_tree(tmp_path, inventory, monkeypatch):
    # Tests replace integrity pins with synthetic source bytes. The CLI offers
    # no option to bypass its fixed official archive or repository integrity.
    data_root = tmp_path / "data"
    data_root.mkdir()
    labels = data_root / "system_logs_labels.zip"
    with zipfile.ZipFile(labels, "w") as archive:
        for member, (source, _) in LABEL_MEMBERS.items():
            rows = [raw_event()] if source == "winlogbeat" else []
            archive.writestr(member, "".join(canonical(row) + "\n" for row in rows))
    import evals.datasets.dedale.join_labels as joiner
    monkeypatch.setattr(joiner, "OFFICIAL_ARCHIVE_SIZE", labels.stat().st_size)
    monkeypatch.setattr(joiner, "OFFICIAL_ARCHIVE_MD5", hashlib.md5(labels.read_bytes()).hexdigest())

    source_root = tmp_path / "research/scoring-source"
    files = []
    csv_names = [
        "gt_internalserver_class_1.csv", "gt_internalserver_class_1_and_2.csv",
        "gt_internalserver_presentation_pdf_class_1.csv",
        "gt_windows_client1_class_1.csv", "gt_windows_client1_class_1_and_2.csv",
        "gt_windows_client2_class_1.csv", "gt_windows_client2_class_1_and_2.csv",
    ]
    paths = ["system_log_labeling/ground_truth/" + name for name in csv_names]
    paths += [f"system_log_labeling/{prefix}_{source}/src/main.rs"
              for prefix in ("label_dedale", "pid_tree_dedale")
              for source in ("auditbeat", "winlogbeat")]
    for relative in paths:
        target = source_root / "repository" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        content = b"// Synthetic source\n"
        if relative.endswith(".csv"):
            content = (b"CLIENT1,synthetic-entity,100,2025-01-07T12:00:00Z,2025-01-07T12:01:00Z\n"
                       if "windows" in relative else
                       b"internalserver,200,2025-01-07T12:00:00Z,2025-01-07T12:01:00Z\n")
        target.write_bytes(content)
        files.append({"path": relative, "sha256": sha256(target), "bytes": len(content),
                      "url": "https://gitlab.inria.fr/api/v4/projects/mlanvin%2Fdedale_labeling/repository/files/"
                             + relative.replace("/", "%2F") + "/raw?ref=" + inventory.PINNED_COMMIT})
    write_new(source_root / "provenance.json", {"resolved_commit": inventory.PINNED_COMMIT, "files": files})
    monkeypatch.setattr(inventory, "PINNED_PROVENANCE_SHA256", sha256(source_root / "provenance.json"))
    write_new(source_root / "commit.json", {"id": inventory.PINNED_COMMIT})
    html = source_root / "site/attack_scenario.html"
    html.parent.mkdir()
    html.write_text("Synthetic official action narrative", encoding="utf-8")
    monkeypatch.setattr(inventory, "PINNED_STAGE_HTML_SHA256", sha256(html))
    write_new(source_root / "stage-review-catalog.json", {
        "fixed_ground_truth_commit": inventory.PINNED_COMMIT,
        "official_stage_source": {"url": "https://dedale.inria.fr/attack_scenario.html", "sha256": sha256(html)},
        "stages": [{"stage": stage} for stage in sorted(STAGES)],
    })
    write_new(source_root / "site/attack-timeline.json", {
        "source_url": "https://dedale.inria.fr/attack_scenario.html", "sha256": sha256(html),
        "rows": [["", "07/01/2025", "12:00 Synthetic action", ""]],
        "timezone": "not specified in website table",
    })

    cases_root = tmp_path / "cases"
    case_root = cases_root / "test/dedale-synthetic"
    observation = parse_event((canonical(raw_event()) + "\n").encode(),
                              archive="system_logs_winlogbeat.zip",
                              relative_log_path="daily_winlogbeat/example.jsonl.bz2", line_number=8)
    observation["dataset_id"] = "dedale-v2.1:dedale-synthetic"
    observation = project_observations(observation)
    gold = _gold(observation, "malicious")
    inputs = {"archive:system_logs_labels.zip": sha256(labels)}
    write_new(case_root / "agent/events.jsonl", [observation], jsonl=True)
    write_new(case_root / "agent/manifest.json", {
        "case_id": "dedale-synthetic", "events_sha256": sha256(case_root / "agent/events.jsonl"),
    })
    write_new(case_root / "scoring/gold.jsonl", [gold], jsonl=True)
    write_new(case_root / "scoring/source-gold.json", {"applicability": {"origin": False}})
    names = ["agent/events.jsonl", "agent/manifest.json", "scoring/gold.jsonl", "scoring/source-gold.json"]
    hashes = {name: sha256(case_root / name) for name in names}
    write_new(case_root / "scoring/manifest.json", {
        "case_id": "dedale-synthetic", "input_sha256": inputs, "artifacts": dict(hashes),
        "case_is_attack": True,
    })
    hashes["scoring/manifest.json"] = sha256(case_root / "scoring/manifest.json")
    selection = {
        "dataset_id": "dedale-v2.1", "official_label_archive_verified": True,
        "N_D": 1, "M_D": 1, "ablation_case_ids": ["dedale-synthetic"],
        "candidate_ledger": [{"case_id": "dedale-synthetic", "reason": "selected_attack"}],
        "input_sha256": inputs,
        "cases": [{"case_id": "dedale-synthetic", "split": "test", "artifacts": hashes,
                   "event_count": 1, "is_attack": True, "host": "CLIENT1.breach.local",
                   "time_from": "2025-01-07T12:00:00Z", "time_to": "2025-01-07T12:30:00Z"}],
    }
    write_new(cases_root / "selection.json", selection)
    return cases_root, data_root, source_root, selection


def test_packet_binds_full_selection_and_contains_original_labeled_observables(inventory, tmp_path, monkeypatch):
    cases, data, source, selection = fixture_tree(tmp_path, inventory, monkeypatch)
    report = inventory.build_inventory(cases_root=cases, data_root=data, scoring_source_root=source)
    assert report["complete"] is False
    assert report["reviewer"] is None
    assert report["selection_sha256"] == hashlib.sha256((canonical(selection) + "\n").encode()).hexdigest()
    assert report["selection_file_sha256"] == sha256(cases / "selection.json")
    assert {row["stage"] for row in report["stages"]} == STAGES
    assert all(row["observable"] is None and row["evidence"] == [] for row in report["stages"])
    assert len(report["artifact_bindings"]) == 5
    event = report["selected_events"][0]
    assert event["original_label"]["raw_event"] == raw_event()
    assert event["gold"]["is_attack"] is True
    assert len(event["original_label"]["locations"]) == 2
    assert event["process_lifecycle_candidates"]
    assert all(row["candidate_only"] is True for row in event["process_lifecycle_candidates"])
    assert "stage" not in event
    from evals.datasets.dedale.audit import _stage_review
    assert _stage_review(report, selection, {}) is False


@pytest.mark.parametrize("relative", ["agent/events.jsonl", "agent/manifest.json", "scoring/gold.jsonl",
                                      "scoring/source-gold.json", "scoring/manifest.json"])
def test_modified_selected_artifact_is_rejected_before_export(inventory, tmp_path, monkeypatch, relative):
    cases, data, source, _ = fixture_tree(tmp_path, inventory, monkeypatch)
    (cases / "test/dedale-synthetic" / relative).write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="artifact.*SHA256"):
        inventory.build_inventory(cases_root=cases, data_root=data, scoring_source_root=source)


def test_rejects_gold_membership_forgery_even_with_rehashed_artifacts(inventory, tmp_path, monkeypatch):
    cases, data, source, selection = fixture_tree(tmp_path, inventory, monkeypatch)
    case_root = cases / "test/dedale-synthetic"
    gold = json.loads((case_root / "scoring/gold.jsonl").read_text())
    gold["provenance"]["event_fingerprint"] = "f" * 64
    observation = json.loads((case_root / "agent/events.jsonl").read_text())
    observation["event_fingerprint"] = "f" * 64
    for relative, value in (("scoring/gold.jsonl", gold), ("agent/events.jsonl", observation)):
        (case_root / relative).write_text(canonical(value) + "\n", encoding="utf-8")
    rehash_case(case_root, cases, selection)
    with pytest.raises(ValueError, match="official label membership"):
        inventory.build_inventory(cases_root=cases, data_root=data, scoring_source_root=source)


def rehash_case(case_root, cases, selection):
    hashes = selection["cases"][0]["artifacts"]
    for relative in hashes:
        if relative != "scoring/manifest.json":
            hashes[relative] = sha256(case_root / relative)
    manifest = json.loads((case_root / "agent/manifest.json").read_text())
    manifest["events_sha256"] = hashes["agent/events.jsonl"]
    (case_root / "agent/manifest.json").write_text(canonical(manifest) + "\n", encoding="utf-8")
    hashes["agent/manifest.json"] = sha256(case_root / "agent/manifest.json")
    scoring = json.loads((case_root / "scoring/manifest.json").read_text())
    scoring["artifacts"] = {key: value for key, value in hashes.items() if key != "scoring/manifest.json"}
    (case_root / "scoring/manifest.json").write_text(canonical(scoring) + "\n", encoding="utf-8")
    hashes["scoring/manifest.json"] = sha256(case_root / "scoring/manifest.json")
    (cases / "selection.json").write_text(canonical(selection) + "\n", encoding="utf-8")


def test_rejects_wrong_observable_for_valid_label_fingerprint(inventory, tmp_path, monkeypatch):
    cases, data, source, selection = fixture_tree(tmp_path, inventory, monkeypatch)
    case_root = cases / "test/dedale-synthetic"
    event = json.loads((case_root / "agent/events.jsonl").read_text())
    event["message"] = "Forged observable action"
    (case_root / "agent/events.jsonl").write_text(canonical(event) + "\n", encoding="utf-8")
    rehash_case(case_root, cases, selection)
    with pytest.raises(ValueError, match="original label projection"):
        inventory.build_inventory(cases_root=cases, data_root=data, scoring_source_root=source)


def test_rejects_replaced_official_label_archive(inventory, tmp_path, monkeypatch):
    cases, data, source, _ = fixture_tree(tmp_path, inventory, monkeypatch)
    with (data / "system_logs_labels.zip").open("ab") as handle:
        handle.write(b"changed")
    with pytest.raises(ValueError, match="official label archive|label archive.*binding"):
        inventory.build_inventory(cases_root=cases, data_root=data, scoring_source_root=source)


def test_rejects_repository_source_changes(inventory, tmp_path, monkeypatch):
    cases, data, source, _ = fixture_tree(tmp_path, inventory, monkeypatch)
    (source / "repository/system_log_labeling/label_dedale_winlogbeat/src/main.rs").write_bytes(b"changed")
    with pytest.raises(ValueError, match="source.*SHA256"):
        inventory.build_inventory(cases_root=cases, data_root=data, scoring_source_root=source)


def test_selection_is_rechecked_after_evidence_is_read(inventory, tmp_path, monkeypatch):
    cases, data, source, selection = fixture_tree(tmp_path, inventory, monkeypatch)
    original_loader = inventory._original_labels

    def change_selection(*args):
        changed = {**selection, "unreviewed_extra_metadata": "changed while reading"}
        (cases / "selection.json").write_text(canonical(changed) + "\n", encoding="utf-8")
        return original_loader(*args)

    monkeypatch.setattr(inventory, "_original_labels", change_selection)
    with pytest.raises(ValueError, match="selection changed"):
        inventory.build_inventory(cases_root=cases, data_root=data, scoring_source_root=source)


def test_packet_cannot_export_into_selected_cases(inventory, tmp_path, monkeypatch):
    cases, data, source, _ = fixture_tree(tmp_path, inventory, monkeypatch)
    import shutil
    copied_source = cases / "test/dedale-synthetic/agent/scoring-source"
    shutil.copytree(source, copied_source)
    output = copied_source / "leak.json"
    with pytest.raises(ValueError, match="selected case"):
        inventory.main(["--cases-root", str(cases), "--data-root", str(data),
                        "--scoring-source-root", str(copied_source), "--output", str(output)])
    assert not output.exists()


def test_pid_reuse_never_links_a_different_native_entity(inventory, tmp_path, monkeypatch):
    _cases, _data, source, _ = fixture_tree(tmp_path, inventory, monkeypatch)
    _, lifecycles = inventory._review_sources(source)
    event = raw_event()
    event["process"]["entity_id"] = "a-later-process-reusing-the-pid"
    assert inventory._lifecycle_candidates(event, lifecycles) == []
    event = raw_event()
    event["@timestamp"] = "2025-01-07T12:02:00Z"
    assert inventory._lifecycle_candidates(event, lifecycles) == []
    event = raw_event()
    event["host"]["name"] = "CLIENT2.breach.local"
    assert inventory._lifecycle_candidates(event, lifecycles) == []


def test_cli_rejects_export_outside_scoring_source(inventory, tmp_path, monkeypatch):
    cases, data, source, _ = fixture_tree(tmp_path, inventory, monkeypatch)
    with pytest.raises(ValueError, match="scoring-source"):
        inventory.main(["--cases-root", str(cases), "--data-root", str(data),
                        "--scoring-source-root", str(source), "--output", str(tmp_path / "leak.json")])
    assert not (tmp_path / "leak.json").exists()


def test_cli_writes_pending_packet_exclusively(inventory, tmp_path, monkeypatch, capsys):
    cases, data, source, _ = fixture_tree(tmp_path, inventory, monkeypatch)
    output = source / "review-packet.json"
    arguments = ["--cases-root", str(cases), "--data-root", str(data),
                 "--scoring-source-root", str(source), "--output", str(output)]
    assert inventory.main(arguments) == 0
    assert json.loads(output.read_text())["complete"] is False
    assert "Synthetic observable" not in capsys.readouterr().out
    with pytest.raises(FileExistsError):
        inventory.main(arguments)
