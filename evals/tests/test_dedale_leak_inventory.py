"""Selected-public-view checks; fixtures are never final acceptance evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from evals.datasets.dedale.common import canonical, read_json, sha256, write_new
from evals.datasets.dedale.neutralize import _emit_case
from evals.datasets.dedale.parse import parse_event

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/dedale_task12_leak_inventory.py"
ARTIFACTS = {"agent/events.jsonl", "agent/manifest.json", "scoring/gold.jsonl",
             "scoring/source-gold.json", "scoring/manifest.json"}
ANNOTATION_PATTERN = (
    r"(?i)(?:technique[_ .-]?(?:id|name)|tactic(?:[_ .-]?(?:id|name))?|"
    r"mitre(?:[._ :/-]?attack)?|attack\.mitre\.org|(?<![a-z0-9])T\d{4}(?:\.\d{3})?(?!\d))"
)


@pytest.fixture
def inventory():
    if not SCRIPT.is_file():
        class MissingInventory:
            def __getattr__(self, name):
                pytest.fail("DEDALE selected free-text inventory is not implemented")
        return MissingInventory()
    spec = importlib.util.spec_from_file_location("dedale_leak_inventory", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def benign_observation():
    # One actual retained calibration observation from the existing benign live
    # context fixture. Its process/message/provenance bytes are left intact;
    # _emit_case supplies only the per-case dataset ID. This tiny tree does not
    # pretend to establish final test-period or official-source acceptance.
    return {
        "dataset_id": "dedale-v2.1", "source": "auditbeat", "event_type": "audit-rule",
        "external_id": "dedale:3d3d7f112ac807cc22985baadcb52d725383d39a7ffa767560c825949fcab48d",
        "archive": "system_logs_auditbeat.zip",
        "relative_log_path": "daily_auditbeat/D14_H21_2025-01-05T21_auditbeat_F334.jsonl.bz2",
        "line_number": 1, "host": "dmzserver", "timestamp": "2025-01-05T21:00:07.056Z",
        "observed_at": "2025-01-05T21:00:07.056Z", "@timestamp": "2025-01-05T21:00:07.056Z",
        "original_timestamp": "2025-01-05T21:00:07.056Z",
        "raw_line_sha256": "35ab2d33137ba90843f0bde7b4066c3bcbc6b476bffd844b6c991f111ffb0fbb",
        "event_fingerprint": "5569ed8033ed5a365145ebe3840a9694c999218cf679da158b9e4139f50cfd20",
        "source_event_id": "22879212", "severity": "info",
        "process": {"executable": "/usr/lib/dovecot/auth", "name": "auth", "pid": 12275,
                    "ppid": 740, "title": "/usr/sbin/dovecot"},
        "parent": {"pid": 740}, "command_line": "/usr/sbin/dovecot",
        "user": {"id": "112", "name": "dovecot"}, "username": "dovecot",
        "message": "process.executable=/usr/lib/dovecot/auth\nprocess.name=auth\nprocess.pid=12275\n"
                   "process.ppid=740\nprocess.title=/usr/sbin/dovecot\nparent.pid=740",
    }


def attack_observation(number):
    raw = {"@timestamp": "2025-01-07T12:00:01Z", "host": {"name": "CLIENT1.breach.local"},
           "agent": {"type": "winlogbeat"}, "winlog": {"record_id": number},
           "process": {"name": "attack_script.exe", "command_line": "attack_script.exe --observe"},
           "message": "RuleName: -\r\nObserved process start"}
    return parse_event((canonical(raw) + "\n").encode(), archive="system_logs_winlogbeat.zip",
                       relative_log_path="daily_winlogbeat/synthetic.jsonl.bz2", line_number=number)


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "cases"
    inputs = {"sources": "a" * 64, "splits": "b" * 64, "label_policy": "c" * 64}
    cases, ledger = [], []
    for kind, observations, labels, start, end in [
        ("attack", [attack_observation(1), attack_observation(2)], ["malicious", "benign"],
         "2025-01-07T12:00:00Z", "2025-01-07T12:30:00Z"),
        ("control", [benign_observation()], ["benign"],
         "2025-01-05T21:00:07.056Z", "2025-01-05T21:30:07.056Z"),
    ]:
        first = observations[0]
        window = {"source": first["source"], "host": first["host"], "time_from": start,
                  "time_to": end, "candidate_kind": kind,
                  "reason": "selected_attack" if kind == "attack" else "selected_normal",
                  "projected_count": len(observations), "raw_window_count": len(observations)}
        case = _emit_case(root, window=window,
                          records=[(None, event, label) for event, label in zip(observations, labels, strict=True)],
                          input_hashes=inputs)
        cases.append(case)
        ledger.append({**window, "case_id": case["case_id"]})
    cases.sort(key=lambda row: row["case_id"])
    selection = {"schema_version": 1, "protocol": "dedale-neutral-v3", "dataset_id": "dedale-v2.1",
                 "split": "test", "status": "prepared_not_frozen", "official_label_archive_verified": True,
                 "candidate_closure": True, "N_D": 2, "M_D": 2,
                 "counts": {"attack": 1, "normal": 1, "unscorable": 0}, "cases": cases,
                 "candidate_ledger": ledger, "ablation_case_ids": [row["case_id"] for row in cases],
                 "input_sha256": inputs}
    write_new(root / "selection.json", selection)
    return root, selection


def selected(selection, *, attack):
    return next(row for row in selection["cases"] if row["is_attack"] is attack)


def save_selection(root, selection):
    (root / "selection.json").write_text(canonical(selection) + "\n", encoding="utf-8")


def rebind(root, selection, case):
    base = root / "test" / case["case_id"]
    agent = read_json(base / "agent/manifest.json")
    agent["events_sha256"] = sha256(base / "agent/events.jsonl")
    (base / "agent/manifest.json").write_text(canonical(agent) + "\n", encoding="utf-8")
    hashes = {name: sha256(base / name) for name in ARTIFACTS - {"scoring/manifest.json"}}
    score = read_json(base / "scoring/manifest.json")
    score["artifacts"] = dict(hashes)
    (base / "scoring/manifest.json").write_text(canonical(score) + "\n", encoding="utf-8")
    hashes["scoring/manifest.json"] = sha256(base / "scoring/manifest.json")
    case["artifacts"] = hashes
    case["agent_manifest_sha256"] = hashes["agent/manifest.json"]
    case["scoring_manifest_sha256"] = hashes["scoring/manifest.json"]
    save_selection(root, selection)


def change_events(root, selection, case, change):
    path = root / "test" / case["case_id"] / "agent/events.jsonl"
    values = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    change(values)
    path.write_text("".join(canonical(value) + "\n" for value in values), encoding="utf-8")
    rebind(root, selection, case)


def test_scans_all_retained_events_and_manifests_but_never_signs_review(inventory, tree):
    root, selection = tree
    before = {path: sha256(path) for path in root.rglob("*") if path.is_file()}
    packet = inventory.build_inventory(cases_root=root)
    assert packet["complete"] is False and packet["scan_complete"] is True
    assert packet["reviewer"] is None and packet["review_status"] == "pending_independent_review"
    assert packet["selection_file_sha256"] == sha256(root / "selection.json")
    assert packet["selection_sha256"] == hashlib.sha256((canonical(selection) + "\n").encode()).hexdigest()
    assert len(packet["artifact_bindings"]) == 10
    assert len(packet["public_file_bindings"]) == 4
    assert {row["path"] for row in packet["artifact_bindings"]} == ARTIFACTS
    for row in packet["public_file_bindings"]:
        assert sha256(root / "test" / row["case_id"] / row["path"]) == row["sha256"]
    stats = packet["statistics"]
    assert stats["selected_cases"] == 2 and stats["selected_events"] == 3
    assert stats["cases_by_class"] == {"attack": 1, "normal": 1}
    assert stats["events_by_case_class"] == {"attack": 2, "normal": 1}
    assert stats["selected_source_labels"] == {"benign": 2, "malicious": 1}
    assert stats["inspected_json_keys"] > 100 and stats["inspected_string_values"] > 70
    assert packet["candidate_hits"] == []
    assert packet["rule_name_values"] == {"message:-": 2}
    assert packet["matching_rules"]["annotation_regex"] == ANNOTATION_PATTERN
    assert {path: sha256(path) for path in before} == before


@pytest.mark.parametrize("content", ["ATT&CK annotation", "att&ck", "T1059.001", "technique_id", "tacticName", "MITRE"])
def test_normal_actual_event_message_is_scanned(inventory, tree, content):
    root, selection = tree
    case = selected(selection, attack=False)
    change_events(root, selection, case, lambda values: values[0].update(message=content))
    report = inventory.build_inventory(cases_root=root)
    hits = [hit for hit in report["candidate_hits"] if hit["case_id"] == case["case_id"]]
    assert hits and any(hit["path"] == "/message" and hit["external_id"] == benign_observation()["external_id"] for hit in hits)
    assert all(hit["review_status"] == "requires_manual_review" for hit in hits)


def test_all_nested_json_keys_values_and_agent_manifest_strings_are_scanned(inventory, tree):
    root, selection = tree
    case = selected(selection, attack=False)
    change_events(root, selection, case, lambda values: values[0].update(extra={"T1090": ["normal", {"nested": "technique name"}]}))
    manifest_path = root / "test" / case["case_id"] / "agent/manifest.json"
    manifest = read_json(manifest_path)
    manifest["alert"]["title"] = "ATT&CK label"
    manifest["tactic_name"] = "context"
    manifest_path.write_text(canonical(manifest) + "\n", encoding="utf-8")
    rebind(root, selection, case)
    hits = inventory.build_inventory(cases_root=root)["candidate_hits"]
    assert any(hit["path"] == "/extra/T1090" and hit["location"] == "json_key" for hit in hits)
    assert any(hit["path"] == "/extra/T1090/1/nested" for hit in hits)
    assert any(hit["file"] == "agent/manifest.json" and hit["path"] == "/alert/title" for hit in hits)
    assert any(hit["file"] == "agent/manifest.json" and hit["path"] == "/tactic_name" for hit in hits)


def test_rule_name_hyphen_is_benign_and_other_values_require_manual_review(inventory, tree):
    root, selection = tree
    case = selected(selection, attack=False)
    def annotate(values):
        values[0]["extra"] = {"RuleName": "-", "Event.Rule_Name": "custom publisher rule"}
        values[0]["message"] = "RuleName: -\r\nRuleName : ordinary command context\nRuleName: T1059"
    change_events(root, selection, case, annotate)
    packet = inventory.build_inventory(cases_root=root)
    assert packet["rule_name_values"] == {"message:-": 3, "message:ordinary command context": 1,
                                          "message:T1059": 1, "structured:-": 1,
                                          "structured:custom publisher rule": 1}
    rule_hits = [hit for hit in packet["candidate_hits"] if hit["rule"].startswith("rule_name")]
    assert len(rule_hits) == 3
    assert all(hit["excerpt"] != "-" for hit in rule_hits)


def test_candidate_command_and_process_names_are_preserved_for_manual_distinction(inventory, tree):
    root, selection = tree
    case = selected(selection, attack=True)
    change_events(root, selection, case, lambda values: values[0].update(
        process={"name": "T1059-demo.exe", "command_line": "echo ATT&CK | example.exe"}))
    path = root / "test" / case["case_id"] / "agent/events.jsonl"
    before = path.read_bytes()
    packet = inventory.build_inventory(cases_root=root)
    assert path.read_bytes() == before
    assert {hit["path"] for hit in packet["candidate_hits"]} >= {"/process/name", "/process/command_line"}
    assert packet["complete"] is False and packet["reviewer"] is None


@pytest.mark.parametrize("relative", sorted(ARTIFACTS))
def test_tampered_or_missing_artifact_fails_closed(inventory, tree, relative):
    root, selection = tree
    path = root / "test" / selection["cases"][0]["case_id"] / relative
    path.write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="artifact SHA256"):
        inventory.build_inventory(cases_root=root)
    path.unlink()
    with pytest.raises((ValueError, OSError)):
        inventory.build_inventory(cases_root=root)


@pytest.mark.parametrize("mutation", ["missing_hash", "bad_hash", "extra_artifact", "old_protocol", "bad_N_D",
                                      "bad_M_D", "bool_count", "bad_counts", "duplicate_case", "unsafe_case_id",
                                      "wrong_neutral_id", "missing_ledger", "duplicate_ledger", "extra_ledger_id",
                                      "wrong_ledger_reason", "wrong_ledger_source", "open_closure", "wrong_ablation"])
def test_selection_identity_and_closure_fail_closed(inventory, tree, mutation):
    root, selection = tree
    case = selection["cases"][0]
    entry = next(row for row in selection["candidate_ledger"] if row["case_id"] == case["case_id"])
    if mutation == "missing_hash":
        del case["artifacts"]["agent/events.jsonl"]
    elif mutation == "bad_hash":
        case["artifacts"]["agent/events.jsonl"] = "not a SHA256"
    elif mutation == "extra_artifact":
        case["artifacts"]["agent/extra.json"] = "a" * 64
    elif mutation == "old_protocol":
        selection["protocol"] = "dedale-v2"
    elif mutation in {"bad_N_D", "bad_M_D"}:
        selection[mutation[4:]] = 1
    elif mutation == "bool_count":
        selection["counts"]["attack"] = True
    elif mutation == "bad_counts":
        selection["counts"]["normal"] = 0
    elif mutation == "duplicate_case":
        selection["cases"][1] = dict(case)
    elif mutation == "unsafe_case_id":
        case["case_id"] = "../escape"
    elif mutation == "wrong_neutral_id":
        case["case_id"] = "dedale-" + "0" * 16
    elif mutation == "missing_ledger":
        selection["candidate_ledger"].remove(entry)
    elif mutation == "duplicate_ledger":
        selection["candidate_ledger"].append(dict(entry))
    elif mutation == "extra_ledger_id":
        selection["candidate_ledger"].append({"case_id": "dedale-" + "f" * 16, "reason": "excluded"})
    elif mutation == "wrong_ledger_reason":
        entry["reason"] = "selected_normal" if case["is_attack"] else "selected_attack"
    elif mutation == "wrong_ledger_source":
        entry["source"] = "winlogbeat" if entry["source"] == "auditbeat" else "auditbeat"
    elif mutation == "open_closure":
        selection["candidate_closure"] = False
    elif mutation == "wrong_ablation":
        selection["ablation_case_ids"] = selection["ablation_case_ids"][:1]
    save_selection(root, selection)
    with pytest.raises(ValueError):
        inventory.build_inventory(cases_root=root)


@pytest.mark.parametrize("relative", ["agent/additional.json", "agent/nested/extra.json", "../unselected/agent/events.jsonl"])
def test_unscanned_agent_files_or_unselected_case_directories_are_rejected(inventory, tree, relative):
    root, selection = tree
    path = root / "test" / selection["cases"][0]["case_id"] / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="public file inventory|case directory closure"):
        inventory.build_inventory(cases_root=root)


@pytest.mark.parametrize("mutation", ["agent_count", "agent_id", "agent_dataset", "agent_events_file", "agent_filters",
                                      "gold_external_id", "event_external_id_duplicate", "event_host", "event_dataset",
                                      "event_source", "event_count", "score_id", "score_artifacts", "score_input"])
def test_rehashed_pairing_and_manifest_forgery_is_rejected(inventory, tree, mutation):
    root, selection = tree
    case = selected(selection, attack=True)
    base = root / "test" / case["case_id"]
    if mutation.startswith("agent_"):
        path = base / "agent/manifest.json"
        value = read_json(path)
        key, replacement = {"agent_count": ("event_count", 1), "agent_id": ("case_id", "wrong"),
                            "agent_dataset": ("dataset_id", "wrong"), "agent_events_file": ("events_file", "elsewhere.jsonl"),
                            "agent_filters": ("filters", {"host": "wrong"})}[mutation]
        value[key] = replacement
        path.write_text(canonical(value) + "\n", encoding="utf-8")
    elif mutation.startswith("event_"):
        def change(values):
            if mutation == "event_external_id_duplicate":
                values[1]["external_id"] = values[0]["external_id"]
            elif mutation == "event_count":
                values.pop()
            else:
                values[0]["dataset_id" if mutation == "event_dataset" else mutation[6:]] = "wrong"
        change_events(root, selection, case, change)
    elif mutation == "gold_external_id":
        path = base / "scoring/gold.jsonl"
        values = [json.loads(line) for line in path.read_text().splitlines()]
        values[0]["external_id"] = "dedale:" + "0" * 64
        path.write_text("".join(canonical(value) + "\n" for value in values), encoding="utf-8")
    else:
        path = base / "scoring/manifest.json"
        value = read_json(path)
        key, replacement = {"score_id": ("case_id", "wrong"), "score_artifacts": ("artifacts", {}),
                            "score_input": ("input_sha256", {})}[mutation]
        value[key] = replacement
        path.write_text(canonical(value) + "\n", encoding="utf-8")
        if mutation == "score_artifacts":
            case["artifacts"]["scoring/manifest.json"] = sha256(path)
            case["scoring_manifest_sha256"] = sha256(path)
            save_selection(root, selection)
    if mutation != "score_artifacts":
        rebind(root, selection, case)
    with pytest.raises(ValueError, match="manifest|identity|count|scope|pairing"):
        inventory.build_inventory(cases_root=root)


@pytest.mark.parametrize("which", ["selection", "artifact", "agent_extra"])
def test_input_stability_is_rechecked_after_scanning(inventory, tree, monkeypatch, which):
    root, selection = tree
    original = inventory._scan_public
    case = selection["cases"][0]
    changed = False
    def mutate(*args, **kwargs):
        nonlocal changed
        result = original(*args, **kwargs)
        if not changed:
            changed = True
            if which == "selection":
                selection["unexpected"] = "changed"
                save_selection(root, selection)
            elif which == "artifact":
                (root / "test" / case["case_id"] / "scoring/source-gold.json").write_bytes(b"{}\n")
            else:
                (root / "test" / case["case_id"] / "agent/late.json").write_bytes(b"{}\n")
        return result
    monkeypatch.setattr(inventory, "_scan_public", mutate)
    with pytest.raises(ValueError, match="changed while reading|public file inventory"):
        inventory.build_inventory(cases_root=root)


@pytest.mark.parametrize("raw", ['{"x":1,"x":2}\n', '{"x":NaN}\n', '{"x":1e9999}\n', '[]\n'])
def test_strict_public_json_rejects_duplicate_nonfinite_and_nonobject_rows(inventory, tree, raw):
    root, selection = tree
    case = selection["cases"][0]
    path = root / "test" / case["case_id"] / "agent/events.jsonl"
    path.write_text(raw, encoding="utf-8")
    rebind(root, selection, case)
    with pytest.raises(ValueError):
        inventory.build_inventory(cases_root=root)


def test_excerpts_paths_and_recorded_hits_are_bounded_without_skipping_scan(inventory, tree):
    root, selection = tree
    case = selected(selection, attack=False)
    def annotate(values):
        values[0]["extra"] = {"x" * 1000: ["z" * 5000 + "ATT&CK"] * 1100}
        values[0]["message"] = "RuleName: " + "a" * 10000
    change_events(root, selection, case, annotate)
    packet = inventory.build_inventory(cases_root=root)
    stats = packet["statistics"]
    assert stats["candidate_hits_total"] == 1101
    assert stats["candidate_hits_recorded"] <= 1000
    assert stats["candidate_hits_omitted"] == 1101 - stats["candidate_hits_recorded"]
    assert stats["inspected_string_values"] > 1100 and packet["scan_complete"] is True
    assert all(len(hit["excerpt"]) <= 240 and len(hit["path"]) <= 512 for hit in packet["candidate_hits"])
    assert all(len(key) <= 240 for key in packet["rule_name_values"])
    assert len(canonical(packet)) < 1_000_000


def test_cli_writes_only_a_new_pending_packet_and_bounded_summary(inventory, tree, tmp_path, capsys):
    root, _selection = tree
    output = tmp_path / "research/packet.json"
    args = ["--cases-root", str(root), "--output", str(output)]
    assert inventory.main(args) == 0
    packet = read_json(output)
    assert packet["scan_complete"] is True and packet["complete"] is False
    summary = capsys.readouterr().out
    assert "dovecot" not in summary and "attack_script" not in summary and len(summary) < 3000
    with pytest.raises(FileExistsError):
        inventory.main(args)


def test_cli_rejects_output_inside_cases_and_invalid_inputs_without_partial_output(inventory, tree, tmp_path):
    root, selection = tree
    output = root / "test" / selection["cases"][0]["case_id"] / "agent/leak.json"
    with pytest.raises(ValueError, match="outside.*selected case"):
        inventory.main(["--cases-root", str(root), "--output", str(output)])
    assert not output.exists()
    selection["M_D"] = 99
    save_selection(root, selection)
    output = tmp_path / "invalid-packet.json"
    # Exercise the process exit contract as well as the callable API.
    result = subprocess.run([sys.executable, str(SCRIPT), "--cases-root", str(root), "--output", str(output)],
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0 and not output.exists()
    assert "dovecot" not in result.stdout + result.stderr


def test_filesystem_links_are_rejected_without_reading_target(inventory, tree, tmp_path):
    root, selection = tree
    case = selection["cases"][0]
    path = root / "test" / case["case_id"] / "agent/events.jsonl"
    destination = tmp_path / "outside-events.jsonl"
    destination.write_bytes(path.read_bytes())
    path.unlink()
    try:
        path.symlink_to(destination)
    except OSError:
        pytest.skip("platform does not permit unprivileged symbolic links")
    with pytest.raises(ValueError, match="filesystem link"):
        inventory.build_inventory(cases_root=root)
