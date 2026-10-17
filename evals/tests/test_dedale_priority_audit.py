"""Tiny raw fixtures exercise independent public-priority replay and fail closure."""
from copy import deepcopy

import pytest

from evals.datasets.dedale.common import canonical
from evals.datasets.dedale.neutralize import neutral_case_id, shift_seconds
from evals.tests.test_dedale_neutralize import Labels, archive, raw
from evals.tests.test_dedale_neutralize import (
    finalized_inputs as finalized_inputs,  # noqa: PLC0414 - pytest fixture export
)
from evals.tests.test_dedale_public_priority import (
    priority_inputs as priority_inputs,  # noqa: PLC0414 - pytest fixture export
)


def window():
    start = "2025-01-07T00:00:00Z"
    return {"case_id": neutral_case_id("auditbeat", "internalserver", start),
            "source": "auditbeat", "host": "internalserver", "time_from": start,
            "time_to": shift_seconds(start, 1800), "candidate_kind": "attack"}


def values():
    rows = [raw(shift_seconds(window()["time_from"], i), i) for i in range(114)]
    for row in rows:
        row["event"] = {"action": "ordinary"}
    rows[-3]["event"]["action"] = " CONNECTED-TO "
    rows[-2]["event"]["action"] = " Execute a remote command "
    rows[-1]["event"]["action"] = "executed"
    return rows


def test_missing_v4_lineage_remains_closed(tmp_path):
    from evals.datasets.dedale.audit import audit_prepared

    report = audit_prepared({"protocol": "dedale-public-priority-v4"}, tmp_path)
    assert report.get("protocol") == "dedale-public-priority-v4"
    assert report["accepted"] is False
    assert report["gates"]["priority_policy"] is False
    assert report["gates"]["raw_priority_replay"] is False


def test_independent_raw_replay_keeps_anchor_and_public_actions(tmp_path):
    from evals.datasets.dedale.priority_audit import replay_windows

    index = archive(tmp_path, values())
    results = replay_windows([window()], data_root=tmp_path, index=index, labels=Labels())
    replay = results[window()["case_id"]]
    selected = [record[1] for record in replay["records"]]
    assert len(selected) == 100
    assert selected[0]["observed_at"] == window()["time_from"]
    assert {row["event_type"].strip().casefold() for row in selected} >= {
        "connected-to", "execute a remote command", "executed"}
    assert replay["sampling_counts"]["raw_priority_counts"] == [2, 1, 111]
    assert replay["sampling_counts"]["retained_priority_counts"] == [2, 1, 97]
    assert replay["raw_window_count"] == 114
    assert replay["priority_pass"][0]["raw_rows"] == 114


def test_replay_labels_cannot_change_public_selection(tmp_path):
    from evals.datasets.dedale.priority_audit import replay_windows

    index = archive(tmp_path, values())
    benign = replay_windows([window()], data_root=tmp_path, index=index, labels=Labels())

    class AttackLabels(Labels):
        def classify(self, source, fingerprint, *, host=None):
            return "malicious"

    attack = replay_windows([window()], data_root=tmp_path, index=index, labels=AttackLabels())
    observations = lambda result: [record[1] for record in result[window()["case_id"]]["records"]]
    assert observations(benign) == observations(attack)


def test_full_member_exhaustion_detects_corruption_outside_window(tmp_path):
    from evals.datasets.dedale.priority_audit import replay_windows

    index = archive(tmp_path, [*values(), raw("2025-01-07T01:00:00Z", 999)], corrupt=True)
    with pytest.raises(ValueError):
        replay_windows([window()], data_root=tmp_path, index=index, labels=Labels())


def test_replay_deduplicates_by_fingerprint_with_smallest_external_id(tmp_path):
    from evals.datasets.dedale.parse import decode_event
    from evals.datasets.dedale.priority_audit import replay_windows

    rows = [raw(window()["time_from"], 1)] * 3
    index = archive(tmp_path, rows)
    replay = replay_windows([window()], data_root=tmp_path, index=index, labels=Labels())[window()["case_id"]]
    originals = [decode_event((canonical(row) + "\n").encode(), archive=index[0]["archive"],
                             relative_log_path=index[0]["member"], line_number=i + 1) for i, row in enumerate(rows)]
    assert len(replay["records"]) == 1
    assert replay["records"][0][1]["external_id"] == min(row.external_id for row in originals)
    assert replay["sampling_counts"]["anchor_external_id"] == min(row.external_id for row in originals)


def stage_report(selection, gold):
    from evals.datasets.dedale.audit import STAGES
    observable = {"execution", "persistence", "discovery", "lateral_movement", "collection"}
    return {"complete": True, "reviewer": "independent action reviewer",
            "selection_sha256": digest_bytes(selection),
            "stages": [{"stage": stage, "observable": stage in observable,
                        "basis_url": "https://dedale.example/official-scenario",
                        "reason": "Reviewed original action and source evidence",
                        "evidence": [{"case_id": "case", "external_id": "event",
                                      "reason": "Source action supports the stage"}] if stage in observable else []}
                       for stage in sorted(STAGES)]}


def digest_bytes(selection):
    import hashlib
    return hashlib.sha256((canonical(selection) + "\n").encode()).hexdigest()


def test_v4_cannot_pass_with_all_stages_false():
    from evals.datasets.dedale.priority_audit import priority_stage_review

    selection, gold = {"cases": []}, {"case": {"event": {"is_attack": True}}}
    report = stage_report(selection, gold)
    assert priority_stage_review(report, selection, gold)
    report["stages"] = [{**row, "observable": False, "evidence": []} for row in report["stages"]]
    assert not priority_stage_review(report, selection, gold)


@pytest.mark.parametrize("tamper", ["missing_stage", "false_observable", "benign_evidence", "missing_rationale"])
def test_v4_stage_coverage_requires_actual_malicious_action_evidence(tamper):
    from evals.datasets.dedale.priority_audit import priority_stage_review

    selection, gold = {"cases": []}, {"case": {"event": {"is_attack": True}}}
    report = stage_report(selection, gold)
    if tamper == "missing_stage":
        report["stages"].pop()
    elif tamper == "false_observable":
        next(row for row in report["stages"] if row["observable"])["observable"] = False
    elif tamper == "benign_evidence":
        gold["case"]["event"]["is_attack"] = False
    else:
        for row in report["stages"]:
            for evidence in row["evidence"]:
                evidence.pop("reason")
    assert not priority_stage_review(report, selection, gold)


def ledger_replay_fixture(tmp_path):
    from evals.datasets.dedale.priority_audit import replay_windows

    original = window()
    index = archive(tmp_path, values())
    replay = replay_windows([original], data_root=tmp_path, index=index, labels=Labels())
    expected = replay[original["case_id"]]
    old = {**original, "reason": "selected_attack", "raw_window_count": expected["raw_window_count"],
           "projected_count": 100, "source_labels": expected["source_labels"],
           "projected_labels": {"benign": 99, "malicious": 1}, "duplicate_retained_rows": 0}
    unselected = {"reason": "not_evaluated_after_first_eligible", "raw_window_count": None}
    neutral = {"candidate_ledger": [old, unselected], "counts": {"unscorable": 0}}
    row = {**old, **{key: value for key, value in expected.items() if key != "records"}, "reason": "no_retained_malicious"}
    row.pop("case_id")
    selection = {"candidate_ledger": [row, deepcopy(unselected)], "counts": {"unscorable": 1}}
    return selection, neutral, index, replay


def test_raw_ranking_can_exclude_attack_without_changing_geometry(tmp_path):
    from evals.datasets.dedale.priority_audit import validate_candidate_ledger

    selection, neutral, index, replay = ledger_replay_fixture(tmp_path)
    assert validate_candidate_ledger(selection, neutral, index, replay) == {}
    assert selection["candidate_ledger"][0]["time_from"] == neutral["candidate_ledger"][0]["time_from"]


@pytest.mark.parametrize("change", ["drop_candidate", "change_nonselected", "invent_identity", "rank_counts",
                                    "anchor", "missing_receipt", "raw_count", "excluded_count", "replay_closure"])
def test_priority_candidate_sampling_tampering_is_rejected(tmp_path, change):
    from evals.datasets.dedale.priority_audit import validate_candidate_ledger

    selection, neutral, index, replay = ledger_replay_fixture(tmp_path)
    row = selection["candidate_ledger"][0]
    if change == "drop_candidate":
        selection["candidate_ledger"].pop()
    elif change == "change_nonselected":
        selection["candidate_ledger"][1]["raw_window_count"] = 0
    elif change == "invent_identity":
        row["case_id"] = window()["case_id"]
    elif change == "rank_counts":
        row["sampling_counts"] = {**row["sampling_counts"], "retained_priority_counts": [0, 0, 100]}
    elif change == "anchor":
        row["sampling_counts"] = {**row["sampling_counts"], "anchor_external_id": "invented"}
    elif change == "missing_receipt":
        row["priority_pass"] = []
    elif change == "raw_count":
        row["raw_window_count"] += 1
    elif change == "excluded_count":
        selection["counts"]["unscorable"] = 0
    else:
        replay.clear()
    with pytest.raises(ValueError):
        validate_candidate_ledger(selection, neutral, index, replay)


def test_actual_selected_content_is_independently_replayed(tmp_path, monkeypatch):
    """A broken finalizer rank cannot teach the acceptance replay the same bug."""
    from evals.datasets.dedale import public_priority
    from evals.datasets.dedale.priority_audit import replay_windows

    index = archive(tmp_path, values())
    monkeypatch.setattr(public_priority, "public_priority", lambda value: 2)
    built = public_priority.scan_window(window(), data_root=tmp_path, index=index, labels=Labels())
    independent = replay_windows([window()], data_root=tmp_path, index=index, labels=Labels())[window()["case_id"]]
    assert [row[1] for row in built["records"]] != [row[1] for row in independent["records"]]


def test_public_priority_audit_policy_is_pinned_to_fixed_bytes():
    from pathlib import Path

    from evals.datasets.dedale.common import sha256
    from evals.datasets.dedale.priority_audit import POLICY_SHA256

    assert sha256(Path(__file__).resolve().parents[2] / "data/manifests/dedale-public-priority-v4.json") == POLICY_SHA256


def test_actual_builder_cases_match_independent_replay_and_artifact_audit(priority_inputs, monkeypatch):
    from evals.datasets.dedale import priority_audit, public_priority
    from evals.datasets.dedale.audit import _audit_cases
    from evals.datasets.dedale.common import sha256
    from evals.datasets.dedale.join_labels import load_label_index
    from evals.datasets.dedale.neutralize import _line_json

    args, _, neutral = priority_inputs
    selection = public_priority.finalize_dataset(**args)
    # Synthetic fixture policies cannot use the real source hashes; all other
    # independently enforced lineage and protocol decisions remain exercised.
    monkeypatch.setattr(priority_audit, "POLICY_SHA256", sha256(args["splits"]))
    priority_audit._policy_and_lineage(selection, neutral, splits=args["splits"],
        neutral_policy=args["neutral_policy"], scan_splits=args["scan_splits"], neutral_root=args["neutral_root"])
    labels = load_label_index(args["data_root"] / "system_logs_labels.zip", exhaustive=True)
    index = neutral["preparation"]["member_index"]
    replay = priority_audit.replay_windows(priority_audit.window_inventory(neutral),
        data_root=args["data_root"], index=index, labels=labels)
    selected = priority_audit.validate_candidate_ledger(selection, neutral, index, replay)
    gates, _, errors = _audit_cases(selection, args["output_root"], selected, labels=labels,
                                    official_labels=True, precise=True)
    assert all(gates.values()), errors
    for identifier in selected:
        actual = _line_json(args["output_root"] / "test" / identifier / "agent/events.jsonl")
        expected = [{**record, "dataset_id": "dedale-v2.1:" + identifier}
                    for _, record, _ in replay[identifier]["records"]]
        assert actual == expected


def leak_groups():
    from evals.datasets.dedale.neutralize import digest

    groups = []
    for number, rule in enumerate(("annotation", "rule_name_message")):
        identity = {"case_id": "case", "file": "agent/events.jsonl", "rule": rule,
                    "external_id": "event-" + str(number), "path_sha256": digest(["path", number]),
                    "location": "string_value", "value_sha256": digest(["value", number])}
        if number:
            identity["line_number"] = 2
        groups.append({"case_id": "case", "file": "agent/events.jsonl", "rule": rule,
                       "count": 1001 if number == 0 else 1, "sha256": digest(["all-group-hits", number]),
                       "example_hit": {**identity, "excerpt": "Actual candidate", "review_status": "requires_manual_review"}})
    return {"candidate_groups": groups, "statistics": {"candidate_hits_total": 1002,
            "candidate_hits_recorded": 1000, "candidate_hits_omitted": 2}}


def group_dispositions(actual):
    keys = {"case_id", "file", "rule", "external_id", "path_sha256", "location", "value_sha256", "line_number"}
    return [{"coverage": {key: group[key] for key in ("case_id", "file", "rule", "count", "sha256")},
             "reason": "Reviewed the actual group and full selected public text",
             "evidence": [{key: value for key, value in group["example_hit"].items() if key in keys}]}
            for group in actual["candidate_groups"]]


def test_leak_dispositions_bind_every_group_including_hits_after_excerpt_cap():
    from evals.datasets.dedale.priority_audit import _validate_leak_dispositions

    actual = leak_groups()
    _validate_leak_dispositions({"dispositions": group_dispositions(actual)}, actual)


@pytest.mark.parametrize("tamper", ["unrelated_string", "missing_group", "duplicate_group", "extra_group",
                                    "count", "digest", "unrelated_reference", "missing_path", "line_number"])
def test_complete_leak_hit_count_cannot_hide_unreviewed_groups(tamper):
    from evals.datasets.dedale.priority_audit import _validate_leak_dispositions

    actual = leak_groups()
    dispositions = group_dispositions(actual)
    if tamper == "unrelated_string":
        dispositions = [{"reason": "everything reviewed", "evidence": "x"}]
    elif tamper == "missing_group":
        dispositions.pop()
    elif tamper == "duplicate_group":
        dispositions.append(deepcopy(dispositions[0]))
    elif tamper == "extra_group":
        dispositions.append({**deepcopy(dispositions[0]), "coverage": {**dispositions[0]["coverage"], "rule": "invented"}})
    elif tamper == "count":
        dispositions[0]["coverage"]["count"] = 1000
    elif tamper == "digest":
        dispositions[0]["coverage"]["sha256"] = "0" * 64
    elif tamper == "unrelated_reference":
        dispositions[0]["evidence"][0]["external_id"] = "unrelated"
    elif tamper == "missing_path":
        dispositions[0]["evidence"][0].pop("path_sha256")
    else:
        dispositions[1]["evidence"][0]["line_number"] += 1
    with pytest.raises(ValueError):
        _validate_leak_dispositions({"dispositions": dispositions}, actual)


def test_zero_hit_group_review_is_empty():
    from evals.datasets.dedale.priority_audit import _validate_leak_dispositions

    _validate_leak_dispositions({"dispositions": []}, {"candidate_groups": [], "statistics": {"candidate_hits_total": 0}})


def acceptance_cross_fixture(tmp_path, monkeypatch):
    from evals.datasets.dedale import priority_audit
    from evals.datasets.dedale.common import sha256, write_new
    from evals.datasets.dedale.public_priority import implementation_hashes
    from scripts.dedale_task12_crosspath_check import _inventory

    names = ("data_root", "rebuild_data_root", "cases_root", "rebuild_cases_root", "prepared_root",
             "rebuild_prepared_root", "neutral_root", "rebuild_neutral_root", "preparation_checkpoints", "rebuild_preparation_checkpoints")
    roots = {name: tmp_path / name for name in names}
    for root in roots.values():
        root.mkdir()
    originals, copied = {}, {}
    for name in ("sources", "splits", "label_policy", "scan_splits", "neutral_policy"):
        original, second = tmp_path / (name + ".json"), roots["rebuild_data_root"] / (name + ".json")
        value = {"metadata_snapshot": {"path": "metadata.json"}} if name == "sources" else {"kind": name}
        write_new(original, value)
        second.write_bytes(original.read_bytes())
        originals[name], copied[name] = original, second
    for name in ("data_root", "rebuild_data_root"):
        (roots[name] / "metadata.json").write_bytes(b"metadata")
        (roots[name] / "archive.zip").write_bytes(b"archive")
    source_report = {"metadata_sha256": sha256(roots["data_root"] / "metadata.json"),
                     "archives": [{"path": "archive.zip", "sha256": sha256(roots["data_root"] / "archive.zip")}]}
    case = {"case_id": "case", "split": "test", "artifacts": {"agent/events.jsonl": digest_bytes({"raw": "case"})}}
    artifact = (canonical({"raw": "case"}) + "\n").encode()
    selection = {"protocol": "dedale-public-priority-v4", "cases": [case],
                 "input_sha256": {name: sha256(originals[name]) for name in ("sources", "splits", "label_policy")}}
    for name in ("cases_root", "rebuild_cases_root", "prepared_root", "rebuild_prepared_root", "neutral_root", "rebuild_neutral_root"):
        write_new(roots[name] / "selection.json", selection)
        path = roots[name] / "test/case/agent/events.jsonl"
        path.parent.mkdir(parents=True)
        path.write_bytes(artifact)
    for name in ("preparation_checkpoints", "rebuild_preparation_checkpoints"):
        (roots[name] / "owner.json").write_bytes(b"{}\n")
    input_files = {name: {"original_path": str(originals[name]), "rebuild_path": str(copied[name]),
                         "sha256": sha256(originals[name])} for name in originals}
    report = {"protocol": selection["protocol"], "all_equal": True, "errors": [], "code_sha256": implementation_hashes(),
              **{"original_" + name: str(roots[name]) for name in ("cases_root", "data_root", "prepared_root", "neutral_root", "preparation_checkpoints")},
              **{name: str(root) for name, root in roots.items() if name.startswith("rebuild_")},
              "input_files": {name: input_files[name] for name in ("sources", "splits", "label_policy")},
              "preparation_input_files": {name: input_files[name] for name in ("scan_splits", "neutral_policy")},
              "checkpoint_verification": {name: {"members_verified": 1344, "checkpoint_files_verified": 1344,
                  "binding": {}, "files_sha256": _inventory(roots[root_name])} for name, root_name in
                  (("original", "preparation_checkpoints"), ("rebuild", "rebuild_preparation_checkpoints"))}}
    # Only exhaustive checkpoint semantics use a stand-in here. Actual source,
    # config, all three output trees and file identity checks remain live.
    index = [None] * 1344
    monkeypatch.setattr(priority_audit, "load_member_index", lambda **kwargs: (index, {}))
    kwargs = {**{name: roots[name] for name in ("cases_root", "data_root", "prepared_root", "neutral_root", "preparation_checkpoints")},
              **originals, "source_report": source_report, "labels": None, "index": index, "binding": {}}
    return report, selection, kwargs, roots, originals, copied


@pytest.mark.parametrize("kind", ["raw", "metadata", "config", "case", "checkpoint"])
def test_acceptance_rejects_post_report_hardlink_replacement(tmp_path, monkeypatch, kind):
    from evals.datasets.dedale.priority_audit import _cross_path_check

    report, selection, kwargs, roots, originals, copied = acceptance_cross_fixture(tmp_path, monkeypatch)
    assert _cross_path_check(report, selection, **kwargs)
    if kind == "raw":
        original, second = roots["data_root"] / "archive.zip", roots["rebuild_data_root"] / "archive.zip"
    elif kind == "metadata":
        original, second = roots["data_root"] / "metadata.json", roots["rebuild_data_root"] / "metadata.json"
    elif kind == "config":
        original, second = originals["splits"], copied["splits"]
    elif kind == "case":
        original, second = (roots[name] / "test/case/agent/events.jsonl" for name in ("prepared_root", "rebuild_prepared_root"))
    else:
        original, second = (roots[name] / "owner.json" for name in ("preparation_checkpoints", "rebuild_preparation_checkpoints"))
    second.unlink()
    second.hardlink_to(original)
    assert original.samefile(second)
    assert not _cross_path_check(report, selection, **kwargs)


def test_final_stability_check_rejects_same_byte_hardlink_swap(tmp_path):
    from evals.datasets.dedale.common import sha256
    from evals.datasets.dedale.priority_audit import _verify_bound_files

    first, other = tmp_path / "first.json", tmp_path / "other.json"
    first.write_bytes(b"same bytes")
    other.write_bytes(first.read_bytes())
    snapshot = {first: sha256(first)}
    _verify_bound_files(snapshot)
    first.unlink()
    first.hardlink_to(other)
    with pytest.raises(ValueError, match="link|independent|alias"):
        _verify_bound_files(snapshot)


def test_cross_review_preserves_initial_preparation_selection_bytes(tmp_path, monkeypatch):
    from evals.datasets.dedale.common import sha256
    from evals.datasets.dedale.priority_audit import _cross_path_check

    report, selection, kwargs, roots, _, _ = acceptance_cross_fixture(tmp_path, monkeypatch)
    first = roots["prepared_root"] / "selection.json"
    second = roots["rebuild_prepared_root"] / "selection.json"
    original_hash = sha256(first)
    bindings = {first: original_hash}
    assert _cross_path_check(report, selection, **kwargs, bound_files=bindings)
    # Parsed selections and independent output equality remain unchanged.
    # Their original byte commitment must still be retained by the audit.
    for path in (first, second):
        path.write_bytes(path.read_bytes() + b" \n")
    assert sha256(first) == sha256(second) != original_hash
    assert not _cross_path_check(report, selection, **kwargs, bound_files=bindings)
    assert bindings[first] == original_hash


def test_acceptance_checks_original_root_spelling_before_resolving_junction(tmp_path, monkeypatch):
    import os
    import subprocess

    from evals.datasets.dedale.priority_audit import _cross_path_check

    report, selection, kwargs, roots, _, _ = acceptance_cross_fixture(tmp_path, monkeypatch)
    assert _cross_path_check(report, selection, **kwargs)
    spelling = roots["rebuild_prepared_root"]
    target = spelling.with_name("actual-second-prepared")
    spelling.rename(target)
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(spelling), str(target)], check=True, capture_output=True)
        assert spelling.is_junction()
    else:
        spelling.symlink_to(target, target_is_directory=True)
    assert spelling.resolve() == target.resolve()
    assert not _cross_path_check(report, selection, **kwargs)


def test_full_leak_review_binds_actual_groups_beyond_excerpt_cap(tmp_path):
    from evals.datasets.dedale.common import sha256, write_new
    from evals.datasets.dedale.priority_audit import _leak_review
    from evals.tests.test_dedale_leak_inventory import change_events, tree
    from scripts.dedale_task12_leak_inventory import build_inventory

    root, selection = tree.__wrapped__(tmp_path)
    first, second = selection["cases"]
    change_events(root, selection, first, lambda values: values[0].update(
        extra={"T" + str(number): "observed filename" for number in range(1000, 2101)}))
    change_events(root, selection, second, lambda values: values[0].update(
        message="RuleName: ActualObservedRule\nMITRE factual filename"))
    packet = build_inventory(cases_root=root)
    assert packet["statistics"]["candidate_hits_omitted"] > 0
    packet_path = tmp_path / "leak-packet.json"
    write_new(packet_path, packet)
    count = packet["statistics"]["candidate_hits_total"]
    report = {"complete": True, "reviewer": "Independent fixture reviewer", "reason": "Full public text reviewed",
              "inventory": {"path": str(packet_path), "sha256": sha256(packet_path)},
              "selection_sha256": packet["selection_sha256"], "selection_file_sha256": packet["selection_file_sha256"],
              "public_file_bindings": packet["public_file_bindings"], "candidate_hits_total": count,
              "reviewed_candidate_hits_total": count, "publisher_answer_annotations_present": False,
              "factual_content_preserved": True, "all_selected_public_text_reviewed": True,
              "dispositions": group_dispositions(packet)}
    assert _leak_review(report, selection, root) == {packet_path: sha256(packet_path)}
    report["dispositions"] = [{"reason": "all reviewed", "evidence": "x"}]
    with pytest.raises(ValueError, match="group|disposition|coverage"):
        _leak_review(report, selection, root)
