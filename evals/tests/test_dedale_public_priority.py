"""Public priority projection tests use synthetic, fully checksummed raw bytes."""
import importlib
import random
from pathlib import Path

import pytest

from evals.datasets.dedale.common import canonical, read_json, sha256, write_new
from evals.datasets.dedale.neutralize import digest, shift_seconds
from evals.datasets.dedale.parse import decode_event, event_fingerprint
from evals.tests import test_dedale_neutralize as neutral_fixtures
from evals.tests.test_dedale_neutralize import Labels, archive, raw

finalized_inputs = neutral_fixtures.finalized_inputs


def module():
    spec = importlib.util.find_spec("evals.datasets.dedale.public_priority")
    assert spec is not None, "registered public priority builder must exist"
    return importlib.import_module(spec.name)


def event(number, *, action="ordinary", timestamp="2025-01-07T00:00:00Z"):
    return {**raw(timestamp, number), "event": {"action": action}}


def window(kind="attack"):
    return {"source": "auditbeat", "host": "internalserver", "time_from": "2025-01-07T00:00:00Z",
            "time_to": "2025-01-07T00:30:00Z", "candidate_kind": kind,
            "reason": "selected_attack" if kind == "attack" else "selected_normal"}


def decoded(value, line_number):
    return decode_event((canonical(value) + "\n").encode(), archive="system_logs_auditbeat.zip",
                        relative_log_path="daily_auditbeat/arbitrary_name.jsonl.bz2", line_number=line_number)


def test_exact_public_priority_normalization_and_no_keyword_matching():
    public = module().public_priority
    assert public("  PROCESS.START \t") == 0
    assert public("Execute a Remote Command") == 0
    assert public("AUTHENTICATION.START") == 1
    assert public("connected-to") == 1
    assert public("process.start extra") == public("process stop") == public("") == 2


def test_anchor_plus_priority99_is_order_independent_and_bounded():
    builder = module()
    values = [decoded(event(0), 1)] + [decoded(event(i, action="process.start", timestamp=shift_seconds(window()["time_from"], i)), i + 1)
                                          for i in range(1, 150)]
    expected = None
    for seed in range(5):
        shuffled = values[:]
        random.Random(seed).shuffle(shuffled)
        collector = builder.PriorityCollector()
        for value in shuffled:
            collector.add(value, "benign")
            assert collector.retained_size <= 101
        records = collector.records()
        identities = [record[1]["external_id"] for record in records]
        expected = expected or identities
        assert identities == expected
        assert identities[0] == values[0].external_id
        assert len(records) == 100
        assert [record[0] for record in records] == sorted(record[0] for record in records)
        assert collector.raw_priority_counts == [149, 0, 1]


def test_duplicate_winner_is_lowest_external_id_and_anchor_fingerprint_excluded():
    builder = module()
    same = event(1)
    duplicates = [decoded(same, number) for number in (1, 2, 3)]
    collector = builder.PriorityCollector()
    for value in sorted(duplicates, key=lambda item: item.external_id, reverse=True):
        collector.add(value, "benign")
    records = collector.records()
    assert len(records) == 1
    assert records[0][1]["external_id"] == min(value.external_id for value in duplicates)
    assert collector.raw_count == 3


def test_window_counts_all_labels_halfopen_and_attack_validity_only_after_ranking(tmp_path):
    builder = module()
    start = window()["time_from"]
    values = [event(0)] + [event(i, action="process.start", timestamp=shift_seconds(start, i)) for i in range(1, 120)]
    values += [event(999, timestamp=window()["time_to"])]
    labels = Labels()
    labels.entries = {("auditbeat", event_fingerprint(values[-2])): {"label": "malicious"}}
    index = archive(tmp_path, values)
    result = builder.scan_window(window(), data_root=tmp_path, index=index, labels=labels)
    assert result["raw_window_count"] == 120
    assert result["source_labels"] == {"benign": 119, "malicious": 1}
    assert result["reason"] == "no_retained_malicious"
    assert result["projected_count"] == 100
    assert result["priority_pass"][0]["raw_rows"] == 121
    assert result["sampling_counts"]["raw_priority_counts"] == [119, 0, 1]
    identities = [item[1]["external_id"] for item in result["records"]]
    other = builder.scan_window(window("control"), data_root=tmp_path, index=index, labels=Labels())
    assert [item[1]["external_id"] for item in other["records"]] == identities


def test_priority_pass_exhausts_md5_and_invalid_trailing_rows(tmp_path):
    builder = module()
    index = archive(tmp_path, [event(1)], corrupt=True)
    with pytest.raises(ValueError, match="MD5"):
        builder.scan_window(window(), data_root=tmp_path, index=index, labels=Labels())
    index = archive(tmp_path, [event(1)], trailing=b"{}\n")
    with pytest.raises(ValueError, match="TIMESTAMP|HOST"):
        builder.scan_window(window(), data_root=tmp_path, index=index, labels=Labels())


@pytest.fixture
def priority_inputs(finalized_inputs):
    from evals.datasets.dedale import neutralize
    args, preparation = finalized_inputs
    neutral = neutralize.finalize_dataset(**args)
    policy = read_json(Path(__file__).resolve().parents[2] / "data/manifests/dedale-public-priority-v4.json")
    policy["neutral_policy_sha256"] = sha256(args["splits"])
    policy["preparation_splits_sha256"] = sha256(args["scan_splits"])
    policy["preparation_code_sha256"] = neutralize.code_hashes()
    policy["preparation_selection_sha256"] = neutral["preparation"]["selection_sha256"]
    policy["preregistration_revision"]["previous_policy_sha256"] = sha256(args["splits"])
    path = args["splits"].with_name("priority-policy.json")
    write_new(path, policy)
    return {**args, "neutral_policy": args["splits"], "splits": path, "neutral_root": args["output_root"],
            "output_root": args["output_root"].with_name("priority")}, preparation, neutral


def test_finalizer_preserves_geometry_lineage_nonselected_rows_and_masks(priority_inputs):
    builder = module()
    args, preparation, neutral = priority_inputs
    result = builder.finalize_dataset(**args)
    assert result["protocol"] == "dedale-public-priority-v4"
    assert result["N_D"] == result["M_D"] == 4
    assert result["scan"] == preparation["scan"]
    assert result["sampling"] == read_json(args["splits"])["event_projection"]
    assert result["neutral_preparation"]["window_inventory_sha256"] == digest(builder.window_inventory(neutral))
    assert result["input_sha256"]["neutral_selection"] == sha256(args["neutral_root"] / "selection.json")
    old_nonselected = [row for row in neutral["candidate_ledger"] if row["reason"] not in {"selected_attack", "selected_normal"}]
    new_nonselected = [row for row in result["candidate_ledger"] if row["reason"] not in {"selected_attack", "selected_normal"}]
    assert new_nonselected == old_nonselected
    for case in result["cases"]:
        score = read_json(args["output_root"] / "test" / case["case_id"] / "scoring/manifest.json")
        assert all(score["case_applicability"][key] is False for key in ("six_class", "phases", "techniques", "origin"))


@pytest.mark.parametrize("mutation", ["ranking", "label_dependence", "type", "unknown"])
def test_policy_validation_fails_closed(priority_inputs, mutation):
    builder = module()
    args, _, _ = priority_inputs
    policy = read_json(args["splits"])
    if mutation == "ranking":
        policy["event_projection"]["priority_0_event_types"].append("arbitrary")
    elif mutation == "label_dependence":
        policy["event_projection"]["uses_source_labels_case_kind_or_stage_for_ranking"] = True
    elif mutation == "type":
        policy["event_projection"]["fallback_priority"] = False
    else:
        policy["unexpected"] = "claim"
    args["splits"].write_text(canonical(policy) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="priority|policy"):
        builder.finalize_dataset(**args)


def test_matching_unknown_fields_in_both_policies_are_not_an_extension_point(priority_inputs):
    builder = module()
    args, _, _ = priority_inputs
    policy, neutral = read_json(args["splits"]), read_json(args["neutral_policy"])
    policy["unknown_rule"] = neutral["unknown_rule"] = "unimplemented"
    with pytest.raises(ValueError, match="fields"):
        builder.validate_priority_policy(policy, neutral, read_json(args["scan_splits"]),
                                         sha256(args["scan_splits"]), sha256(args["neutral_policy"]))


def test_cache_resume_semantics_hash_owner_and_lineage_tamper(priority_inputs, monkeypatch, tmp_path):
    builder = module()
    args, _, _ = priority_inputs
    emit = builder.emit_priority_cases
    monkeypatch.setattr(builder, "emit_priority_cases", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("interrupt")))
    with pytest.raises(RuntimeError, match="interrupt"):
        builder.finalize_dataset(**args)
    assert not args["output_root"].exists()
    monkeypatch.setattr(builder, "emit_priority_cases", emit)
    cache = args["output_root"].with_name(args["output_root"].name + "-priority-work")
    path = next(cache.glob("case-*.json"))
    payload = read_json(path)
    payload["result"]["sampling_counts"]["retained_priority_counts"] = [999, 0, 0]
    payload["payload_sha256"] = digest({key: value for key, value in payload.items() if key != "payload_sha256"})
    path.write_text(canonical(payload) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="priority|counts"):
        builder.finalize_dataset(**args)


def test_complete_case_cache_resumes_without_raw_projection_and_rejects_unknown_files(priority_inputs, monkeypatch):
    builder = module()
    args, _, _ = priority_inputs
    emit = builder.emit_priority_cases
    monkeypatch.setattr(builder, "emit_priority_cases", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("interrupt")))
    with pytest.raises(RuntimeError, match="interrupt"):
        builder.finalize_dataset(**args)
    cache = args["output_root"].with_name(args["output_root"].name + "-priority-work")
    sentinel = cache / "unexpected.json"
    sentinel.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected"):
        builder.finalize_dataset(**args)
    sentinel.unlink()
    owner = cache / "owner.json"
    original = owner.read_bytes()
    value = read_json(owner)
    value["data_root"] += "-wrong-owner"
    owner.write_text(canonical(value) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="owner"):
        builder.finalize_dataset(**args)
    owner.write_bytes(original)
    monkeypatch.setattr(builder, "emit_priority_cases", emit)
    monkeypatch.setattr(builder, "scan_window", lambda *args, **kwargs: pytest.fail("verified completed case was rescanned"))
    selection = builder.finalize_dataset(**args)
    assert selection["N_D"] == 4


def test_raw_archive_changed_during_projection_prevents_publication(priority_inputs, monkeypatch):
    builder = module()
    args, _, _ = priority_inputs
    scan = builder.scan_window
    changed = False

    def mutate_after_scan(*positional, **kwargs):
        nonlocal changed
        value = scan(*positional, **kwargs)
        if not changed:
            import os
            path = args["data_root"] / "system_logs_auditbeat.zip"
            stat = path.stat()
            os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
            changed = True
        return value

    monkeypatch.setattr(builder, "scan_window", mutate_after_scan)
    with pytest.raises(ValueError, match="source|changed"):
        builder.finalize_dataset(**args)
    assert not args["output_root"].exists()


def test_atomic_work_write_retries_windows_sharing_error(tmp_path, monkeypatch):
    builder = module()
    original = Path.replace
    attempts = []

    def transient(path, target):
        attempts.append(path)
        if len(attempts) < 3:
            failure = PermissionError("synthetic sharing violation")
            failure.winerror = 32
            raise failure
        return original(path, target)

    monkeypatch.setattr(Path, "replace", transient)
    monkeypatch.setattr(builder.time, "sleep", lambda seconds: None)
    builder._atomic_write(tmp_path / "case.json", {"bound": True})
    assert read_json(tmp_path / "case.json") == {"bound": True}
    assert len(attempts) == 3


def test_v3_artifact_tamper_rejected_before_priority_raw_scan(priority_inputs, monkeypatch):
    builder = module()
    args, _, neutral = priority_inputs
    path = args["neutral_root"] / "test" / neutral["cases"][0]["case_id"] / "agent/events.jsonl"
    path.write_bytes(path.read_bytes() + b"{}\n")
    monkeypatch.setattr(builder, "scan_window", lambda *args, **kwargs: pytest.fail("unverified lineage reached raw priority scan"))
    with pytest.raises(ValueError, match="artifact|preparation"):
        builder.finalize_dataset(**args)
