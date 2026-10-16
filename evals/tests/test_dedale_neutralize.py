"""Synthetic raw archives verify neutral finalization, never freeze evidence."""
import bz2
import hashlib
import shutil
import zipfile
from pathlib import Path
from typing import ClassVar

import pytest

from evals.datasets.dedale.common import canonical
from evals.datasets.dedale.neutralize import (
    candidate_cut,
    canonical_clock,
    control_candidates,
    neutral_case_id,
    scan_candidate,
    shift_seconds,
    start_exclusion,
)
from evals.tests.test_dedale_scan import (
    label_archive,
    line,
    pin_fixture,
    raw_archive,
    raw_event,
)


class Labels:
    entries: ClassVar[dict] = {}
    official_verified = False
    exhaustive = False

    def classify(self, source, fingerprint, *, host=None):
        return self.entries.get((source, fingerprint), {}).get("label", "benign")


def raw(timestamp, number=1):
    return {"@timestamp": timestamp, "host": {"name": "internalserver"},
            "agent": {"type": "auditbeat"}, "auditd": {"sequence": number},
            "message": "synthetic observable"}


def archive(root, values, *, corrupt=False, trailing=b""):
    name = "system_logs_auditbeat.zip"
    member = "daily_auditbeat/arbitrary_name.jsonl.bz2"
    payload = b"".join((canonical(value) + "\n").encode() for value in values) + trailing
    digest = "0" * 32 if corrupt else hashlib.md5(payload).hexdigest()
    with zipfile.ZipFile(root / name, "w") as target:
        target.writestr(member, bz2.compress(payload))
        target.writestr("daily_auditbeat/auditbeat_md5sum.sig", f"{digest}  ./arbitrary_name.jsonl\n")
    index = [{"archive": name, "member": member, "source": "auditbeat", "jsonl_md5": digest,
              "minimum": "2025-01-07T00:00:00Z", "maximum": "2025-01-07T02:00:00Z",
              "hosts": {"auditbeat:internalserver": len(values)}, "raw_rows": len(values)}]
    return index


def candidate(base="2025-01-07T00:00:00Z"):
    return {"source": "auditbeat", "host": "internalserver", "base_start": base,
            "base_end": shift_seconds(base, 1800)}


def test_id_cannot_be_predicted_by_two_kind_trials():
    expected = "dedale-" + hashlib.sha256(canonical(["auditbeat", "internalserver", "2025-01-07T00:00:00.123Z"]).encode()).hexdigest()[:16]
    assert neutral_case_id("auditbeat", "internalserver", "2025-01-07T00:00:00.123Z") == expected


def test_controls_use_real_fractional_source_timestamp_and_full_halfopen_count(tmp_path):
    item = candidate()
    cut = candidate_cut(item)
    start = shift_seconds(cut, 1).replace("Z", "000123Z") if "." in cut else shift_seconds(cut, 1).replace("Z", ".000123Z")
    end = shift_seconds(start, 1800)
    index = archive(tmp_path, [raw(end, 4), raw(shift_seconds(start, 2), 3), raw(start, 1), raw(start, 2)])
    result = scan_candidate(item, data_root=tmp_path, index=index, labels=Labels(), attack_windows=[])
    assert result["reason"] == "selected_normal"
    assert result["time_from"] == start
    assert result["time_to"] == end
    assert result["raw_window_count"] == result["projected_count"] == 3
    assert [row[1]["observed_at"] for row in result["records"]] == [start, start, shift_seconds(start, 2)]
    assert result["passes"]["anchor"][0]["jsonl_md5_verified"] is True
    assert result["passes"]["window"][0]["jsonl_md5_verified"] is True
    assert result["time_from"].endswith("000123Z")


def test_member_md5_is_exhausted_after_early_anchor(tmp_path):
    item = candidate()
    index = archive(tmp_path, [raw(shift_seconds(candidate_cut(item), 1))], corrupt=True)
    with pytest.raises(ValueError, match="MD5"):
        scan_candidate(item, data_root=tmp_path, index=index, labels=Labels(), attack_windows=[])


def test_invalid_trailing_raw_row_cannot_hide_behind_anchor(tmp_path):
    item = candidate()
    index = archive(tmp_path, [raw(shift_seconds(candidate_cut(item), 1))], trailing=b"{}\n")
    with pytest.raises(ValueError, match="TIMESTAMP|HOST"):
        scan_candidate(item, data_root=tmp_path, index=index, labels=Labels(), attack_windows=[])


def test_no_anchor_is_explicit_and_second_pass_not_invented(tmp_path):
    item = candidate()
    index = archive(tmp_path, [raw("2025-01-07T00:00:00Z")])
    result = scan_candidate(item, data_root=tmp_path, index=index, labels=Labels(), attack_windows=[])
    assert result["reason"] == "no_event_after_cut"
    assert result["raw_window_count"] is None
    assert result["passes"]["window"] is None


@pytest.mark.parametrize(("start", "attacks", "reason"), [
    ("2025-01-19T23:59:00.001Z", [], "crosses_test_boundary"),
    ("2025-01-07T23:59:00.001Z", [], "crosses_utc_day"),
    ("2025-01-07T00:10:00.001Z", [("2025-01-07T00:30:00Z", "2025-01-07T01:00:00Z")], "overlaps_registered_attack_window"),
    ("2025-01-07T00:00:00Z", [("2025-01-07T00:30:00Z", "2025-01-07T01:00:00Z")], None),
])
def test_start_exclusion_reasons_and_halfopen_nonoverlap(start, attacks, reason):
    assert start_exclusion(start, attacks) == reason


def test_candidate_list_only_uses_verified_pure_nonoverlap_grid():
    base = {"source": "auditbeat", "host": "internalserver", "time_from": "2025-01-07T00:00:00Z",
            "time_to": "2025-01-07T00:30:00Z", "candidate_kind": "grid", "reason": "selected_normal",
            "source_labels": {"benign": 17}, "raw_window_count": 17}
    rows = [base, {**base, "time_from": "2025-01-07T01:00:00Z", "reason": "overlaps_registered_attack_window"},
            {**base, "time_from": "2025-01-07T02:00:00Z", "source_labels": {"benign": 1, "malicious-related": 1}},
            {**base, "candidate_kind": "attack"}]
    groups = control_candidates(rows)
    assert len(groups) == 1
    assert len(next(iter(groups.values()))) == 1


def test_shift_keeps_source_fraction_without_microsecond_rounding():
    assert shift_seconds("2025-01-07T00:00:00.123456789Z", 1800) == "2025-01-07T00:30:00.123456789Z"


def test_equivalent_attack_and_control_clocks_have_identical_public_encoding_and_id():
    attack = "2025-01-07T00:00:00.199000Z"
    control = "2025-01-07T00:00:00.199Z"
    assert canonical_clock(attack) == canonical_clock(control) == control
    assert neutral_case_id("auditbeat", "internalserver", attack) == neutral_case_id("auditbeat", "internalserver", control)
    assert canonical_clock("2025-01-07T00:00:00.000000000Z") == "2025-01-07T00:00:00Z"
    assert canonical_clock("2025-01-07T00:00:00.199000001000Z") == "2025-01-07T00:00:00.199000001Z"


def test_all_window_labels_count_even_after_projection_fills(tmp_path):
    from evals.datasets.dedale.parse import event_fingerprint
    item = candidate()
    start = shift_seconds(candidate_cut(item), 1)
    values = [raw(start, number) for number in range(1, 102)]
    labels = Labels()
    labels.entries = {("auditbeat", event_fingerprint(values[-1])): {"source": "auditbeat", "host": "internalserver",
                      "timestamp": start, "label": "malicious-related"}}
    index = archive(tmp_path, values)
    result = scan_candidate(item, data_root=tmp_path, index=index, labels=labels, attack_windows=[])
    assert result["reason"] == "window_not_entirely_benign"
    assert result["raw_window_count"] == 101
    assert result["projected_count"] == 100
    assert result["source_labels"] == {"benign": 100, "malicious-related": 1}
    assert "records" not in result


def test_remaining_candidates_are_unknown_after_first_eligible(tmp_path):
    from evals.datasets.dedale.neutralize import evaluate_group
    first, later = candidate(), candidate("2025-01-07T01:00:00Z")
    index = archive(tmp_path, [raw(shift_seconds(candidate_cut(first), 1))])
    result = evaluate_group([first, later], data_root=tmp_path, index=index, labels=Labels(), attack_windows=[])
    assert [row["reason"] for row in result] == ["selected_normal", "not_evaluated_after_first_eligible"]
    assert result[1]["raw_window_count"] is result[1]["source_labels"] is result[1]["passes"]["anchor"] is None


@pytest.fixture
def finalized_inputs(tmp_path, monkeypatch):
    from evals.datasets.dedale import common, neutralize
    from evals.datasets.dedale.checkpoint import code_hashes
    from evals.datasets.dedale.scan import prepare_dataset

    root = tmp_path / "raw"
    root.mkdir()
    paths = {"sources": tmp_path / "sources.json", "splits": tmp_path / "scan-splits.json",
             "label_policy": tmp_path / "labels.json", "data_root": root, "output_root": tmp_path / "prepared"}
    workspace = Path(__file__).resolve().parents[2]
    paths["splits"].write_bytes((workspace / "data/manifests/dedale-scan-splits-v2.json").read_bytes())
    paths["label_policy"].write_bytes((workspace / "data/manifests/dedale-label-policy.json").read_bytes())
    label_archive(root / "system_logs_labels.zip")
    for source in ("winlogbeat", "auditbeat"):
        raw_archive(root / f"system_logs_{source}.zip", source, {
            "unrelated_filename": line(raw_event(source, 1)) + line(raw_event(source, 2)),
            "other_name": line(raw_event(source, 3, timestamp="2025-01-07T13:29:59.999Z")),
        })
    pin_fixture(paths, monkeypatch)
    monkeypatch.setattr(neutralize, "OFFICIAL", common.OFFICIAL)
    checkpoints = tmp_path / "checkpoints"
    preparation = prepare_dataset(**paths, workers=1, checkpoint_root=checkpoints)
    policy = common.read_json(workspace / "data/manifests/dedale-neutral-policy-v3.json")
    policy["preparation_splits_sha256"] = common.sha256(paths["splits"])
    policy["preparation_code_sha256"] = code_hashes()
    new_policy = tmp_path / "policy.json"
    common.write_new(new_policy, policy)
    return {"sources": paths["sources"], "scan_splits": paths["splits"], "splits": new_policy,
            "label_policy": paths["label_policy"], "data_root": root, "prepared_root": paths["output_root"],
            "preparation_checkpoints": checkpoints, "output_root": tmp_path / "final", "workers": 1}, preparation


def test_finalization_rebuilds_normal_raw_and_both_classes_use_neutral_ids(finalized_inputs):
    from evals.datasets.dedale import neutralize
    args, preparation = finalized_inputs
    selection = neutralize.finalize_dataset(**args)
    assert selection["protocol"] == "dedale-neutral-v3"
    assert selection["counts"]["attack"] == selection["counts"]["normal"] == 2
    assert selection["N_D"] == selection["M_D"] == 4
    assert selection["preparation_ledger"] == preparation["candidate_ledger"]
    assert selection["scan"] == preparation["scan"]
    assert all(row["time_from"].split(".")[-1] == "999Z" for row in selection["cases"] if not row["is_attack"])
    for row in selection["candidate_ledger"]:
        if "case_id" in row:
            assert row["case_id"] == neutral_case_id(row["source"], row["host"], row["time_from"])
    assert len(selection["preparation"]["member_index"]) == 4
    assert not any("malicious" in (args["output_root"] / "test" / case["case_id"] / "agent/manifest.json").read_text() for case in selection["cases"])


def test_fresh_raw_root_and_independent_preparation_emit_identical_final_bytes(finalized_inputs, tmp_path):
    from evals.datasets.dedale import neutralize
    from evals.datasets.dedale.common import sha256
    from evals.datasets.dedale.scan import prepare_dataset

    args, _ = finalized_inputs
    neutralize.finalize_dataset(**args)
    other_raw = tmp_path / "copied-raw"
    shutil.copytree(args["data_root"], other_raw)
    other_prepared, other_checkpoints = tmp_path / "other-prepared", tmp_path / "other-checkpoints"
    prepare_dataset(sources=args["sources"], splits=args["scan_splits"], label_policy=args["label_policy"],
                    data_root=other_raw, output_root=other_prepared, workers=1, checkpoint_root=other_checkpoints)
    other_output = tmp_path / "other-final"
    neutralize.finalize_dataset(**{**args, "data_root": other_raw, "prepared_root": other_prepared,
        "preparation_checkpoints": other_checkpoints, "output_root": other_output})
    inventory = lambda root: {path.relative_to(root).as_posix(): sha256(path) for path in root.rglob("*") if path.is_file()}
    assert inventory(args["output_root"]) == inventory(other_output)


def test_checkpoint_cannot_be_reused_from_another_raw_owner(finalized_inputs, tmp_path):
    from evals.datasets.dedale import neutralize
    args, _ = finalized_inputs
    copied = tmp_path / "different-raw"
    shutil.copytree(args["data_root"], copied)
    with pytest.raises(ValueError, match="owner"):
        neutralize.finalize_dataset(**{**args, "data_root": copied})


@pytest.mark.parametrize(("section", "key", "value"), [
    ("normal_control", "jitter_milliseconds_mod", 1),
    ("normal_control", "require_all_raw_labels", "benign-or-related"),
    ("normal_control", "reject_attack_overlap", 1),
    ("case_identity", "formula", "sha256(canonical([kind,source,host,start]))[:16]"),
])
def test_policy_cannot_claim_a_different_unimplemented_rule(finalized_inputs, section, key, value):
    from evals.datasets.dedale import neutralize
    from evals.datasets.dedale.common import read_json
    args, _ = finalized_inputs
    policy = read_json(args["splits"])
    policy[section][key] = value
    args["splits"].write_text(canonical(policy) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=section):
        neutralize.finalize_dataset(**args)


def test_complete_group_cache_survives_interruption_without_partial_final_output(finalized_inputs, monkeypatch):
    from evals.datasets.dedale import neutralize
    args, _ = finalized_inputs
    original_emit = neutralize.emit_neutral_cases

    def interrupted(**kwargs):
        original_emit(**kwargs)
        raise RuntimeError("synthetic interruption before atomic publication")

    monkeypatch.setattr(neutralize, "emit_neutral_cases", interrupted)
    with pytest.raises(RuntimeError, match="interruption"):
        neutralize.finalize_dataset(**args)
    assert not args["output_root"].exists()
    monkeypatch.setattr(neutralize, "emit_neutral_cases", original_emit)

    def must_not_rescan(*_args, **_kwargs):
        pytest.fail("verified completed control group was not resumed")

    monkeypatch.setattr(neutralize, "scan_candidate", must_not_rescan)
    selection = neutralize.finalize_dataset(**args)
    assert selection["N_D"] == 4
    assert (args["output_root"] / "selection.json").is_file()


def test_control_cache_tampering_does_not_become_a_verified_resume(finalized_inputs, monkeypatch):
    from evals.datasets.dedale import neutralize
    from evals.datasets.dedale.common import read_json
    args, _ = finalized_inputs

    def interrupted(**_kwargs):
        raise RuntimeError("synthetic interruption")

    monkeypatch.setattr(neutralize, "emit_neutral_cases", interrupted)
    with pytest.raises(RuntimeError, match="interruption"):
        neutralize.finalize_dataset(**args)
    cache = args["output_root"].with_name(args["output_root"].name + "-control-work")
    path = next(cache.glob("control-*.json"))
    result = read_json(path)
    result["results"][0]["raw_window_count"] = 999
    path.write_text(canonical(result) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="payload"):
        neutralize.finalize_dataset(**args)


def test_atomic_publication_retries_transient_windows_access_denial(tmp_path, monkeypatch):
    from evals.datasets.dedale import neutralize
    publish = getattr(neutralize, "publish_staging", None)
    assert publish is not None, "Windows transient publication retry is missing"
    staging, final = tmp_path / "staging", tmp_path / "final"
    staging.mkdir()
    (staging / "selection.json").write_bytes(b"complete selection")
    rename, attempts = Path.rename, []

    def transient(path, target):
        attempts.append(path)
        if len(attempts) < 3:
            error = PermissionError("temporary Windows sharing restriction")
            error.winerror = 5
            raise error
        return rename(path, target)

    monkeypatch.setattr(Path, "rename", transient)
    monkeypatch.setattr(neutralize.time, "sleep", lambda seconds: None)
    publish(staging, final)
    assert len(attempts) == 3
    assert not staging.exists()
    assert (final / "selection.json").read_bytes() == b"complete selection"


def test_atomic_publication_has_bounded_retries_and_preserves_staging(tmp_path, monkeypatch):
    from evals.datasets.dedale import neutralize
    publish = getattr(neutralize, "publish_staging", None)
    assert publish is not None, "Windows transient publication retry is missing"
    staging, final = tmp_path / "staging", tmp_path / "final"
    staging.mkdir()
    attempts = []

    def denied(path, target):
        attempts.append(path)
        error = PermissionError("persistent Windows access denial")
        error.winerror = 5
        raise error

    monkeypatch.setattr(Path, "rename", denied)
    monkeypatch.setattr(neutralize.time, "sleep", lambda seconds: None)
    with pytest.raises(PermissionError, match="persistent"):
        publish(staging, final)
    assert len(attempts) == 6
    assert staging.exists() and not final.exists()


def test_atomic_publication_never_replaces_a_competing_destination(tmp_path, monkeypatch):
    from evals.datasets.dedale import neutralize
    publish = getattr(neutralize, "publish_staging", None)
    assert publish is not None, "Windows transient publication retry is missing"
    staging, final = tmp_path / "staging", tmp_path / "final"
    staging.mkdir()

    def competing(path, target):
        final.mkdir()
        (final / "existing.json").write_bytes(b"preserve this output")
        error = PermissionError("temporary Windows sharing restriction")
        error.winerror = 32
        raise error

    monkeypatch.setattr(Path, "rename", competing)
    monkeypatch.setattr(neutralize.time, "sleep", lambda seconds: None)
    with pytest.raises(FileExistsError):
        publish(staging, final)
    assert staging.exists()
    assert (final / "existing.json").read_bytes() == b"preserve this output"
