"""Real v3 emission must agree with all local acceptance checks.

The tiny archives are pinned by the existing synthetic fixture. They cannot
establish the publisher's 1,344-member / 15,783-label coverage or live runtime
evidence; those gates are kept separate from the v3 structural checks.
"""
from __future__ import annotations

from copy import deepcopy

import pytest

from evals.datasets.dedale import audit, neutral_audit, neutralize
from evals.datasets.dedale.common import canonical
from evals.datasets.dedale.join_labels import load_label_index
from evals.tests import test_dedale_neutralize

finalized_inputs = test_dedale_neutralize.finalized_inputs


def test_emitted_final_cases_pass_actual_policy_checkpoint_and_artifact_checks(finalized_inputs):
    args, preparation = finalized_inputs
    selection = neutralize.finalize_dataset(**args)
    old_splits = neutral_audit._policy_and_lineage(
        selection, preparation, sources=args["sources"], splits=args["splits"],
        scan_splits=args["scan_splits"], label_policy=args["label_policy"],
        prepared_root=args["prepared_root"],
    )
    labels = load_label_index(args["data_root"] / "system_logs_labels.zip", exhaustive=True)
    index, binding = neutralize.load_member_index(
        data_root=args["data_root"], prepared_root=args["prepared_root"],
        preparation_checkpoints=args["preparation_checkpoints"], selection=preparation,
        labels=labels, scan_splits=old_splits,
    )
    assert index == selection["preparation"]["member_index"]
    assert binding == selection["preparation"]["checkpoint_binding"]
    selected = neutral_audit.validate_candidate_ledger(selection, preparation, index)
    gates, gold, errors = audit._audit_cases(
        selection, args["output_root"], selected, labels=labels, official_labels=True, precise=True,
    )
    assert gates == {"artifacts": True, "candidate_closure": True, "minimum_size": True}
    assert errors == []
    assert len(gold) == selection["N_D"] == 4
    neutral_audit._observation_lineage(
        selection, preparation, args["output_root"], args["prepared_root"], selected,
    )


def test_neutral_acceptance_runs_real_structural_checks_while_external_gates_stay_pending(
    finalized_inputs, monkeypatch,
):
    args, preparation = finalized_inputs
    selection = neutralize.finalize_dataset(**args)
    original_audit = audit.audit_prepared

    def audit_tiny_preparation(value, root, **kwargs):
        # Run the actual v2 source, label, ledger and artifact checks first.
        # Only publisher-size constants cannot be satisfied by this fixture.
        assert value == preparation and value.get("protocol") != neutralize.PROTOCOL
        report = original_audit(value, root, **kwargs)
        for name in ("official_sources", "official_labels", "artifacts", "candidate_closure", "minimum_size"):
            assert report["gates"][name], report
        assert report["errors"] == []
        assert not report["gates"]["dates"]
        assert not report["gates"]["complete_label_join"]
        report["gates"]["dates"] = report["gates"]["complete_label_join"] = True
        return report

    monkeypatch.setattr(audit, "audit_prepared", audit_tiny_preparation)
    report = neutral_audit.audit_neutral_prepared(
        selection, args["output_root"],
        **{name: args[name] for name in ("sources", "data_root", "prepared_root", "preparation_checkpoints",
                                        "splits", "scan_splits", "label_policy")},
    )
    assert report["errors"] == []
    for name in ("official_sources", "official_labels", "artifacts", "candidate_closure", "minimum_size",
                 "preparation_lineage", "neutral_policy", "targeted_member_receipts", "finalizer_code"):
        assert report["gates"][name], report
    assert set(report["failed_gates"]) == {
        "stage_coverage", "live_context", "scoring_filesystem_isolation", "cross_path_rebuild", "resource_measurement",
    }
    assert report["accepted"] is False
    assert report["model_invocations"] == 0


@pytest.mark.parametrize("change", ["attack_observation", "normal_anchor"])
def test_changed_final_observations_fail_real_lineage(finalized_inputs, change):
    args, preparation = finalized_inputs
    selection = neutralize.finalize_dataset(**args)
    selected = neutral_audit.validate_candidate_ledger(
        selection, preparation, selection["preparation"]["member_index"],
    )
    attack = change == "attack_observation"
    case = next(case for case in selection["cases"] if case["is_attack"] is attack)
    path = args["output_root"] / "test" / case["case_id"] / "agent/events.jsonl"
    observations = deepcopy(neutralize._line_json(path))
    if attack:
        observations[0]["message"] = "replacement that was never observed"
    else:
        observations[0]["observed_at"] = neutralize.shift_seconds(observations[0]["observed_at"], 1)
    path.write_text("".join(canonical(event) + "\n" for event in observations), encoding="utf-8")
    with pytest.raises(ValueError, match="observations changed|anchor"):
        neutral_audit._observation_lineage(
            selection, preparation, args["output_root"], args["prepared_root"], selected,
        )
