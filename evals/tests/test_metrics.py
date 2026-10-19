"""Hand-calculable Task13 denominator and provenance regression cases."""
from importlib.util import find_spec

import pytest


def metrics():
    assert find_spec("evals.metrics.classification") is not None, "Task13 metric implementation missing"
    from evals.metrics import score_rows
    return score_rows


def row(truth, verdict=None, *, status="succeeded", classes=(), predicted=()):
    return {"case_id": "case", "applicability": {"attack_binary": True, "six_class": True},
            "gold": {"is_attack": truth, "attack_types": list(classes)},
            "diagnostic_status": status, "execution_status": "succeeded",
            "diagnosis": {"verdict": verdict, "attack_types": list(predicted), "evidence_ids": []}}


def test_unknown_failed_missing_keep_gold_denominator():
    rows = [row(True, "attack"), row(True, "unknown"), row(True, "attack", status="failed"),
            row(False, "benign"), row(False, "unknown"), row(False, status="missing")]
    value = metrics()(rows)["classification"]["binary"]
    assert value["applicable_n"] == 6
    assert value["precision"] == 1
    assert value["recall"] == pytest.approx(1 / 3)
    assert value["f1"] == pytest.approx(0.5)
    assert value["accuracy"] == pytest.approx(1 / 3)
    assert value["fpr"] == 0
    assert value["benign_correct_rate"] == pytest.approx(1 / 3)
    assert value["answer_coverage"] == pytest.approx(1 / 3)
    assert value["confusion"]["attack"]["failed"] == 1
    assert value["confusion"]["benign"]["missing"] == 1


def test_fixed_six_classes_include_zero_support_and_ignore_inapplicable_rows():
    rows = [row(True, "attack", classes=("reconnaissance",), predicted=("reconnaissance",)),
            row(False, "benign")]
    excluded = row(True, "attack", predicted=("credential_attack",))
    excluded["applicability"]["six_class"] = False
    rows.append(excluded)
    value = metrics()(rows)["classification"]["six_class"]
    assert value["macro_f1"] == pytest.approx(1 / 6)
    assert value["supported_macro_f1"] == 1
    assert value["per_class"]["credential_attack"]["support"] == 0
    assert value["per_class"]["credential_attack"]["f1"] == 0
    assert value["applicable_n"] == 2


def test_evidence_dedup_padding_cross_case_and_human_uncertainty():
    value = row(True, "attack")
    value["diagnosis"]["evidence_ids"] = ["E1", "E1", "E2", "OTHER"]
    value["evidence_registry"] = {"E1": {"case_id": "case", "content_sha256": "a" * 64},
                                  "E2": {"case_id": "case", "content_sha256": "b" * 64},
                                  "OTHER": {"case_id": "another", "content_sha256": "c" * 64}}
    value["human_review"] = {"reviewed": True, "relevance": {"E1": "supported", "E2": "uncertain"},
                             "claims": [{"judgment": "unsupported"}, {"judgment": "supported"},
                                        {"judgment": "uncertain"}]}
    scored = metrics()([value])["evidence"]
    assert scored["citation_validity"] == pytest.approx(3 / 4)
    assert scored["citation_count"] == 4
    assert scored["p_at_5_lower"] == pytest.approx(1 / 5)
    assert scored["p_at_5_upper"] == pytest.approx(2 / 5)
    assert scored["ucr_lower"] == pytest.approx(1 / 3)
    assert scored["ucr_upper"] == pytest.approx(2 / 3)
    assert scored["semantic_reviewed_reports"] == 1


def test_empty_evidence_is_na_and_missing_usage_is_not_zero():
    scored = metrics()([row(False, "benign")])
    assert scored["evidence"]["citation_validity"] is None
    assert scored["evidence"]["p_at_5_lower"] is None
    assert scored["evidence"]["zero_citation_report_rate"] == 1
    assert scored["resources"]["input_tokens"] is None
    assert scored["resources"]["cost"] is None
    assert scored["resources"]["usage_missing_count"] == 1


def test_repeated_stage_instances_and_partial_order_not_collapsed():
    value = row(True, "attack")
    value["applicability"]["phases"] = True
    value["gold"]["stage_instances"] = [
        {"instance_id": "g1", "phase": "recon", "evidence_ids": ["E1"]},
        {"instance_id": "g2", "phase": "recon", "evidence_ids": ["E2"]},
        {"instance_id": "g3", "phase": "execute", "evidence_ids": ["E3"]}]
    value["gold"]["precedes"] = [["g1", "g3"], ["g2", "g3"]]
    value["diagnosis"]["stage_instances"] = [
        {"instance_id": "p1", "phase": "recon", "sequence": 1, "evidence_ids": ["E1"]},
        {"instance_id": "p3", "phase": "execute", "sequence": 2, "evidence_ids": ["E3"]}]
    scored = metrics()([value])["attack_chain"]
    assert scored["stage_recall"] == pytest.approx(2 / 3)
    assert scored["stage_f1"] == pytest.approx(0.8)
    assert scored["order_accuracy"] == pytest.approx(0.5)
    assert scored["comparable_pairs"] == 2
    value["gold"]["precedes"] = []
    assert metrics()([value])["attack_chain"]["order_accuracy"] is None


def test_late_execution_failure_does_not_erase_successful_diagnosis():
    value = row(True, "attack")
    value["execution_status"] = "failed"
    assert metrics()([value])["classification"]["binary"]["recall"] == 1


def test_unknown_prediction_is_not_a_six_class_positive():
    value = row(True, "unknown", classes=("reconnaissance",), predicted=("reconnaissance",))
    result = metrics()([value])["classification"]["six_class"]["per_class"]["reconnaissance"]
    assert result["true_positive"] == 0
    assert result["false_negative"] == 1


def test_adapter_result_contract_diagnosis_status_alias():
    value = {"case_id": "case", "applicability": {"attack_binary": True},
             "gold": {"is_attack": True},
             "result": {"diagnosis_status": "succeeded", "diagnostic_snapshot": {"verdict": "attack"}}}
    assert metrics()([value])["classification"]["binary"]["recall"] == 1


def test_backend_sealed_snapshot_and_wrong_case_pairing_are_explicit():
    value = {"case_id": "case", "applicability": {"attack_binary": True}, "gold": {"is_attack": True},
             "result": {"diagnosis_status": "succeeded", "diagnostic_snapshot": {"diagnosis": {"verdict": "attack"}}}}
    assert metrics()([value])["classification"]["binary"]["recall"] == 1
    assert metrics()([value])["classification"]["binary"]["applicable_case_ids"] == ["case"]


def test_partial_order_uses_transitive_comparable_pairs_and_rejects_cycles():
    value = row(True, "attack")
    value["applicability"]["phases"] = True
    value["gold"]["stage_instances"] = [
        {"instance_id": str(i), "phase": "scan", "evidence_ids": [f"E{i}"]} for i in range(3)]
    value["diagnosis"]["stage_instances"] = [
        {"instance_id": str(i), "phase": "scan", "sequence": i, "evidence_ids": [f"E{i}"]} for i in range(3)]
    value["gold"]["precedes"] = [["0", "1"], ["1", "2"]]
    assert metrics()([value])["attack_chain"]["comparable_pairs"] == 3
    value["gold"]["precedes"].append(["2", "0"])
    with pytest.raises(ValueError, match="acyclic"):
        metrics()([value])


def test_verification_uses_identical_executable_pairs_and_disabled_is_unverified():
    from evals import metrics as package
    assert hasattr(package, "score_verification"), "Task13 paired verification metric missing"
    slots = [{"pair_id": "p1", "case_id": "c1", "condition": "failure"},
             {"pair_id": "p2", "case_id": "c2", "condition": "failure"}]
    records = [{"pair_id": "p1", "branch": "enabled", "status": "completed", "approval_status": "approved", "outcome": "failure"},
               {"pair_id": "p1", "branch": "disabled", "status": "completed", "approval_status": "approved", "outcome": "unverified"},
               {"pair_id": "p2", "branch": "enabled", "status": "completed", "approval_status": "approved", "outcome": "success"},
               {"pair_id": "p2", "branch": "disabled", "status": "failed", "approval_status": "approved"}]
    value = package.score_verification(records, slots)
    assert value["planned_pairs"] == 2
    assert value["complete_pairs"] == 1
    assert value["conditions"]["failure"]["branches"]["enabled"]["failure_recognition_rate"] == 1
    assert value["conditions"]["failure"]["branches"]["enabled"]["false_success_rate"] == 0
    assert value["conditions"]["failure"]["branches"]["disabled"]["false_success_rate"] is None
    assert value["conditions"]["failure"]["branches"]["enabled"]["all_outcome_counts"]["success"] == 1
    assert value["cost"] is None


def test_actual_tool_ledger_attempts_are_not_hidden_by_logical_count():
    value = row(False, "benign")
    value["tool_calls"] = [{"call_id": "t1", "attempts": 3}]
    value["model_calls"] = [{"logical_call_id": "m1", "physical_attempts": 2}]
    score = metrics()([value])["resources"]
    assert score["tool_logical_calls"] == 1
    assert score["tool_physical_attempts"] == 3
    assert score["model_retries"] == 1


def test_cache_reuse_does_not_double_charge_tool_attempts():
    value = row(False, "benign")
    value["tool_calls"] = [{"call_id": "t1", "attempts": 3, "charged": True},
                           {"call_id": "t2", "source_call_id": "t1", "attempts": 3, "charged": False}]
    score = metrics()([value])["resources"]
    assert score["tool_logical_calls"] == 1
    assert score["tool_physical_attempts"] == 3


def test_nested_references_are_counted_and_p_at_5_has_one_frozen_order():
    from evals.metrics import evidence as module
    assert hasattr(module, "ordered_citations"), "Frozen nested citation traversal missing"
    value = row(True, "attack")
    value["diagnosis"].update(evidence_ids=["E1"], origin={"evidence_ids": ["E2"]},
        stage_instances=[{"evidence_ids": ["E1"]}], claims=[{"evidence_ids": ["FAKE"]}])
    value["evidence_registry"] = {"E1": {"case_id": "case", "content_sha256": "a" * 64},
                                  "E2": {"case_id": "case", "content_sha256": "b" * 64}}
    assert module.ordered_citations(value["diagnosis"]) == ["E1", "E2", "E1", "FAKE"]
    scored = metrics()([value])["evidence"]
    assert scored["citation_count"] == 4
    assert scored["citation_validity"] == pytest.approx(.75)
    del value["evidence_registry"]["E2"]["content_sha256"]
    assert metrics()([value])["evidence"]["citation_validity"] == .5


def test_optional_explicit_citation_digest_must_match_trusted_content():
    value = row(True, "attack")
    value["diagnosis"].update(evidence_ids=["E1", "E2"], evidence_hashes={"E1": "b" * 64})
    value["evidence_registry"] = {"E1": {"case_id": "case", "content_sha256": "a" * 64},
                                  "E2": {"case_id": "case", "content_sha256": "c" * 64}}
    assert metrics()([value])["evidence"]["citation_validity"] == .5
    value["diagnosis"]["evidence_hashes"]["E1"] = "a" * 64
    assert metrics()([value])["evidence"]["citation_validity"] == 1


def test_nested_top5_dedup_preserves_origin_before_stages_and_claims():
    value = row(True, "attack")
    value["diagnosis"].update(evidence_ids=["E1", "E1"], origin={"evidence_ids": ["E2", "E3"]},
        stage_instances=[{"evidence_ids": ["E4", "E5"]}], claims=[{"evidence_ids": ["E6"]}])
    value["evidence_registry"] = {f"E{i}": {"case_id": "case", "content_sha256": "a" * 64} for i in range(1, 7)}
    value["human_review"] = {"reviewed": True, "relevance": {f"E{i}": "supported" for i in range(2, 7)}}
    scored = metrics()([value])["evidence"]
    assert scored["citation_count"] == 7
    assert scored["actual_unique_reference_counts"] == [6]
    assert scored["p_at_5_lower"] == .8


def test_verification_completion_requires_branch_appropriate_observed_outcomes():
    from evals.metrics import score_verification
    slots = [{"pair_id": condition, "case_id": "case", "condition": condition}
             for condition in ("success", "failure", "no_change")]
    records = [{"pair_id": condition, "branch": branch, "status": "completed", "approval_status": "approved",
                "outcome": "unverified" if branch == "disabled" else None}
               for condition in ("success", "failure", "no_change") for branch in ("enabled", "disabled")]
    result = score_verification(records, slots)
    assert result["complete_pairs"] == 0
    assert result["cases_complete_all_conditions"] == 0
    assert result["observed_branches"] == 6
    assert result["conditions"]["failure"]["branches"]["enabled"]["false_success_rate"] is None


def test_unknown_tool_export_keeps_totals_null_and_retains_observed_subtotals():
    known, incomplete = row(False, "benign"), row(False, status="failed")
    known.update(tool_ledger_complete=True, tool_calls=[{"call_id": "t1", "attempts": 3, "charged": True},
        {"call_id": "reuse", "attempts": 3, "charged": False, "source_call_id": "t1"}])
    incomplete.update(tool_ledger_complete=False, tool_calls=[{"call_id": "partial", "attempts": 1, "charged": True}])
    score = metrics()([known, incomplete])["resources"]
    assert score["tool_logical_calls"] is None
    assert score["tool_physical_attempts"] is None
    assert score["known_subtotals"]["tool_logical_calls"] == 2
    assert score["known_subtotals"]["tool_physical_attempts"] == 4
    assert score["tool_ledger_missing_count"] == 1


def test_known_empty_tool_ledger_is_zero_and_absent_ledger_is_unknown():
    known = row(False, "benign")
    known.update(tool_ledger_complete=True, tool_calls=[])
    score = metrics()([known])["resources"]
    assert score["tool_logical_calls"] == 0
    assert score["tool_physical_attempts"] == 0
    assert score["known_subtotals"]["tool_logical_calls"] == 0
    assert score["tool_ledger_missing_count"] == 0
    del known["tool_ledger_complete"]
    assert metrics()([known])["resources"]["tool_logical_calls"] == 0  # legacy explicit list
    unknown = metrics()([row(False, status="missing")])["resources"]
    assert unknown["tool_logical_calls"] is None
    assert unknown["tool_physical_attempts"] is None
    assert unknown["known_subtotals"]["tool_logical_calls"] is None
    assert unknown["tool_ledger_missing_count"] == 1


@pytest.mark.parametrize("source", ["diagnosis", "result", "both"])
def test_full_sealed_report_citations_drive_validity_and_manual_top5(source):
    from evals.metrics.evidence import ordered_citations

    value = row(True, "attack", classes=("reconnaissance",), predicted=("reconnaissance",))
    canonical = value.pop("diagnosis")
    canonical.update(
        evidence_ids=["E1"],
        claims=[{"claim_id": "c1", "text": "diagnosis assertion", "evidence_ids": ["E1"]}],
    )
    snapshot = {
        "diagnosis": canonical,
        "origin": {"observed_source_ip": "192.0.2.19", "evidence_ids": ["E2"]},
        "classification": {"attack_types": ["credential_attack"], "evidence_ids": ["E3"]},
        "attack_steps": [{"description": "actual reconstruction", "evidence_ids": ["E4", "E4"]}],
        "claims": [{"claim_id": "native", "text": "native assertion", "evidence_ids": ["E5"]}],
    }
    if source in {"result", "both"}:
        value["result"] = {"diagnostic_snapshot": snapshot, "diagnosis_status": "succeeded"}
        if source == "both":
            value["diagnosis"] = canonical
    else:
        value["diagnosis"] = snapshot
    value["evidence_registry"] = {
        f"E{i}": {"case_id": "case" if i < 5 else "another", "content_sha256": "a" * 64}
        for i in range(1, 6)
    }
    value["human_review"] = {
        "reviewed": True,
        "relevance": {"E1": "supported", "E2": "uncertain", "E3": "supported", "E4": "supported", "E5": "supported"},
        "claims": [{"judgment": "supported"}, {"judgment": "unsupported"}, {"judgment": "uncertain"}],
    }
    assert ordered_citations(snapshot) == ["E1", "E1", "E2", "E3", "E4", "E4", "E5"]
    scores = metrics()([value])
    evidence = scores["evidence"]
    assert evidence["citation_count"] == 7
    assert evidence["valid_citation_count"] == 6
    assert evidence["citation_validity"] == pytest.approx(6 / 7)
    assert evidence["actual_unique_reference_counts"] == [5]
    assert evidence["p_at_5_lower"] == pytest.approx(3 / 5)
    assert evidence["p_at_5_upper"] == pytest.approx(4 / 5)
    assert evidence["semantic_denominator_slots"] == 5
    assert evidence["reviewed_claim_count"] == 3
    assert evidence["ucr_lower"] == pytest.approx(1 / 3)
    assert evidence["ucr_upper"] == pytest.approx(2 / 3)
    assert scores["classification"]["six_class"]["per_class"]["reconnaissance"]["true_positive"] == 1
    assert scores["classification"]["six_class"]["per_class"]["credential_attack"]["false_positive"] == 0
    del value["human_review"]
    evidence = metrics()([value])["evidence"]
    assert evidence["citation_count"] == 7
    assert evidence["reviewed_claim_count"] == 0
    assert evidence["p_at_5_lower"] is None and evidence["ucr_lower"] is None


def test_full_report_traversal_keeps_canonical_nested_order_before_outer_facts():
    from evals.metrics.evidence import ordered_citations

    snapshot = {
        "diagnosis": {
            "evidence_ids": ["D1"], "origin": {"evidence_ids": ["D2"]},
            "stage_instances": [{"evidence_ids": ["D3"]}], "claims": [{"evidence_ids": ["D4"]}],
        },
        "evidence_ids": ["S1"], "origin": {"evidence_ids": ["S2"]},
        "classification": {"evidence_ids": ["S3"]},
        "attack_steps": [{"evidence_ids": ["S4"]}], "claims": [{"evidence_ids": ["S5"]}],
    }
    assert ordered_citations(snapshot) == ["D1", "D2", "D3", "D4", "S1", "S2", "S3", "S4", "S5"]


def test_full_report_preserves_digest_constraints_from_both_report_layers():
    value = row(True, "attack")
    value["diagnosis"] = {
        "diagnosis": {"verdict": "attack", "evidence_ids": ["E1"], "evidence_hashes": {"E1": "b" * 64}},
        "attack_steps": [{"evidence_ids": ["E2"]}],
        "evidence_hashes": {"E2": "b" * 64},
    }
    value["evidence_registry"] = {
        reference: {"case_id": "case", "content_sha256": "a" * 64}
        for reference in ("E1", "E2")
    }
    evidence = metrics()([value])["evidence"]
    assert evidence["citation_count"] == 2
    assert evidence["citation_validity"] == 0
    value["diagnosis"]["diagnosis"]["evidence_hashes"]["E1"] = "a" * 64
    assert metrics()([value])["evidence"]["citation_validity"] == .5
    value["diagnosis"]["evidence_hashes"]["E2"] = "a" * 64
    assert metrics()([value])["evidence"]["citation_validity"] == 1
