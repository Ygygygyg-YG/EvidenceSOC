import json

import pytest

from evals.contracts import canonical_hash
from evals.review import blinded_bundle, build_review_plan, validated_reviews


def rows():
    return [
        {
            "row_id": f"{dataset}-{i}-{group}",
            "dataset": dataset,
            "case_id": f"case{i}",
            "group_id": group,
            "gold": {"is_attack": i < 2},
            "diagnosis": {
                "claims": [
                    {"claim_id": "c1", "text": "observed", "evidence_ids": ["EV1"]}
                ],
                "evidence_ids": ["EV1"],
            },
        }
        for dataset in ("ait", "dedale")
        for i in range(4)
        for group in ("B0", "B1", "B2", "B3", "A1", "A2", "A3", "A4")
    ]


def bundled_record(plan, data):
    target = plan["slots"][0]["slot_id"]
    return next(record for record in blinded_bundle(plan, data)["records"] if record["slot_id"] == target)


def test_review_plan_locks_eight_cases_and_sixtyfour_slots():
    first = build_review_plan(rows())
    assert first == build_review_plan(rows())
    assert len(first["slots"]) == 64
    assert first["underlying_cases"] == 8
    assert "gold" not in json.dumps(first)
    assert len(first["presentation_order"]) == 64
    assert set(first["presentation_order"]) == {slot["slot_id"] for slot in first["slots"]}
    assert first["presentation_order"] != [slot["slot_id"] for slot in first["slots"]]


def test_blinded_bundle_follows_preregistered_presentation_order():
    data = rows()
    plan = build_review_plan(data)
    plan["presentation_order"] = [slot["slot_id"] for slot in reversed(plan["slots"])]
    bundle = blinded_bundle(plan, data)
    assert [record["slot_id"] for record in bundle["records"]] == plan["presentation_order"]


@pytest.mark.parametrize("invalid", ["missing", "short", "duplicate", "unregistered"])
def test_blinded_bundle_and_import_reject_incomplete_presentation_order(tmp_path, invalid):
    data = rows()
    plan = build_review_plan(data)
    order = [slot["slot_id"] for slot in plan["slots"]]
    if invalid == "short":
        order.pop()
    elif invalid == "duplicate":
        order[-1] = order[0]
    elif invalid == "unregistered":
        order[-1] = "unknown-slot"
    if invalid != "missing":
        plan["presentation_order"] = order
    else:
        plan.pop("presentation_order", None)
    with pytest.raises(ValueError, match="presentation"):
        blinded_bundle(plan, data)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    path = tmp_path / "review.json"
    path.write_text(json.dumps({
        "review_plan": str(plan_path), "review_plan_sha256": canonical_hash(plan),
        "reviewer": "user", "records": [],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="presentation"):
        validated_reviews(path, data)


def test_review_import_requires_all_actual_claims_and_human_identity(tmp_path):
    data = rows()
    plan = build_review_plan(data)
    path = tmp_path / "review-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    slot = plan["slots"][0]
    source = {
        "review_plan": str(path),
        "review_plan_sha256": canonical_hash(plan),
        "reviewer": "user",
        "records": [
            {
                "slot_id": slot["slot_id"],
                "reviewed_at": "2026-10-18T21:00:00+08:00",
                "claims": [],
                "relevance": {},
            }
        ],
    }
    review = tmp_path / "review.json"
    review.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(ValueError, match="claims"):
        validated_reviews(review, data)
    source["records"][0]["claims"] = [
        {"claim_id": "c1", "judgment": "supported", "basis": "source event EV1"}
    ]
    source["records"][0]["relevance"] = {"EV1": "supported"}
    source["records"][0]["report_sha256"] = canonical_hash(
        next(row for row in data if row["row_id"] == slot["row_id"])["diagnosis"]
    )
    review.write_text(json.dumps(source), encoding="utf-8")
    imported = validated_reviews(review, data)
    assert imported[slot["row_id"]]["reviewed"] is True
    source["reviewer"] = "Codex"
    review.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(ValueError, match="human"):
        validated_reviews(review, data)


def test_blinded_bundle_accepts_runner_rows_without_dataset_field():
    data = rows()
    plan = build_review_plan(data)
    collected = [
        {key: value for key, value in row.items() if key != "dataset"} for row in data
    ]
    bundle = blinded_bundle(plan, collected)
    assert len(bundle["records"]) == 64
    assert all(
        "group_id" not in item and "row_id" not in item for item in bundle["records"]
    )


def test_two_dataset_review_import_uses_matching_scoring_process(tmp_path):
    data = rows()
    plan = build_review_plan(data)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    other = next(slot for slot in plan["slots"] if slot["dataset"] == "dedale")
    envelope = {
        "review_plan": str(path),
        "review_plan_sha256": canonical_hash(plan),
        "reviewer": "user",
        "records": [{"slot_id": other["slot_id"]}],
    }
    review = tmp_path / "review.json"
    review.write_text(json.dumps(envelope), encoding="utf-8")
    assert (
        validated_reviews(review, [row for row in data if row["dataset"] == "ait"])
        == {}
    )


def test_review_requires_nested_origin_and_stage_top5_citations(tmp_path):
    data = rows()
    plan = build_review_plan(data)
    slot = plan["slots"][0]
    row = next(row for row in data if row["row_id"] == slot["row_id"])
    row["diagnosis"].update(
        origin={"evidence_ids": ["EV2"]}, stage_instances=[{"instance_id":"stage1","phase":"discovery","sequence":1,"evidence_ids": ["EV3"]}]
    )
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    record = {
        "slot_id": slot["slot_id"],
        "reviewed_at": "2026-10-19T19:00:00+08:00",
        "claims": [{"claim_id": "c1", "judgment": "supported", "basis": "EV1"},
                   {"claim_id":"typed:stage.0","judgment":"supported","basis":"EV3"}],
        "relevance": {"EV1": "supported"},
        "report_sha256": canonical_hash(row["diagnosis"]),
    }
    review = tmp_path / "review.json"
    review.write_text(
        json.dumps(
            {
                "review_plan": str(path),
                "review_plan_sha256": canonical_hash(plan),
                "reviewer": "user",
                "records": [record],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="top5"):
        validated_reviews(review, data)


def test_review_cannot_reuse_judgments_after_report_changes(tmp_path):
    data = rows()
    plan = build_review_plan(data)
    slot = plan["slots"][0]
    row = next(row for row in data if row["row_id"] == slot["row_id"])
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    record = {
        "slot_id": slot["slot_id"],
        "reviewed_at": "2026-10-19T19:00:00+08:00",
        "claims": [{"claim_id": "c1", "judgment": "supported", "basis": "source EV1"}],
        "relevance": {"EV1": "supported"},
        "report_sha256": canonical_hash(row["diagnosis"]),
    }
    review = tmp_path / "review.json"
    review.write_text(
        json.dumps(
            {
                "review_plan": str(plan_path),
                "review_plan_sha256": canonical_hash(plan),
                "reviewer": "user",
                "records": [record],
            }
        ),
        encoding="utf-8",
    )
    row["diagnosis"]["claims"][0]["text"] = "a different unsupported conclusion"
    with pytest.raises(ValueError, match="report"):
        validated_reviews(review, data)


def test_blinded_review_includes_structured_facts_when_model_omits_claim_list():
    data=rows()
    plan=build_review_plan(data)
    selected=next(row for row in data if row['row_id']==plan['slots'][0]['row_id'])
    selected['diagnosis']={'verdict':'attack','taxonomy_status':'mapped',
                           'attack_types':['reconnaissance'],'evidence_ids':['EV1'],'claims':[]}
    report=bundled_record(plan,data)
    assert {claim['claim_id'] for claim in report['claims']}=={'typed:verdict','typed:attack_types'}


def snapshot_review_data(source="result"):
    data = rows()
    plan = build_review_plan(data)
    row = next(row for row in data if row["row_id"] == plan["slots"][0]["row_id"])
    snapshot = {
        "diagnosis": row.pop("diagnosis"),
        "origin": {
            "observed_source_ip": "192.0.2.19",
            "source_scope": "external",
            "evidence_ids": ["EV2"],
        },
        "classification": {
            "primary_type": "reconnaissance",
            "attack_types": ["reconnaissance"],
            "attack_phase": "discovery",
            "evidence_ids": ["EV3"],
        },
        "attack_steps": [
            {
                "attack_step_id": "step-1",
                "sequence": 1,
                "phase": "discovery",
                "technique_id": "T1046",
                "description": "The source scanned the entry host.",
                "occurred_at": "2026-10-18T11:00:00+00:00",
                "evidence_ids": ["EV4"],
            }
        ],
        "claims": [
            {"claim_id": "c1", "text": "The scan preceded login.", "evidence_ids": ["EV5"]}
        ],
        "evidence": [{"evidence_id": "EV4", "summary": "source scan event"}],
        "knowledge": [],
        "sealed_after": "reconstruct",
        "sealed_at": "2026-10-18T11:02:00+00:00",
    }
    registry = {
        f"EV{index}": {
            "evidence_id": f"EV{index}",
            "case_id": row["case_id"],
            "summary": f"case observation {index}",
            "content_sha256": str(index) * 64,
        }
        for index in range(1, 6)
    }
    if source in {"result", "both"}:
        row["result"] = {"diagnostic_snapshot": snapshot, "evidence_registry": registry}
        if source == "both":
            row["diagnosis"] = snapshot["diagnosis"]
    else:
        row["diagnosis"] = snapshot
        row["evidence_registry"] = registry
    return data, plan, row, snapshot, registry


def write_review(tmp_path, plan, record):
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    review_path = tmp_path / "review.json"
    review_path.write_text(
        json.dumps({
            "review_plan": str(plan_path),
            "review_plan_sha256": canonical_hash(plan),
            "reviewer": "user",
            "records": [record],
        }),
        encoding="utf-8",
    )
    return review_path


def complete_review_record(record):
    return {
        **record,
        "reviewed_at": "2026-10-19T19:00:00+08:00",
        "claims": [
            {"claim_id": claim["claim_id"], "judgment": "supported", "basis": "source observation"}
            for claim in record["claims"]
        ],
        "relevance": {reference: "supported" for reference in record["evidence_ids"][:5]},
    }


@pytest.mark.parametrize("source", ["diagnosis", "result", "both"])
def test_blinded_review_binds_complete_original_snapshot_and_facts(source):
    data, plan, row, snapshot, registry = snapshot_review_data(source)
    row.update(model="hidden-model", requested_model="hidden-model", group="B3")
    record = bundled_record(plan, data)
    assert record["report_sha256"] == canonical_hash(snapshot)
    claims = {claim["claim_id"]: claim for claim in record["claims"]}
    assert {
        "c1", "snapshot:c1", "typed:snapshot.origin.observed_source_ip",
        "typed:snapshot.classification.primary_type",
        "typed:snapshot.classification.attack_types",
        "typed:snapshot.classification.attack_phase",
        "typed:snapshot.attack_steps.0.description",
        "typed:snapshot.attack_steps.0.occurred_at",
        "typed:snapshot.attack_steps.0.technique_id",
    } <= set(claims)
    assert "The source scanned the entry host." in claims["typed:snapshot.attack_steps.0.description"]["text"]
    assert claims["snapshot:c1"]["text"] == "The scan preceded login."
    assert record["evidence_ids"] == ["EV1", "EV2", "EV3", "EV4", "EV5"]
    assert record["evidence_registry"] == registry
    assert "hidden-model" not in json.dumps(record)
    assert "group_id" not in record and "group" not in record and "row_id" not in record
    assert record["relevance"] == {} and record["reviewed_at"] is None
    assert all("judgment" not in claim for claim in record["claims"])


@pytest.mark.parametrize(
    "section,field,replacement",
    [
        ("origin", "observed_source_ip", "203.0.113.5"),
        ("classification", "primary_type", "credential_attack"),
        ("attack_steps", "description", "An unsupported account compromise occurred."),
        ("attack_steps", "occurred_at", "2026-10-18T12:00:00+00:00"),
        ("claims", "text", "The login preceded the scan."),
    ],
)
def test_review_rejects_reused_judgments_after_original_report_changes(tmp_path, section, field, replacement):
    data, plan, _, snapshot, _ = snapshot_review_data()
    record = complete_review_record(bundled_record(plan, data))
    path = write_review(tmp_path, plan, record)
    assert validated_reviews(path, data)[plan["slots"][0]["row_id"]]["reviewed"] is True
    value = snapshot[section]
    if isinstance(value, list):
        value = value[0]
    value[field] = replacement
    with pytest.raises(ValueError, match="report"):
        validated_reviews(path, data)


def test_review_requires_original_snapshot_claims_even_when_canonical_diagnosis_is_reviewed(tmp_path):
    data, plan, _, snapshot, _ = snapshot_review_data()
    record = {
        "slot_id": plan["slots"][0]["slot_id"],
        "report_sha256": canonical_hash(snapshot),
        "reviewed_at": "2026-10-19T19:00:00+08:00",
        "claims": [{"claim_id": "c1", "judgment": "supported", "basis": "EV1"}],
        "relevance": {"EV1": "supported"},
    }
    with pytest.raises(ValueError, match="claims"):
        validated_reviews(write_review(tmp_path, plan, record), data)


def test_review_requires_top5_citations_from_original_snapshot(tmp_path):
    data, plan, _, _, _ = snapshot_review_data()
    record = complete_review_record(bundled_record(plan, data))
    record["relevance"].pop("EV5", None)
    with pytest.raises(ValueError, match="top5"):
        validated_reviews(write_review(tmp_path, plan, record), data)
