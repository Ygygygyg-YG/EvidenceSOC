"""Synthetic successor fixtures never create real consent or factual credit."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from evals.tests.test_human_review_v2 import (
    ORDER,
    PLAN,
    ROOT,
    completed_fixture,
    pin,
)

AUTH = ROOT / (
    "supplements/task13-repair-202610-v2/audit/"
    "startup-recovery-authorization-20261030/actual-user-instructions.json"
)


def save(tmp_path, name, value):
    path = tmp_path / (name + ".json")
    path.write_text(json.dumps(value), encoding="utf8")
    return pin(path)


def successor_authority(tmp_path):
    policy = {
        "schema_version": "task13-human16-participation-v1",
        "review_window": "anytime",
        "reviewer": "user",
        "applies_to": "new-registered-sixteen-slot-sample-only",
        "judgment_mode": "individual-actual-user",
        "campaign_id": "fixture-new-formal",
        "bundle_sha256": "b" * 64,
        "human_plan": pin(PLAN),
        "presentation_order": pin(ORDER),
        "anytime_authorization": pin(AUTH),
    }
    scope = {
        "schema_version": "task13-rolling-joint-scope-v1",
        "campaign_id": policy["campaign_id"],
        "bundle_sha256": policy["bundle_sha256"],
        "human_review_participation": policy,
    }
    sp = save(tmp_path, "scope", scope)
    decision = {
        "schema_version": "task13-rolling-joint-user-decision-v1",
        "role": "user",
        "decision": "approved",
        "scope_packet_sha256": sp["sha256"],
        "record_id": "fixture-only-joint-decision",
        "text": "unit fixture; never actual consent",
        "decided_at": "2026-10-31T10:00:00+08:00",
    }
    return scope, decision, sp, save(tmp_path, "decision", decision)


def anytime_fixture(tmp_path):
    m, rows, pp, start, reply, store = completed_fixture(tmp_path)
    scope, decision, sp, dp = successor_authority(tmp_path)
    legacy = m.read_pin(pp)
    prepared = m.prepare_reviews(
        pin(PLAN), pin(ORDER), rows, joint_scope_pin=sp, joint_decision_pin=dp
    )
    pp = save(tmp_path, "prepared", prepared)
    for item in (start, reply):
        item["prepared_sha256"] = pp["sha256"]
        item["title"] = (
            f"{prepared['records'][0]['display_code']} factual review {pp['sha256']}"
        )
    return m, rows, pp, start, reply, store, scope, decision, sp, dp, legacy


@pytest.mark.parametrize("hour", ["12:00", "00:00"])
def test_successor_accepts_anytime_and_keeps_blind_records(tmp_path, hour):
    m, rows, pp, start, reply, store, scope, _, sp, dp, legacy = anytime_fixture(
        tmp_path
    )
    prepared = m.read_pin(pp)
    assert prepared["schema_version"] == "task13-human-review-prepared-v3"
    assert prepared["records"] == legacy["records"]
    assert prepared["joint_scope"] == sp
    assert prepared["joint_decision"] == dp
    assert prepared["human_review_participation"] == scope["human_review_participation"]
    for item in (start, reply):
        item["captured_at"] = f"2026-11-01T{hour}:00+08:00"
    result = m.validate_reviews(
        pp, store(), rows, joint_scope_pin=sp, joint_decision_pin=dp
    )
    assert len(result) == 16
    assert sum(r["reviewed"] for r in result.values()) == 1
    assert result[rows[0]["slot_id"]]["measured_duration_seconds"] is None


@pytest.mark.parametrize(
    "hour,allowed", [("12:00", False), ("00:00", False), ("20:00", True)]
)
def test_legacy_window_shape_and_semantics_remain_with_external_authority(
    tmp_path, hour, allowed
):
    m, rows, pp, start, reply, store = completed_fixture(tmp_path)
    _, _, sp, dp = successor_authority(tmp_path)
    assert set(m.read_pin(pp)) == {
        "schema_version",
        "human_plan",
        "presentation_order",
        "records",
    }
    for item in (start, reply):
        item["captured_at"] = f"2026-11-01T{hour}:00+08:00"
    if allowed:
        assert m.validate_reviews(
            pp, store(), rows, joint_scope_pin=sp, joint_decision_pin=dp
        )[rows[0]["slot_id"]]["reviewed"]
    else:
        with pytest.raises(ValueError, match="window"):
            m.validate_reviews(
                pp, store(), rows, joint_scope_pin=sp, joint_decision_pin=dp
            )


@pytest.mark.parametrize(
    "change",
    [
        "absent",
        "f8_only",
        "unknown",
        "extra",
        "window",
        "reviewer",
        "applies",
        "mode",
        "campaign",
        "bundle",
        "plan",
        "order",
        "authorization",
        "auth_provenance",
        "rejected",
        "assistant",
        "wrong_scope",
        "missing_decision",
        "future",
        "naive",
        "synthetic",
        "automatic",
    ],
)
def test_malformed_successor_cannot_enable_anytime(tmp_path, change):
    m, rows, *_ = completed_fixture(tmp_path)
    scope, decision, _, _ = successor_authority(tmp_path)
    policy = scope["human_review_participation"]
    if change in {"absent", "f8_only"}:
        del scope["human_review_participation"]
        if change == "f8_only":
            scope["participation_policy"] = {"dispatch_window": "anytime"}
    if change == "unknown":
        policy["schema_version"] = "task13-human16-participation-v99"
    if change == "extra":
        policy["automatic_credit"] = True
    fields = {
        "window": "review_window",
        "reviewer": "reviewer",
        "applies": "applies_to",
        "mode": "judgment_mode",
        "campaign": "campaign_id",
        "bundle": "bundle_sha256",
    }
    if change in fields:
        policy[fields[change]] = "changed"
    if change in {"plan", "order", "authorization"}:
        key = {
            "plan": "human_plan",
            "order": "presentation_order",
            "authorization": "anytime_authorization",
        }[change]
        policy[key] = {**policy[key], "sha256": "0" * 64}
    if change == "auth_provenance":
        auth = json.loads(AUTH.read_text(encoding="utf8"))
        auth["source"] = "assistant"
        policy["anytime_authorization"] = save(tmp_path, "forged-auth", auth)
    sp = save(tmp_path, "scope", scope)
    decision["scope_packet_sha256"] = sp["sha256"]
    if change == "rejected":
        decision["decision"] = "rejected"
    if change == "assistant":
        decision["role"] = "assistant"
    if change == "wrong_scope":
        decision["scope_packet_sha256"] = "0" * 64
    if change == "future":
        decision["decided_at"] = "2099-01-01T10:00:00+08:00"
    if change == "naive":
        decision["decided_at"] = "2026-10-31T10:00:00"
    if change in {"synthetic", "automatic"}:
        decision[
            {
                "synthetic": "synthetic_control_fixture",
                "automatic": "automatic_approval",
            }[change]
        ] = True
    dp = None if change == "missing_decision" else save(tmp_path, "decision", decision)
    with pytest.raises((ValueError, PermissionError)):
        m.prepare_reviews(
            pin(PLAN), pin(ORDER), rows, joint_scope_pin=sp, joint_decision_pin=dp
        )


@pytest.mark.parametrize(
    "change",
    [
        "no_authority",
        "scope_only",
        "decision_only",
        "other_scope",
        "other_decision",
        "changed_raw",
        "changed_output",
        "before_activation",
        "unknown_prepared",
        "legacy_smuggling",
        "authority_changed",
    ],
)
def test_successor_requires_external_exact_authority_and_activation(tmp_path, change):
    m, rows, pp, start, _reply, store, scope, decision, sp, dp, _ = anytime_fixture(
        tmp_path
    )
    if change == "no_authority":
        sp = dp = None
    if change == "scope_only":
        dp = None
    if change == "decision_only":
        sp = None
    if change == "other_scope":
        scope["campaign_id"] = "other"
        sp = save(tmp_path, "other-scope", scope)
    if change == "other_decision":
        decision["record_id"] = "other"
        dp = save(tmp_path, "other-decision", decision)
    if change == "authority_changed":
        decision["decision"] = "rejected"
        save(tmp_path, "decision", decision)
    if change == "changed_raw":
        Path(pp["path"]).write_bytes(Path(pp["path"]).read_bytes() + b" ")
    if change == "changed_output":
        rows[0]["output_sha256"] = "0" * 64
    if change == "before_activation":
        start["captured_at"] = "2026-10-31T09:59:59+08:00"
    if change in {"unknown_prepared", "legacy_smuggling"}:
        prepared = m.read_pin(pp)
        prepared["schema_version"] = (
            "unknown"
            if change == "unknown_prepared"
            else "task13-human-review-prepared-v2"
        )
        pp = save(tmp_path, "modified-prepared", prepared)
    with pytest.raises((ValueError, PermissionError)):
        m.validate_reviews(pp, store(), rows, joint_scope_pin=sp, joint_decision_pin=dp)


@pytest.mark.parametrize(
    "change",
    [
        "assistant",
        "automatic",
        "synthetic",
        "copied_old",
        "missing_basis",
        "missing_citation",
        "future",
        "clock",
        "question",
        "order",
    ],
)
def test_successor_preserves_individual_actual_judgment_guards(tmp_path, change):
    m, rows, pp, start, reply, store, _, _, sp, dp, _ = anytime_fixture(tmp_path)
    if change == "assistant":
        reply["role"] = "assistant"
    if change == "automatic":
        reply["automatic_approval"] = True
    if change == "synthetic":
        start["synthetic_control_fixture"] = True
    if change == "copied_old":
        reply["prepared_sha256"] = "0" * 64
    if change in {"missing_basis", "missing_citation"}:
        judgment = json.loads(reply["text"])
        if change == "missing_basis":
            del judgment["claims"][0]["basis"]
        else:
            judgment["relevance"] = {}
        reply["text"] = json.dumps(judgment)
    if change == "future":
        reply["captured_at"] = "2099-01-01T12:00:00+08:00"
    if change == "clock":
        start.update(monotonic_ns=10, clock_session_id="a")
        reply.update(monotonic_ns=1, clock_session_id="a")
    if change == "question":
        reply["question"] = "approve"
    captures = store()
    if change == "order":
        captures += captures
    with pytest.raises((ValueError, KeyError)):
        m.validate_reviews(
            pp, captures, rows, joint_scope_pin=sp, joint_decision_pin=dp
        )


def test_successor_keeps_all_missing_slots_and_no_deadline_for_offline_reviews(
    tmp_path,
):
    m, rows, *_ = completed_fixture(tmp_path)
    _, decision, sp, _ = successor_authority(tmp_path)
    decision["decided_at"] = "2026-10-30T20:00:00+08:00"
    dp = save(tmp_path, "decision", decision)
    for row in rows:
        row["result"] = row["output_sha256"] = None
    prepared = m.prepare_reviews(
        pin(PLAN), pin(ORDER), rows, joint_scope_pin=sp, joint_decision_pin=dp
    )
    pp = save(tmp_path, "prepared", prepared)
    result = m.validate_reviews(pp, [], rows, joint_scope_pin=sp, joint_decision_pin=dp)
    assert len(result) == 16
    assert all(
        r["reason"] == "missing_output" and not r["reviewed"] for r in result.values()
    )


def test_successor_rejects_reused_question_across_fresh_slot_replies(tmp_path):
    m, rows, pp, start, reply, store, _, _, sp, dp, _ = anytime_fixture(tmp_path)
    captures = store()
    record = m.read_pin(pp)["records"][1]
    start2, reply2 = deepcopy(start), deepcopy(reply)
    for item in (start2, reply2):
        item.update(
            slot_id=record["slot_id"],
            title=f"{record['display_code']} factual review {pp['sha256']}",
            question=json.dumps(record, ensure_ascii=False, sort_keys=True),
            captured_at="2026-10-31T20:01:00+08:00",
        )
    reply2["record_id"] = "distinct-new-slot-reply"
    captures.append(
        {
            "presentation": save(tmp_path, "start2", start2),
            "reply": save(tmp_path, "reply2", reply2),
        }
    )
    with pytest.raises(ValueError, match="question delivery"):
        m.validate_reviews(
            pp, captures, rows, joint_scope_pin=sp, joint_decision_pin=dp
        )


def test_successor_offline_judgment_can_follow_formal_admission_deadline(
    tmp_path, monkeypatch
):
    from datetime import UTC, datetime

    m, rows, pp, start, reply, store, _, _, sp, dp, _ = anytime_fixture(tmp_path)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 11, 7, tzinfo=UTC)

    monkeypatch.setattr(m, "datetime", Later)
    for item in (start, reply):
        item["captured_at"] = "2026-11-06T12:00:00+08:00"
    result = m.validate_reviews(
        pp, store(), rows, joint_scope_pin=sp, joint_decision_pin=dp
    )
    assert result[rows[0]["slot_id"]]["reviewed"]


@pytest.mark.parametrize(
    "mode", ["successor", "legacy", "other_scope", "other_decision"]
)
def test_scorer_uses_native_audited_human_authority_and_exports_window(
    tmp_path, monkeypatch, mode
):
    import evals.scoring_v2 as scoring

    _m, rows, pp, start, reply, store, scope, decision, sp, dp, legacy = (
        anytime_fixture(tmp_path)
    )
    if mode == "legacy":
        pp = save(tmp_path, "legacy", legacy)
        for item in (start, reply):
            item["prepared_sha256"] = pp["sha256"]
            item["title"] = (
                f"{legacy['records'][0]['display_code']} factual review {pp['sha256']}"
            )
    else:
        start["captured_at"] = reply["captured_at"] = "2026-11-01T12:00:00+08:00"
    audited = {"joint_scope": sp, "joint_decision": dp}
    if mode == "other_scope":
        other = deepcopy(scope)
        other["extra_control"] = "different whole scope"
        audited["joint_scope"] = save(tmp_path, "other-scope", other)
    if mode == "other_decision":
        other = deepcopy(decision)
        other["record_id"] = "different-real-reply"
        audited["joint_decision"] = save(tmp_path, "other-decision", other)
    bundle = {"campaign_id": "fixture", "source_commit": "c" * 40}
    bundle_pin = save(tmp_path, "bundle", bundle)
    plans = {d: {"controller": {"dataset": d}} for d in ("ait", "dedale")}
    scoring_pins = {d: {"sha256": d} for d in plans}
    (tmp_path / "agent").mkdir()
    (tmp_path / "agent" / "manifest.json").write_text("{}")
    for row in rows:
        row.update(
            dataset=row["case_id"].split("-", 1)[0],
            input_hashes={},
            attempts=[],
            request={
                "budget": {"max_tool_calls": 0},
                "model": {"requested_model": "fixture", "published_version": "fixture"},
            },
        )
    # Isolate the sealed-native audit boundary; factual validation remains real.
    monkeypatch.setattr(scoring, "load_original_plans", lambda _: plans)
    monkeypatch.setattr(scoring, "validate_f8_scope", lambda *a, **k: audited)
    monkeypatch.setattr(scoring, "collect_regression", lambda *a: rows)
    monkeypatch.setattr(scoring, "validate_scoring_row", lambda *a: (tmp_path, {}))
    monkeypatch.setattr(scoring, "load_gold", lambda *a: ({}, {}, {}))
    monkeypatch.setattr(
        scoring, "score_rows", lambda values: {"planned_n": len(values)}
    )
    monkeypatch.setattr(scoring, "native_f8", lambda _: None)

    def score():
        return scoring.score_bundle(
            bundle_pin,
            tmp_path,
            scoring_plan_pins=scoring_pins,
            prepared_pin=pp,
            captures=store(),
            verification_campaign=object(),
            joint_scope_pin=sp,
            joint_decision_pin=dp,
        )

    if mode.startswith("other_"):
        with pytest.raises(ValueError, match="external"):
            score()
    else:
        result = score()
        human = result["human_review"]
        assert len(human["records"]) == 16
        assert result["metadata"]["score_status"] == "independent_intermediate"
        assert (
            sum(v["planned_n"] for gs in result["groups"].values() for v in gs.values())
            == 16
        )
        if mode == "successor":
            assert human["review_window"] == "anytime"
            assert (
                human["human_review_participation"]
                == scope["human_review_participation"]
            )
            assert human["joint_scope"] == sp and human["joint_decision"] == dp
        else:
            assert human["review_window"] == "19:00-00:00 Asia/Shanghai"
            assert human["human_review_participation"] is None
            assert human["joint_scope"] is None and human["joint_decision"] is None
