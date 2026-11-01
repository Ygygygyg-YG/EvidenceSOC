"""Offline contracts only: mock captures and user-origin fields are synthetic test data.
No fixture here is evidence of actual user consent or real execution.
"""

import asyncio
import importlib
import importlib.util
from copy import deepcopy
from datetime import datetime, timezone

import pytest


def module():
    assert importlib.util.find_spec("evals.task13_rolling"), (
        "durable rolling controller required"
    )
    return importlib.import_module("evals.task13_rolling")


class Operations:
    synthetic = True

    def __init__(self):
        self.rows = []
        for i in range(88):
            case = ("ait-" + f"{i:024x}") if i < 22 else ("dedale-" + f"{i:016x}")
            for group in ("B3", "B2"):
                self.rows.append(
                    {
                        "slot_id": f"{i}-{group}",
                        "case_id": case,
                        "group": group,
                        "status": "not_started",
                    }
                )
        self.calls = []
        self.plan = False

    def guard(self):
        self.calls.append("guard")

    def status(self):
        return {"rows": deepcopy(self.rows)}

    def execute(self, row_limit):
        self.calls.append(("execute", row_limit))
        for row in [r for r in self.rows if r["status"] == "not_started"][:row_limit]:
            row["status"] = "completed"

    async def prepare(self, case):
        self.calls.append(("prepare", case))
        if not self.plan:
            return {"gap": "no_response_plan"}
        return {
            "source": {"case_id": case},
            "packet": {"case_id": case, "review_window": "anytime"},
        }

    async def decide(self, claim, decision):
        self.calls.append(("decide", decision))
        return {"source": claim["source"], "receipt": {"approved": True}}

    async def verify(self, claim, result):
        self.calls.append("verify")

    async def run_f8(self, case, result):
        self.calls.append(("f8", case))
        return {"status": "completed"}

    def reconcile(self):
        self.calls.append("reconcile")
        return {"status": "verified"}


def make(tmp_path):
    m = module()
    ops = Operations()
    ctl = m.RollingController(
        tmp_path,
        ops.rows,
        ops,
        scope_sha256="a" * 64,
        synthetic=True,
        clock=lambda: datetime(2026, 11, 2, tzinfo=timezone.utc),
    )
    return ctl, ops


def test_pair_order_half_pair_and_gap(tmp_path):
    ctl, ops = make(tmp_path)
    ops.rows[0]["status"] = "completed"
    out = asyncio.run(ctl.advance())
    assert out["status"] == "gap"
    assert ("execute", 1) in ops.calls
    assert ops.calls.index("reconcile") > ops.calls.index(
        ("prepare", ops.rows[0]["case_id"])
    )
    assert ops.rows[2]["status"] == "not_started"


def test_single_pending_survives_restart_and_decision_precedes_f8(tmp_path):
    ctl, ops = make(tmp_path)
    ops.plan = True
    pending = asyncio.run(ctl.advance())
    assert pending["status"] == "pending_approval"
    count = len(ops.calls)
    ctl2 = module().RollingController(
        tmp_path, ops.rows, ops, scope_sha256="a" * 64, synthetic=True, clock=ctl.clock
    )
    assert asyncio.run(ctl2.advance()) == pending
    assert len(ops.calls) == count
    out = asyncio.run(
        ctl2.decide(
            question_id="real-question",
            decision="approved",
            reason="actual user",
            packet_sha256=pending["packet_sha256"],
        )
    )
    assert out["status"] == "completed"
    assert (
        ops.calls.index("verify")
        < ops.calls.index(("f8", ops.rows[0]["case_id"]))
        < ops.calls.index("reconcile")
    )
    with pytest.raises(PermissionError):
        asyncio.run(
            ctl2.decide(
                question_id="again",
                decision="approved",
                reason="retry",
                packet_sha256=pending["packet_sha256"],
            )
        )


def test_unknown_deadline_and_stale_lock_never_dispatch(tmp_path):
    ctl, ops = make(tmp_path)
    ops.rows[0]["status"] = "unknown"
    with pytest.raises(PermissionError):
        asyncio.run(ctl.advance())
    assert not any(isinstance(x, tuple) and x[0] == "execute" for x in ops.calls)
    ops.rows[0]["status"] = "not_started"
    ctl.clock = lambda: datetime(2026, 11, 6, tzinfo=timezone.utc)
    assert asyncio.run(ctl.advance())["status"] == "deadline_stopped"
    (tmp_path / ".writer-lock").mkdir()
    with pytest.raises(PermissionError):
        asyncio.run(ctl.advance())


def test_crashed_decision_is_not_replayed(tmp_path):
    ctl, ops = make(tmp_path)
    ops.plan = True
    pending = asyncio.run(ctl.advance())

    async def crashed(*args):
        raise RuntimeError("transport uncertain")

    ops.decide = crashed
    with pytest.raises(RuntimeError):
        asyncio.run(
            ctl.decide(
                question_id="q",
                decision="approved",
                reason="user",
                packet_sha256=pending["packet_sha256"],
            )
        )
    with pytest.raises(PermissionError, match="uncertain"):
        asyncio.run(ctl.advance())


def test_no_minimum_early_stop_and_chain_tamper(tmp_path):
    ctl, ops = make(tmp_path)
    for _ in range(88):
        assert asyncio.run(ctl.advance())["status"] == "gap"
    assert asyncio.run(ctl.advance())["status"] == "all_candidates_processed"
    assert all(row["status"] == "completed" for row in ops.rows)
    event = sorted((tmp_path / "rolling-events").glob("*.json"))[1]
    event.write_text("{}")
    with pytest.raises(PermissionError):
        asyncio.run(ctl.advance())


def test_native_review_uses_generic_request_and_rejects_model_calls(
    monkeypatch, tmp_path
):
    m = module()
    assert hasattr(m, "NativeRollingOperations"), "actual native composition required"
    native = object.__new__(m.NativeRollingOperations)
    native.options = {"phase": "verification"}
    native.identity = {"source_commit": "a" * 40}
    native.rows = [
        {
            "case_id": "ait-" + "1" * 24,
            "group": "B3",
            "request": {"agent_sha256": "b" * 64},
        }
    ]
    native.agents = {"ait-" + "1" * 24: tmp_path}
    native.audit_dir = tmp_path / "audit"
    source = {
        "case_id": "ait-" + "1" * 24,
        "dataset": "ait",
        "state": {"incident_id": "incident"},
        "resources": {
            "database_name": "task13_" + "2" * 32,
            "index_name": "security-events-task13-" + "2" * 32,
        },
    }
    from scripts import task13_worker_runtime

    seen = []

    async def run(request, agent, options):
        seen.append(request)
        return {
            "status": "completed",
            "request_id": request.request_id,
            "input_sha256": m.canonical_hash(request),
            "source": source,
            "model_ledger": [],
            "isolation_evidence": {"status": "passed"},
        }

    monkeypatch.setattr(task13_worker_runtime, "run_source_review_container", run)
    result = asyncio.run(native._review(source, "read_packet"))
    assert seen[0].schema_version == "task13-source-review-worker-v1"
    assert seen[0].operation == "read_packet"
    assert result["source"] == source

    async def paid(request, agent, options):
        return {**await run(request, agent, options), "model_ledger": [{}]}

    monkeypatch.setattr(task13_worker_runtime, "run_source_review_container", paid)
    with pytest.raises(PermissionError):
        asyncio.run(native._review(source, "read_packet"))


def test_expired_decision_preserves_gap_and_continues_next_pair(tmp_path):
    ctl, ops = make(tmp_path)
    ops.plan = True
    pending = asyncio.run(ctl.advance())

    async def expired(claim, decision):
        return {"gap": "plan_expired"}

    ops.decide = expired
    outcome = asyncio.run(
        ctl.decide(
            question_id="q",
            decision="approved",
            reason="user",
            packet_sha256=pending["packet_sha256"],
        )
    )
    assert outcome["status"] == "gap" and outcome["reason"] == "plan_expired"
    assert "verify" not in ops.calls
    assert not any(isinstance(x, tuple) and x[0] == "f8" for x in ops.calls)
    assert asyncio.run(ctl.advance())["case_id"] == ops.rows[2]["case_id"]


def test_scope_rebinding_and_synthetic_authority_rejected(tmp_path):
    _ctl, ops = make(tmp_path)
    with pytest.raises(PermissionError):
        module().RollingController(
            tmp_path, ops.rows, ops, scope_sha256="b" * 64, synthetic=True
        )
    with pytest.raises(PermissionError):
        module().RollingController(
            tmp_path / "real", ops.rows, ops, scope_sha256="a" * 64, synthetic=False
        )


def test_native_retained_source_hash_and_nonce_are_checked_before_container(tmp_path):
    import json
    from types import SimpleNamespace

    m = module()
    native = object.__new__(m.NativeRollingOperations)
    case = "ait-" + "1" * 24
    nonce = "2" * 32
    state = {"response_plan": {"actions": []}, "diagnostic_snapshot_sha256": "3" * 64}
    native.identity = {
        "source_commit": "a" * 40,
        "campaign_id": "c",
        "source_sha256": "s",
        "config_sha256": "g",
        "plan_sha256": "p",
    }
    native.rows = [
        {
            "case_id": case,
            "slot_id": "slot",
            "request": {"group": "B3", "run_id": "run"},
        }
    ]
    native.data = {"runtime_options": {"output_dir": str(tmp_path / "worker")}}
    native.host = SimpleNamespace(
        _root=tmp_path / "host",
        status=lambda: {"rows": [{"slot_id": "slot", "status": "completed"}]},
    )
    ref = {
        "plan_sha256": m.canonical_hash(state["response_plan"]),
        "snapshot_sha256": "3" * 64,
        "source_commit": "a" * 40,
    }
    result = {
        "verification": {"case_reference": ref},
        "isolation_evidence": {"status": "passed", "probe": {"nonce": nonce}},
        "artifact_hashes": {"investigation_state": m.canonical_hash(state)},
    }
    result_path = native.host._root / "slot" / "result.json"
    result_path.parent.mkdir(parents=True)
    result_path.write_text(json.dumps(result))
    state_path = (
        tmp_path / "worker" / "run" / case / "B3" / nonce / "investigation-state.json"
    )
    state_path.parent.mkdir(parents=True)
    state_path.write_text(json.dumps(state))
    assert native._source(case)["state"] == state
    state_path.write_text("{}")
    with pytest.raises(PermissionError, match="retained artifact"):
        native._source(case)
    result["isolation_evidence"]["probe"]["nonce"] = "../../escape"
    result_path.write_text(json.dumps(result))
    with pytest.raises(PermissionError, match="nonce"):
        native._source(case)


def test_native_persisted_receipt_mismatch_stops_before_f8(tmp_path, monkeypatch):
    m = module()
    native = object.__new__(m.NativeRollingOperations)
    native.audit_dir = tmp_path / "audit"
    source = {"state": {"approval": {"decision": "approved"}}}

    async def read(*args):
        return {"source": source}

    native._review = read
    from evals import verification

    calls = []
    monkeypatch.setattr(
        verification,
        "verify_source_approval",
        lambda s: calls.append(s) or {"actual": "persisted"},
    )
    # Avoid Windows hardlink in this unit test; independent native audit publication
    # is covered by the generic-review shape test.
    native._save = lambda *args: None
    with pytest.raises(PermissionError, match="original product approval"):
        asyncio.run(
            native.verify(
                {},
                {"source": source, "receipt": {"forged": True}, "decision": "approved"},
            )
        )
    assert calls == [source]


def test_original_total_preserves_held_two_cny(tmp_path):
    import sqlite3

    from evals.adapters.remediation_worker import read_budget_identity

    m = module()
    native = object.__new__(m.NativeRollingOperations)
    database = tmp_path / "synthetic.sqlite"
    with sqlite3.connect(database) as db:
        db.executescript(
            "CREATE TABLE config(key TEXT,value TEXT);INSERT INTO config VALUES('total','100'),('development','15');CREATE TABLE reservations(id TEXT,request_key TEXT,phase TEXT,upper REAL,actual REAL,settled INTEGER);INSERT INTO reservations VALUES('old','old','formal',95,95,1);CREATE TABLE supplement_requests(reservation_id TEXT,campaign_id TEXT,purpose TEXT);"
        )
    baseline = read_budget_identity(database)
    with sqlite3.connect(database) as db:
        db.executescript(
            "INSERT INTO reservations VALUES('new','new','formal',4,4,1);INSERT INTO supplement_requests VALUES('new','campaign','regression');"
        )
    native.data = {
        "core_config": {
            "active_budget_path": str(database),
            "budget_identity": baseline,
        }
    }
    native.identity = {"campaign_id": "campaign"}
    native._save = lambda *args: None
    with pytest.raises(PermissionError, match="caps"):
        native.reconcile()


def test_native_scope_requires_actual_controller_source_in_freeze(tmp_path):
    m = module()
    assert hasattr(m, "require_rolling_source_files"), (
        "outer controller and pool validator require frozen actual bytes"
    )
    with pytest.raises(PermissionError):
        m.require_rolling_source_files({})


def test_native_failed_isolation_cannot_be_treated_as_case_gap(tmp_path):
    import json
    from types import SimpleNamespace

    m = module()
    native = object.__new__(m.NativeRollingOperations)
    native.host = SimpleNamespace(
        _root=tmp_path, status=lambda: {"rows": [{"slot_id": "s", "status": "failed"}]}
    )
    (tmp_path / "s").mkdir()
    (tmp_path / "s" / "result.json").write_text(
        json.dumps({"isolation_evidence": {"status": "failed"}})
    )
    with pytest.raises(PermissionError, match="isolation"):
        native.status()


def test_truncated_journal_cannot_replay_a_prior_claim(tmp_path):
    ctl, ops = make(tmp_path)
    ops.plan = True
    asyncio.run(ctl.advance())
    for path in sorted((tmp_path / "rolling-events").glob("*.json"))[-2:]:
        path.unlink()
    with pytest.raises(PermissionError, match="head"):
        asyncio.run(ctl.advance())


def test_joint_scope_can_precede_actual_reply_without_hash_cycle():
    m = module()
    assert hasattr(m, "regression_host_proposal"), (
        "acyclic concrete host proposal required"
    )
    manifest = {
        "schema_version": "task13-regression-host-v1",
        "synthetic": False,
        "output_dir": "fixed-root",
        "inputs": {
            "bundle": {"sha256": "b" * 64},
            "final_freeze": {"sha256": "f" * 64},
            "scope_packet": {"sha256": "old"},
            "scope_decision": {"sha256": "old"},
        },
    }
    proposal = m.regression_host_proposal(manifest)
    assert set(proposal["inputs"]) == {"bundle", "final_freeze"}
    joint = {
        "regression_host_proposal_sha256": m.canonical_hash(proposal),
        "campaign_id": "campaign",
        "final_freeze_sha256": "f" * 64,
        "bundle_sha256": "b" * 64,
        "registered_rows": 176,
        "deadline_at": m.DEADLINE,
    }
    decision = {
        "schema_version": "task13-rolling-joint-user-decision-v1",
        "role": "user",
        "decision": "approved",
        "scope_packet_sha256": "c" * 64,
        "record_id": "real-user-record",
        "text": "actual user reply",
        "decided_at": "2026-11-01T10:00:00+08:00",
    }
    packet, derived = m.materialize_regression_scope(
        proposal, joint, "c" * 64, decision, "d" * 64
    )
    assert (
        derived["text"] == decision["text"]
        and derived["record_id"] == decision["record_id"]
    )
    assert derived["joint_decision_sha256"] == "d" * 64
    assert packet["joint_scope_sha256"] == "c" * 64
    manifest["inputs"]["scope_packet"] = {"sha256": "newactualpacket"}
    manifest["inputs"]["scope_decision"] = {"sha256": "newactualdecision"}
    assert m.regression_host_proposal(manifest) == proposal
    manifest["output_dir"] = "other-root"
    with pytest.raises(PermissionError):
        m.materialize_regression_scope(
            m.regression_host_proposal(manifest), joint, "c" * 64, decision, "d" * 64
        )
    decision["decision"] = "pending"
    with pytest.raises(PermissionError):
        m.materialize_regression_scope(proposal, joint, "c" * 64, decision, "d" * 64)


@pytest.mark.parametrize(
    "message",
    [
        "remaining TTL must exceed 1.5 * observed maximum + 300 seconds",
        "registered regression deadline has passed",
    ],
)
def test_native_admission_expiry_preserves_gap_without_stopping_other_cases(
    tmp_path, monkeypatch, message
):
    from datetime import timedelta
    from types import SimpleNamespace

    from evals import verification, verification_v2

    m = module()
    native = object.__new__(m.NativeRollingOperations)
    case = "ait-" + "1" * 24
    native.data = {"e_timing_receipt": {}}
    native.identity = {}
    native._save = lambda *args: None

    async def rejected(*args, **kwargs):
        raise PermissionError(message)

    native.campaign = SimpleNamespace(
        run_case=rejected,
        snapshot=lambda: {
            "cases": {case: {"binding": None}},
            "records": [{"case_id": case, "status": "not_started"} for _ in range(6)],
        },
    )
    monkeypatch.setattr(verification, "_eligibility", lambda *args: (None, None))
    monkeypatch.setattr(verification_v2, "observed_timing_max", lambda *args: 1.0)
    source = {
        "state": {
            "response_plan": {
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(minutes=20)
                ).isoformat()
            }
        }
    }
    outcome = asyncio.run(native.run_f8(case, {"source": source, "receipt": {}}))
    assert outcome["status"] == "gap"
    assert outcome["reason"] in {"insufficient_original_plan_ttl", "deadline_stopped"}


def test_real_controller_does_not_accept_injected_clock(tmp_path):
    m = module()
    native = object.__new__(m.NativeRollingOperations)
    native.bind_controller = lambda *args: None
    with pytest.raises(PermissionError, match="clock"):
        m.RollingController(
            tmp_path,
            Operations().rows,
            native,
            scope_sha256="a" * 64,
            clock=lambda: datetime(2026, 11, 1, tzinfo=timezone.utc),
        )


def test_outer_journal_root_is_bound_to_joint_scope(tmp_path):
    m = module()
    native = object.__new__(m.NativeRollingOperations)
    native._check_scope = lambda: None
    native.scope = {"rolling_output_dir": str(tmp_path / "approved")}
    native.scope_pin = {"sha256": "a" * 64}
    native.rows = [{**r, "request": {"group": r["group"]}} for r in Operations().rows]
    rows = [{k: r[k] for k in ("slot_id", "case_id", "group")} for r in native.rows]
    with pytest.raises(PermissionError, match="journal root"):
        native.bind_controller({"scope_sha256": "a" * 64}, rows, tmp_path / "other")


def test_rolling_quiescence_is_explicit_and_composes_with_native_locks(tmp_path):
    from contextlib import ExitStack

    from evals.adapters.source_epochs import _lock_controller_roots

    m = module()
    ctl, ops = make(tmp_path)
    assert hasattr(m, "rolling_quiescence"), "companion rolling quiescence required"
    assert (tmp_path / "rolling-events").is_dir() and not (tmp_path / "events").exists()
    roots = [str(tmp_path.resolve())]
    with m.rolling_quiescence([ctl], roots) as proof:
        assert proof["status"] == "verified"
        with ExitStack() as stack:
            _lock_controller_roots(roots, stack)
        with pytest.raises(PermissionError, match="adoption"):
            asyncio.run(ctl.advance())
    with (
        pytest.raises(PermissionError, match="unlisted"),
        m.rolling_quiescence([], roots),
    ):
        pass
    ops.plan = True
    asyncio.run(ctl.advance())
    with (
        pytest.raises(PermissionError, match="pending"),
        m.rolling_quiescence([ctl], roots),
    ):
        pass


def test_runtime_equivalence_checks_full_options_and_measured_family():
    m = module()
    assert hasattr(m, "require_runtime_equivalence")
    formal = {
        "phase": "formal",
        "output_dir": "formal-output",
        "image_id": "image",
        "dependencies_lock_sha256": "lock",
        "network": "isolated",
        "knowledge_sha256": "knowledge",
        "cpu_limit": 2,
    }
    verification = {**formal, "phase": "verification", "output_dir": "f8-output"}
    binding = {
        "image_id": "image",
        "dependencies_lock_sha256": "lock",
        "dependencies_tree_sha256": "tree",
        "knowledge_sha256": "knowledge",
    }
    conditions = {
        **binding,
        "received_model": {"response_model": "model", "fingerprint": "fp"},
    }
    core = {"model_identity": {"response_model": "model", "fingerprint": "fp"}}
    m.require_runtime_equivalence(verification, formal, binding, conditions, core)
    for key in ("image_id", "dependencies_lock_sha256", "network", "cpu_limit"):
        changed = {**verification, key: "changed"}
        with pytest.raises(PermissionError):
            m.require_runtime_equivalence(changed, formal, binding, conditions, core)
    with pytest.raises(PermissionError):
        m.require_runtime_equivalence(
            verification, formal, binding, {**conditions, "image_id": "other"}, core
        )


def test_relative_journal_root_rejected():
    m = module()
    with pytest.raises(PermissionError, match="absolute"):
        m.RollingController(
            "relative-journal",
            Operations().rows,
            Operations(),
            scope_sha256="a" * 64,
            synthetic=True,
        )


@pytest.mark.parametrize("target", ["event", "head"])
def test_hardlinked_rolling_evidence_rejected(tmp_path, target):
    import os

    ctl, _ = make(tmp_path)
    path = (
        next((tmp_path / "rolling-events").glob("*.json"))
        if target == "event"
        else tmp_path / "head.json"
    )
    os.link(path, tmp_path / "linked-copy")
    with pytest.raises(PermissionError, match="link|chain|head"):
        asyncio.run(ctl.advance())


def _real_pending(tmp_path):
    m = module()
    ops = Operations()
    ops.plan = True
    native = object.__new__(m.NativeRollingOperations)
    native.bind_controller = lambda *args: None
    for name in (
        "guard",
        "status",
        "execute",
        "prepare",
        "decide",
        "verify",
        "run_f8",
        "reconcile",
    ):
        setattr(native, name, getattr(ops, name))

    async def prepare(case):
        value = await ops.prepare(case)
        value["packet"].update(incident_id="incident", plan_sha256="1" * 64)
        return value

    native.prepare = prepare
    ctl = m.RollingController(tmp_path, ops.rows, native, scope_sha256="a" * 64)
    return ctl, ops, asyncio.run(ctl.advance())


def _pin_json(path, value):
    import json
    from hashlib import sha256

    raw = json.dumps(value).encode()
    path.write_bytes(raw)
    return {"path": str(path), "sha256": sha256(raw).hexdigest()}


def _actual_reply(tmp_path, ctl, pending, *, after_capture=False):
    import json
    from pathlib import Path

    question = json.loads(Path(pending["prepared_question"]["path"]).read_bytes())
    item = json.dumps(["request_user_input_async", "call_actual_test_tool", 0])
    captured_before_observation = datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    )
    original_reply = [
        {
            "questionItemId": item,
            "title": question["title"],
            "question": question["question"],
            "answer": question["approved_answer"],
        }
    ]
    delivery = {
        "schema_version": "task13-rolling-question-delivery-v1",
        "record_kind": "actual_tool_question_delivery",
        "tool_name": "request_user_input_async",
        "tool_call_id": "call_actual_test_tool",
        "question_item_id": item,
        "prepared_question": pending["prepared_question"],
        "title": question["title"],
        "question": question["question"],
        "delivery_observed_at": datetime.now(timezone.utc).isoformat(
            timespec="microseconds"
        ),
        "observation_source": "actual_tool_call",
        "synthetic_control_fixture": False,
        "automatic_approval": False,
    }
    if after_capture:
        delivery.update(
            observation_source="actual_question_reply",
            actual_question_reply_sha256=module().canonical_hash(original_reply),
        )
    delivery_pin = _pin_json(tmp_path / "actual-delivery.json", delivery)
    ctl.bind_question_delivery(delivery_pin)
    captured = (
        captured_before_observation
        if after_capture
        else datetime.now(timezone.utc).isoformat(timespec="microseconds")
    )
    reply = {
        "schema_version": "task13-rolling-actual-user-reply-v1",
        "record_kind": "actual_tool_user_response",
        "role": "user",
        "origin": "actual_user",
        "record_id": "actual-reply-record",
        "synthetic_control_fixture": False,
        "automatic_approval": False,
        "prepared_question": pending["prepared_question"],
        "question_delivery": delivery_pin,
        "case_id": pending["case_id"],
        "incident_id": question["incident_id"],
        "packet_sha256": pending["packet_sha256"],
        "source_sha256": question["source_sha256"],
        "plan_sha256": question["plan_sha256"],
        "captured_at": captured,
        "decided_at": captured,
        "text": question["approved_answer"],
        "decision": "approved",
        "reason": question["approved_answer"],
        "actual_question_reply": [
            {
                "questionItemId": item,
                "title": question["title"],
                "question": question["question"],
                "answer": question["approved_answer"],
            }
        ],
    }
    return reply


def test_real_reply_requires_exact_delivery_and_raw_user_capture(tmp_path):
    ctl, ops, pending = _real_pending(tmp_path)
    assert "prepared_question" in pending, (
        "real pending must persist immutable prepared question"
    )
    with pytest.raises(PermissionError):
        asyncio.run(
            ctl.decide(
                question_id="invented",
                decision="approved",
                reason="made up",
                packet_sha256=pending["packet_sha256"],
            )
        )
    reply = _actual_reply(tmp_path, ctl, pending)
    result = asyncio.run(
        ctl.decide(actual_chat_record=_pin_json(tmp_path / "reply.json", reply))
    )
    assert result["status"] == "completed"
    actual = next(x[1] for x in ops.calls if isinstance(x, tuple) and x[0] == "decide")
    assert actual["decided_at"] == reply["captured_at"]
    assert actual["actual_chat_record"]["sha256"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", "assistant"),
        ("origin", "model"),
        ("synthetic_control_fixture", True),
        ("packet_sha256", "0" * 64),
        ("decision", "rejected"),
        ("captured_at", "2099-01-01T00:00:00.000001+00:00"),
    ],
)
def test_bad_actual_reply_stops_before_product_write(tmp_path, field, value):
    ctl, ops, pending = _real_pending(tmp_path)
    assert "prepared_question" in pending
    reply = _actual_reply(tmp_path, ctl, pending)
    reply[field] = value
    with pytest.raises(PermissionError):
        asyncio.run(
            ctl.decide(actual_chat_record=_pin_json(tmp_path / "bad-reply.json", reply))
        )
    assert not any(isinstance(x, tuple) and x[0] == "decide" for x in ops.calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("questionItemId", '["request_user_input_async", "call_stale", 0]'),
        ("title", "edited title"),
        ("question", "edited question"),
        ("answer", "approve everything"),
    ],
)
def test_actual_question_metadata_cannot_be_relabelled(tmp_path, field, value):
    ctl, ops, pending = _real_pending(tmp_path)
    reply = _actual_reply(tmp_path, ctl, pending)
    reply["actual_question_reply"][0][field] = value
    with pytest.raises(PermissionError):
        asyncio.run(
            ctl.decide(
                actual_chat_record=_pin_json(tmp_path / "bad-ui-reply.json", reply)
            )
        )
    assert not any(isinstance(x, tuple) and x[0] == "decide" for x in ops.calls)


def test_junction_nested_event_directory_is_rejected(tmp_path):
    import sys

    ctl, _ = make(tmp_path)
    directory = tmp_path / "rolling-events"
    moved = tmp_path / "moved-events"
    directory.rename(moved)
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(moved), str(directory))
    else:
        directory.symlink_to(moved, target_is_directory=True)
    with pytest.raises(PermissionError, match="link|junction"):
        asyncio.run(ctl.advance())


def test_linked_event_rejected_by_append_even_after_successful_load(tmp_path):
    import os

    ctl, _ = make(tmp_path)
    event = next((tmp_path / "rolling-events").glob("*.json"))
    os.link(event, tmp_path / "event-hardlink")
    with pytest.raises(PermissionError):
        ctl._append("unexpected")


def test_delivery_observed_from_reply_retains_capture_across_resume(tmp_path):
    ctl, _, pending = _real_pending(tmp_path)
    reply = _actual_reply(tmp_path, ctl, pending, after_capture=True)
    resumed = module().RollingController(
        tmp_path, ctl.rows, ctl.ops, scope_sha256="a" * 64
    )
    assert asyncio.run(resumed.advance()) == pending
    outcome = asyncio.run(
        resumed.decide(
            actual_chat_record=_pin_json(tmp_path / "after-capture.json", reply)
        )
    )
    assert outcome["status"] == "completed"


def test_head_change_during_append_cannot_be_overwritten(tmp_path, monkeypatch):
    import json

    m = module()
    ctl, _ = make(tmp_path)
    original = m._write_rolling

    def changed(path, raw):
        original(path, raw)
        if path.parent.name == "rolling-events":
            (tmp_path / "head.json").write_text(
                json.dumps({"count": 999, "sha256": "bad"})
            )

    monkeypatch.setattr(m, "_write_rolling", changed)
    with pytest.raises(PermissionError, match="head"):
        ctl._append("test_append")
