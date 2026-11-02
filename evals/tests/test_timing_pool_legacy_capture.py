"""Host-only compatibility for the one retained root-captured old approval."""

import json
from copy import copy, deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from evals import timing_pool as pool
from evals import timing_pool_recovery as recovery

ORIGINAL = Path(
    r"D:\传智杯\data\task13\supplements\task13-repair-202610-v2\development\timing-pool-candidate-20261101-2f360b77"
)
ROOT = ORIGINAL / "pool-059220946fb6436786ec3566765983f3-child-1/host-output/timing"


@pytest.fixture(scope="module")
def retained():
    if not ROOT.is_dir():
        pytest.skip("genuine original stopped pool is unavailable")
    view = pool._view(ROOT)
    host = pool._json(ROOT.parent / "host-binding.json")
    inputs = pool._load_host_inputs(view, host)
    budget = Path(inputs["runtime_options"]["budget_dir"]) / "campaign.sqlite"

    def snapshot():
        paths = [p for p in ORIGINAL.rglob("*") if p.is_file()]
        paths += [Path(str(budget) + suffix) for suffix in ("", "-wal", "-shm")]
        return {
            str(p): sha256(p.read_bytes()).hexdigest() if p.exists() else None
            for p in paths
        }

    before = snapshot()
    context = pool._validate_host_semantics(view, host, inputs)
    reader = context["reader"]
    request = next(r for r in reader._requests if r.trial_id == recovery.TRIAL_ID)
    slot = reader._root / "slots" / request.planning_slot_id
    plan = pool._json(slot / "plan-terminal.json")
    terminal = pool._json(slot / "decision-terminal.json")
    started = pool._json(slot / "decision-started.json")
    decided = recovery._pin(terminal["runtime_result"])
    stop = pool._json(ORIGINAL / "activation/root-first-attempt-stop-evidence.json")
    assert started["chat_record"] == stop["actual_plan_approval"]
    assert terminal["chat_record"]["sha256"] == recovery.APPROVAL_SHA256
    chat = recovery._pin(stop["actual_plan_approval"])
    source = reader._source(
        request,
        decided["source"]["state"],
        recovery._pin(plan["retained_state"]),
        recovery._pin(plan["resources"]),
    )
    events = [
        json.loads(line)
        for line in Path(stop["pool_journal"]["path"]).read_bytes().splitlines()
    ]
    before_trial = events[8]["payload"]["quiescence"]["inspected_at"]
    yield {
        "context": context,
        "trial": view.trials[recovery.TRIAL_ID],
        "source": source,
        "chat": chat,
        "started": started,
        "decided": decided,
        "approved_before": before_trial,
        "pin": stop["actual_plan_approval"],
    }
    assert snapshot() == before, "original artifacts or raw SQLite/WAL/SHM changed"


def validate(retained, *, direct=True, historical_pin=None, **changes):
    args = {
        key: retained[key]
        for key in ("context", "trial", "source", "chat", "started", "decided")
    }
    args.update(changes)
    kwargs = (
        {"historical_direct_capture": historical_pin or retained["pin"]}
        if direct
        else {}
    )
    return pool._validate_approval_semantics(
        **args,
        archives=pool._archive_context({}),
        approved_before=retained["approved_before"],
        **kwargs,
    )


def write_pin(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}


def modern_capture(retained, tmp_path):
    chat = deepcopy(retained["chat"])
    reply = chat.pop("actual_incoming_reply")[0]
    question = {
        "schema_version": "task13-preloaded-specific-plan-question-v1",
        "synthetic_control_fixture": False,
        "automatic_approval": False,
        "record_kind": "prepared_question_not_user_consent",
        **{
            key: chat[key]
            for key in ("case_id", "incident_id", "packet_sha256", "scope")
        },
        "question": reply["question"],
        "approved_answer": reply["answer"],
        "created_at": chat["decided_at"],
    }
    chat["prepared_question"] = write_pin(tmp_path / "question.json", question)
    chat["actual_question_reply"] = [reply]
    started = deepcopy(retained["started"])
    started["chat_record"] = write_pin(tmp_path / "modern-chat.json", chat)
    return chat, started, question


def test_genuine_direct_capture_passes_full_approval_closure(retained):
    assert "prepared_question" not in retained["chat"]
    assert "actual_question_reply" not in retained["chat"]
    validate(retained)


def test_genuine_direct_capture_requires_explicit_quarantine_route(retained):
    with pytest.raises(PermissionError, match="prepared|historical"):
        validate(retained, direct=False)


@pytest.mark.parametrize("identity", ["current-v2", "different-v1"])
def test_direct_capture_rejects_other_pool_identities(retained, identity):
    context = dict(retained["context"])
    reader = copy(context["reader"])
    reader._inputs = deepcopy(reader._inputs)
    context["reader"] = reader
    authority = reader._inputs["pool_authority"]
    if identity == "current-v2":
        authority["schema_version"] = pool.RECOVERY_REGISTRATION_SCHEMA
    else:
        authority["source_commit"] = "0" * 40
    with pytest.raises(PermissionError, match="historical"):
        validate(retained, context=context)


@pytest.mark.parametrize(
    "damage",
    [
        "answer",
        "question",
        "question-id",
        "record-id",
        "source",
        "text",
        "missing-reply",
        "multiple-replies",
    ],
)
def test_modified_or_spliced_direct_capture_cannot_authenticate(
    retained, tmp_path, damage
):
    chat = deepcopy(retained["chat"])
    if damage in {"answer", "question", "question-id"}:
        field = {"question-id": "questionItemId"}.get(damage, damage)
        chat["actual_incoming_reply"][0][field] = "SYNTHETIC splice"
    elif damage == "missing-reply":
        chat.pop("actual_incoming_reply")
    elif damage == "multiple-replies":
        chat["actual_incoming_reply"] *= 2
    else:
        chat[{"record-id": "record_id"}.get(damage, damage)] = "SYNTHETIC splice"
    started = deepcopy(retained["started"])
    started["chat_record"] = write_pin(tmp_path / "forged-direct.json", chat)
    with pytest.raises(PermissionError, match="historical"):
        validate(
            retained,
            chat=chat,
            started=started,
            historical_pin=started["chat_record"],
        )


def test_equal_decoded_capture_cannot_substitute_its_original_raw_pin(
    retained, tmp_path
):
    started = deepcopy(retained["started"])
    started["chat_record"] = write_pin(
        tmp_path / "reserialized-direct.json", retained["chat"]
    )
    assert started["chat_record"]["sha256"] != recovery.APPROVAL_SHA256
    with pytest.raises(PermissionError, match="historical"):
        validate(retained, started=started, historical_pin=started["chat_record"])


def test_exact_old_digest_cannot_authenticate_different_raw_bytes(retained, tmp_path):
    chat = deepcopy(retained["chat"])
    chat["actual_incoming_reply"][0]["answer"] = "SYNTHETIC splice"
    ref = write_pin(tmp_path / "wrong-bytes.json", chat)
    ref["sha256"] = recovery.APPROVAL_SHA256
    started = deepcopy(retained["started"])
    started["chat_record"] = ref
    with pytest.raises(PermissionError, match="raw evidence"):
        validate(retained, chat=chat, started=started)


def test_present_prepared_question_keeps_normal_strict_route(retained, tmp_path):
    chat, started, _ = modern_capture(retained, tmp_path)
    validate(retained, direct=False, chat=chat, started=started)


@pytest.mark.parametrize(
    "damage",
    [
        "answer",
        "question",
        "question-id",
        "packet",
        "automatic",
        "created-after",
        "rawpin",
    ],
)
def test_modern_malformed_capture_still_fails_strict_route(retained, tmp_path, damage):
    chat, started, question = modern_capture(retained, tmp_path)
    if damage in {"answer", "question", "question-id"}:
        field = {"question-id": "questionItemId"}.get(damage, damage)
        chat["actual_question_reply"][0][field] = (
            "" if damage == "question-id" else "SYNTHETIC splice"
        )
    elif damage == "rawpin":
        chat["prepared_question"]["sha256"] = "0" * 64
    else:
        field, value = {
            "packet": ("packet_sha256", "0" * 64),
            "automatic": ("automatic_approval", True),
            "created-after": ("created_at", "2026-11-01T04:51:25+00:00"),
        }[damage]
        question[field] = value
        chat["prepared_question"] = write_pin(tmp_path / "question.json", question)
    started["chat_record"] = write_pin(tmp_path / "modern-chat.json", chat)
    with pytest.raises(PermissionError, match="prepared|raw evidence"):
        validate(retained, direct=False, chat=chat, started=started)


@pytest.mark.parametrize("mixed", [False, True])
def test_prepared_record_cannot_opt_into_historical_direct_route(
    retained, tmp_path, mixed
):
    chat, started, _ = modern_capture(retained, tmp_path)
    if mixed:
        chat["actual_incoming_reply"] = deepcopy(
            retained["chat"]["actual_incoming_reply"]
        )
        started["chat_record"] = write_pin(tmp_path / "modern-chat.json", chat)
    with pytest.raises(PermissionError, match="historical"):
        validate(retained, chat=chat, started=started)


@pytest.mark.parametrize(
    "damage",
    ["persisted-reason", "receipt", "model-ledger", "request-id", "runtime-input"],
)
def test_historical_compatibility_preserves_downstream_checks(retained, damage):
    source, decided = deepcopy(retained["source"]), deepcopy(retained["decided"])
    if damage == "persisted-reason":
        source["state"]["approval"]["reason"] = "SYNTHETIC mismatch"
    elif damage == "receipt":
        decided["approval_receipt"] = {}
    else:
        key, value = {
            "model-ledger": ("model_ledger", [{"SYNTHETIC": True}]),
            "request-id": ("request_id", "SYNTHETIC mismatch"),
            "runtime-input": ("input_sha256", "0" * 64),
        }[damage]
        decided[key] = value
    with pytest.raises((PermissionError, KeyError, ValueError)):
        validate(retained, source=source, decided=decided)
