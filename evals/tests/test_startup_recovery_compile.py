"""Free startup-v3 compiler tests; synthetic messages grant no actual authority."""

from copy import deepcopy
from pathlib import Path

import pytest


def test_startup_core_consumes_failed_attempt_without_changing_business_inputs():
    from scripts import task13_manual_recovery as compiler

    original = {
        "combined_development_calls": deepcopy(compiler.RECOVERY_COUNTS),
        "model_identity": {"id": "old", "response_model": "unchanged"},
        "deadline": compiler.DEADLINE,
        "plan_ttl_seconds": 1800,
    }
    before = deepcopy(original)
    value = compiler.recovery_core(original, "new", profile="startup-v3")
    assert original == before
    assert value["combined_development_calls"] == {
        **compiler.RECOVERY_COUNTS,
        "planning_logical_already_consumed": 9,
        "planning_physical_already_consumed": 27,
        "new_planning_logical_max": 4,
        "new_planning_physical_max": 12,
    }
    assert value["plan_ttl_seconds"] == 1800
    assert value["model_identity"] == {**before["model_identity"], "id": "new"}
    with pytest.raises(PermissionError):
        compiler.recovery_core(original, "new", profile="caller-selected-4")


def test_startup_draft_preparation_adoption_are_explicit_and_three_plus_one(tmp_path):
    from scripts import task13_manual_recovery as compiler
    from scripts.task13_pool_prepare import Documents, pin, read

    old = Path(
        r"D:\传智杯\data\task13\supplements\task13-repair-202610-v2\development\manual-recovery-candidate-20261102-503d559bd4094de88d49de92cdbc3043"
    )
    p = read(pin(old / "activation/preparation-receipt.json"))
    m = read(pin(old / "activation/materialization.json"))
    receipt = read(pin(old / "source/source_receipt.json"))
    worker = {name: (old / "source" / name).read_bytes() for name in receipt["files"]}
    tree = Path(compiler.__file__).resolve().parents[1]
    host_files = {
        str(tree / name): pin(tree / name)["sha256"]
        for name in m["source"]["entrypoints"]
    }
    docs, draft_pin = compiler.compile_draft(
        p,
        m,
        root=tmp_path / "candidate",
        tree=tree,
        commit="a" * 40,
        identity="b" * 32,
        source_receipt=receipt,
        worker_bytes=worker,
        host_files=host_files,
        predecessor_materialization=pin(old / "activation/materialization.json"),
        predecessor_preparation=pin(old / "activation/preparation-receipt.json"),
        profile="startup-v3",
    )
    assert not (tmp_path / "candidate").exists()
    docs.publish()
    draft = read(draft_pin)
    assert draft["schema_version"] == "task13-manual-startup-recovery-draft-v1"
    assert draft["source"]["epoch_number"] == 12
    assert draft["model"]["model_epoch_number"] == 9
    assert (
        read(draft["recovery_plan"])["schema_version"]
        == "task13-manual-startup-recovery-plan-v1"
    )
    evidence = Documents(tmp_path / "evidence")
    qpin = evidence.stage(
        "quarantine.json",
        {
            "parent_journal": {
                "path": str(tmp_path / "old-journal"),
                "sha256": "2" * 64,
                "head_sha256": "39be936e93a21e627e33deb4d8b8cbc215379b3629454cefb697fe1f454b0bf5",
            }
        },
    )
    apin = evidence.stage("acceptance.json", {"synthetic": True})
    evidence.publish()
    eq = {
        "original_execution": {"synthetic": True},
        "candidate_execution": {"synthetic": True},
        "policy_pin": {"path": str(tmp_path / "policy"), "sha256": "3" * 64},
    }
    docs, preparation_pin = compiler.compile_preparation(
        draft,
        draft_pin,
        quarantine_pin=qpin,
        equivalence=eq,
        acceptance_pin=apin,
        free_policy=p["pool"]["free_admission"],
    )
    docs.publish()
    prepared = read(preparation_pin)
    assert prepared["schema_version"] == "task13-manual-startup-recovery-preparation-v1"
    pool = prepared["pool"]
    assert pool["schema_version"] == "task13-e-timing-pool-registration-v3"
    assert len(pool["attempt_order"]) == 4 and len(pool["denied_attempts"]) == 2
    assert pool["migration_grant"]["consumed_logical"] == 9
    assert pool["migration_grant"]["consumed_physical"] == 27
    packet = read(prepared["scope_packet"])
    assert packet["schema_version"] == "task13-e-timing-pool-pending-v3"
    question = read(prepared["prepared_question"])
    assert "4次逻辑规划/最多12次物理请求" in question["question"]
    assert question["actual_user_reply"] is None
    consent = Documents(tmp_path / "synthetic-no-human-credit")
    request = {
        "schema_version": "task13-pool-question-delivery-v1",
        "scope_packet": prepared["scope_packet"],
        "prepared_question": prepared["prepared_question"],
        "question_item_id": '["request_user_input_async","SYNTHETIC_NO_HUMAN_CREDIT",0]',
    }
    rpin = consent.stage("request.json", request)
    cpin = consent.stage(
        "chat.json",
        {
            "role": "user",
            "source": "actual_current_send_user_message_question_reply",
            "captured_at": "2026-11-01T00:00:00+00:00",
            "synthetic_test_not_human_approval": True,
            "question_reply": [
                {
                    "questionItemId": request["question_item_id"],
                    "question": question["question"],
                    "answer": question["approved_answer"],
                }
            ],
        },
    )
    consent.publish()
    material_docs, material, _ = compiler.compile_adoption(
        prepared, preparation_pin, rpin, cpin
    )
    assert (
        material["schema_version"]
        == "task13-manual-startup-recovery-materialization-v1"
    )
    assert [
        len(c["authority"]["authorized_request_sha256s"]) for c in material["children"]
    ] == [3, 1]
    assert [
        len(c["authority"]["denied_request_sha256s"]) for c in material["children"]
    ] == [0, 2]
    assert all(
        c["authority"]["schema_version"] == "task13-e-planning-authority-v3"
        for c in material["children"]
    )
    host = __import__("json").loads(
        material_docs.values[Path(material["pool_host_manifest"]["path"])]
    )
    assert host["schema_version"] == "task13-e-timing-pool-host-v3"
    for ordinal, cid in enumerate(host["hosts"], 1):
        options = __import__("json").loads(
            material_docs.values[
                tmp_path / "candidate" / cid / "activation/runtime-options.json"
            ]
        )
        assert options["temporary_root"] == f"D:/传智杯/.tmp/t13v3-{'b' * 12}-{ordinal}"
    assert not any(path.exists() for path in material_docs.values)
