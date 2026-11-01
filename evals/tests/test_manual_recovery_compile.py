"""Free compiler checks; fixture messages are not actual scope authority."""

from copy import deepcopy

import pytest


def test_inert_draft_consumes_no_authority_and_builds_latest_successors(tmp_path):
    from scripts import task13_manual_recovery as compiler
    from scripts.task13_pool_prepare import pin, read

    old = __import__("pathlib").Path(
        r"D:\传智杯\data\task13\supplements\task13-repair-202610-v2\development\timing-pool-candidate-20261101-2f360b77"
    )
    p = read(pin(old / "activation/preparation-receipt.json"))
    m = read(pin(old / "activation/materialization.json"))
    receipt = read(pin(old / "source/source_receipt.json"))
    worker = {name: (old / "source" / name).read_bytes() for name in receipt["files"]}
    tree = __import__("pathlib").Path(compiler.__file__).resolve().parents[1]
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
    )
    assert not (tmp_path / "candidate").exists()
    docs.publish()
    draft = read(draft_pin)
    assert draft["source"]["epoch_number"] == 11
    assert draft["model"]["model_epoch_number"] == 8
    assert draft["source"]["predecessor_epoch_id"] == m["source"]["epoch_id"]
    assert draft["source"]["authority"]["packet_sha256"] is None
    assert draft["model"]["source_manifest_sha256"] is None
    assert draft["actual_authority_created"] == draft["provider_requests"] == 0
    assert read(draft["recovery_plan"])["quota"]["new_planning_logical_max"] == 5
    assert not list((tmp_path / "candidate").rglob("*.sqlite"))
    assert not list((tmp_path / "candidate").rglob("*authority*"))
    from scripts.task13_pool_prepare import Documents

    evidence = Documents(tmp_path / "evidence")
    qpin = evidence.stage(
        "quarantine.json",
        {
            "parent_journal": {
                "path": str(tmp_path / "old-journal"),
                "sha256": "2" * 64,
                "head_sha256": compiler.PREDECESSOR_HEAD,
            }
        },
    )
    eq = {
        "original_execution": {"synthetic": True},
        "candidate_execution": {"synthetic": True},
        "policy_pin": {"path": str(tmp_path / "synthetic-policy"), "sha256": "3" * 64},
    }
    apin = evidence.stage("acceptance.json", {"synthetic": True})
    evidence.publish()
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
    pool = prepared["pool"]
    assert len(pool["attempt_order"]) == 5 and len(pool["denied_attempts"]) == 1
    assert all("authority" not in c for c in pool["children"])
    assert pool["migration_grant"]["scope_packet_sha256"] == "0" * 64
    assert read(prepared["prepared_question"])["actual_user_reply"] is None
    question = read(prepared["prepared_question"])
    consent = Documents(tmp_path / "synthetic-no-human-credit")
    request = {
        "schema_version": "task13-pool-question-delivery-v1",
        "scope_packet": prepared["scope_packet"],
        "prepared_question": prepared["prepared_question"],
        "question_item_id": '["request_user_input_async","SYNTHETIC_NO_HUMAN_CREDIT",0]',
    }
    request_pin = consent.stage("request.json", request)
    chat_pin = consent.stage(
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
        prepared, preparation_pin, request_pin, chat_pin
    )
    assert (
        material["pool"]["migration_grant"]["scope_packet_sha256"]
        == prepared["scope_packet"]["sha256"]
    )
    assert [
        len(c["authority"]["authorized_request_sha256s"]) for c in material["children"]
    ] == [3, 2]
    assert not any(path.exists() for path in material_docs.values)
    # Every immutable-file crash boundary must resume with identical bytes.
    for index, (target, payload) in enumerate(material_docs.values.items()):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        material_docs.validate_existing()
    material_docs.publish_missing()
    for child in material["pool"]["children"]:
        compiler.initialize_timing_genesis(child)
        compiler.initialize_timing_genesis(child)
    compiler.require_inert_outputs(material["pool"])
    child_root = (
        __import__("pathlib")
        .Path(material["pool"]["children"][1]["evidence_root"])
        .parent
    )
    forbidden = child_root / "slots" / "denied-sixth" / "plan-started.json"
    forbidden.parent.mkdir(parents=True)
    forbidden.write_text('{"synthetic_not_execution":true}', encoding="utf-8")
    with pytest.raises(PermissionError):
        compiler.require_inert_outputs(material["pool"])


def test_limited_child_metadata_check_keeps_denied_request_unclaimed(tmp_path):
    from evals.adapters.e_planning_journal import register_planning_slots
    from evals.contracts import canonical_hash
    from evals.tests.test_e_planning_limited_authority import limited_fixture
    from scripts.task13_manual_recovery import require_unclaimed_limited_child

    registrations, authorities = limited_fixture(tmp_path)
    r, a = registrations[1], authorities[1]
    child = {"planning": r, "authority": a}
    assert require_unclaimed_limited_child(child) is False
    register_planning_slots(
        a["journal_path"],
        r,
        expected_registration_sha256=canonical_hash(r),
        authority=a,
        expected_authority_sha256=canonical_hash(a),
    )
    assert require_unclaimed_limited_child(child) is True


def test_recovery_core_preserves_model_and_caps_while_moving_consumption():
    from scripts.task13_manual_recovery import recovery_core

    original = {
        "combined_development_calls": {
            "analysis_logical_already_consumed": 1,
            "analysis_logical_max": 1,
            "analysis_physical_already_consumed": 1,
            "analysis_physical_max": 1,
            "new_analysis_logical_max": 0,
            "new_analysis_physical_max": 0,
            "new_planning_logical_max": 6,
            "new_planning_physical_max": 18,
            "planning_logical_already_consumed": 7,
            "planning_logical_max": 13,
            "planning_physical_already_consumed": 21,
            "planning_physical_max": 39,
            "total_logical_max": 14,
            "total_physical_max": 40,
        },
        "model_identity": {
            "id": "model-old",
            "response_model": "deepseek-flash",
            "fingerprint": "bc19ba97cbe016479903222bb1578db6",
        },
        "deadline": "2026-11-02T23:59:59+08:00",
        "plan_ttl_seconds": 1800,
    }
    before = deepcopy(original)
    core = recovery_core(original, "model-new")
    assert original == before
    counts = core["combined_development_calls"]
    assert (
        counts["planning_logical_already_consumed"],
        counts["planning_physical_already_consumed"],
    ) == (8, 24)
    assert (
        counts["new_planning_logical_max"],
        counts["new_planning_physical_max"],
    ) == (5, 15)
    assert (
        counts["planning_logical_max"],
        counts["planning_physical_max"],
        counts["total_physical_max"],
    ) == (13, 39, 40)
    assert core["model_identity"] == {**before["model_identity"], "id": "model-new"}
    assert core["plan_ttl_seconds"] == 1800


@pytest.mark.parametrize(
    "name,value",
    [
        ("planning_logical_already_consumed", 8),
        ("planning_physical_max", 40),
        ("new_analysis_logical_max", 1),
    ],
)
def test_recovery_core_refuses_a_different_predecessor_quota(name, value):
    from scripts.task13_manual_recovery import ORIGINAL_COUNTS, recovery_core

    core = {
        "combined_development_calls": {**ORIGINAL_COUNTS, name: value},
        "model_identity": {"id": "old"},
        "deadline": "2026-11-02T23:59:59+08:00",
    }
    with pytest.raises(PermissionError):
        recovery_core(core, "new")


def test_development_reply_cannot_authorize_recovery_execution(tmp_path):
    from scripts.task13_manual_recovery import derive_decision

    with pytest.raises(PermissionError):
        derive_decision(
            {"schema_version": "task13-pool-question-delivery-v1"},
            {
                "role": "user",
                "source": "actual_current_send_user_message_question_reply",
                "question_reply": [{"answer": "允许受限扩展，先免费实现和审查"}],
            },
            {"path": str(tmp_path / "absent-packet.json"), "sha256": "f" * 64},
            {"path": str(tmp_path / "chat.json"), "sha256": "a" * 64},
        )


def test_actual_scope_review_requires_independent_exact_pins():
    from scripts.task13_manual_recovery import validate_actual_scope_review

    ref = lambda letter: {"path": "D:/synthetic/" + letter, "sha256": letter * 64}
    spec = dict(
        zip(
            ("preparation", "authorization_request", "actual_scope_chat"),
            map(ref, "abc"),
        )
    )
    p = {"scope_packet": ref("d"), "controller_manifest": ref("e")}
    review = {
        "schema_version": "task13-manual-recovery-actual-scope-review-v1",
        "status": "passed",
        "review_kind": "independent_actual_scope",
        "reviewer_identity": "synthetic-reviewer-not-human-approval",
        "critical": 0,
        "important": 0,
        **spec,
        **p,
    }
    assert validate_actual_scope_review(review, spec, p) == review
    for field, value in [
        ("reviewer_identity", ""),
        ("critical", False),
        ("actual_scope_chat", ref("f")),
    ]:
        with pytest.raises(PermissionError):
            validate_actual_scope_review({**review, field: value}, spec, p)


@pytest.mark.parametrize("prefix", [(False, False), (True, False), (True, True)])
def test_exact_durable_epoch_prefixes_preserve_unrelated_rows(prefix):
    import json

    from evals.contracts import canonical_hash
    from scripts.task13_pool_prepare import validate_epoch_prefix

    source = {
        "epoch_id": "new",
        "campaign_id": "synthetic",
        "epoch_number": 11,
        "predecessor_epoch_id": "old",
    }
    model = {
        "model_epoch_id": "newmodel",
        "campaign_id": "synthetic",
        "model_epoch_number": 8,
        "predecessor_model_epoch_id": "oldmodel",
    }
    sa, ma = {"scope": "synthetic-no-approval"}, {"scope": "synthetic-no-approval"}
    material = {
        "source": source,
        "model": model,
        "source_authority": sa,
        "model_authority": ma,
    }
    before = {
        "schema": [],
        "tables": {
            "supplement_source_epochs": [],
            "supplement_model_epochs": [],
            "config": ['["halt", "original"]'],
        },
    }
    after = deepcopy(before)
    if prefix[0]:
        after["tables"]["supplement_source_epochs"] = [
            json.dumps(
                [
                    "new",
                    "synthetic",
                    11,
                    "old",
                    json.dumps(source),
                    canonical_hash(source),
                    canonical_hash(sa),
                    "t",
                    "t",
                ]
            )
        ]
    if prefix[1]:
        after["tables"]["supplement_model_epochs"] = [
            json.dumps(
                [
                    "newmodel",
                    "synthetic",
                    8,
                    "oldmodel",
                    json.dumps(model),
                    canonical_hash(model),
                    json.dumps(ma),
                    canonical_hash(ma),
                    "t",
                    "t",
                ]
            )
        ]
    assert validate_epoch_prefix(before, after, material) == prefix
    after["tables"]["config"] = ['["halt", "cleared"]']
    with pytest.raises(PermissionError):
        validate_epoch_prefix(before, after, material)


def test_adoption_has_no_development_permission_shortcut():
    from scripts.task13_manual_recovery import adopt

    with pytest.raises(PermissionError):
        adopt({"development_permission": "call_7ea4eaaa5a3a4ce6b4d9f8f87d719644"})


def adoption_crash_fixture(tmp_path, monkeypatch):
    """Synthetic scope/epoch seams, real public adoption, SQL prefixes and locks."""
    import json
    import sqlite3
    from contextlib import ExitStack

    from evals import timing_pool
    from evals.adapters import model_identities, source_epochs
    from evals.contracts import canonical_hash
    from evals.tests.test_timing_pool_recovery import pinned, target_genesis
    from scripts import task13_manual_recovery as compiler
    from scripts import task13_pool_prepare as prepare

    recovery, locks, old, target = target_genesis(tmp_path, monkeypatch)
    target.path.unlink()  # First public adopt must create the actual parent genesis.
    pool = json.loads((tmp_path / "target.json").read_bytes())
    (tmp_path / "target.json").unlink()
    pool["children"] = []  # Native child genesis is covered in the other regression.
    pool["denied_attempts"] = [{"child_id": "synthetic", "trial_id": "denied-sixth"}]
    preserved = {str(old.path): prepare.pin(old.path)["sha256"]}
    quarantine = {
        "pool_host_manifest": locks["pool_host_manifest"],
        "stop_evidence": locks["stop_evidence"],
        "fee_audit": locks["fee_audit"],
        "old_controller_state_roots": [str(old.path.parent)],
        "preserved_files": preserved,
        "preserved_files_sha256": canonical_hash(preserved),
    }
    pool["quarantine_record"] = pinned(tmp_path / "quarantine.json", quarantine)
    pool["quarantined_predecessor"]["quarantine_record"] = pool["quarantine_record"]
    pool["migration_grant"]["quarantine_record_sha256"] = pool["quarantine_record"][
        "sha256"
    ]
    pool["migration_grant_sha256"] = canonical_hash(pool["migration_grant"])
    budget = tmp_path / "synthetic-account.sqlite"
    with sqlite3.connect(budget) as db:
        for table, size in (
            ("supplement_source_epochs", 9),
            ("supplement_model_epochs", 10),
        ):
            db.execute(
                f"CREATE TABLE {table} ({','.join('c' + str(i) for i in range(size))})"
            )
        db.execute("CREATE TABLE config (key TEXT, value TEXT)")
        db.executemany(
            "INSERT INTO config VALUES (?, ?)",
            [("halt", "original"), ("unknown", "legacy-two")],
        )
    original = prepare.snapshot(budget)
    source = {
        "epoch_id": "synthetic-source11",
        "campaign_id": "synthetic",
        "epoch_number": 11,
        "predecessor_epoch_id": "synthetic-source10",
        "budget_path": str(budget),
        "budget_identity": "synthetic-only",
        "controller_state_roots": locks["controller_state_roots"],
    }
    model = {
        "model_epoch_id": "synthetic-model8",
        "campaign_id": "synthetic",
        "model_epoch_number": 8,
        "predecessor_model_epoch_id": "synthetic-model7",
    }
    material_docs = prepare.Documents(tmp_path)
    pool_pin = material_docs.stage("target.json", pool)
    host_pin = material_docs.stage(
        "activation/target-host.json", {"pool_registration": pool_pin}
    )
    material = {
        "pool": pool,
        "pool_host_manifest": host_pin,
        "children": [],
        "source": source,
        "model": model,
        "source_authority": {"synthetic_scope": "source"},
        "model_authority": {"synthetic_scope": "model"},
    }
    material_pin = material_docs.stage("activation/materialization.json", material)
    docs = prepare.Documents(tmp_path)
    packet = docs.stage(
        "scope-packet.json", {"source_tree": str(tmp_path), "source_commit": "a" * 40}
    )
    preparation = {
        "schema_version": "task13-manual-recovery-preparation-v1",
        "status": "pending_no_authority_or_registration",
        "actual_authority_created": 0,
        "scope_packet": packet,
        "controller_manifest": packet,
        "source_files": {},
        "pool": {
            "recovery_equivalence": {
                "original_execution": {"source_receipt_pin": packet}
            }
        },
        "database_snapshots": {str(budget): original},
        "preservation": [prepare.pin(old.path)],
        "recovery_plan": locks["expected_scope"],
    }
    spec = {
        "preparation": docs.stage("activation/preparation.json", preparation),
        "authorization_request": docs.stage(
            "request.json", {"synthetic_no_authority_credit": True}
        ),
        "actual_scope_chat": docs.stage(
            "reply.json", {"synthetic_no_authority_credit": True}
        ),
    }
    spec["actual_scope_review"] = docs.stage(
        "review.json",
        {
            "schema_version": "task13-manual-recovery-actual-scope-review-v1",
            "status": "passed",
            "review_kind": "independent_actual_scope",
            "reviewer_identity": "synthetic-review-only",
            "critical": 0,
            "important": 0,
            **spec,
            "scope_packet": packet,
            "controller_manifest": packet,
        },
    )
    docs.publish()
    monkeypatch.setattr(compiler, "committed_recovery_source", lambda *args: None)
    monkeypatch.setattr(
        compiler,
        "compile_adoption",
        lambda *args: (material_docs, material, material_pin),
    )
    monkeypatch.setattr(timing_pool, "validate_pool_registration", lambda value: value)
    monkeypatch.setattr(prepare, "require_native_prefix", lambda *args: None)
    monkeypatch.setattr(
        recovery, "validate_quarantine_evidence", lambda value, **kwargs: value
    )
    monkeypatch.setattr(recovery, "_audit_prefix", lambda *args: deepcopy(quarantine))

    def register(path, value, *, locked_audit, **kwargs):
        kind = "source" if "epoch_id" in value else "model"
        table = "supplement_" + kind + "_epochs"
        authority = material[kind + "_authority"]
        row = (
            [
                value["epoch_id"],
                value["campaign_id"],
                value["epoch_number"],
                value["predecessor_epoch_id"],
            ]
            if kind == "source"
            else [
                value["model_epoch_id"],
                value["campaign_id"],
                value["model_epoch_number"],
                value["predecessor_model_epoch_id"],
            ]
        )
        row += [json.dumps(value), canonical_hash(value)]
        if kind == "model":
            row.append(json.dumps(authority))
        row += [canonical_hash(authority), "synthetic-time", "synthetic-time"]
        with ExitStack() as stack, sqlite3.connect(path) as db:
            owned = source_epochs._lock_controller_roots(
                source["controller_state_roots"], stack
            )
            db.execute("BEGIN IMMEDIATE")
            locked_audit(
                db=db,
                controller_state_roots=tuple(source["controller_state_roots"]),
                owned_locks=owned,
            )
            db.execute(
                f"INSERT INTO {table} VALUES ({','.join('?' for _ in row)})", row
            )

    monkeypatch.setattr(source_epochs, "register_source_epoch", register)
    monkeypatch.setattr(model_identities, "register_model_identity", register)
    publish = prepare.Documents.publish

    class PublicationCrash(Exception):
        pass

    def crash_after_parent(self):
        if any(path.name == "adoption-result.json" for path in self.values):
            assert compiler._pool_genesis(pool)
            raise PublicationCrash("parent genesis durable, result not published")
        publish(self)

    monkeypatch.setattr(prepare.Documents, "publish", crash_after_parent)
    with pytest.raises(PublicationCrash):
        compiler.adopt(spec)
    monkeypatch.setattr(prepare.Documents, "publish", publish)
    assert not (tmp_path / "activation/adoption-result.json").exists()
    return compiler, spec, material, old, budget


@pytest.mark.parametrize("change", [None, "unlisted", "changed", "begun", "stopped"])
def test_public_adopt_resumes_after_parent_genesis_only_for_exact_inert_target(
    tmp_path, monkeypatch, change
):
    from pathlib import Path

    from evals.contracts import canonical_hash
    from evals.timing_pool import pool_policy
    from evals.timing_pool_controller import PoolJournal
    from scripts.task13_pool_prepare import snapshot

    compiler, spec, material, old, budget = adoption_crash_fixture(
        tmp_path, monkeypatch
    )
    pool = material["pool"]
    target_path = Path(pool["execution_journal_path"])
    old_bytes, target_bytes, account = (
        old.path.read_bytes(),
        target_path.read_bytes(),
        snapshot(budget),
    )
    if change == "unlisted":
        (target_path.parent / "unlisted").mkdir()
        (target_path.parent / "unlisted/pool-journal.jsonl").write_bytes(target_bytes)
    elif change == "changed":
        (tmp_path / "target.json").write_text("{}", encoding="utf-8")
    elif change in ("begun", "stopped"):
        journal = PoolJournal(
            target_path, pool_sha256=canonical_hash(pool), policy=pool_policy(pool)
        )
        if change == "begun":
            journal.begin(
                pool["attempt_order"][0]["trial_id"],
                now=__import__("datetime").datetime(
                    2026, 11, 1, tzinfo=__import__("datetime").timezone.utc
                ),
                quiescent=True,
                reserved_yuan="0.1",
            )
        else:
            journal.stop("unknown_native_execution")
    if change is not None:
        with pytest.raises(PermissionError):
            compiler.adopt(spec, resume=True)
    else:
        result = compiler.adopt(spec, resume=True)
        assert result["new_unclaimed_logical_slots"] == 5
        assert result["denied_structural_slots"] == 1
        assert result["provider_requests"] == result["plan_approval_credit"] == 0
        assert compiler.adopt(spec, resume=True) == result
        assert target_path.read_bytes() == target_bytes
    assert old.path.read_bytes() == old_bytes
    assert snapshot(budget) == account
