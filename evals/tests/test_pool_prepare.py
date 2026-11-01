"""Free tests; never adopt or register a production epoch."""

from copy import deepcopy

import pytest

from scripts.task13_pool_prepare import (
    COUNTS,
    compile_core,
    derive_decision,
    encode,
    snapshot,
)


@pytest.fixture
def native_inputs():
    """Read-only original native templates; no original writes or registrations."""
    from pathlib import Path

    from evals.timing_pool import C10_EVIDENCE_ROOT
    from scripts.task13_pool_prepare import MATERIALIZATION_SHA, pin, read

    root = C10_EVIDENCE_ROOT.parent.parent
    ref = {
        "path": str(root / "activation/materialization.json"),
        "sha256": MATERIALIZATION_SHA,
    }
    m = read(ref)
    data = {
        key: read(m[field])
        for key, field in {
            "source": "source_manifest",
            "model": "model_manifest",
            "planning": "planning_registration",
            "lineage": "recovery_lineage",
            "runtime": "runtime_options",
            "controller": "controller_code_manifest",
            "scope": "execution_scope_packet",
        }.items()
    }
    data.update(
        receipt=read(pin(root / "source/source_receipt.json")),
        host=read(pin(root / "activation/host-manifest.json")),
        old_root=root,
        materialization_pin=ref,
        observation={"actual_conditions": {"TEST_ONLY": True}},
        preservation=[],
        database_snapshots={},
    )
    return data, Path(__file__).resolve().parents[2]


def test_pure_compiler_native_children_and_inverse(tmp_path, native_inputs):
    from evals.contracts import canonical_hash
    from evals.timing_pool_controller import pool_scope_proposal
    from scripts.task13_pool_prepare import build_children, compile_pending

    data, tree = native_inputs
    original = deepcopy(data)
    files = {
        name: (data["old_root"] / "source" / name).read_bytes()
        for name in data["receipt"]["files"]
    }
    receipt = {**data["receipt"], "source_commit": "a" * 40}
    host_files = {
        str(tree / name): digest
        for name, digest in data["source"]["entrypoints"].items()
    }
    docs, prep = compile_pending(
        data,
        root=tmp_path / "SYNTHETIC-never-register",
        tree=tree,
        commit="a" * 40,
        identity="1" * 32,
        source_receipt=receipt,
        worker_bytes=files,
        host_files=host_files,
        free_policy={},
        acceptance_pin={},
        baseline={},
    )
    import json
    from pathlib import Path

    p = json.loads(docs.values[Path(prep["path"])])
    assert data == original
    assert not (tmp_path / "SYNTHETIC-never-register").exists()
    assert p["source"]["authority"]["packet_sha256"] is None
    assert p["model"]["adoption_decision_sha256"] is None
    from evals.adapters.model_identities import _validate_manifest as validate_model
    from evals.adapters.source_epochs import _validate_manifest as validate_source

    for manifest, validator in (
        (p["source"], validate_source),
        (p["model"], validate_model),
    ):
        with pytest.raises((ValueError, PermissionError)):
            validator(manifest)
    assert len(p["pool"]["attempt_order"]) == 6
    assert len({a["trial_id"] for a in p["pool"]["attempt_order"]}) == 6
    children, binding = build_children(
        p["source"],
        p["model"],
        p["core"],
        p["old_planning"],
        p["lineage"],
        p["source_files"],
        Path(prep["path"]).parent.parent,
        packet_pin={"sha256": "a" * 64},
        decision_pin={"sha256": "b" * 64},
        decided_at="2026-11-01T01:00:00+00:00",
    )
    actual = deepcopy(p["pool"])
    for child in children:
        child.pop("authority")
        assert (
            child["registration"]["planning_registration"]["recovery_lineage"]
            == p["lineage"]
        )
    actual["children"] = children
    actual["formal_binding"] = {k: binding[k] for k in actual["formal_binding"]}
    assert pool_scope_proposal(actual) == pool_scope_proposal(p["pool"])
    assert canonical_hash(actual) != canonical_hash(p["pool"])
    files[next(iter(files))] += b"tamper"
    with pytest.raises(PermissionError, match="worker bytes"):
        compile_pending(
            data,
            root=tmp_path / "other",
            tree=tree,
            commit="a" * 40,
            identity="1" * 32,
            source_receipt=receipt,
            worker_bytes=files,
            host_files=host_files,
            free_policy={},
            acceptance_pin={},
            baseline={},
        )


def test_core_delta_preserves_nonquota_conditions():
    old = {
        "combined_development_calls": dict.fromkeys(COUNTS, 0),
        "model_identity": {"id": "old", "response_model": "same"},
        "deadline": "fixed",
    }
    before = deepcopy(old)
    new = compile_core(old, "new")
    assert old == before
    assert new["combined_development_calls"] == COUNTS
    assert new["deadline"] == "fixed"
    assert new["model_identity"] == {"id": "new", "response_model": "same"}


def test_snapshot_readonly_preserves_all_rows(tmp_path):
    import sqlite3

    db = tmp_path / "SYNTHETIC.sqlite"
    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE evidence (id INTEGER, bytes BLOB)")
        connection.execute("INSERT INTO evidence VALUES (1, ?)", (b"original",))
    before = db.read_bytes()
    assert snapshot(db) == snapshot(db)
    assert db.read_bytes() == before


def test_actual_reply_must_bind_exact_question_and_packet(tmp_path):
    from evals.tests.pool_composite_prepare_fixture import compile_fixture_documents
    from scripts.task13_pool_prepare import pin, read

    fixture = compile_fixture_documents(tmp_path, {"SYNTHETIC": True})
    request, chat = read(fixture["request_pin"]), read(fixture["chat_pin"])
    result = derive_decision(
        request, chat, request["scope_packet"], {"sha256": "b" * 64}
    )
    assert result["question_item_id"] == request["question_item_id"]
    assert result["decided_at"] == chat["captured_at"]
    wrong = deepcopy(chat)
    wrong["question_reply"][0]["question"] = "Implement a plan?"
    with pytest.raises(PermissionError):
        derive_decision(request, wrong, request["scope_packet"], {"sha256": "b" * 64})
    assert encode(result) == encode(result)
    # An arbitrary semantically unrelated prepared question fails even if both
    # its raw hash and the returned UI text agree with each other.
    unrelated = read(request["prepared_question"])
    unrelated["question"] = "Should I implement the code plan?"
    unrelated_path = tmp_path / "SYNTHETIC-unrelated-question.json"
    unrelated_path.write_bytes(encode(unrelated))
    request["prepared_question"] = pin(unrelated_path)
    chat["question_reply"][0]["question"] = unrelated["question"]
    with pytest.raises(PermissionError, match="concrete packet"):
        derive_decision(request, chat, request["scope_packet"], fixture["chat_pin"])


def test_wrong_source_rejected_before_git(tmp_path, monkeypatch):
    import subprocess

    from scripts.task13_pool_prepare import committed_source

    def forbidden(*args, **kwargs):
        raise AssertionError("wrong source reached git")

    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(PermissionError, match="evaluated source tree"):
        committed_source(tmp_path, "a" * 40, {})


def test_historical_rows_and_schema_cannot_be_reidentified():
    from scripts.task13_pool_prepare import require_exact_epoch_appends

    before = {
        "schema": [],
        "tables": {
            "supplement_source_epochs": ["source9"],
            "supplement_model_epochs": ["model6"],
            "reservations": ["unknown-original-1", "unknown-original-2"],
        },
    }
    after = deepcopy(before)
    after["tables"]["supplement_source_epochs"].append("source10")
    after["tables"]["supplement_model_epochs"].append("model7")
    require_exact_epoch_appends(before, after)
    after["tables"]["reservations"][0] = "settled-forged"
    with pytest.raises(PermissionError, match="original SQL rows"):
        require_exact_epoch_appends(before, after)


def test_pure_adoption_keeps_same_answer_and_parent_packet(tmp_path, native_inputs):
    import json
    from pathlib import Path

    from scripts.task13_pool_prepare import (
        Documents,
        compile_adoption,
        compile_pending,
        pin,
    )

    data, tree = native_inputs
    root = tmp_path / "SYNTHETIC-OFFLINE-never-register"
    files = {
        name: (data["old_root"] / "source" / name).read_bytes()
        for name in data["receipt"]["files"]
    }
    host_files = {
        str(tree / name): pin(tree / name)["sha256"]
        for name in data["source"]["entrypoints"]
    }
    docs, prep_pin = compile_pending(
        data,
        root=root,
        tree=tree,
        commit="a" * 40,
        identity="2" * 32,
        source_receipt={**data["receipt"], "source_commit": "a" * 40},
        worker_bytes=files,
        host_files=host_files,
        free_policy={},
        acceptance_pin={},
        baseline={},
    )
    preparation = json.loads(docs.values[Path(prep_pin["path"])])
    # Publish inert test proposal inputs, never the resulting authority documents.
    docs.publish()
    incoming = Documents(root)
    from scripts.task13_pool_prepare import read

    prepared = read(preparation["prepared_question"])
    question = {
        "schema_version": "task13-pool-question-delivery-v1",
        "scope_packet": preparation["scope_packet"],
        "prepared_question": preparation["prepared_question"],
        "question_item_id": '["request_user_input_async","SYNTHETIC",0]',
    }
    chat = {
        "role": "user",
        "source": "actual_current_send_user_message_question_reply",
        "captured_at": "2026-11-01T01:00:00+00:00",
        "question_reply": [
            {
                "questionItemId": question["question_item_id"],
                "question": prepared["question"],
                "answer": prepared["approved_answer"],
            }
        ],
    }
    request_pin = incoming.stage("SYNTHETIC-question.json", question)
    chat_pin = incoming.stage("SYNTHETIC-chat.json", chat)
    incoming.publish()
    adopted, m, _ = compile_adoption(preparation, prep_pin, request_pin, chat_pin)
    assert not (root / "activation/source-epoch-manifest.json").exists()
    assert (
        m["source"]["authority"]["packet_sha256"]
        == preparation["scope_packet"]["sha256"]
    )
    assert len(m["children"]) == 2
    for child in m["children"]:
        assert (
            child["authority"]["scope_packet_sha256"]
            == preparation["scope_packet"]["sha256"]
        )
        assert (
            child["authority"]["decision_record_sha256"]
            == m["scope_decision"]["sha256"]
        )
    adoption = json.loads(
        adopted.values[root / "activation/model-adoption-decision.json"]
    )
    assert adoption["question_item_id"] == question["question_item_id"]
    assert adoption["decided_at"] == chat["captured_at"]
    assert adoption["is_additional_user_answer"] is False
    tampered = deepcopy(preparation)
    tampered["source"]["controller_state_roots"].append(str(root / "unapproved-root"))
    with pytest.raises(PermissionError, match="approved concrete packet"):
        compile_adoption(tampered, prep_pin, request_pin, chat_pin)


def test_native_cow_metadata_recovers_each_completed_durability_boundary(
    tmp_path, monkeypatch
):
    """One copied account progresses across simulated crashes, never real registration."""
    import json
    from hashlib import sha256
    from pathlib import Path
    from unittest.mock import patch

    from evals.adapters import e_planning_journal, model_identities, source_epochs
    from evals.tests.pool_composite_fixture import isolated_native_io
    from evals.tests.pool_composite_prepare_fixture import (
        compile_fixture_documents,
        original_templates,
    )
    from evals.timing_pool_controller import PoolJournal
    from scripts import task13_pool_prepare as operator
    from scripts.task13_e_trial import ETrialController

    class Crash(RuntimeError):
        pass

    mkdir, rmdir, stat = Path.mkdir, Path.rmdir, Path.stat
    with isolated_native_io(tmp_path) as namespace:
        # Native historical root locks AND companion fences are virtualized only
        # at filesystem transport; stat observes the same real temporary inode
        # that mkdir acquires and rmdir releases. Native validators stay intact.
        fences = tmp_path / "SYNTHETIC-COMPANION-FENCES"
        fences.mkdir()

        def mapped(path):
            if path.name in {
                ".writer-lock",
                ".analysis36-campaign-lock",
                ".pool-adoption-fence",
                ".rolling-adoption-lock",
            } and not path.is_relative_to(tmp_path):
                # Check the actual historical path without our stat redirection.
                # An existing actual lock must never be hidden by the fixture.
                with pytest.raises(FileNotFoundError):
                    stat(path)
                return fences / sha256(str(path).encode()).hexdigest()
            return path

        with (
            patch.object(
                Path, "mkdir", lambda path, *a, **k: mkdir(mapped(path), *a, **k)
            ),
            patch.object(Path, "rmdir", lambda path: rmdir(mapped(path))),
            patch.object(
                Path, "stat", lambda path, *a, **k: stat(mapped(path), *a, **k)
            ),
        ):
            data = original_templates()
            budget = Path(data["source"]["budget_path"])
            old_journal = Path(data["runtime"]["import_dispatch_path"])
            # Build exact legacy rows in new private databases; never trim a
            # live-account copy to impersonate the historical prefix.
            from evals.tests.pool_composite_fixture import (
                reconstruct_historical_databases,
            )

            reconstruct_historical_databases(data)
            fixture = compile_fixture_documents(
                tmp_path,
                {"SYNTHETIC": True},
                data_override=data,
                publish_adoption=False,
            )
            p, m, root = (
                fixture["preparation"],
                fixture["materialization"],
                fixture["root"],
            )
            docs = fixture["adoption_documents"]
            spec = {
                "preparation": fixture["preparation_pin"],
                "authorization_request": fixture["request_pin"],
                "actual_scope_chat": fixture["chat_pin"],
                "actual_scope_review": {"SYNTHETIC_TEST_ONLY": True},
            }
            marker = operator.adoption_marker(spec, fixture["materialization_pin"])
            before = p["database_snapshots"][str(budget)]
            stages = []

            def invoke(resume):
                operator.assert_preserved(p, skip_budget=budget)
                docs.validate_existing()
                prefix = operator.validate_epoch_prefix(before, snapshot(budget), m)
                operator.require_native_prefix(budget, m, prefix)
                for child in m["children"]:
                    operator.require_unclaimed_child(child)
                for child in m["pool"]["children"]:
                    operator.require_timing_genesis(child)
                pool_present = operator.require_pool_genesis(m["pool"])
                with operator.offline_metadata():
                    return operator.complete_adoption(
                        spec,
                        p,
                        root,
                        budget,
                        m,
                        docs,
                        fixture["materialization_pin"],
                        marker,
                        before,
                        pool_present,
                        resume=resume,
                    )

            original_publish = operator.Documents.publish

            def crash_marker(self):
                original_publish(self)
                if root / "activation/adoption-started.json" in self.values:
                    raise Crash("start-marker")

            with (
                patch.object(operator.Documents, "publish", crash_marker),
                pytest.raises(Crash, match="start-marker"),
            ):
                invoke(False)
            stages.append("start-marker")

            for module, name, label in (
                (source_epochs, "register_source_epoch", "source"),
                (model_identities, "register_model_identity", "model"),
            ):
                original = getattr(module, name)

                def fail_after(*args, _original=original, _label=label, **kwargs):
                    _original(*args, **kwargs)
                    raise Crash(_label)

                with (
                    patch.object(module, name, fail_after),
                    pytest.raises(Crash, match=label),
                ):
                    invoke(True)
                stages.append(label)

            original_register = e_planning_journal.register_planning_slots
            for index in (0, 1):
                wanted = m["children"][index]["authority"]["journal_path"]

                def fail_child(path, *args, _wanted=wanted, **kwargs):
                    result = original_register(path, *args, **kwargs)
                    if str(path) == _wanted:
                        raise Crash("child")
                    return result

                with (
                    patch.object(
                        e_planning_journal, "register_planning_slots", fail_child
                    ),
                    pytest.raises(Crash, match="child"),
                ):
                    invoke(True)
                stages.append("child-" + str(index))

            original_missing = operator.Documents.publish_missing

            def partial_documents(self):
                if self is docs:
                    target, payload = next(iter(self.values.items()))
                    one = operator.Documents(root)
                    one.stage(str(target.relative_to(root)), payload)
                    original_missing(one)
                    raise Crash("partial-documents")
                return original_missing(self)

            with (
                patch.object(operator.Documents, "publish_missing", partial_documents),
                pytest.raises(Crash, match="partial-documents"),
            ):
                invoke(True)
            stages.append("partial-documents")

            campaign = ETrialController._campaign
            for index in (0, 1):
                wanted = Path(m["pool"]["children"][index]["evidence_root"]).parent

                def fail_host(self, *args, _wanted=wanted, **kwargs):
                    value = campaign(self, *args, **kwargs)
                    if self._root == _wanted:
                        raise Crash("host")
                    return value

                with (
                    patch.object(ETrialController, "_campaign", fail_host),
                    pytest.raises(Crash, match="host"),
                ):
                    invoke(True)
                stages.append("host-" + str(index))

            original_pool = PoolJournal.prepare

            def fail_pool(*args, **kwargs):
                original_pool(*args, **kwargs)
                raise Crash("pool-genesis")

            with (
                patch.object(PoolJournal, "prepare", fail_pool),
                pytest.raises(Crash, match="pool-genesis"),
            ):
                invoke(True)
            stages.append("pool-genesis")

            def fail_result(self):
                original_missing(self)
                if root / "activation/adoption-result.json" in self.values:
                    raise Crash("result")

            with (
                patch.object(operator.Documents, "publish_missing", fail_result),
                pytest.raises(Crash, match="result"),
            ):
                invoke(True)
            stages.append("result")
            final_sql = snapshot(budget)
            result = invoke(True)
            assert snapshot(budget) == final_sql
            assert result["source_rows_appended"] == result["model_rows_appended"] == 1
            assert result["new_unclaimed_logical_slots"] == 6
            assert len(stages) == 10
            assert operator.validate_epoch_prefix(before, final_sql, m) == (True, True)
            assert snapshot(old_journal) == p["database_snapshots"][str(old_journal)]
            assert namespace["redirected"]
            assert operator.initial_pool_spent(m["pool"]) == "0.6837285600000000039"
            changed = deepcopy(final_sql)
            for index, encoded in enumerate(
                changed["tables"]["supplement_source_epochs"]
            ):
                import json

                row = json.loads(encoded)
                if row[0] == m["source"]["epoch_id"]:
                    row[6] = "0" * 64
                    changed["tables"]["supplement_source_epochs"][index] = json.dumps(
                        row
                    )
            with pytest.raises(PermissionError, match="different exact authority"):
                operator.validate_epoch_prefix(before, changed, m)
            model_without_source = deepcopy(final_sql)
            model_without_source["tables"]["supplement_source_epochs"] = before[
                "tables"
            ]["supplement_source_epochs"]
            with pytest.raises(PermissionError, match="model append without source"):
                operator.validate_epoch_prefix(before, model_without_source, m)
            assert operator.adoption_marker(
                spec, fixture["materialization_pin"]
            ) != operator.adoption_marker(
                {**spec, "actual_scope_chat": {"sha256": "0" * 64}},
                fixture["materialization_pin"],
            )
            # Corrupt existing metadata stops before any missing write or DB action.
            target = next(iter(docs.values))
            original_bytes = target.read_bytes()
            target.write_bytes(b"SYNTHETIC-DIVERGENCE")
            with pytest.raises(PermissionError, match="bytes diverge"):
                invoke(True)
            assert snapshot(budget) == final_sql
            target.write_bytes(original_bytes)
            child = m["children"][0]
            from evals.e_planning import planning_requests

            native = e_planning_journal.EPlanningDispatchJournal.open_existing(
                child["authority"]["journal_path"],
                expected_registration_sha256=operator.canonical_hash(child["planning"]),
                expected_authority_sha256=operator.canonical_hash(child["authority"]),
            )
            native.claim_planning_slot(planning_requests(child["planning"])[0])
            with pytest.raises(PermissionError, match="slot claimed"):
                invoke(True)
            assert snapshot(budget) == final_sql
        assert not list(fences.iterdir())


def test_ownerless_native_lock_is_not_removed(tmp_path):
    from scripts.task13_pool_prepare import require_no_active_metadata_locks

    lock = tmp_path / ".writer-lock"
    lock.mkdir()
    with pytest.raises(PermissionError, match="never remove"):
        require_no_active_metadata_locks([tmp_path])
    assert lock.is_dir()


def test_metadata_adoption_stops_at_exact_engineering_cutoff(tmp_path, monkeypatch):
    from datetime import datetime

    from scripts import task13_pool_prepare as operator

    class Cutoff(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromisoformat(operator.DEADLINE)

    monkeypatch.setattr(operator, "datetime", Cutoff)
    monkeypatch.setattr(
        operator,
        "read",
        lambda ref: {
            "status": "pending_no_authority_or_registration",
            "actual_authority_created": 0,
        },
    )
    with pytest.raises(PermissionError, match="engineering deadline elapsed"):
        operator.adopt(
            {"preparation": {"path": str(tmp_path / "activation/preparation.json")}}
        )
