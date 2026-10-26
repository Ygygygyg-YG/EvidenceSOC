"""Source epoch acceptance uses synthetic temporary accounts and no live transport."""

import json
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from evals.adapters.model_client import BudgetAccount
from evals.contracts import canonical_hash
from evals.tests.test_budget_v2 import finished, started, supplement


def test_every_nested_journal_requires_its_own_preregistered_writer_lock(tmp_path):
    from evals.tests.test_verification_v2 import registration
    from evals.verification_v2 import VerificationCampaign, file_sha256

    path, identity, controller = historical_account(tmp_path)
    source_file = tmp_path / "synthetic_source.py"
    source_file.write_text("# synthetic\n", encoding="utf-8")
    child = controller / "journal"
    VerificationCampaign(
        registration(),
        child,
        source_commit="a" * 40,
        source_files={str(source_file): file_sha256(source_file)},
        config={},
    )
    manifest = manifest_for(identity, controller)
    with pytest.raises(PermissionError, match="journal root.*registered.*locked"):
        register(path, manifest)
    manifest["controller_state_roots"].append(str(child.resolve()))
    register(path, manifest)
    assert not list(controller.rglob(".writer-lock"))
    assert not list(controller.rglob(".analysis36-campaign-lock"))


def historical_account(tmp_path):
    path = tmp_path / "campaign.sqlite"
    account = BudgetAccount(path)
    reservation = account.reserve("historical", 0.1, "formal")
    account.settle(reservation, 0)
    supplement(path)
    with sqlite3.connect(path) as db:
        rows = db.execute(
            "SELECT rowid,id,request_key,phase,upper,actual,settled "
            "FROM reservations ORDER BY rowid"
        ).fetchall()
    identity = {
        "schema_version": "task13-original-budget-identity-v1",
        "baseline_count": len(rows),
        "baseline_max_rowid": rows[-1][0],
        "baseline_sha256": canonical_hash(rows),
    }
    controller = tmp_path / "controller"
    controller.mkdir()
    return path, identity, controller


def manifest_for(identity, controller, number=0, **overrides):
    entrypoints = {
        "scripts/task13_worker_runtime.py": "1" * 64,
        "evals/remediation.py": "2" * 64,
        "evals/adapters/budget_v2.py": "3" * 64,
    }
    value = {
        "schema_version": "task13-supplement-source-epoch-v1",
        "campaign_id": "task13-repair-202610-v2",
        "epoch_id": f"synthetic-epoch-{number}",
        "epoch_number": number,
        "predecessor_epoch_id": None
        if number == 0
        else f"synthetic-epoch-{number - 1}",
        "source_commit": "1" * 40,
        "source_sha256": ("a" if number == 0 else "d") * 64,
        "config_sha256": ("b" if number == 0 else "e") * 64,
        "entrypoints": entrypoints,
        "entrypoints_sha256": canonical_hash(entrypoints),
        "runtime_binding": {
            "image_id": "sha256:" + "4" * 64,
            "dependencies_lock_sha256": "5" * 64,
            "dependencies_tree_sha256": "6" * 64,
            "knowledge_sha256": "7" * 64,
            "controller_manifest_sha256": "8" * 64,
        },
        "budget_identity": identity,
        "budget_path": str((controller.parent / "campaign.sqlite").resolve()),
        "budget_limits": {
            "total": 100,
            "development": 15,
            "supplement": 30,
            "purposes": {"development": 6, "regression": 16, "f8": 6},
            "held": 2,
        },
        "controller_state_roots": [str(controller.resolve())],
        "authority": {
            "kind": "legacy_source_attestation"
            if number == 0
            else "phase_scope_consent",
            "packet_sha256": "9" * 64,
            "decision_record_sha256": "0" * 64,
        },
    }
    value.update(overrides)
    return value


def register(path, manifest, **overrides):
    from evals.adapters.source_epochs import register_source_epoch

    authority = {
        "schema_version": "task13-source-epoch-authority-v1",
        **manifest["authority"],
        "campaign_id": manifest["campaign_id"],
        "epoch_id": manifest["epoch_id"],
        "manifest_sha256": canonical_hash(manifest),
        "budget_identity_sha256": canonical_hash(manifest["budget_identity"]),
        "decision": "attested" if manifest["epoch_number"] == 0 else "approved",
    }
    arguments = {
        "expected_manifest_sha256": canonical_hash(manifest),
        "budget_identity": manifest["budget_identity"],
        "authority": authority,
        "expected_authority_sha256": canonical_hash(authority),
    }
    arguments.update(overrides)
    return register_source_epoch(path, manifest, **arguments)


def epoch_account(path, number=1, **overrides):
    binding = {
        "epoch_id": f"synthetic-epoch-{number}",
        "source_sha256": ("a" if number == 0 else "d") * 64,
        "config_sha256": ("b" if number == 0 else "e") * 64,
    }
    binding.update(overrides)
    return supplement(path, **binding)


def test_host_registration_appends_without_rewriting_old_campaign_or_rows(tmp_path):
    from evals.adapters.source_epochs import require_registered_epoch

    path, identity, controller = historical_account(tmp_path)
    legacy = supplement(path)
    reservation = legacy.reserve("legacy", 1, "development", metadata=started())
    legacy.settle(reservation, None, metadata=finished())
    with sqlite3.connect(path) as db:
        before = {
            table: db.execute(f"SELECT * FROM {table}").fetchall()
            for table in ("reservations", "supplement_campaigns", "supplement_requests")
        }
    for number in (0, 1):
        manifest = manifest_for(identity, controller, number)
        register(path, manifest)
        assert (
            require_registered_epoch(
                path,
                manifest["epoch_id"],
                source_sha256=manifest["source_sha256"],
                config_sha256=manifest["config_sha256"],
                budget_identity=identity,
                manifest_sha256=canonical_hash(manifest),
            )
            == manifest
        )
    with sqlite3.connect(path) as db:
        for table, rows in before.items():
            assert db.execute(f"SELECT * FROM {table}").fetchall() == rows
        assert (
            db.execute("SELECT COUNT(*) FROM supplement_request_epochs").fetchone()[0]
            == 0
        )
        assert (
            db.execute("SELECT COUNT(*) FROM supplement_source_epochs").fetchone()[0]
            == 2
        )


def test_explicit_constructor_is_read_only_and_cannot_register(tmp_path):
    missing = tmp_path / "missing.sqlite"
    with pytest.raises(ValueError, match="existing|registered"):
        epoch_account(missing)
    assert not missing.exists()
    path, identity, controller = historical_account(tmp_path)
    with pytest.raises(ValueError, match="registered"):
        epoch_account(path)
    with sqlite3.connect(path) as db:
        assert (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='supplement_source_epochs'"
            ).fetchone()
            is None
        )
    register(path, manifest_for(identity, controller))
    with pytest.raises(ValueError, match="registered"):
        epoch_account(path)
    register(path, manifest_for(identity, controller, 1))
    before = path.read_bytes()
    account = epoch_account(path)
    assert path.read_bytes() == before
    assert account.request_binding()["epoch_id"] == "synthetic-epoch-1"
    assert account.supplement_summary()["accounted_cny"] == 0


def test_registered_epoch_reserve_and_settle_keep_an_atomic_epoch_mapping(tmp_path):
    path, identity, controller = historical_account(tmp_path)
    for number in (0, 1):
        register(path, manifest_for(identity, controller, number))
    account = epoch_account(path)
    reservation = account.reserve("new", 1, "development", metadata=started())
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT * FROM supplement_request_epochs").fetchall() == [
            (reservation, "synthetic-epoch-1")
        ]
    with pytest.raises(ValueError, match="epoch|binding"):
        epoch_account(path, number=0).settle(reservation, None, metadata=finished())
    account.settle(reservation, None, metadata=finished())
    assert account.supplement_summary()["unknown_reserved_cny"] == 1


def test_legacy_binding_and_physical_key_remain_exact(tmp_path):
    path, identity, controller = historical_account(tmp_path)
    account = supplement(path)
    expected = {
        "campaign_id": "task13-repair-202610-v2",
        "case_id": "synthetic-case",
        "group": "B3",
        "attempt": 1,
        "purpose": "development",
        "source_sha256": "a" * 64,
        "config_sha256": "b" * 64,
    }
    assert account.request_binding() == expected
    key = account.physical_request_key("logical-key", 1, explicit_call_id="stable")
    assert key == canonical_hash([expected, "logical-key", 1])
    register(path, manifest_for(identity, controller))
    register(path, manifest_for(identity, controller, 1))
    reopened = supplement(path)
    assert reopened.request_binding() == expected
    assert (
        reopened.physical_request_key("logical-key", 1, explicit_call_id="stable")
        == key
    )
    with pytest.raises(ValueError, match="retired"):
        epoch_account(path, number=0).reserve(
            "retired", 1, "development", metadata=started()
        )


@pytest.mark.parametrize("same_role", [True, False])
def test_source_change_cannot_replay_semantic_request_or_global_id(tmp_path, same_role):
    from evals.adapters.model_client import BudgetLimit

    path, identity, controller = historical_account(tmp_path)
    legacy = supplement(path)
    reservation = legacy.reserve("old", 1, "development", metadata=started())
    legacy.settle(reservation, None, metadata=finished())
    for number in (0, 1):
        register(path, manifest_for(identity, controller, number))
    account = epoch_account(path)
    with pytest.raises(BudgetLimit, match="already|duplicate"):
        account.reserve("new-id", 1, "development", metadata=started())
    call = started("new-id", role="analyze" if same_role else "respond")
    if same_role:
        with pytest.raises(BudgetLimit, match="replay|already|duplicate"):
            account.reserve("new-key", 1, "development", metadata=call)
    else:
        # Role is part of the existing binding: distinct role calls stay distinct.
        account.reserve("new-key", 1, "development", metadata=call)
    assert len(account.requests()) == (1 if same_role else 2)


def test_legacy_cannot_replay_a_new_epoch_semantic_request(tmp_path):
    from evals.adapters.model_client import BudgetLimit

    path, identity, controller = historical_account(tmp_path)
    register(path, manifest_for(identity, controller))
    account = epoch_account(path, number=0)
    account.reserve("new-epoch", 1, "development", metadata=started())
    with pytest.raises(BudgetLimit, match="replay|already|duplicate"):
        supplement(path).reserve(
            "legacy-key", 1, "development", metadata=started("legacy-id")
        )
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 2
        assert (
            db.execute("SELECT COUNT(*) FROM supplement_request_epochs").fetchone()[0]
            == 1
        )


@pytest.mark.parametrize(
    "change",
    [
        {"epoch_number": 2, "predecessor_epoch_id": "synthetic-epoch-1"},
        {"epoch_number": 1, "predecessor_epoch_id": "wrong"},
        {"source_sha256": "f" * 64},
        {"entrypoints_sha256": "f" * 64},
        {"budget_limits": {"total": 101}},
        {"runtime_binding": {}},
        {"controller_state_roots": []},
        {"authority": {}},
    ],
)
def test_host_rejects_invalid_initial_manifest_without_changing_old_rows(
    tmp_path, change
):
    path, identity, controller = historical_account(tmp_path)
    before = path.read_bytes()
    with pytest.raises(
        (ValueError, PermissionError), match="epoch|manifest|source|runtime|roots"
    ):
        register(path, manifest_for(identity, controller, **change))
    assert path.read_bytes() == before


def test_manifest_identity_and_external_authority_have_independent_pins(tmp_path):
    path, identity, controller = historical_account(tmp_path)
    manifest = manifest_for(identity, controller)
    for overrides in (
        {"expected_manifest_sha256": "f" * 64},
        {"expected_authority_sha256": "f" * 64},
        {"authority": {}},
        {"budget_identity": {**identity, "baseline_sha256": "f" * 64}},
    ):
        with pytest.raises((ValueError, PermissionError)):
            register(path, manifest, **overrides)
    wrong = manifest_for({**identity, "baseline_sha256": "f" * 64}, controller)
    with pytest.raises(ValueError, match="identity"):
        register(path, wrong)


def test_registration_requires_existing_campaign_and_fixed_identity_prefix(tmp_path):
    path = tmp_path / "campaign.sqlite"
    account = BudgetAccount(path)
    reservation = account.reserve("original", 1, "formal")
    account.settle(reservation, 1)
    with sqlite3.connect(path) as db:
        rows = db.execute("SELECT rowid,* FROM reservations ORDER BY rowid").fetchall()
    identity = {
        "schema_version": "task13-original-budget-identity-v1",
        "baseline_count": 1,
        "baseline_max_rowid": 1,
        "baseline_sha256": canonical_hash(rows),
    }
    controller = tmp_path / "controller"
    controller.mkdir()
    with pytest.raises((ValueError, sqlite3.Error), match="campaign|supplement"):
        register(path, manifest_for(identity, controller))
    with sqlite3.connect(path) as db:
        assert (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='supplement_source_epochs'"
            ).fetchone()
            is None
        )


@pytest.mark.parametrize(
    "active",
    ["writer", "nested_writer", "started", "unknown", "bad_result", "inflight"],
)
def test_registration_refuses_active_or_unreconciled_controller_and_ledger(
    tmp_path, active
):
    path, identity, controller = historical_account(tmp_path)
    slot = controller / "slot"
    slot.mkdir()
    if active == "writer":
        (controller / ".writer-lock").mkdir()
    elif active == "nested_writer":
        (slot / ".writer-lock").mkdir()
    elif active == "inflight":
        supplement(path).reserve("inflight", 1, "development", metadata=started())
    else:
        (slot / "started.json").write_text(
            json.dumps({"bundle_sha256": "a" * 64, "slot_id": "slot"})
        )
        if active != "started":
            (slot / "result.json").write_text("{}")
            (slot / "attempt.json").write_text(
                json.dumps(
                    {
                        "bundle_sha256": "a" * 64,
                        "slot_id": "slot",
                        "status": "unknown" if active == "unknown" else "completed",
                        "result_sha256": "f" * 64,
                    }
                )
            )
    with pytest.raises(
        PermissionError, match="active|quiescent|reconciliation|in-flight"
    ):
        register(path, manifest_for(identity, controller))
    with sqlite3.connect(path) as db:
        assert (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='supplement_source_epochs'"
            ).fetchone()
            is None
        )
    if active != "writer":
        assert not (controller / ".writer-lock").exists()


def test_successor_cannot_drop_previous_controller_roots(tmp_path):
    path, identity, controller = historical_account(tmp_path)
    register(path, manifest_for(identity, controller))
    replacement = tmp_path / "empty"
    replacement.mkdir()
    with pytest.raises(ValueError, match="roots"):
        register(path, manifest_for(identity, replacement, 1))
    with sqlite3.connect(path) as db:
        assert (
            db.execute("SELECT COUNT(*) FROM supplement_source_epochs").fetchone()[0]
            == 1
        )


def test_epoch_and_mapping_are_append_only_and_tamper_is_detected(tmp_path):
    from evals.adapters.source_epochs import require_registered_epoch

    path, identity, controller = historical_account(tmp_path)
    register(path, manifest_for(identity, controller))
    account = epoch_account(path, number=0)
    reservation = account.reserve("one", 1, "development", metadata=started())
    with sqlite3.connect(path) as db:
        for table in ("supplement_source_epochs", "supplement_request_epochs"):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                db.execute(f"DELETE FROM {table}")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute(
                "UPDATE supplement_request_epochs SET epoch_id='wrong' WHERE reservation_id=?",
                (reservation,),
            )
        db.execute("DROP TRIGGER supplement_source_epochs_no_update")
        manifest = manifest_for(identity, controller, source_sha256="f" * 64)
        db.execute(
            "UPDATE supplement_source_epochs SET manifest_json=?",
            (json.dumps(manifest),),
        )
    with pytest.raises(ValueError, match="altered"):
        require_registered_epoch(
            path, "synthetic-epoch-0", source_sha256="a" * 64, config_sha256="b" * 64
        )
    with pytest.raises(ValueError, match="altered"):
        account.settle(reservation, None, metadata=finished())
    assert account.summary()["in_flight"] == 1


@pytest.mark.parametrize(
    "purpose,phase,limit",
    [
        ("development", "development", 6),
        ("regression", "formal", 16),
        ("f8", "verification", 6),
    ],
)
def test_unknown_and_inflight_across_epochs_share_each_purpose_cap(
    tmp_path, purpose, phase, limit
):
    from evals.adapters.model_client import BudgetLimit

    path, identity, controller = historical_account(tmp_path)
    legacy = supplement(path, purpose=purpose)
    reservation = legacy.reserve("legacy-unknown", limit - 1, phase, metadata=started())
    legacy.settle(reservation, None, metadata=finished())
    for number in (0, 1):
        register(path, manifest_for(identity, controller, number))
    account = epoch_account(path, purpose=purpose, case_id="new-case")
    account.reserve("epoch-inflight", 1, phase, metadata=started("epoch-inflight"))
    with pytest.raises(BudgetLimit, match=purpose):
        epoch_account(path, purpose=purpose, case_id="overflow").reserve(
            "overflow", 0.01, phase, metadata=started("overflow")
        )
    summary = account.supplement_summary()
    assert summary["accounted_cny"] == limit
    assert summary["unknown_reserved_cny"] == limit - 1
    assert summary["in_flight_reserved_cny"] == 1


def test_epochs_share_original_total_and_development_caps(tmp_path):
    from evals.adapters.model_client import BudgetLimit

    path, identity, controller = historical_account(tmp_path)
    original = BudgetAccount(path)
    for key, phase, amount in (
        ("historic-dev", "development", 12),
        ("historic-formal", "formal", 80),
    ):
        reservation = original.reserve(key, amount, phase)
        original.settle(reservation, amount)
    for number in (0, 1):
        register(path, manifest_for(identity, controller, number))
    account = epoch_account(path)
    account.reserve("dev", 3, "development", metadata=started("dev"))
    with pytest.raises(BudgetLimit, match="development"):
        epoch_account(path, case_id="other").reserve(
            "dev-over", 0.1, "development", metadata=started("dev-over")
        )
    regression = epoch_account(path, purpose="regression")
    regression.reserve("formal", 5, "formal", metadata=started("formal"))
    with pytest.raises(BudgetLimit, match="total"):
        epoch_account(path, purpose="f8").reserve(
            "total-over", 0.1, "verification", metadata=started("total-over")
        )
    assert original.summary()["accounted_cny"] == 100
    assert regression.supplement_summary()["accounted_cny"] == 8


def test_concurrent_epoch_accounts_preserve_prior_epoch_charges(tmp_path):
    from evals.adapters.model_client import BudgetLimit

    path, identity, controller = historical_account(tmp_path)
    legacy = supplement(path)
    old = legacy.reserve("old", 2, "development", metadata=started("old"))
    legacy.settle(old, None, metadata=finished("old"))
    for number in (0, 1):
        register(path, manifest_for(identity, controller, number))

    def reserve(index):
        account = epoch_account(
            path, number=0 if index % 2 == 0 else 1, case_id=f"case-{index}"
        )
        try:
            return account.reserve(
                str(index), 2, "development", metadata=started(str(index))
            )
        except BudgetLimit:
            return None
        except ValueError as error:
            assert "retired" in str(error)
            return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(reserve, range(12)))
    assert sum(value is not None for value in results) == 2
    assert epoch_account(path).supplement_summary()["accounted_cny"] == 6
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM supplement_requests").fetchone()[0] == 3
        assert db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 4
        assert (
            db.execute(
                "SELECT COUNT(*) FROM supplement_request_epochs e LEFT JOIN supplement_requests s "
                "ON s.reservation_id=e.reservation_id WHERE s.reservation_id IS NULL"
            ).fetchone()[0]
            == 0
        )


def test_successor_retires_new_code_legacy_reserve_without_changing_constructor(
    tmp_path,
):
    path, identity, controller = historical_account(tmp_path)
    register(path, manifest_for(identity, controller))
    legacy = supplement(path)
    reservation = legacy.reserve("legacy-epoch0", 1, "development", metadata=started())
    legacy.settle(reservation, None, metadata=finished())
    key = legacy.physical_request_key("logical", 1, explicit_call_id="stable")
    register(path, manifest_for(identity, controller, 1))
    reopened = supplement(path)
    assert reopened.request_binding() == legacy.request_binding()
    assert reopened.physical_request_key("logical", 1, explicit_call_id="stable") == key
    with pytest.raises(ValueError, match="retired"):
        reopened.reserve(
            "legacy-after-switch",
            1,
            "development",
            metadata=started("new", logical_call_id="new"),
        )
    assert len(reopened.requests()) == 1


def test_host_registration_is_not_available_in_worker(tmp_path, monkeypatch):
    path, identity, controller = historical_account(tmp_path)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-worker")
    with pytest.raises(PermissionError, match="host-only"):
        register(path, manifest_for(identity, controller))


def test_host_cli_reads_explicit_json_and_never_creates_consent(tmp_path, capsys):
    from scripts.task13_register_source_epoch import main

    path, identity, controller = historical_account(tmp_path)
    manifest = manifest_for(identity, controller)
    authority = {
        "schema_version": "task13-source-epoch-authority-v1",
        **manifest["authority"],
        "campaign_id": manifest["campaign_id"],
        "epoch_id": manifest["epoch_id"],
        "manifest_sha256": canonical_hash(manifest),
        "budget_identity_sha256": canonical_hash(identity),
        "decision": "attested",
    }
    for name, value in (
        ("manifest", manifest),
        ("identity", identity),
        ("authority", authority),
    ):
        (tmp_path / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
    authority_bytes = (tmp_path / "authority.json").read_bytes()
    assert (
        main(
            [
                "--budget",
                str(path),
                "--manifest",
                str(tmp_path / "manifest.json"),
                "--expected-manifest-sha256",
                canonical_hash(manifest),
                "--budget-identity",
                str(tmp_path / "identity.json"),
                "--authority",
                str(tmp_path / "authority.json"),
                "--expected-authority-sha256",
                canonical_hash(authority),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["epoch_id"] == manifest["epoch_id"]
    assert (tmp_path / "authority.json").read_bytes() == authority_bytes
    assert sorted(p.name for p in tmp_path.glob("*.json")) == [
        "authority.json",
        "identity.json",
        "manifest.json",
    ]


def test_same_prefix_clone_cannot_be_registered_as_the_original_budget(tmp_path):
    path, identity, controller = historical_account(tmp_path)
    clone = tmp_path / "copy.sqlite"
    shutil.copyfile(path, clone)
    with pytest.raises(ValueError, match="path|original"):
        register(clone, manifest_for(identity, controller))


def test_settlement_requires_epoch_mapping_even_when_source_config_match(tmp_path):
    path, identity, controller = historical_account(tmp_path)
    register(path, manifest_for(identity, controller))
    register(
        path,
        manifest_for(
            identity, controller, 1, source_sha256="a" * 64, config_sha256="b" * 64
        ),
    )
    account = supplement(path, epoch_id="synthetic-epoch-1")
    reservation = account.reserve("one", 1, "development", metadata=started())
    for wrong in (supplement(path), epoch_account(path, number=0)):
        with pytest.raises(ValueError, match="epoch mapping"):
            wrong.settle(reservation, None, metadata=finished())
    assert account.summary()["in_flight"] == 1
    account.settle(reservation, None, metadata=finished())


def test_epoch_model_transport_is_mocked_and_ledger_has_epoch_binding(tmp_path):
    import asyncio

    import httpx
    from pydantic import BaseModel

    from evals.adapters.model_client import TrackedModel
    from evals.contracts import ModelConfig

    class Answer(BaseModel):
        verdict: str

    path, identity, controller = historical_account(tmp_path)
    for number in (0, 1):
        register(path, manifest_for(identity, controller, number))
    sent = []

    def response(request):
        sent.append(request)
        return httpx.Response(
            200,
            json={
                "id": "synthetic-provider",
                "model": "synthetic-model",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"verdict":"attack"}'},
                    }
                ],
            },
        )

    model = TrackedModel(
        ModelConfig(),
        api_key="synthetic",
        account=epoch_account(path),
        phase="development",
        transport=httpx.MockTransport(response),
    )
    answer = asyncio.run(
        model.structured("analyze", Answer, {"_model_call_id": "synthetic-stable"})
    )
    assert answer.verdict == "attack"
    assert len(sent) == len(model.ledger) == 1
    assert model.ledger[0]["epoch_id"] == "synthetic-epoch-1"
    assert model.account.summary()["in_flight"] == 0


@pytest.mark.parametrize("origin", ["legacy", "epoch0"])
def test_real_model_stable_hint_cannot_replay_across_source_epochs(tmp_path, origin):
    import asyncio

    import httpx
    from pydantic import BaseModel

    from evals.adapters.model_client import BudgetLimit, TrackedModel
    from evals.contracts import ModelConfig

    class Answer(BaseModel):
        verdict: str

    path, identity, controller = historical_account(tmp_path)
    sent = []

    def response(request):
        sent.append(request)
        return httpx.Response(
            200,
            json={
                "id": "synthetic-provider",
                "model": "synthetic-model",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"verdict":"attack"}'},
                    }
                ],
            },
        )

    def model(account):
        return TrackedModel(
            ModelConfig(),
            api_key="synthetic",
            account=account,
            phase="development",
            transport=httpx.MockTransport(response),
        )

    if origin == "epoch0":
        register(path, manifest_for(identity, controller))
    legacy = model(
        supplement(path) if origin == "legacy" else epoch_account(path, number=0)
    )
    state = {"_model_call_id": "stable-original-slot"}
    asyncio.run(legacy.structured("analyze", Answer, state))
    for number in (0, 1) if origin == "legacy" else (1,):
        register(path, manifest_for(identity, controller, number))
    previous_rows = legacy.account.requests()

    def reopen_and_replay(_index):
        current = model(epoch_account(path))
        with pytest.raises(BudgetLimit, match="already|replay"):
            asyncio.run(current.structured("analyze", Answer, state))
        assert current.ledger == []

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(reopen_and_replay, range(4)))
    assert len(sent) == 1
    assert epoch_account(path).requests() == previous_rows

    # The cache uses the full stable role/schema/hint key, so a distinct
    # preregistered hint remains a different logical call.
    current = model(epoch_account(path))
    asyncio.run(
        current.structured(
            "analyze", Answer, {"_model_call_id": "distinct-original-slot"}
        )
    )
    assert len(sent) == 2


@pytest.mark.parametrize("field", ["source_sha256", "config_sha256"])
def test_registered_epoch_constructor_rejects_a_wrong_binding(tmp_path, field):
    path, identity, controller = historical_account(tmp_path)
    register(path, manifest_for(identity, controller))
    before = path.read_bytes()
    with pytest.raises(ValueError, match="binding"):
        epoch_account(path, number=0, **{field: "f" * 64})
    assert path.read_bytes() == before


def test_mapping_insert_failure_rolls_back_global_and_supplement_reservation(tmp_path):
    path, identity, controller = historical_account(tmp_path)
    register(path, manifest_for(identity, controller))
    account = epoch_account(path, number=0)
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TRIGGER synthetic_mapping_failure BEFORE INSERT ON supplement_request_epochs "
            "BEGIN SELECT RAISE(ABORT,'synthetic mapping unavailable'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="synthetic mapping"):
        account.reserve("one", 1, "development", metadata=started())
    assert account.summary()["accounted_cny"] == 0
    assert account.requests() == []
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 1


def test_each_reservation_rechecks_the_frozen_original_identity(tmp_path):
    path, identity, controller = historical_account(tmp_path)
    register(path, manifest_for(identity, controller))
    account = epoch_account(path, number=0)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE reservations SET actual=0.01 WHERE request_key='historical'")
    with pytest.raises(ValueError, match="identity"):
        account.reserve("one", 1, "development", metadata=started())
    assert account.requests() == []


def test_reconciled_terminal_controller_is_quiescent(tmp_path):
    from hashlib import sha256

    path, identity, controller = historical_account(tmp_path)
    slot = controller / "slot"
    slot.mkdir()
    (slot / "started.json").write_text(
        json.dumps({"bundle_sha256": "a" * 64, "slot_id": "slot"})
    )
    result = b'{"synthetic": true}'
    (slot / "result.json").write_bytes(result)
    (slot / "attempt.json").write_text(
        json.dumps(
            {
                "bundle_sha256": "a" * 64,
                "slot_id": "slot",
                "status": "failed",
                "result_sha256": sha256(result).hexdigest(),
            }
        )
    )
    register(path, manifest_for(identity, controller))
    assert not (controller / ".writer-lock").exists()


@pytest.mark.parametrize("first_epoch", [True, False])
def test_epoch_zero_and_legacy_stable_hint_alias_is_refused(tmp_path, first_epoch):
    import asyncio

    import httpx
    from pydantic import BaseModel

    from evals.adapters.model_client import BudgetLimit, TrackedModel
    from evals.contracts import ModelConfig

    class Answer(BaseModel):
        verdict: str

    path, identity, controller = historical_account(tmp_path)
    register(path, manifest_for(identity, controller))
    sent = []

    def response(request):
        sent.append(request)
        return httpx.Response(
            200,
            json={
                "id": "synthetic-provider",
                "model": "synthetic-model",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "message": {"content": '{"verdict":"attack"}'},
                        "finish_reason": "stop",
                    }
                ],
            },
        )

    for index in range(2):
        use_epoch = first_epoch if index == 0 else not first_epoch
        account = epoch_account(path, number=0) if use_epoch else supplement(path)
        model = TrackedModel(
            ModelConfig(),
            api_key="synthetic",
            account=account,
            phase="development",
            transport=httpx.MockTransport(response),
        )
        operation = model.structured(
            "analyze", Answer, {"_model_call_id": "same-stable-slot"}
        )
        if index == 0:
            asyncio.run(operation)
        else:
            with pytest.raises(BudgetLimit, match="replay|already"):
                asyncio.run(operation)
    assert len(sent) == 1


@pytest.mark.parametrize(
    "state", ["unknown", "dispatched", "running", "pending_approval"]
)
def test_registration_reads_real_verification_journal_not_stale_projection(
    tmp_path, state
):
    from evals.tests.test_verification_v2 import registration
    from evals.verification_v2 import VerificationCampaign, file_sha256

    path, identity, controller = historical_account(tmp_path)
    source_file = tmp_path / "synthetic_source.py"
    source_file.write_text("# synthetic\n", encoding="utf-8")
    plan = registration()
    store = VerificationCampaign(
        plan,
        controller,
        source_commit="a" * 40,
        source_files={str(source_file): file_sha256(source_file)},
        config={},
    )
    first_case = next(iter(store.cases))
    first_request = next(iter(store.records))
    patch = {"case_id": first_case, "case_patch": {"status": state}}
    if state in {"unknown", "dispatched"}:
        patch["branches"] = {first_request: {"status": state}}
    store._append(patch)
    # A stale mutable projection cannot hide the actual hash-chain state.
    (controller / "latest.json").write_text(
        '{"status":"not_started"}', encoding="utf-8"
    )
    assert not list(controller.rglob("started.json"))
    with pytest.raises(PermissionError, match="quiescent|journal|pending"):
        register(path, manifest_for(identity, controller))


def test_registration_refuses_existing_analysis_campaign_lock(tmp_path):
    path, identity, controller = historical_account(tmp_path)
    lock = controller / ".analysis36-campaign-lock"
    lock.mkdir()
    with pytest.raises(PermissionError, match="lock|active"):
        register(path, manifest_for(identity, controller))
    assert lock.is_dir()


def test_readonly_journal_accepts_a_previous_dispatch_with_terminal_failure(tmp_path):
    from evals.tests.test_verification_v2 import registration
    from evals.verification_v2 import VerificationCampaign, file_sha256

    path, identity, controller = historical_account(tmp_path)
    source_file = tmp_path / "synthetic_source.py"
    source_file.write_text("# synthetic\n", encoding="utf-8")
    store = VerificationCampaign(
        registration(),
        controller,
        source_commit="a" * 40,
        source_files={str(source_file): file_sha256(source_file)},
        config={},
    )
    case, request = next(iter(store.cases)), next(iter(store.records))
    store._append(
        {
            "case_id": case,
            "case_patch": {"status": "running"},
            "branches": {request: {"status": "dispatched"}},
        }
    )
    store._append(
        {
            "case_id": case,
            "case_patch": {"status": "failed"},
            "branches": {request: {"status": "failed"}},
        }
    )
    before = {
        p.relative_to(controller): p.read_bytes()
        for p in controller.rglob("*")
        if p.is_file()
    }
    register(path, manifest_for(identity, controller))
    assert before == {
        p.relative_to(controller): p.read_bytes()
        for p in controller.rglob("*")
        if p.is_file()
    }


@pytest.mark.parametrize("pending", [False, True])
def test_epoch_registration_reads_bootstrap_journal_without_writing_it(
    tmp_path, pending
):
    from evals.tests.test_e_timing import setup

    path, identity, _ = historical_account(tmp_path)
    _, store, _, _ = setup.__wrapped__(tmp_path)
    if pending:
        trial = next(iter(store.trials))
        store._append(
            {
                "kind": "synthetic-pending",
                "trial_id": trial,
                "trial_patch": {"review_pending": True},
            }
        )
    before = {
        p.relative_to(store.root): p.read_bytes()
        for p in store.root.rglob("*")
        if p.is_file()
    }
    if pending:
        with pytest.raises(PermissionError, match="quiescent|pending"):
            register(path, manifest_for(identity, store.root))
    else:
        register(path, manifest_for(identity, store.root))
    assert before == {
        p.relative_to(store.root): p.read_bytes()
        for p in store.root.rglob("*")
        if p.is_file()
    }
