"""Free, synthetic contract checks for explicit Task 13 model identity."""

from copy import deepcopy

import pytest
from pydantic import BaseModel

from evals.adapters.e_planning_contracts import EPlanningRequest
from evals.adapters.epoch_remediation import EpochRemediationRequest
from evals.contracts import canonical_hash
from evals.e_planning import EPlanningRegistration, planning_requests
from evals.tests.test_e_planning_contracts import registration_fixture
from evals.tests.test_remediation import request_values

REFERENCE = {"model_epoch_id": "model-epoch-1", "model_identity_sha256": "9" * 64}
DESCRIPTOR = {
    "id": "model-epoch-1",
    "response_model": "synthetic-model",
    "fingerprint": "synthetic-fingerprint",
}


def explicit_registration():
    value = registration_fixture()
    value["core_config"]["model_identity"] = deepcopy(DESCRIPTOR)
    value["core_config_sha256"] = canonical_hash(value["core_config"])
    value["epoch_binding"]["model_identity_binding"] = deepcopy(REFERENCE)
    assert (
        "model_identity_binding"
        in EPlanningRegistration.model_fields["epoch_binding"].annotation.model_fields
    ), "epoch binding must carry the explicitly adopted model reference"
    return EPlanningRegistration.model_validate(value).model_dump(mode="json")


def regression_request(reference=None):
    values = {
        **request_values("regression"),
        "epoch_id": "synthetic-epoch-1",
        "epoch_manifest_sha256": "e" * 64,
    }
    if reference is not None:
        values["model_identity_binding"] = reference
        assert "model_identity_binding" in EpochRemediationRequest.model_fields, (
            "v3 request must carry model identity"
        )
    return EpochRemediationRequest.model_validate(values)


def test_legacy_registration_and_request_golden_bytes_and_nested_dump():
    registration = registration_fixture()
    request = planning_requests(registration)[0]
    assert (
        canonical_hash(registration)
        == "25f2ae2b4bc485656c30d5f620a14d85976e41cd0905580c4c3edab0beac541e"
    )
    assert (
        canonical_hash(request.model_dump(mode="json"))
        == "862e3e31697287792acc9f48ea217a840008053af2130df991b52d9773f2cc5f"
    )

    class Envelope(BaseModel):
        registration: EPlanningRegistration
        request: EPlanningRequest
        regression: EpochRemediationRequest

    nested = Envelope(
        registration=registration, request=request, regression=regression_request()
    ).model_dump(mode="json")
    assert "model_identity_binding" not in nested["registration"]["epoch_binding"]
    assert "model_identity_binding" not in nested["request"]
    assert "model_identity_binding" not in nested["regression"]


def test_explicit_registration_propagates_to_request_budget_and_claim():
    from evals.adapters.e_planning_worker import _claim_binding

    registration = explicit_registration()
    request = planning_requests(registration)[0]
    assert request.model_dump(mode="json")["model_identity_binding"] == REFERENCE
    binding = request.budget_binding()
    assert binding["model_epoch_id"] == REFERENCE["model_epoch_id"]
    assert binding["model_identity_sha256"] == REFERENCE["model_identity_sha256"]
    assert _claim_binding(request, {})["model_identity_binding"] == REFERENCE
    legacy = planning_requests(registration_fixture())[0]
    assert "model_identity_binding" not in _claim_binding(legacy, {})


def test_regression_v3_passes_reference_to_original_account_kwargs():
    request = regression_request(REFERENCE)
    assert request.model_dump(mode="json")["model_identity_binding"] == REFERENCE
    assert request.budget_binding()["model_epoch_id"] == REFERENCE["model_epoch_id"]
    assert (
        request.budget_binding()["model_identity_sha256"]
        == REFERENCE["model_identity_sha256"]
    )
    assert "model_epoch_id" not in regression_request().budget_binding()


@pytest.mark.parametrize(
    "change",
    [
        "missing_reference",
        "missing_descriptor",
        "different_id",
        "extra_descriptor",
        "missing_fingerprint",
        "manifest_in_core",
    ],
)
def test_registration_rejects_mismatched_or_malformed_identity(change):
    value = explicit_registration()
    if change == "missing_reference":
        del value["epoch_binding"]["model_identity_binding"]
    elif change == "missing_descriptor":
        del value["core_config"]["model_identity"]
    elif change == "different_id":
        value["core_config"]["model_identity"]["id"] = "other-model"
    elif change == "extra_descriptor":
        value["core_config"]["model_identity"]["extra"] = True
    elif change == "missing_fingerprint":
        value["core_config"]["model_identity"]["fingerprint"] = ""
    else:
        value["core_config"]["model_identity"]["model_identity_sha256"] = REFERENCE[
            "model_identity_sha256"
        ]
    value["core_config_sha256"] = canonical_hash(value["core_config"])
    with pytest.raises(ValueError):
        EPlanningRegistration.model_validate(value)


@pytest.mark.parametrize(
    "reference",
    [
        {"model_epoch_id": "model-epoch-1"},
        {"model_epoch_id": "model-epoch-1", "model_identity_sha256": "bad"},
        {**REFERENCE, "extra": True},
        {**REFERENCE, "model_epoch_id": ""},
    ],
)
def test_both_requests_reject_malformed_references(reference):
    registration = explicit_registration()
    value = planning_requests(registration)[0].model_dump(mode="json")
    value["model_identity_binding"] = reference
    with pytest.raises(ValueError):
        EPlanningRequest.model_validate(value)
    with pytest.raises(ValueError):
        regression_request(reference)


def test_core_descriptor_without_epoch_reference_cannot_be_registered():
    value = registration_fixture()
    value["core_config"]["model_identity"] = deepcopy(DESCRIPTOR)
    value["core_config_sha256"] = canonical_hash(value["core_config"])
    with pytest.raises(ValueError):
        EPlanningRegistration.model_validate(value)


def test_readonly_dispatch_guard_requires_adoption_and_checks_halts(tmp_path):
    import sqlite3
    from types import SimpleNamespace

    from evals.adapters.model_identity_runtime import require_dispatch_identity
    from evals.tests.test_model_identities import adopt, fixture

    path, manifest = fixture(tmp_path)
    reference = {
        "model_epoch_id": manifest["model_epoch_id"],
        "model_identity_sha256": canonical_hash(manifest),
    }
    binding = {
        "campaign_id": manifest["campaign_id"],
        "case_id": "ait-001",
        "group": "B3",
        "attempt": 1,
        "purpose": "development",
        "source_sha256": manifest["source_sha256"],
        "config_sha256": manifest["config_sha256"],
        "epoch_id": manifest["epoch_id"],
        **reference,
    }
    request = SimpleNamespace(
        model_identity_binding=reference, budget_binding=lambda: binding
    )
    with pytest.raises(ValueError):
        require_dispatch_identity(path, request)
    adopt(path, manifest)
    assert (
        require_dispatch_identity(path, request)["expected_model"]
        == manifest["expected_model"]
    )
    with sqlite3.connect(path) as db:
        db.execute("INSERT OR REPLACE INTO config VALUES ('halt','provider HTTP 401')")
        db.execute(
            "INSERT OR REPLACE INTO config VALUES ('halt','observable model version changed')"
        )
    with pytest.raises(RuntimeError):
        require_dispatch_identity(path, request)


def test_planning_host_rejects_runtime_reference_mismatch_before_source_access(
    monkeypatch,
):
    from evals.adapters import remediation_worker
    from scripts.task13_worker_runtime import validate_e_planning_host

    request = planning_requests(explicit_registration())[0]
    called = []
    monkeypatch.setattr(
        remediation_worker,
        "validate_exported_source",
        lambda *args, **kwargs: called.append(True),
    )
    options = {
        "phase": "development",
        "budget_identity": request.budget_identity,
        "model_identity_binding": {**REFERENCE, "model_epoch_id": "other"},
    }
    with pytest.raises(ValueError):
        validate_e_planning_host(request, None, options, {})
    assert not called


def test_raw_result_requires_adopted_record_and_physical_mapping(tmp_path):
    from types import SimpleNamespace

    from evals.adapters.budget_v2 import SupplementBudgetAccount
    from evals.adapters.model_identity_runtime import verify_identity_ledger
    from evals.tests.test_budget_v2 import started
    from evals.tests.test_model_identities import adopt, fixture

    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    reference = {
        "model_epoch_id": manifest["model_epoch_id"],
        "model_identity_sha256": canonical_hash(manifest),
    }
    binding = {
        "campaign_id": manifest["campaign_id"],
        "case_id": "ait-001",
        "group": "B3",
        "attempt": 1,
        "purpose": "development",
        "source_sha256": manifest["source_sha256"],
        "config_sha256": manifest["config_sha256"],
        "epoch_id": manifest["epoch_id"],
        **reference,
    }
    request = SimpleNamespace(
        model_identity_binding=reference, budget_binding=lambda: binding
    )
    account = SupplementBudgetAccount(path, **binding)
    metadata = started("new")
    reservation = account.reserve("new", 0.1, "development", metadata=metadata)
    record = {
        **{
            key: metadata[key]
            for key in ("role", "logical_call_id", "physical_attempt", "request_sha256")
        },
        **reference,
        "reservation_id": reservation,
        "physical_request_id": "new",
        "response_model": "approved",
        "system_fingerprint": "approved-fp",
        "http_status": 200,
        "raw_response": {"model": "approved", "system_fingerprint": "approved-fp"},
    }
    verify_identity_ledger(path, request, [record])
    for key in (
        "model_epoch_id",
        "reservation_id",
        "physical_request_id",
        "response_model",
        "request_sha256",
        "logical_call_id",
    ):
        altered = deepcopy(record)
        altered[key] = "wrong"
        with pytest.raises(ValueError):
            verify_identity_ledger(path, request, [altered])
    altered = deepcopy(record)
    altered["raw_response"]["system_fingerprint"] = "wrong"
    with pytest.raises(ValueError):
        verify_identity_ledger(path, request, [altered])


def test_e_host_checks_adopted_descriptor_and_preserves_local_halt(tmp_path):
    from types import SimpleNamespace

    from evals.tests.test_model_identities import adopt, fixture
    from scripts.task13_e_trial import ETrialController

    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    reference = {
        "model_epoch_id": manifest["model_epoch_id"],
        "model_identity_sha256": canonical_hash(manifest),
    }
    binding = {
        "campaign_id": manifest["campaign_id"],
        "case_id": "ait-001",
        "group": "B3",
        "attempt": 1,
        "purpose": "development",
        "source_sha256": manifest["source_sha256"],
        "config_sha256": manifest["config_sha256"],
        "epoch_id": manifest["epoch_id"],
        **reference,
    }
    request = SimpleNamespace(
        model_identity_binding=reference,
        budget_binding=lambda: binding,
        budget_identity=manifest["budget_identity"],
    )
    host = ETrialController.__new__(ETrialController)
    host._root = tmp_path / "host"
    host._root.mkdir()
    host._requests = (request,)
    host._inputs = {"runtime_options": {"budget_dir": str(path.parent)}}
    host._planning = {"core_config": {"model_identity": manifest["expected_model"]}}
    host._observed_model = {
        key: manifest["inherited_global"][key]
        for key in ("response_model", "fingerprint")
    }
    host._model_runtime_guard()
    host._observed_model["fingerprint"] = "wrong-anchor"
    with pytest.raises(PermissionError):
        host._model_runtime_guard()
    host._observed_model["fingerprint"] = manifest["inherited_global"]["fingerprint"]
    host._planning["core_config"]["model_identity"] = {
        **manifest["expected_model"],
        "fingerprint": "wrong",
    }
    with pytest.raises(PermissionError):
        host._model_runtime_guard()
    (host._root / "model-runtime-halt.json").write_text("{}", encoding="utf-8")
    with pytest.raises(PermissionError, match="halted"):
        host._model_runtime_guard()


def test_v3_bundle_binds_reference_to_every_request_and_core():
    from evals.remediation import prepare_bundle, validate_bundle
    from evals.tests.test_remediation import budget_config, registration

    core = budget_config()
    core["model_identity"] = deepcopy(DESCRIPTOR)
    epoch = {
        "epoch_id": "epoch-1",
        "epoch_manifest_sha256": "e" * 64,
        "model_identity_binding": REFERENCE,
    }
    bundle = prepare_bundle(
        registration(),
        source_commit="a" * 40,
        source_sha256="b" * 64,
        config=core,
        epoch_binding=epoch,
    )
    validate_bundle(bundle)
    assert all(
        row["request"]["model_identity_binding"] == REFERENCE for row in bundle["rows"]
    )
    crossed = deepcopy(bundle)
    crossed["rows"][0]["request"]["model_identity_binding"]["model_epoch_id"] = "other"
    crossed["bundle_sha256"] = canonical_hash(
        {k: v for k, v in crossed.items() if k != "bundle_sha256"}
    )
    with pytest.raises(ValueError):
        validate_bundle(crossed)


def test_regression_host_rejects_crossed_runtime_reference_before_free_dispatch(
    tmp_path,
):
    from types import SimpleNamespace

    from scripts.task13_regression import RegressionHost

    host = RegressionHost.__new__(RegressionHost)
    called = []
    host._free = SimpleNamespace(runtime_validator=lambda *_: called.append(True))
    host._manifest = {}
    core = {
        "budget_identity": {},
        "active_budget_path": str(tmp_path / "campaign.sqlite"),
    }
    data = {
        "core_config": core,
        "bundle": {"source_commit": "a" * 40, "model_identity_binding": REFERENCE},
        "runtime_options": {
            "phase": "formal",
            "source_commit": "a" * 40,
            "budget_identity": {},
            "budget_dir": str(tmp_path),
            "model_identity_binding": {**REFERENCE, "model_epoch_id": "other"},
        },
    }
    with pytest.raises(PermissionError):
        host._runtime(data)
    assert not called


def test_planning_probe_checks_identity_before_source_access(monkeypatch, tmp_path):
    from evals.adapters import analysis_package
    from scripts.task13_worker_runtime import e_planning_worker_probe

    request = planning_requests(explicit_registration())[0]
    monkeypatch.setenv("TASK13_BUDGET_DB", str(tmp_path / "missing.sqlite"))
    monkeypatch.setenv("TASK13_IMPORT_SOURCE_DIR", str(tmp_path))
    accessed = []
    monkeypatch.setattr(
        analysis_package,
        "verify_portable_analysis_package",
        lambda *args: accessed.append(True),
    )
    with pytest.raises((ValueError, FileNotFoundError)):
        e_planning_worker_probe(request)
    assert not accessed


def test_model_reference_accepts_task1_safe_identity_tokens():
    reference = {**REFERENCE, "model_epoch_id": "provider.v2:epoch-1"}
    assert (
        regression_request(reference).model_identity_binding.model_epoch_id
        == reference["model_epoch_id"]
    )


def test_v3_rejects_explicit_null_reference_key():
    from evals.remediation import prepare_bundle
    from evals.tests.test_remediation import budget_config, registration

    with pytest.raises(ValueError):
        prepare_bundle(
            registration(),
            source_commit="a" * 40,
            source_sha256="b" * 64,
            config=budget_config(),
            epoch_binding={
                "epoch_id": "epoch-1",
                "epoch_manifest_sha256": "e" * 64,
                "model_identity_binding": None,
            },
        )


def test_failed_e_before_any_call_does_not_create_identity_halt(tmp_path):
    from types import SimpleNamespace

    from scripts.task13_e_trial import ETrialController

    host = ETrialController.__new__(ETrialController)
    host._root = tmp_path
    host._requests = (SimpleNamespace(model_identity_binding=REFERENCE),)
    host._observed_model = {"response_model": "old", "fingerprint": "old-fp"}
    host._planning = {"core_config": {"model_identity": DESCRIPTOR}}
    host._inputs = {"runtime_options": {"budget_dir": str(tmp_path)}}
    host._verify_model_result({"execution_status": "failed", "model_ledger": []}, {})
    assert not (tmp_path / "model-runtime-halt.json").exists()


def test_failed_regression_before_any_call_does_not_create_identity_halt(tmp_path):
    import json

    from scripts.task13_regression import RegressionHost

    host = RegressionHost.__new__(RegressionHost)
    host._free = None
    host._root = tmp_path
    (tmp_path / "slot").mkdir()
    (tmp_path / "slot" / "result.json").write_text(
        json.dumps({"execution_status": "failed", "model_ledger": []}), encoding="utf-8"
    )
    row = {
        "slot_id": "slot",
        "request": regression_request(REFERENCE).model_dump(mode="json"),
    }
    data = {
        "core_config": {
            "original_observed_model_binding": {
                "response_model": "old",
                "fingerprint": "old",
            },
            "model_identity": DESCRIPTOR,
            "active_budget_path": str(tmp_path / "missing.sqlite"),
        },
        "bundle": {"model_identity_binding": REFERENCE},
    }
    host._received_model_guard(data, row)
    assert not (tmp_path / "model-runtime-halt.json").exists()


def test_planning_physical_ledger_cannot_cross_slots(tmp_path):
    from types import SimpleNamespace

    from evals.adapters.budget_v2 import SupplementBudgetAccount
    from evals.adapters.model_identity_runtime import verify_identity_ledger
    from evals.tests.test_budget_v2 import started
    from evals.tests.test_model_identities import adopt, fixture

    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    reference = {
        "model_epoch_id": manifest["model_epoch_id"],
        "model_identity_sha256": canonical_hash(manifest),
    }
    binding = {
        "campaign_id": manifest["campaign_id"],
        "case_id": "ait-001",
        "group": "B3",
        "attempt": 1,
        "purpose": "development",
        "source_sha256": manifest["source_sha256"],
        "config_sha256": manifest["config_sha256"],
        "epoch_id": manifest["epoch_id"],
        **reference,
    }
    request = SimpleNamespace(
        model_identity_binding=reference,
        budget_binding=lambda: binding,
        planning_slot_id="slot-1",
    )
    hint = "e-planning-respond-" + canonical_hash(request.planning_slot_id)
    logical_key = canonical_hash(["respond", "ResponseOutput", hint])
    account = SupplementBudgetAccount(path, **binding)
    physical = account.physical_request_key(logical_key, 1, explicit_call_id=hint)
    metadata = started(physical, role="respond")
    reservation = account.reserve(physical, 0.1, "development", metadata=metadata)
    record = {
        **reference,
        **{
            key: metadata[key]
            for key in ("role", "logical_call_id", "physical_attempt", "request_sha256")
        },
        "reservation_id": reservation,
        "physical_request_id": physical,
        "response_model": "approved",
        "system_fingerprint": "approved-fp",
        "http_status": 200,
        "raw_response": {"model": "approved", "system_fingerprint": "approved-fp"},
    }
    verify_identity_ledger(path, request, [record])
    request.planning_slot_id = "slot-2"
    with pytest.raises(ValueError):
        verify_identity_ledger(path, request, [record])


def test_review_admission_rechecks_adopted_identity_before_journal(
    tmp_path, monkeypatch
):
    from evals.adapters import e_planning_review as review
    from evals.adapters import model_identity_runtime
    from evals.tests.test_e_planning_review import reference

    planning = planning_requests(explicit_registration())[0]
    request = review.build_review_request(
        planning, reference(planning), operation="read_packet"
    )
    monkeypatch.setenv("TASK13_SOURCE_DIR", str(tmp_path))
    monkeypatch.setenv("TASK13_BUDGET_DB", str(tmp_path / "campaign.sqlite"))
    monkeypatch.setattr(review, "validate_exported_source", lambda *args: None)
    monkeypatch.setattr(review, "require_existing_budget", lambda *args: None)
    monkeypatch.setattr(review, "require_registered_epoch", lambda *args, **kwargs: {})

    def reject(*args):
        raise ValueError("unadopted")

    monkeypatch.setattr(model_identity_runtime, "require_dispatch_identity", reject)
    with pytest.raises(ValueError, match="unadopted"):
        review.validate_review_inputs(request, tmp_path)


def test_dispatch_guard_rejects_crossed_purpose(tmp_path):
    from types import SimpleNamespace

    from evals.adapters.model_identity_runtime import require_dispatch_identity
    from evals.tests.test_model_identities import adopt, fixture

    path, manifest = fixture(tmp_path)
    adopt(path, manifest)
    binding = {
        "campaign_id": manifest["campaign_id"],
        "case_id": "ait-001",
        "group": "B3",
        "attempt": 1,
        "purpose": "regression",
        "source_sha256": manifest["source_sha256"],
        "config_sha256": manifest["config_sha256"],
        "epoch_id": manifest["epoch_id"],
        "model_epoch_id": manifest["model_epoch_id"],
        "model_identity_sha256": canonical_hash(manifest),
    }
    request = SimpleNamespace(budget_binding=lambda: binding)
    with pytest.raises(ValueError):
        require_dispatch_identity(path, request)
