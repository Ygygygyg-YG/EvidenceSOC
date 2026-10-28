"""Explicit E source metadata and trusted verifier dispatch; no paid providers."""

import importlib
import importlib.util
from copy import deepcopy

import pytest

from evals.adapters.epoch_development import EpochDevelopmentRequest
from evals.contracts import ModelConfig, canonical_hash
from evals.e_planning import build_e_planning_registration, planning_requests
from evals.tests.test_epoch_development import request_data

MODE = "additional-development-replicates-v1"
KIND = "additional-development-v1"
RULE = "single-registered-development-analysis-v1"


def selection_module():
    assert importlib.util.find_spec("evals.additional_source_selection") is not None, (
        "additional source requires its own strict metadata contract"
    )
    return importlib.import_module("evals.additional_source_selection")


def core_config():
    return {
        "model": ModelConfig().model_dump(mode="json"),
        "model_identity": {
            "id": "model-0",
            "response_model": "approved",
            "fingerprint": "approved-fp",
        },
        "f8_plan_sha256": "f" * 64,
        "synthetic": True,
    }


def selection_fixture():
    request = EpochDevelopmentRequest.model_validate(
        {
            **request_data(),
            "config_sha256": canonical_hash(core_config()),
        }
    )
    policy = {"synthetic": True, "rule": "only-listed-case", "cases": [request.case_id]}
    registration = {
        "schema_version": "task13-additional-development-registration-v1",
        "registration_id": "additional-development-synthetic-e",
        "synthetic": True,
        "request": request.model_dump(mode="json"),
        "request_sha256": canonical_hash(request),
        "raw_case_id": request.case_id,
        "raw_agent_sha256": request.agent_sha256,
        "selection_policy": policy,
        "selection_policy_sha256": canonical_hash(policy),
        "core_sha256": request.config_sha256,
        "epoch_id": request.epoch_id,
        "epoch_manifest_sha256": request.epoch_manifest_sha256,
        "model_identity_binding": request.model_identity_binding.model_dump(
            mode="json"
        ),
    }
    source = {
        "source_row_id": request.slot_id,
        "order_index": 0,
        "case_id": request.case_id,
        "dataset": request.case_id.split("-", 1)[0],
        "agent_sha256": request.agent_sha256,
        "request_sha256": canonical_hash(request),
        "manifest_sha256": "b" * 64,
        "analysis_output_sha256": "c" * 64,
        "imported_values_sha256": "d" * 64,
        "source_identity": canonical_hash(
            [request.case_id, request.slot_id, canonical_hash(request)]
        ),
        "source_package_manifest_sha256": "b" * 64,
        "source_kind": KIND,
        "source_registration_sha256": canonical_hash(registration),
    }
    return {
        "schema_version": "task13-additional-analysis-source-selection-v1",
        "rule": RULE,
        "rule_sha256": canonical_hash(RULE),
        "status": "selected",
        "additional_registration": registration,
        "additional_registration_sha256": canonical_hash(registration),
        "source": source,
        "result_artifact_sha256": "e" * 64,
    }


def build_registration(selection, **changes):
    development = selection["additional_registration"]["request"]
    options = {
        "registration_id": "1" * 32,
        "mode": MODE,
        "source_package_manifest_sha256": selection["source"][
            "source_package_manifest_sha256"
        ],
        "epoch_binding": {
            key: development[key]
            for key in (
                "epoch_id",
                "epoch_manifest_sha256",
                "source_commit",
                "source_sha256",
                "budget_identity",
                "model_identity_binding",
            )
        },
        "budget_source_receipt_sha256": development["source_sha256"],
        "core_config": core_config(),
        "synthetic": True,
    }
    options.update(changes)
    return build_e_planning_registration(selection, **options)


def test_additional_selection_and_planning_metadata_are_explicit():
    selection = selection_fixture()
    assert (
        selection_module().validate_additional_source_selection(selection) == selection
    )
    registration = build_registration(selection)
    assert registration["mode"] == MODE
    assert registration["qualified_source_count"] == 1
    for request in planning_requests(registration):
        assert request.mode == MODE
        assert request.source.model_dump(mode="json") == selection["source"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_row_id", "development-" + "1" * 24),
        ("case_id", "ait-" + "1" * 24),
        ("agent_sha256", "0" * 64),
        ("request_sha256", "0" * 64),
        ("source_registration_sha256", "0" * 64),
        ("manifest_sha256", "0" * 64),
        ("source_kind", None),
        ("order_index", 1),
    ],
)
def test_selection_rejects_crossed_source_even_after_rehash(field, value):
    selection = selection_fixture()
    selection["source"][field] = value
    source = selection["source"]
    source["source_identity"] = canonical_hash(
        [source["case_id"], source["source_row_id"], source["request_sha256"]]
    )
    with pytest.raises(ValueError):
        selection_module().validate_additional_source_selection(selection)


@pytest.mark.parametrize(
    "change",
    ["mode", "package", "epoch", "core", "model", "synthetic", "commit", "budget"],
)
def test_planning_rejects_crossed_additional_binding(change):
    selection = selection_fixture()
    options = {}
    if change == "mode":
        options["mode"] = "same-source-replicates-v1"
    elif change == "package":
        options["source_package_manifest_sha256"] = "a" * 64
    elif change == "core":
        options["core_config"] = {**core_config(), "new": True}
    elif change == "synthetic":
        options["synthetic"] = False
    else:
        request = selection["additional_registration"]["request"]
        epoch = {
            key: deepcopy(request[key])
            for key in (
                "epoch_id",
                "epoch_manifest_sha256",
                "source_commit",
                "source_sha256",
                "budget_identity",
                "model_identity_binding",
            )
        }
        if change == "epoch":
            epoch["epoch_id"] = "new-epoch"
        elif change == "model":
            epoch["model_identity_binding"]["model_identity_sha256"] = "0" * 64
        elif change == "commit":
            epoch["source_commit"] = "0" * 40
        else:
            epoch["budget_identity"]["baseline_sha256"] = "0" * 64
        options["epoch_binding"] = epoch
    with pytest.raises(ValueError):
        build_registration(selection, **options)


async def actual_fixture(tmp_path, monkeypatch):
    from evals.adapters.planning_analysis import ADDITIONAL_ENTRYPOINTS
    from evals.tests import test_additional_analysis as packages
    from evals.tests import test_epoch_development as epoch_tests
    from evals.tests import test_remediation_worker as worker_tests

    monkeypatch.setattr(
        epoch_tests,
        "WORKER_ENTRIES",
        epoch_tests.WORKER_ENTRIES
        | ADDITIONAL_ENTRYPOINTS
        | {
            "evals/adapters/e_planning_worker.py",
            "evals/adapters/e_planning_journal.py",
            "evals/adapters/analysis_package.py",
            "evals/adapters/analysis_import.py",
            "evals/e_planning.py",
            "evals/adapters/e_planning_no_plan.py",
            "evals/adapters/e_planning_review.py",
            "evals/adapters/verification_worker.py",
        },
    )

    factory = worker_tests.request_for

    def with_core(*args, **kwargs):
        request, agent, source = factory(*args, **kwargs)
        return (
            request.model_copy(update={"config_sha256": canonical_hash(core_config())}),
            agent,
            source,
        )

    monkeypatch.setattr(worker_tests, "request_for", with_core)
    original = await packages.additional_source(tmp_path / "analysis", monkeypatch)
    package = tmp_path / "package"
    receipt = packages.export(original, package)
    imported = packages.verify(original, package, receipt["manifest_sha256"])
    selection = selection_module().build_additional_source_selection(
        original.registration, imported
    )
    registration = build_registration(selection)
    return original, package, imported, selection, registration


@pytest.mark.asyncio
async def test_builder_uses_real_typed_replayed_analysis_and_rechecks_bytes(
    tmp_path, monkeypatch
):
    original, package, imported, selection, registration = await actual_fixture(
        tmp_path, monkeypatch
    )
    assert (
        selection["result_artifact_sha256"]
        == imported.provenance["artifacts"]["result"]["sha256"]
    )
    assert (
        selection["source"]["manifest_sha256"]
        == imported.provenance["source_package_manifest_sha256"]
    )
    assert registration["source_selection_receipt"] == selection
    with pytest.raises(TypeError):
        selection_module().build_additional_source_selection(
            original.registration, imported.product_values()
        )
    (package / "extra.json").write_text("{}")
    with pytest.raises(ValueError):
        selection_module().build_additional_source_selection(
            original.registration, imported
        )


def dispatcher_module():
    assert importlib.util.find_spec("evals.adapters.planning_analysis") is not None, (
        "planning must select its verifier from the trusted request source kind"
    )
    return importlib.import_module("evals.adapters.planning_analysis")


def test_dispatcher_is_a_separate_explicit_source_boundary():
    assert callable(dispatcher_module().verify_planning_analysis)


@pytest.mark.asyncio
async def test_dispatcher_replays_real_package_and_rejects_cross_epoch_core_identity(
    tmp_path, monkeypatch
):
    original, package, imported, _selection, registration = await actual_fixture(
        tmp_path, monkeypatch
    )
    request = planning_requests(registration)[0]
    dispatch = dispatcher_module().verify_planning_analysis
    assert dispatch(request, package, original.budget).provenance == imported.provenance
    for changes in (
        {"epoch_id": "other-epoch"},
        {"epoch_manifest_sha256": "0" * 64},
        {"config_sha256": "0" * 64, "core_config_sha256": "0" * 64},
        {
            "model_identity_binding": request.model_identity_binding.model_copy(
                update={"model_identity_sha256": "0" * 64}
            )
        },
    ):
        with pytest.raises(ValueError):
            dispatch(request.model_copy(update=changes), package, original.budget)


@pytest.mark.asyncio
async def test_dispatcher_uses_independent_registration_pin_and_never_package_self_label(
    tmp_path, monkeypatch
):
    from evals.adapters.e_planning_contracts import (
        EPlanningRequest,
        EPlanningSource,
        build_selected_source_lineage,
    )

    original, package, _imported, _selection, registration = await actual_fixture(
        tmp_path, monkeypatch
    )
    request = planning_requests(registration)[0]
    dispatch = dispatcher_module().verify_planning_analysis
    for wrong in ("registration", "kind"):
        value = request.model_dump(mode="json")
        if wrong == "registration":
            value["source"]["source_registration_sha256"] = "0" * 64
        else:
            value["mode"] = "same-source-replicates-v1"
            del value["source"]["source_kind"]
            del value["source"]["source_registration_sha256"]
        lineage = build_selected_source_lineage(
            EPlanningSource.model_validate(value["source"]),
            value["source_selection_receipt_sha256"],
        )
        value.update(
            selected_source_lineage=lineage.model_dump(mode="json"),
            selected_source_lineage_sha256=canonical_hash(lineage),
        )
        with pytest.raises(ValueError):
            dispatch(EPlanningRequest.model_validate(value), package, original.budget)


@pytest.mark.asyncio
async def test_worker_admission_replays_additional_source_under_actual_temp_journal(
    tmp_path, monkeypatch
):
    from evals.adapters.e_planning_worker import validate_planning_inputs
    from evals.tests.test_e_planning_journal import register_fixture

    original, package, imported, _selection, registration = await actual_fixture(
        tmp_path, monkeypatch
    )
    request = planning_requests(registration)[0]
    monkeypatch.delenv("TASK13_WORKER_NONCE")
    monkeypatch.setattr("os.getpid", lambda: 999)
    journal_path = tmp_path / "dispatch/e-planning.sqlite"
    journal_path.parent.mkdir()
    _, authority, _ = register_fixture(journal_path, registration)
    monkeypatch.setattr("os.getpid", lambda: 1)
    monkeypatch.setenv("TASK13_WORKER_NONCE", "synthetic-additional")
    monkeypatch.setenv("TASK13_IMPORT_DISPATCH_DB", str(journal_path))
    monkeypatch.setenv("TASK13_IMPORT_AUTHORITY_SHA256", canonical_hash(authority))
    monkeypatch.setenv("TASK13_IMPORT_SOURCE_DIR", str(package))
    monkeypatch.delenv("TASK13_EPOCH_HOST_BUDGET_PATH", raising=False)
    monkeypatch.delenv("TASK13_IMPORT_HOST_JOURNAL_PATH", raising=False)
    value, source, journal, budget = validate_planning_inputs(
        request, original.paths["events"].parent
    )
    assert value == request and source.provenance == imported.provenance
    assert budget == original.budget
    assert journal.validate_request(value)["status"] == "unclaimed"


def test_minimal_worker_export_contains_additional_selection_contract():
    from scripts.task13_worker_runtime import EXPORT_PATHS

    assert "evals/additional_source_selection.py" in EXPORT_PATHS
