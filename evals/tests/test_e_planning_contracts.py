"""Synthetic E2 registration/requests: no service, model or real authority."""

from copy import deepcopy

import pytest

from evals.contracts import ModelConfig, canonical_hash


def selection_receipt(qualified=1):
    rows = []
    for index in range(36):
        row = {
            "source_row_id": "development-" + f"{index:024x}",
            "order_index": index,
            "case_id": "ait-" + f"{index:024x}",
            "dataset": "ait",
            "agent_sha256": "a" * 64,
            "manifest_sha256": "b" * 64,
            "request_sha256": canonical_hash(["original-request", index]),
            "analysis_output_sha256": canonical_hash(["original-analysis", index]),
            "imported_values_sha256": canonical_hash(["original-bounded-input", index]),
            "source_status": "completed" if index < qualified else "failed",
            "status": "selected" if index < qualified else "rejected",
            "reason": None if index < qualified else "synthetic failed source",
        }
        rows.append(row)
    rule = "first-three-qualified-original-36-v1"
    return {
        "schema_version": "task13-analysis-source-selection-v1",
        "rule": rule,
        "rule_sha256": canonical_hash(rule),
        "status": "insufficient_qualified_sources",
        "original_bundle_sha256": "c" * 64,
        "rows": rows,
        "selected_sources": [
            {
                key: value
                for key, value in row.items()
                if key not in {"source_status", "status", "reason"}
            }
            for row in rows[:qualified]
        ],
        "related_case_duplicates": [],
    }


def registration_fixture(qualified=1):
    from evals.e_planning import build_e_planning_registration

    return build_e_planning_registration(
        selection_receipt(qualified),
        registration_id="1" * 32,
        source_package_manifest_sha256="d" * 64,
        budget_source_receipt_sha256="1" * 64,
        epoch_binding={
            "epoch_id": "synthetic-epoch-1",
            "epoch_manifest_sha256": "e" * 64,
            "source_commit": "f" * 40,
            "source_sha256": "1" * 64,
            "budget_identity": {
                "schema_version": "task13-original-budget-identity-v1",
                "baseline_count": 1,
                "baseline_max_rowid": 1,
                "baseline_sha256": "2" * 64,
            },
        },
        core_config={"model": ModelConfig().model_dump(mode="json"), "synthetic": True},
        synthetic=True,
    )


def test_one_source_remains_insufficient_and_yields_three_independent_slots():
    from evals.e_planning import planning_requests, validate_e_planning_registration

    registration = registration_fixture()
    before = deepcopy(registration)
    validate_e_planning_registration(registration)
    assert registration == before
    assert registration["source_selection_receipt"] == selection_receipt()
    assert registration["mode"] == "same-source-replicates-v1"
    assert registration["qualified_source_count"] == 1
    assert (
        registration["distinct_source_count"]
        == registration["distinct_case_count"]
        == 1
    )
    assert registration["f8_approval_credit"] == 0
    requests = planning_requests(registration)
    assert len(requests) == 3
    for key in (
        "slot_id",
        "request_id",
        "namespace",
        "incident_id",
        "run_id",
        "trial_id",
    ):
        assert len({getattr(request, key) for request in requests}) == 3
    assert len({request.source_identity for request in requests}) == 1
    assert len({request.analysis_output_sha256 for request in requests}) == 1
    assert planning_requests(registration) == requests
    source = registration["source_selection_receipt"]["selected_sources"][0]
    for request in requests:
        assert request.original_request_sha256 == source["request_sha256"]
        assert request.original_manifest_sha256 == source["manifest_sha256"]
        assert request.analysis_output_sha256 == source["analysis_output_sha256"]
        assert request.imported_values_sha256 == source["imported_values_sha256"]
        assert request.registration_sha256 == canonical_hash(registration)
        assert request.response_call_limit.model_dump() == {"logical": 1, "physical": 3}
        assert request.plan_ttl_seconds == 1800
        assert request.auto_renew is False
        assert request.execution_policy == "import-analysis-respond-only-v1"
        assert request.worker_spec().budget.max_model_calls == 1
        assert request.budget_binding()["epoch_id"] == "synthetic-epoch-1"
        assert type(request.budget_identity) is dict


def test_two_qualified_sources_still_use_mechanical_first_one():
    from evals.e_planning import planning_requests

    registration = registration_fixture(2)
    assert registration["qualified_source_count"] == 2
    assert len(registration["source_selection_receipt"]["selected_sources"]) == 2
    assert {r.source_row_id for r in planning_requests(registration)} == {
        selection_receipt(2)["selected_sources"][0]["source_row_id"]
    }


@pytest.mark.parametrize("qualified", [0, 3])
def test_same_source_mode_requires_genuine_shortage(qualified):
    with pytest.raises(ValueError):
        registration_fixture(qualified)


@pytest.mark.parametrize(
    "target,value",
    [
        ("source_identity", "0" * 64),
        ("analysis_output_sha256", "0" * 64),
        ("imported_values_sha256", "0" * 64),
        ("original_request_sha256", "0" * 64),
        ("original_manifest_sha256", "0" * 64),
        ("incident_id", "IN-wrong"),
        ("trial_id", "0" * 32),
        ("slot_id", "development-eplan-" + "0" * 24),
        ("purpose", "f8"),
        ("plan_ttl_seconds", 1799),
        ("auto_renew", True),
        ("execution_policy", "full-b3"),
        ("response_call_limit", {"logical": 2, "physical": 3}),
        ("budget", {"max_model_calls": 2}),
    ],
)
def test_modified_request_binding_or_policy_is_rejected(target, value):
    from evals.adapters.e_planning_contracts import EPlanningRequest
    from evals.e_planning import planning_requests

    request = planning_requests(registration_fixture())[0].model_dump(mode="json")
    request[target] = value
    with pytest.raises(ValueError):
        EPlanningRequest.model_validate(request)


@pytest.mark.parametrize("mutation", ["source", "selection", "slot", "model", "extra"])
def test_registration_cannot_change_frozen_source_slots_model_or_schema(mutation):
    from evals.e_planning import validate_e_planning_registration

    registration = registration_fixture()
    if mutation == "source":
        registration["source"]["analysis_output_sha256"] = "0" * 64
    elif mutation == "selection":
        registration["source_selection_receipt"]["status"] = "selected"
    elif mutation == "slot":
        registration["slots"][1] = deepcopy(registration["slots"][0])
    elif mutation == "model":
        registration["core_config"]["model"]["max_tokens"] = 8192
    else:
        registration["user_approved"] = True
    with pytest.raises(ValueError):
        validate_e_planning_registration(registration)


def test_missing_original_bundle_hash_or_malformed_terminal_row_is_rejected():
    from evals.e_planning import validate_e_planning_registration

    for broken in ({}, None):
        registration = registration_fixture()
        registration["source_selection_receipt"]["rows"][20] = broken
        with pytest.raises(ValueError):
            validate_e_planning_registration(registration)
    registration = registration_fixture()
    registration["source_selection_receipt"]["original_bundle_sha256"] = "not-a-hash"
    registration["source_selection_receipt_sha256"] = canonical_hash(
        registration["source_selection_receipt"]
    )
    with pytest.raises(ValueError):
        validate_e_planning_registration(registration)


def test_selected_lineage_is_mechanically_frozen_from_original_first_source():
    from evals.e_planning import planning_requests

    registration = registration_fixture(2)
    first = registration["source_selection_receipt"]["selected_sources"][0]
    expected = {
        "schema_version": "task13-e-selected-source-lineage-v1",
        "source_selection_receipt_sha256": canonical_hash(selection_receipt(2)),
        "selected_sources": [
            {
                **{
                    key: first[key]
                    for key in (
                        "source_row_id",
                        "order_index",
                        "case_id",
                        "dataset",
                        "agent_sha256",
                        "imported_values_sha256",
                    )
                },
                "source_identity": registration["source"]["source_identity"],
                "original_request_sha256": first["request_sha256"],
                "original_artifact_manifest_sha256": first["manifest_sha256"],
                "source_package_manifest_sha256": "d" * 64,
                "source_analysis_output_sha256": first["analysis_output_sha256"],
            }
        ],
    }
    assert registration["selected_source_lineage"] == expected
    assert registration["selected_source_lineage_sha256"] == canonical_hash(expected)
    for request in planning_requests(registration):
        assert request.selected_source_lineage.model_dump(mode="json") == expected
        assert request.selected_source_lineage_sha256 == canonical_hash(expected)
        with pytest.raises(ValueError, match="frozen"):
            request.selected_source_lineage.source_selection_receipt_sha256 = "0" * 64
        with pytest.raises(ValueError, match="frozen"):
            request.selected_source_lineage.selected_sources[
                0
            ].source_row_id = "changed"
        assert isinstance(request.selected_source_lineage.selected_sources, tuple)


@pytest.mark.parametrize(
    "field",
    [
        "source_row_id",
        "order_index",
        "case_id",
        "dataset",
        "agent_sha256",
        "source_identity",
        "original_request_sha256",
        "original_artifact_manifest_sha256",
        "source_package_manifest_sha256",
        "source_analysis_output_sha256",
        "imported_values_sha256",
    ],
)
def test_rebound_lineage_hash_cannot_replace_actual_first_selected_source(field):
    from evals.e_planning import validate_e_planning_registration

    registration = registration_fixture(2)
    original_hash = canonical_hash(registration)
    entry = registration["selected_source_lineage"]["selected_sources"][0]
    replacements = {
        "source_row_id": "development-" + "f" * 24,
        "order_index": 1,
        "case_id": "ait-" + "f" * 24,
        "dataset": "dedale",
    }
    entry[field] = replacements.get(field, "0" * 64)
    registration["selected_source_lineage_sha256"] = canonical_hash(
        registration["selected_source_lineage"]
    )
    assert canonical_hash(registration) != original_hash
    with pytest.raises(ValueError, match="lineage"):
        validate_e_planning_registration(registration)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_receipt",
        "missing_hash",
        "hash",
        "selection",
        "version",
        "extra",
        "two_sources",
    ],
)
def test_registration_requires_complete_strict_lineage_even_with_outer_hash_rebound(
    mutation,
):
    from evals.e_planning import validate_e_planning_registration

    registration = registration_fixture()
    if mutation == "missing_receipt":
        registration.pop("selected_source_lineage")
    elif mutation == "missing_hash":
        registration.pop("selected_source_lineage_sha256")
    elif mutation == "hash":
        registration["selected_source_lineage_sha256"] = "0" * 64
    else:
        receipt = registration["selected_source_lineage"]
        if mutation == "selection":
            receipt["source_selection_receipt_sha256"] = "0" * 64
        elif mutation == "version":
            receipt["schema_version"] = "task13-e-selected-source-lineage-v2"
        elif mutation == "extra":
            receipt["self_declared_verified"] = True
        else:
            receipt["selected_sources"].append(deepcopy(receipt["selected_sources"][0]))
        registration["selected_source_lineage_sha256"] = canonical_hash(receipt)
    # A caller may hash any JSON again; it cannot redefine a valid source receipt.
    assert len(canonical_hash(registration)) == 64
    with pytest.raises(ValueError):
        validate_e_planning_registration(registration)


@pytest.mark.parametrize(
    "mutation", ["missing_receipt", "missing_hash", "hash", "aliases"]
)
def test_request_rejects_missing_lineage_or_receipt_alias_substitution(mutation):
    from evals.adapters.e_planning_contracts import EPlanningRequest
    from evals.e_planning import planning_requests

    request = planning_requests(registration_fixture())[0].model_dump(mode="json")
    if mutation == "missing_receipt":
        request.pop("selected_source_lineage")
    elif mutation == "missing_hash":
        request.pop("selected_source_lineage_sha256")
    elif mutation == "hash":
        request["selected_source_lineage_sha256"] = "0" * 64
    else:
        request["selected_source_lineage"]["selected_sources"][0][
            "original_request_sha256"
        ] = "0" * 64
        request["original_request_sha256"] = "0" * 64
        request["selected_source_lineage_sha256"] = canonical_hash(
            request["selected_source_lineage"]
        )
        request["registration_sha256"] = canonical_hash(
            ["rebound-registration", request]
        )
    with pytest.raises(ValueError):
        EPlanningRequest.model_validate(request)


def test_explicit_budget_source_receipt_is_frozen_alias_of_execution_source_receipt():
    from evals.e_planning import planning_requests

    registration = registration_fixture()
    assert (
        registration["budget_source_receipt_sha256"]
        == registration["epoch_binding"]["source_sha256"]
    )
    for request in planning_requests(registration):
        assert request.budget_source_receipt_sha256 == request.source_sha256 == "1" * 64


@pytest.mark.parametrize("target", ["registration", "request"])
@pytest.mark.parametrize("mutation", ["missing", "different"])
def test_budget_source_receipt_alias_cannot_be_missing_or_replaced(target, mutation):
    from evals.adapters.e_planning_contracts import EPlanningRequest
    from evals.e_planning import planning_requests, validate_e_planning_registration

    registration = registration_fixture()
    value = (
        registration
        if target == "registration"
        else planning_requests(registration)[0].model_dump(mode="json")
    )
    if mutation == "missing":
        value.pop("budget_source_receipt_sha256")
    else:
        value["budget_source_receipt_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        if target == "registration":
            validate_e_planning_registration(value)
        else:
            EPlanningRequest.model_validate(value)


def test_rebinding_complete_source_and_receipt_cannot_choose_second_original_source():
    from evals.e_planning import validate_e_planning_registration

    registration = registration_fixture(2)
    second = registration["source_selection_receipt"]["selected_sources"][1]
    source = registration["source"]
    source.update(second)
    source["source_identity"] = canonical_hash(
        [second["case_id"], second["source_row_id"], second["request_sha256"]]
    )
    entry = registration["selected_source_lineage"]["selected_sources"][0]
    entry.update(
        {
            key: second[key]
            for key in (
                "source_row_id",
                "order_index",
                "case_id",
                "dataset",
                "agent_sha256",
                "imported_values_sha256",
            )
        }
    )
    entry.update(
        {
            "source_identity": source["source_identity"],
            "original_request_sha256": second["request_sha256"],
            "original_artifact_manifest_sha256": second["manifest_sha256"],
            "source_analysis_output_sha256": second["analysis_output_sha256"],
        }
    )
    registration["selected_source_lineage_sha256"] = canonical_hash(
        registration["selected_source_lineage"]
    )
    assert len(canonical_hash(registration)) == 64
    with pytest.raises(ValueError, match="frozen source"):
        validate_e_planning_registration(registration)


def test_builder_requires_explicit_matching_budget_source_receipt():
    from evals.e_planning import build_e_planning_registration

    registration = registration_fixture()
    arguments = {
        "registration_id": registration["registration_id"],
        "source_package_manifest_sha256": registration["source"][
            "source_package_manifest_sha256"
        ],
        "epoch_binding": registration["epoch_binding"],
        "core_config": registration["core_config"],
        "synthetic": True,
    }
    with pytest.raises(TypeError, match="budget_source_receipt_sha256"):
        build_e_planning_registration(selection_receipt(), **arguments)
    with pytest.raises(ValueError, match="budget source receipt"):
        build_e_planning_registration(
            selection_receipt(), **arguments, budget_source_receipt_sha256="0" * 64
        )
