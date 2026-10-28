"""Explicit additive E source identity; old source bytes retain their meaning."""

from copy import deepcopy

import pytest

from evals.adapters.e_planning_contracts import (
    EPlanningRequest,
    EPlanningSource,
    build_selected_source_lineage,
)
from evals.contracts import canonical_hash
from evals.e_planning import planning_requests
from evals.tests.test_model_identity_runtime import explicit_registration

KIND = "additional-development-v1"
MODE = "additional-development-replicates-v1"


def additional_source():
    original = deepcopy(explicit_registration()["source"])
    original.update(
        source_kind=KIND,
        source_registration_sha256="a" * 64,
        order_index=0,
    )
    return original


def additional_request():
    request = planning_requests(explicit_registration())[0].model_dump(mode="json")
    source = EPlanningSource.model_validate(additional_source())
    lineage = build_selected_source_lineage(
        source, request["source_selection_receipt_sha256"]
    ).model_dump(mode="json")
    request.update(
        mode=MODE,
        source=source.model_dump(mode="json"),
        selected_source_lineage=lineage,
        selected_source_lineage_sha256=canonical_hash(lineage),
    )
    return request


def test_additional_source_identity_survives_lineage_and_request():
    request = EPlanningRequest.model_validate(additional_request())
    encoded = request.model_dump(mode="json")
    assert encoded["mode"] == MODE
    assert encoded["source"]["source_kind"] == KIND
    entry = encoded["selected_source_lineage"]["selected_sources"][0]
    assert entry["source_kind"] == KIND
    assert entry["source_registration_sha256"] == "a" * 64


@pytest.mark.parametrize("missing", ["source_kind", "source_registration_sha256"])
def test_additional_source_requires_paired_kind_and_registration(missing):
    source = additional_source()
    del source[missing]
    with pytest.raises(ValueError):
        EPlanningSource.model_validate(source)


def test_additional_source_has_its_own_single_row_order():
    source = additional_source()
    source["order_index"] = 8
    with pytest.raises(ValueError):
        EPlanningSource.model_validate(source)


def test_original_mode_cannot_import_an_additional_source():
    request = additional_request()
    request["mode"] = "same-source-replicates-v1"
    with pytest.raises(ValueError):
        EPlanningRequest.model_validate(request)


def test_additional_mode_cannot_relabel_an_original_source():
    request = planning_requests(explicit_registration())[0].model_dump(mode="json")
    request["mode"] = MODE
    with pytest.raises(ValueError):
        EPlanningRequest.model_validate(request)


def test_additional_source_requires_explicit_model_adoption():
    request = additional_request()
    del request["model_identity_binding"]
    with pytest.raises(ValueError):
        EPlanningRequest.model_validate(request)


def test_legacy_source_omits_additional_fields():
    original = planning_requests(explicit_registration())[0].model_dump(mode="json")
    assert "source_kind" not in original["source"]
    assert "source_registration_sha256" not in original["source"]
    entry = original["selected_source_lineage"]["selected_sources"][0]
    assert "source_kind" not in entry
    assert "source_registration_sha256" not in entry
