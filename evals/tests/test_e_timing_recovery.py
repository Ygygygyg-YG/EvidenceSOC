"""Opt-in, read-only timing admission of an actual preserved recovery result.

Set TASK13_TIMING_RECOVERY_MATERIALIZATION and its independent SHA256 pin.
These checks never construct a host, open a service/database, or run a worker.
"""

import json
import os
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.contracts import canonical_hash
from evals.e_planning import planning_requests
from evals.e_timing import _validate_replicate_source
from scripts.task13_e_trial import ETrialController


@pytest.fixture
def actual_recovery():
    path = os.environ.get("TASK13_TIMING_RECOVERY_MATERIALIZATION")
    digest = os.environ.get("TASK13_TIMING_RECOVERY_MATERIALIZATION_SHA256")
    if path is None and digest is None:
        pytest.skip("explicit actual recovery materialization and raw pin required")
    assert path and digest, "both independent materialization inputs are required"

    def pinned(reference):
        raw = Path(reference["path"]).read_bytes()
        assert sha256(raw).hexdigest() == reference["sha256"], "artifact pin differs"
        return json.loads(raw)

    materialization = pinned({"path": path, "sha256": digest})
    host_path = Path(path).parent / "host-manifest.json"
    host = json.loads(host_path.read_bytes())
    timing = pinned(host["inputs"]["timing_registration"])
    planning = pinned(materialization["planning_registration"])
    assert timing["planning_registration"] == planning
    request = planning_requests(planning)[0]
    terminal_path = Path(path).parent / "host-cli/ordinal-1-plan/result.json"
    terminal_raw = terminal_path.read_bytes()
    terminal = json.loads(terminal_raw)
    assert terminal["status"] == "unknown"
    state, resources, provenance, result = (
        pinned(terminal[key])
        for key in ("retained_state", "resources", "provenance", "runtime_result")
    )
    assert result["artifact_hashes"] == {
        "investigation_state": canonical_hash(state),
        "case_resource": canonical_hash(resources),
        "import_provenance": canonical_hash(provenance),
    }
    assert state["analysis_import_provenance"] == provenance
    source = ETrialController._source(
        SimpleNamespace(_timing=timing), request, state, state, resources
    )
    yield deepcopy(timing), deepcopy(timing["trials"][0]), deepcopy(source)
    assert terminal_path.read_bytes() == terminal_raw, "terminal must stay unchanged"


def test_actual_recovery_plan_passes_offline_timing_admission(actual_recovery):
    _validate_replicate_source(*actual_recovery)


@pytest.mark.parametrize(
    "fault,reason",
    [
        ("missing_request_lineage", "recovery"),
        ("missing_registered_lineage", "recovery"),
        ("original_request", "recovery original"),
        ("execution_source", "recovery execution"),
    ],
)
def test_recovery_timing_rejects_missing_or_forged_lineage(
    actual_recovery, fault, reason
):
    registration, registered, source = actual_recovery
    request = registered["planning_request"]
    if fault == "missing_request_lineage":
        request.pop("recovery_lineage")
    elif fault == "missing_registered_lineage":
        registration["planning_registration"].pop("recovery_lineage")
    else:
        lineage = deepcopy(request["recovery_lineage"])
        if fault == "original_request":
            lineage["original_request_sha256"] = "0" * 64
        else:
            lineage["execution_epoch_binding"]["source_commit"] = "0" * 40
        request["recovery_lineage"] = lineage
        registration["planning_registration"]["recovery_lineage"] = lineage
    # Reach the lineage check with a self-consistent outer request pin. The
    # independent saved state/resource/provenance bytes stay unchanged.
    source["planning_request"] = deepcopy(request)
    registered["planning_request_sha256"] = canonical_hash(request)
    with pytest.raises(PermissionError) as refused:
        _validate_replicate_source(registration, registered, source)
    assert refused.value.__cause__ is not None
    assert reason in str(refused.value.__cause__)


@pytest.mark.parametrize("fault", ["state", "admission", "resource"])
def test_recovery_timing_preserves_existing_retention_guards(actual_recovery, fault):
    registration, registered, source = actual_recovery
    if fault == "state":
        source["state"]["diagnostic_snapshot_sha256"] = "0" * 64
    elif fault == "admission":
        source["state"]["analysis_import_provenance"]["planning_admission"][
            "epoch_id"
        ] = "forged-current-epoch"
    else:
        source["resources"]["source_commit"] = "0" * 40
        source["resources_sha256"] = canonical_hash(source["resources"])
    with pytest.raises(PermissionError):
        _validate_replicate_source(registration, registered, source)
