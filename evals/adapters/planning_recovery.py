"""Explicit read-only reuse of settled analysis across an execution source epoch.

These records never register, reserve, dispatch, approve or renew anything. The
trusted host pins this record in its concrete scope; normal execution admission
still requires the latest source/model epochs and their actual authority.
"""

from __future__ import annotations

import ast
import sqlite3
from copy import deepcopy
from pathlib import Path
from typing import Literal

from pydantic import Field

from evals.adapters.e_planning_contracts import OriginalBudgetIdentity
from evals.contracts import SHA256, Contract, canonical_hash


def validate_identity_contract_equivalence(original_bytes):
    """Compare data only: the analysis identity class must keep the exact AST."""
    current = (Path(__file__).resolve().parent / "e_planning_contracts.py").read_bytes()

    def identity_class(raw):
        matches = [
            node
            for node in ast.parse(raw).body
            if isinstance(node, ast.ClassDef) and node.name == "ModelIdentityBinding"
        ]
        if len(matches) != 1:
            raise ValueError(
                "original analysis identity contract is missing or duplicated"
            )
        return ast.dump(matches[0], include_attributes=False)

    if identity_class(original_bytes) != identity_class(current):
        raise ValueError("original analysis identity contract semantics differ")


class RecoveryLineage(Contract):
    schema_version: Literal["task13-e-analysis-recovery-lineage-v1"]
    recovery_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,120}$")
    original_registration_sha256: str = Field(pattern=SHA256)
    original_request_sha256: str = Field(pattern=SHA256)
    original_package_manifest_sha256: str = Field(pattern=SHA256)
    original_analysis_output_sha256: str = Field(pattern=SHA256)
    original_imported_values_sha256: str = Field(pattern=SHA256)
    original_epoch_binding: dict
    original_core_config_sha256: str = Field(pattern=SHA256)
    execution_epoch_binding: dict
    execution_core_config_sha256: str = Field(pattern=SHA256)
    authorization_record_sha256: str = Field(pattern=SHA256)
    predecessor_terminal_sha256: str = Field(pattern=SHA256)
    synthetic: bool = Field(strict=True)


def _original_epoch(request):
    return {
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


def _execution(binding):
    required = {
        "epoch_id",
        "source_commit",
        "source_sha256",
        "budget_identity",
        "model_epoch_id",
    }
    if set(binding) != required:
        raise ValueError("recovery execution descriptor must omit future manifest pins")
    OriginalBudgetIdentity.model_validate(binding["budget_identity"])
    if (
        not isinstance(binding["epoch_id"], str)
        or not binding["epoch_id"]
        or not isinstance(binding["model_epoch_id"], str)
        or not binding["model_epoch_id"]
    ):
        raise ValueError("explicit recovery execution epoch/model IDs required")
    import re

    if (
        re.fullmatch(r"[0-9a-f]{40}", binding["source_commit"]) is None
        or re.fullmatch(SHA256, binding["source_sha256"]) is None
    ):
        raise ValueError("recovery execution source pins differ")
    return deepcopy(binding)


def validate_recovery_lineage(value):
    record = RecoveryLineage.model_validate(value).model_dump(mode="json")
    from evals.e_planning import EpochBinding

    original = EpochBinding.model_validate(record["original_epoch_binding"]).model_dump(
        mode="json"
    )
    execution = _execution(record["execution_epoch_binding"])
    if (
        original != record["original_epoch_binding"]
        or original["epoch_id"] == execution["epoch_id"]
        or original["budget_identity"] != execution["budget_identity"]
    ):
        raise ValueError(
            "recovery must explicitly preserve its predecessor budget/source"
        )
    return record


def build_recovery_lineage(
    *,
    original_registration,
    source,
    execution_epoch_binding,
    execution_core_config_sha256,
    authorization_record_sha256,
    predecessor_terminal_sha256,
    recovery_id,
):
    from evals.adapters.additional_analysis import (
        validate_additional_development_registration,
    )
    from evals.adapters.e_planning_contracts import EPlanningSource

    registration = validate_additional_development_registration(original_registration)
    selected = EPlanningSource.model_validate(source).model_dump(mode="json")
    request = registration["request"]
    if (
        selected.get("source_registration_sha256") != canonical_hash(registration)
        or selected["request_sha256"] != registration["request_sha256"]
        or selected["case_id"] != request["case_id"]
        or selected["agent_sha256"] != request["agent_sha256"]
    ):
        raise ValueError("recovery original selected registration/request differs")
    return validate_recovery_lineage(
        {
            "schema_version": "task13-e-analysis-recovery-lineage-v1",
            "recovery_id": recovery_id,
            "original_registration_sha256": canonical_hash(registration),
            "original_request_sha256": registration["request_sha256"],
            "original_package_manifest_sha256": selected[
                "source_package_manifest_sha256"
            ],
            "original_analysis_output_sha256": selected["analysis_output_sha256"],
            "original_imported_values_sha256": selected["imported_values_sha256"],
            "original_epoch_binding": _original_epoch(request),
            "original_core_config_sha256": registration["core_sha256"],
            "execution_epoch_binding": _execution(execution_epoch_binding),
            "execution_core_config_sha256": execution_core_config_sha256,
            "authorization_record_sha256": authorization_record_sha256,
            "predecessor_terminal_sha256": predecessor_terminal_sha256,
            "synthetic": registration["synthetic"],
        }
    )


def validate_recovery_original(lineage, registration, manifest_sha256, request_sha256):
    value = validate_recovery_lineage(lineage)
    request = registration["request"]
    if (
        value["original_registration_sha256"] != canonical_hash(registration)
        or value["original_request_sha256"] != request_sha256
        or value["original_package_manifest_sha256"] != manifest_sha256
        or value["original_epoch_binding"] != _original_epoch(request)
        or value["original_core_config_sha256"] != registration["core_sha256"]
        or value["synthetic"] is not registration["synthetic"]
    ):
        raise ValueError(
            "recovery original analysis registration/package/epoch differs"
        )
    return value


def validate_recovery_execution(lineage, epoch_binding, core_sha256):
    value = validate_recovery_lineage(lineage)
    binding = deepcopy(epoch_binding)
    projection = {
        key: binding[key]
        for key in ("epoch_id", "source_commit", "source_sha256", "budget_identity")
    }
    projection["model_epoch_id"] = binding["model_identity_binding"]["model_epoch_id"]
    if (
        projection != value["execution_epoch_binding"]
        or core_sha256 != value["execution_core_config_sha256"]
    ):
        raise ValueError("recovery execution source/core/model differs")
    return value


def validate_recovery_provenance(lineage, provenance):
    value = validate_recovery_lineage(lineage)
    expected = {
        "source_registration_sha256": value["original_registration_sha256"],
        "request_sha256": value["original_request_sha256"],
        "source_package_manifest_sha256": value["original_package_manifest_sha256"],
        "analysis_output_sha256": value["original_analysis_output_sha256"],
        "imported_values_sha256": value["original_imported_values_sha256"],
        "source_core_sha256": value["original_core_config_sha256"],
        "source_epoch_id": value["original_epoch_binding"]["epoch_id"],
        "source_epoch_manifest_sha256": value["original_epoch_binding"][
            "epoch_manifest_sha256"
        ],
        "source_model_identity_binding": value["original_epoch_binding"][
            "model_identity_binding"
        ],
        "source_commit": value["original_epoch_binding"]["source_commit"],
        "source_sha256": value["original_epoch_binding"]["source_sha256"],
    }
    if any(provenance.get(key) != item for key, item in expected.items()):
        raise ValueError("recovery original verified analysis provenance differs")


def verify_historical_identity_ledger(path, request, ledger, lineage):
    """SELECT only, full original physical mapping; never permits a reservation."""
    from evals.adapters.model_identities import require_model_identity_in_transaction
    from evals.adapters.source_epochs import require_registered_epoch

    value = validate_recovery_lineage(lineage)
    execution = value["execution_epoch_binding"]
    latest = require_registered_epoch(
        path,
        execution["epoch_id"],
        source_sha256=execution["source_sha256"],
        config_sha256=value["execution_core_config_sha256"],
        budget_identity=execution["budget_identity"],
        latest=True,
    )
    if latest["source_commit"] != execution["source_commit"]:
        raise ValueError("recovery latest execution commit differs")
    binding = request.budget_binding()
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        model = require_model_identity_in_transaction(
            db,
            binding["model_epoch_id"],
            epoch_id=binding["epoch_id"],
            source_sha256=binding["source_sha256"],
            config_sha256=binding["config_sha256"],
            purpose="development",
            manifest_sha256=binding["model_identity_sha256"],
            latest=False,
        )
        successor_model = require_model_identity_in_transaction(
            db,
            execution["model_epoch_id"],
            epoch_id=execution["epoch_id"],
            source_sha256=execution["source_sha256"],
            config_sha256=value["execution_core_config_sha256"],
            purpose="development",
            latest=True,
        )
        if any(
            model["expected_model"][key] != successor_model["expected_model"][key]
            for key in ("response_model", "fingerprint")
        ):
            raise ValueError(
                "recovery may not change the original observed model identity"
            )
        for call in ledger:
            expected = (
                binding["model_epoch_id"],
                binding["model_identity_sha256"],
                call.get("physical_request_id"),
                binding["campaign_id"],
                binding["case_id"],
                binding["group"],
                binding["attempt"],
                binding["purpose"],
                binding["source_sha256"],
                binding["config_sha256"],
                call.get("role"),
                call.get("logical_call_id"),
                call.get("physical_attempt"),
                call.get("request_sha256"),
            )
            row = db.execute(
                "SELECT m.model_epoch_id,m.identity_manifest_sha256,r.request_id,r.campaign_id,r.case_id,r.group_name,r.attempt,r.purpose,r.source_sha256,r.config_sha256,r.role,r.logical_call_id,r.physical_attempt,r.request_sha256 FROM supplement_request_models m JOIN supplement_requests r ON r.reservation_id=m.reservation_id WHERE m.reservation_id=?",
                (call.get("reservation_id"),),
            ).fetchone()
            raw, identity = call.get("raw_response"), model["expected_model"]
            if row != expected or (
                (call.get("http_status") == 200 or isinstance(raw, dict))
                and (
                    not isinstance(raw, dict)
                    or call.get("response_model") != identity["response_model"]
                    or call.get("system_fingerprint") != identity["fingerprint"]
                    or raw.get("model") != identity["response_model"]
                    or raw.get("system_fingerprint") != identity["fingerprint"]
                )
            ):
                raise ValueError("recovery historical physical identity differs")
