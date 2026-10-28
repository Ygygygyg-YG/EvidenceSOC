"""Static no-plan proof shared by the worker and independently admitting host.

Callers supply a trusted portable source and provenance from the actual existing
started claim. Explicit identity mode reads the adopted identity and reservation
mapping from the budget. This module never mutates budgets or claims slots.
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from evidencesoc.agents.graph import _plan_hash
from evidencesoc.agents.models import ResponseOutput

from evals.contracts import canonical_hash

SEALED_FIELDS = (
    "diagnosis",
    "origin",
    "classification",
    "attack_steps",
    "claims",
    "evidence",
    "knowledge",
)


def _artifact(root, name):
    root = Path(root).resolve()
    if (
        not isinstance(name, str)
        or Path(name).is_absolute()
        or ".." in Path(name).parts
    ):
        raise ValueError("no-plan payload path differs")
    path = root / name
    if not path.resolve().is_relative_to(root):
        raise ValueError("no-plan payload escapes output")
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise ValueError("no-plan payload contains links")
        if part == root:
            break
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("no-plan payload must be an actual regular artifact")
    return path.read_bytes()


def verify_no_plan(
    *,
    request,
    imported,
    expected_provenance,
    state,
    ledger,
    payloads,
    output_root,
    budget_path=None,
):
    """Reparse raw null and bind source, exact admission, attempts and HTTP bodies."""
    from scripts.task13_worker_runtime import _validate_planning_source

    if request.model_identity_binding is not None:
        if budget_path is None:
            raise ValueError("independent budget identity authority required")
        from evals.adapters.model_identity_runtime import verify_identity_ledger

        verify_identity_ledger(Path(budget_path), request, ledger)
    imported.revalidate()
    _validate_planning_source(request, imported)
    seal = state.get("diagnostic_snapshot")
    original = imported.product_values()
    if (
        state.get("incident_id") != request.incident_id
        or state.get("status") != "manual_review"
        or state.get("response_reason") != "model_returned_null"
        or state.get("stop_reason") != "model_returned_null"
        or state.get("plan_source") != "model"
        or state.get("response_plan") is not None
        or state.get("approval") is not None
        or state.get("errors")
        or any(
            state.get(key)
            for key in (
                "simulation",
                "simulation_results",
                "simulation_execution",
                "validation_result",
                "approved_plan_sha256",
                "approved_plan_version",
            )
        )
        or state.get("analysis_import_provenance") != expected_provenance
        or not isinstance(seal, dict)
        or seal.get("sealed_after") != "analysis_import"
        or state.get("diagnostic_snapshot_sha256") != _plan_hash(seal)
        or seal.get("analysis_import_provenance") != expected_provenance
        or any(
            state.get(key) != seal.get(key) or state.get(key) != original.get(key)
            for key in SEALED_FIELDS
        )
    ):
        raise ValueError("no-plan source, seal or terminal state differs")
    attempts = state.get("response_attempts")
    if (
        not isinstance(attempts, list)
        or not attempts
        or attempts[-1].get("status") != "valid"
    ):
        raise ValueError("no-plan requires the actual final valid model attempt")
    attempt = attempts[-1]
    if (
        attempt.get("raw_source") != "model_ledger"
        or not isinstance(ledger, list)
        or not ledger
    ):
        raise ValueError("no-plan requires the physical model ledger")
    refs = ("logical_call_id", "request_id", "request_ordinal")
    if any(attempt.get("ledger_" + key) is None for key in refs):
        raise ValueError("no-plan physical attempt reference is missing")
    matches = [
        record
        for record in ledger
        if all(record.get(key) == attempt["ledger_" + key] for key in refs)
    ]
    if len(matches) != 1 or matches[0] is not ledger[-1]:
        raise ValueError("no-plan final physical response is ambiguous")
    record = matches[0]
    try:
        choice = record["raw_response"]["choices"][0]
        content = choice["message"]["content"]
        if (
            record.get("http_status") != 200
            or record.get("parse_status") != "valid"
            or record.get("role") != "respond"
            or choice.get("finish_reason") != "stop"
            or not isinstance(content, str)
            or sha256(content.encode()).hexdigest() != attempt.get("raw_content_sha256")
        ):
            raise ValueError("no-plan raw response identity differs")
        output = ResponseOutput.model_validate_json(content)
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError("no-plan raw response is missing") from error
    if output.response_plan is not None:
        raise ValueError("no-plan raw response contains a plan")
    reason = output.no_plan_reason
    reason = reason if reason and reason.strip() else None
    if state.get("no_plan_reason") != reason or state.get(
        "no_plan_reason_missing"
    ) is not (reason is None):
        raise ValueError("no-plan reason differs from raw model response")
    if not isinstance(payloads, list) or len(payloads) != len(ledger):
        raise ValueError("no-plan requires the complete physical payload index")
    physical_ids = [call.get("physical_request_id") for call in ledger]
    if any(not isinstance(key, str) or not key for key in physical_ids) or len(
        set(physical_ids)
    ) != len(ledger):
        raise ValueError("no-plan physical request identity is ambiguous")
    for call in ledger:
        indexed = [
            item
            for item in payloads
            if item.get("physical_request_id") == call["physical_request_id"]
        ]
        if len(indexed) != 1:
            raise ValueError("no-plan physical payload identity differs")
        item = indexed[0]
        payload = json.loads(_artifact(output_root, item.get("payload_path")))
        body = _artifact(output_root, item.get("http_body_path"))
        digest = canonical_hash(payload)
        if (
            digest != call.get("request_sha256")
            or digest != item.get("request_sha256")
            or sha256(body).hexdigest() != item.get("http_body_sha256")
            or json.loads(body) != payload
            or canonical_hash(payload.get("messages")) != item.get("messages_sha256")
        ):
            raise ValueError("no-plan actual HTTP payload bytes differ")
    return {
        "status": "no_plan",
        "response_reason": "model_returned_null",
        "no_plan_reason": reason,
        "no_plan_reason_missing": reason is None,
        "timing_eligible": False,
        "source_state_sha256": canonical_hash(state),
    }
