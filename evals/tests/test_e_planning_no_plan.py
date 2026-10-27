"""Offline no-plan proofs bind a real synthetic claim to source and raw bytes."""

import json
from copy import deepcopy
from hashlib import sha256

import pytest
from evidencesoc.agents.analysis_import import PlanningAdmission
from evidencesoc.agents.graph import _plan_hash

from evals.adapters.e_planning_worker import _claim_binding
from evals.contracts import canonical_hash
from evals.e_planning import planning_requests
from evals.tests.test_e_planning_journal import open_fixture, register_fixture
from evals.tests.test_e_planning_worker import product_registration, product_source


@pytest.fixture
def proof(tmp_path):
    source = product_source(tmp_path)
    registration = product_registration(source)
    request = planning_requests(registration)[0]
    path = tmp_path / "synthetic-dispatch.sqlite"
    _, authority, _ = register_fixture(path, registration)
    journal = open_fixture(path, registration, authority)
    binding = _claim_binding(request, journal.claim_planning_slot(request))
    provenance = PlanningAdmission._from_existing_claim(
        binding, lambda: _claim_binding(request, journal.validate_request(request))
    ).provenance_for(source, request.incident_id)
    state = {
        **source.product_values(),
        "incident_id": request.incident_id,
        "analysis_import_provenance": provenance,
        "status": "manual_review",
        "response_reason": "model_returned_null",
        "stop_reason": "model_returned_null",
        "plan_source": "model",
        "response_plan": None,
        "approval": None,
        "errors": [],
        "no_plan_reason": None,
        "no_plan_reason_missing": True,
    }
    seal = {
        key: deepcopy(state[key])
        for key in (
            "diagnosis",
            "origin",
            "classification",
            "attack_steps",
            "claims",
            "evidence",
            "knowledge",
            "analysis_import_provenance",
        )
    }
    seal["sealed_after"] = "analysis_import"
    state.update(diagnostic_snapshot=seal, diagnostic_snapshot_sha256=_plan_hash(seal))
    payload = {"messages": [{"role": "user", "content": "{}"}]}
    body = json.dumps(payload).encode()
    (tmp_path / "payload.json").write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "body.json").write_bytes(body)
    content = '{"response_plan":null}'
    ledger = [
        {
            "role": "respond",
            "logical_call_id": "logical",
            "request_id": "provider",
            "request_ordinal": 1,
            "physical_request_id": "physical",
            "physical_attempt": 1,
            "http_status": 200,
            "parse_status": "valid",
            "request_sha256": canonical_hash(payload),
            "raw_response": {
                "choices": [{"finish_reason": "stop", "message": {"content": content}}]
            },
        }
    ]
    state["response_attempts"] = [
        {
            "status": "valid",
            "raw_source": "model_ledger",
            "attempt": 1,
            "ledger_logical_call_id": "logical",
            "ledger_request_id": "provider",
            "ledger_request_ordinal": 1,
            "raw_content_sha256": sha256(content.encode()).hexdigest(),
        }
    ]
    payloads = [
        {
            "physical_request_id": "physical",
            "payload_path": "payload.json",
            "http_body_path": "body.json",
            "http_body_sha256": sha256(body).hexdigest(),
            "request_sha256": canonical_hash(payload),
            "messages_sha256": canonical_hash(payload["messages"]),
        }
    ]
    return {
        "request": request,
        "imported": source,
        "expected_provenance": provenance,
        "state": state,
        "ledger": ledger,
        "payloads": payloads,
        "output_root": tmp_path,
    }


def verify(proof):
    from evals.adapters.e_planning_no_plan import verify_no_plan

    return verify_no_plan(**proof)


@pytest.mark.parametrize("reason", [None, "", "   ", "No safe candidate"])
def test_raw_null_optional_reason_is_derived_and_bound(proof, reason):
    if reason is not None:
        content = json.dumps({"response_plan": None, "no_plan_reason": reason})
        proof["ledger"][0]["raw_response"]["choices"][0]["message"]["content"] = content
        proof["state"]["response_attempts"][0]["raw_content_sha256"] = sha256(
            content.encode()
        ).hexdigest()
    normalized = reason if reason and reason.strip() else None
    proof["state"].update(
        no_plan_reason=normalized, no_plan_reason_missing=normalized is None
    )
    assert verify(proof) == {
        "status": "no_plan",
        "response_reason": "model_returned_null",
        "no_plan_reason": normalized,
        "no_plan_reason_missing": normalized is None,
        "timing_eligible": False,
        "source_state_sha256": canonical_hash(proof["state"]),
    }


def test_no_plan_seal_uses_product_hash_with_non_ascii_provenance(proof):
    state = proof["state"]
    seal = state["diagnostic_snapshot"]
    assert any(ord(char) > 127 for char in json.dumps(seal, ensure_ascii=False))
    assert state["diagnostic_snapshot_sha256"] == _plan_hash(seal)
    assert state["diagnostic_snapshot_sha256"] != canonical_hash(seal)
    assert verify(proof)["status"] == "no_plan"
    state["diagnostic_snapshot_sha256"] = canonical_hash(seal)
    with pytest.raises(ValueError, match="seal"):
        verify(proof)


@pytest.mark.parametrize(
    "tamper",
    [
        "incident",
        "source",
        "rehash_seal",
        "seal_hash",
        "provenance",
        "seal_provenance",
        "slot",
        "epoch",
        "authority",
        "response_plan",
        "approval",
        "errors",
        "simulation",
        "reason",
        "missing",
        "raw_plan",
        "raw_hash",
        "attempt_id",
        "attempt_ordinal",
        "attempt_logical",
        "ledger_duplicate",
        "http",
        "parse",
        "finish",
        "role",
        "payload_identity",
        "payload_hash",
        "body_hash",
        "body_bytes",
        "payload_bytes",
        "payload_missing",
        "traversal",
        "status",
        "fallback",
    ],
)
def test_no_plan_rejects_contradictory_or_forged_proofs(proof, tamper):
    state, ledger = proof["state"], proof["ledger"][0]
    if tamper == "incident":
        state["incident_id"] = "other"
    elif tamper == "source":
        state["diagnosis"] = {"forged": True}
    elif tamper == "rehash_seal":
        state["origin"] = "forged"
        state["diagnostic_snapshot"]["origin"] = "forged"
        state["diagnostic_snapshot_sha256"] = _plan_hash(state["diagnostic_snapshot"])
    elif tamper == "seal_hash":
        state["diagnostic_snapshot_sha256"] = "0" * 64
    elif tamper in {"provenance", "seal_provenance"}:
        if tamper == "provenance":
            state["analysis_import_provenance"] = {}
        else:
            state["diagnostic_snapshot"]["analysis_import_provenance"] = {}
            state["diagnostic_snapshot_sha256"] = _plan_hash(
                state["diagnostic_snapshot"]
            )
    elif tamper in {"slot", "epoch", "authority"}:
        key = {
            "slot": "planning_slot_id",
            "epoch": "epoch_id",
            "authority": "authority_sha256",
        }[tamper]
        forged = deepcopy(state["analysis_import_provenance"])
        forged["planning_admission"][key] = "forged"
        state["analysis_import_provenance"] = forged
        state["diagnostic_snapshot"]["analysis_import_provenance"] = forged
        state["diagnostic_snapshot_sha256"] = _plan_hash(state["diagnostic_snapshot"])
    elif tamper in {"response_plan", "approval", "simulation"}:
        state[tamper if tamper != "simulation" else "simulation_results"] = {
            "forged": True
        }
    elif tamper == "errors":
        state["errors"] = [{"code": "actual_error"}]
    elif tamper == "reason":
        state["no_plan_reason"] = "invented"
    elif tamper == "missing":
        state["no_plan_reason_missing"] = False
    elif tamper == "raw_plan":
        from evals.tests.test_e_planning_worker import pending_state

        content = json.dumps({"response_plan": pending_state()["response_plan"]})
        ledger["raw_response"]["choices"][0]["message"]["content"] = content
        state["response_attempts"][0]["raw_content_sha256"] = sha256(
            content.encode()
        ).hexdigest()
    elif tamper == "raw_hash":
        state["response_attempts"][0]["raw_content_sha256"] = "0" * 64
    elif tamper.startswith("attempt_"):
        key = {
            "attempt_id": "ledger_request_id",
            "attempt_ordinal": "ledger_request_ordinal",
            "attempt_logical": "ledger_logical_call_id",
        }[tamper]
        state["response_attempts"][0][key] = "wrong"
    elif tamper == "ledger_duplicate":
        proof["ledger"].append(deepcopy(ledger))
    elif tamper in {"http", "parse", "role"}:
        ledger[
            {"http": "http_status", "parse": "parse_status", "role": "role"}[tamper]
        ] = "wrong"
    elif tamper == "finish":
        ledger["raw_response"]["choices"][0]["finish_reason"] = "length"
    elif tamper in {"payload_identity", "payload_hash", "body_hash", "traversal"}:
        key = {
            "payload_identity": "physical_request_id",
            "payload_hash": "request_sha256",
            "body_hash": "http_body_sha256",
            "traversal": "payload_path",
        }[tamper]
        proof["payloads"][0][key] = (
            "../payload.json" if tamper == "traversal" else "wrong"
        )
    elif tamper in {"body_bytes", "payload_bytes"}:
        (
            proof["output_root"]
            / ("body.json" if tamper == "body_bytes" else "payload.json")
        ).write_bytes(b"{}")
    elif tamper == "payload_missing":
        proof["payloads"] = []
    elif tamper == "status":
        state["status"] = "awaiting_approval"
    elif tamper == "fallback":
        state["plan_source"] = "rule_fallback"
    with pytest.raises((ValueError, PermissionError)):
        verify(proof)
