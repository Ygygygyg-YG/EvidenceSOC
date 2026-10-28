"""Read-only explicit model identity admission on the existing account."""

import sqlite3

from evals.adapters.budget_v2 import SupplementBudgetAccount
from evals.adapters.model_identities import require_model_identity_in_transaction
from evals.contracts import canonical_hash


def require_dispatch_identity(path, request):
    """Validate the adopted identity and durable dispatch blockers atomically."""
    binding = request.budget_binding()
    account = SupplementBudgetAccount(path, **binding)
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        account._check_dispatch_in_transaction(db)
        return require_model_identity_in_transaction(
            db,
            binding["model_epoch_id"],
            epoch_id=binding["epoch_id"],
            source_sha256=binding["source_sha256"],
            config_sha256=binding["config_sha256"],
            purpose=binding["purpose"],
            manifest_sha256=binding["model_identity_sha256"],
            latest=True,
        )


def verify_identity_ledger(path, request, ledger):
    """Bind each physical result to the adopted identity and stored reservation."""
    binding = request.budget_binding()
    if not isinstance(ledger, list) or not ledger:
        raise ValueError("physical identity ledger required")
    account = SupplementBudgetAccount(path, **binding)
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        account._require_epoch(db, latest=True)
        manifest = require_model_identity_in_transaction(
            db,
            binding["model_epoch_id"],
            epoch_id=binding["epoch_id"],
            source_sha256=binding["source_sha256"],
            config_sha256=binding["config_sha256"],
            purpose=binding["purpose"],
            manifest_sha256=binding["model_identity_sha256"],
            latest=True,
        )
        expected = manifest["expected_model"]
        reservations = [
            call.get("reservation_id") for call in ledger if isinstance(call, dict)
        ]
        if len(reservations) != len(ledger) or len(set(reservations)) != len(
            reservations
        ):
            raise ValueError("physical ledger reservation identities must be unique")
        for call in ledger:
            if not isinstance(call, dict) or any(
                call.get(k) != binding[k]
                for k in ("model_epoch_id", "model_identity_sha256")
            ):
                raise ValueError("physical ledger identity differs")
            row = db.execute(
                "SELECT m.model_epoch_id, m.identity_manifest_sha256, r.request_id, r.campaign_id, r.case_id, r.group_name, r.attempt, r.purpose, r.source_sha256, r.config_sha256, r.role, r.logical_call_id, r.physical_attempt, r.request_sha256 FROM supplement_request_models m JOIN supplement_requests r ON r.reservation_id=m.reservation_id WHERE m.reservation_id=?",
                (call.get("reservation_id"),),
            ).fetchone()
            if row != (
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
            ):
                raise ValueError("physical ledger reservation mapping differs")
            if hasattr(request, "planning_slot_id"):
                hint = "e-planning-respond-" + canonical_hash(request.planning_slot_id)
                logical_key = canonical_hash(["respond", "ResponseOutput", hint])
                if call.get("role") != "respond" or account.physical_request_key(
                    logical_key, call.get("physical_attempt"), explicit_call_id=hint
                ) != call.get("physical_request_id"):
                    raise ValueError("physical ledger belongs to another planning slot")
            raw = call.get("raw_response")
            if (call.get("http_status") == 200 or isinstance(raw, dict)) and (
                not isinstance(raw, dict)
                or call.get("response_model") != expected["response_model"]
                or call.get("system_fingerprint") != expected["fingerprint"]
                or raw.get("model") != expected["response_model"]
                or raw.get("system_fingerprint") != expected["fingerprint"]
            ):
                raise ValueError("physical raw model identity differs")
    return manifest
