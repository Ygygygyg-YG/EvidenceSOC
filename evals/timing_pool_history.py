"""Host-only historical planning replay; workers keep current-epoch guards."""

import builtins
import os
import sqlite3
from types import FunctionType, SimpleNamespace

from evals.adapters.planning_recovery import validate_recovery_lineage


def _historical_identity_ledger(path, request, ledger, lineage):
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
        latest=False,
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
            latest=False,
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


def read_historical_planning_analysis(request, root, budget_path):
    """Replay native package code with a private, pinned historical ledger reader.

    No module, builtin, worker or dispatch global is modified. ImportedAnalysis's
    revalidation callback retains this same private verification namespace.
    """
    from evals.adapters import additional_analysis, planning_analysis, planning_recovery
    from evals.adapters.e_planning_contracts import EPlanningRequest
    from evals.adapters.model_identities import require_registered_model_identity
    from evals.adapters.source_epochs import require_registered_epoch
    from evals.contracts import canonical_hash

    if os.getpid() == 1 or os.environ.get("TASK13_WORKER_NONCE"):
        raise PermissionError("historical planning reader is host-only")
    request = EPlanningRequest.model_validate(request.model_dump(mode="json"))
    if (
        request.source.source_kind != "additional-development-v1"
        or request.recovery_lineage is None
    ):
        return planning_analysis.verify_planning_analysis(request, root, budget_path)

    def pinned_ledger(path, original_request, ledger, lineage):
        if lineage != request.recovery_lineage:
            raise PermissionError("historical recovery lineage changed")
        epoch = require_registered_epoch(
            path,
            request.epoch_id,
            source_sha256=request.source_sha256,
            config_sha256=request.config_sha256,
            budget_identity=request.budget_identity,
            manifest_sha256=request.epoch_manifest_sha256,
            latest=False,
        )
        model = request.model_identity_binding
        require_registered_model_identity(
            path,
            model.model_epoch_id,
            epoch_id=request.epoch_id,
            source_sha256=request.source_sha256,
            config_sha256=request.config_sha256,
            purpose=request.purpose,
            manifest_sha256=model.model_identity_sha256,
            latest=False,
        )
        if (
            epoch["source_commit"] != request.source_commit
            or canonical_hash(epoch) != request.epoch_manifest_sha256
        ):
            raise PermissionError("historical execution source differs")
        return _historical_identity_ledger(path, original_request, ledger, lineage)

    native_import = builtins.__import__
    recovery = SimpleNamespace(
        **{
            **vars(planning_recovery),
            "verify_historical_identity_ledger": pinned_ledger,
        }
    )
    additional = SimpleNamespace()

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == "evals.adapters.planning_recovery" and fromlist:
            return recovery
        if level == 0 and name == "evals.adapters.additional_analysis" and fromlist:
            return additional
        return native_import(name, globals, locals, fromlist, level)

    local_builtins = {**vars(builtins), "__import__": local_import}

    def private_functions(module):
        namespace = {**vars(module), "__builtins__": local_builtins}
        for name, value in vars(module).items():
            if isinstance(value, FunctionType) and value.__module__ == module.__name__:
                clone = FunctionType(
                    value.__code__,
                    namespace,
                    name,
                    value.__defaults__,
                    value.__closure__,
                )
                clone.__kwdefaults__ = value.__kwdefaults__
                namespace[name] = clone
        return namespace

    additional.__dict__.update(private_functions(additional_analysis))
    planning = private_functions(planning_analysis)
    return planning["verify_planning_analysis"](request, root, budget_path)
