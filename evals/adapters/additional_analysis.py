"""One independently registered development analysis; never original-36 authority.

Registration is immutable metadata, not dispatch permission. All reads are local,
source Python is compared as data, and the existing budget is opened read-only.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from hashlib import sha256
from pathlib import Path
from typing import Literal, Self

from evidencesoc.agents.analysis_import import ImportedAnalysis
from evidencesoc.agents.models import AnalysisOutput
from evidencesoc.agents.nodes import validate_output_citations
from pydantic import Field, StrictBool, model_validator

from evals.adapters.analysis_import import (
    Artifact,
    _original_validator_equivalence,
    _regular,
    _replay_verified_analysis,
    validation_source_hashes,
)
from evals.adapters.analysis_package import (
    _inventory,
    _json,
    _parts,
    _read_ref,
    _resolve,
    _root,
)
from evals.adapters.budget_v2 import SupplementBudgetAccount
from evals.adapters.diagnosis import validate_diagnosis
from evals.adapters.e_planning_contracts import ModelIdentityBinding
from evals.adapters.epoch_development import EpochDevelopmentRequest
from evals.adapters.model_identity_runtime import verify_identity_ledger
from evals.adapters.remediation_worker import require_existing_budget
from evals.adapters.source_epochs import require_registered_epoch
from evals.contracts import SHA256, AdapterResult, Contract, canonical_hash

SOURCE_KIND = "additional-development-v1"


class AdditionalDevelopmentRegistration(Contract):
    schema_version: Literal["task13-additional-development-registration-v1"]
    registration_id: str = Field(
        pattern=r"^additional-development-[A-Za-z0-9_.:-]{1,192}$"
    )
    synthetic: StrictBool
    request: EpochDevelopmentRequest
    request_sha256: str = Field(pattern=SHA256)
    raw_case_id: str
    raw_agent_sha256: str = Field(pattern=SHA256)
    selection_policy: dict
    selection_policy_sha256: str = Field(pattern=SHA256)
    core_sha256: str = Field(pattern=SHA256)
    epoch_id: str
    epoch_manifest_sha256: str = Field(pattern=SHA256)
    model_identity_binding: ModelIdentityBinding

    @model_validator(mode="after")
    def consistent(self) -> Self:
        request = self.request
        if (
            canonical_hash(request) != self.request_sha256
            or self.raw_case_id != request.case_id
            or self.raw_agent_sha256 != request.agent_sha256
            or not self.selection_policy
            or canonical_hash(self.selection_policy) != self.selection_policy_sha256
            or self.core_sha256 != request.config_sha256
            or self.epoch_id != request.epoch_id
            or self.epoch_manifest_sha256 != request.epoch_manifest_sha256
            or self.model_identity_binding != request.model_identity_binding
        ):
            raise ValueError("additional development registration binding differs")
        return self


def validate_additional_development_registration(value) -> dict:
    """Return canonical metadata; never register an account or authorize a send."""
    registration = AdditionalDevelopmentRegistration.model_validate(value).model_dump(
        mode="json"
    )
    json.dumps(registration, allow_nan=False)
    return registration


class AdditionalDevelopmentStarted(Contract):
    schema_version: Literal["task13-additional-development-started-v1"]
    registration_id: str
    registration_sha256: str = Field(pattern=SHA256)
    request_sha256: str = Field(pattern=SHA256)
    slot_id: str


class AdditionalDevelopmentAttempt(Contract):
    schema_version: Literal["task13-additional-development-attempt-v1"]
    registration_id: str
    registration_sha256: str = Field(pattern=SHA256)
    request_sha256: str = Field(pattern=SHA256)
    slot_id: str
    status: Literal["completed"]
    result_sha256: str = Field(pattern=SHA256)


class AdditionalAnalysisAnchor(Contract):
    schema_version: Literal["task13-additional-analysis-anchor-v1"]
    source_kind: Literal["additional-development-v1"]
    source_row_id: str
    case_id: str
    order_index: Literal[0]
    registration_sha256: str = Field(pattern=SHA256)
    request_sha256: str = Field(pattern=SHA256)
    manifest_sha256: str = Field(pattern=SHA256)


class AdditionalAnalysisManifest(Contract):
    schema_version: Literal["task13-additional-analysis-package-v1"]
    source_kind: Literal["additional-development-v1"]
    order_index: Literal[0]
    source_row_id: str
    case_id: str
    registration_sha256: str = Field(pattern=SHA256)
    request_sha256: str = Field(pattern=SHA256)
    successful_physical_request_id: str
    validation_source_sha256: dict[str, str]
    package_verifier_sha256: str = Field(pattern=SHA256)
    artifacts: dict[str, Artifact]


def _pins(*values):
    if any(
        not isinstance(value, str) or not re.fullmatch(SHA256, value)
        for value in values
    ):
        raise ValueError("independent SHA256 pins are required")


def _validation_source_hashes():
    root = Path(__file__).resolve().parents[2]
    dependencies = {
        "portable_path_verifier": "evals/adapters/analysis_package.py",
        "epoch_development_request": "evals/adapters/epoch_development.py",
        "identity_ledger": "evals/adapters/model_identity_runtime.py",
        "source_epoch": "evals/adapters/source_epochs.py",
        "model_identity": "evals/adapters/model_identities.py",
        "budget_account": "evals/adapters/budget_v2.py",
        "request_contracts": "evals/adapters/remediation_contracts.py",
        "budget_identity": "evals/adapters/remediation_worker.py",
        "evaluation_contracts": "evals/contracts.py",
        "model_transport": "evals/adapters/model_client.py",
        "model_identity_contract": "evals/adapters/e_planning_contracts.py",
    }
    return validation_source_hashes() | {
        name: sha256((root / relative).read_bytes()).hexdigest()
        for name, relative in dependencies.items()
    }


def _validate_recovery_validation_sources(manifest, blobs):
    """Authenticate original bytes before the narrow, proved AST exceptions."""
    from evals.adapters.planning_recovery import (
        validate_identity_contract_equivalence,
        validate_registration_validator_delegation,
        validate_response_transport_equivalence,
        validate_timing_registry_equivalence,
    )

    current = _validation_source_hashes()
    old = manifest.validation_source_sha256
    contract = blobs.get("original_source:evals/adapters/e_planning_contracts.py")
    verifier = blobs.get("original_source:evals/adapters/additional_analysis.py")
    transport = blobs.get("original_source:evals/adapters/model_client.py")
    registry = blobs.get("original_source:evals/adapters/source_epochs.py")
    registry_changed = old.get("source_epoch") != current.get("source_epoch")
    registration_delegated = (
        registry_changed or old.get("model_identity") != current.get("model_identity")
    ) and validate_registration_validator_delegation(manifest, blobs)
    if (
        old.keys() != current.keys()
        or contract is None
        or verifier is None
        or transport is None
        or old.get("model_identity_contract") != sha256(contract).hexdigest()
        or old.get("model_transport") != sha256(transport).hexdigest()
        or manifest.package_verifier_sha256 != sha256(verifier).hexdigest()
        or (
            registry_changed
            and (
                registry is None
                or old.get("source_epoch") != sha256(registry).hexdigest()
            )
        )
        or any(
            old[name] != digest
            for name, digest in current.items()
            if name
            not in {"model_identity_contract", "model_transport", "source_epoch"}
            and not (name == "model_identity" and registration_delegated)
        )
    ):
        raise ValueError(
            "recovery analysis validator semantics or original metadata drift"
        )
    validate_identity_contract_equivalence(contract)
    validate_response_transport_equivalence(transport)
    if registry_changed and not registration_delegated:
        validate_timing_registry_equivalence(registry)


def _budget_location(budget_path, epoch, mounted_host_budget_path):
    if mounted_host_budget_path is not None:
        if (
            os.name != "posix"
            or os.getpid() != 1
            or not os.environ.get("TASK13_WORKER_NONCE")
            or str(budget_path) != "/app/budget/campaign.sqlite"
            or mounted_host_budget_path != epoch["budget_path"]
        ):
            raise ValueError(
                "additional worker requires inspected PID1 and original host budget mount"
            )
    elif str(budget_path.resolve()) != epoch["budget_path"]:
        raise ValueError("additional analysis must use its original budget path")


def _ledger(
    request, ledger, budget_path, mounted_host_budget_path=None, recovery_lineage=None
):
    """Bind every physical attempt to its independently derived analysis slot."""
    budget_path = Path(budget_path)
    require_existing_budget(budget_path, request.budget_identity)
    epoch = require_registered_epoch(
        budget_path,
        request.epoch_id,
        source_sha256=request.source_sha256,
        config_sha256=request.config_sha256,
        budget_identity=request.budget_identity,
        manifest_sha256=request.epoch_manifest_sha256,
        latest=recovery_lineage is None,
    )
    _budget_location(budget_path, epoch, mounted_host_budget_path)
    if recovery_lineage is None:
        verify_identity_ledger(budget_path, request, ledger)
    else:
        from evals.adapters.planning_recovery import verify_historical_identity_ledger

        verify_historical_identity_ledger(
            budget_path, request, ledger, recovery_lineage
        )
    account = SupplementBudgetAccount(budget_path, **request.budget_binding())
    hint = "v2-" + canonical_hash([request.slot_id, "analyze", 1])
    logical_key = canonical_hash(["analyze", "AnalysisOutput", hint])
    if (
        not 1 <= len(ledger) <= 3
        or len({call.get("logical_call_id") for call in ledger}) != 1
    ):
        raise ValueError(
            "additional analysis must have one logical call and at most three attempts"
        )
    with sqlite3.connect(budget_path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        for index, call in enumerate(ledger, 1):
            physical = account.physical_request_key(
                logical_key, index, explicit_call_id=hint
            )
            if (
                call.get("role") != "analyze"
                or call.get("slot_id") != request.slot_id
                or call.get("run_id") != request.run_id
                or call.get("stable_logical_call_id") != hint
                or call.get("physical_attempt") != index
                or call.get("physical_request_id") != physical
                or any(call.get(k) != v for k, v in request.budget_binding().items())
            ):
                raise ValueError(
                    "additional physical analysis slot or budget binding differs"
                )
            row = db.execute(
                "SELECT r.request_key,r.phase,r.upper,r.actual,r.settled,e.epoch_id,"
                "s.requested_at,s.finished_at,s.usage_json,s.provider_request_id,s.parse_status,"
                "s.error_type,s.usage_missing_reason,s.duration_ms "
                "FROM reservations r JOIN supplement_requests s ON s.reservation_id=r.id "
                "JOIN supplement_request_epochs e ON e.reservation_id=r.id WHERE r.id=?",
                (call.get("reservation_id"),),
            ).fetchone()
            if (
                row is None
                or row
                != (
                    physical,
                    "development",
                    call.get("reserved_cny"),
                    call.get("cost_cny"),
                    1,
                    request.epoch_id,
                    call.get("requested_at"),
                    call.get("finished_at"),
                    json.dumps(call.get("usage"), allow_nan=False, sort_keys=True),
                    call.get("request_id"),
                    call.get("parse_status"),
                    call.get("error_type"),
                    call.get("usage_missing_reason"),
                    call.get("duration_ms"),
                )
                or row[3] is None
                or row[12] is not None
            ):
                raise ValueError(
                    "additional physical accounting is unsettled, unknown or differs"
                )


def _conditions(request, result, blobs):
    detail = _json(blobs["condition"])
    lookup = [
        call
        for call in result.tool_ledger
        if call.get("tool_name") == "lookup_attack_technique"
    ]
    if (
        not isinstance(detail, dict)
        or detail.get("initial_query") != request.initial_query
        or detail.get("initial_query_sha256") != request.initial_query_sha256
        or detail.get("repeat") != request.repeat
        or detail.get("entry_prompt_sha256")
        != sha256(request.entry_prompt.encode()).hexdigest()
        or detail.get("retrieval_requests") != len(lookup)
        or len(lookup) != (0 if request.rag_mode == "disabled" else 1)
        or any(
            call.get("arguments")
            != {"query": request.initial_query, "limit": request.seed.knowledge_top_k}
            or call.get("success") is not True
            for call in lookup
        )
    ):
        raise ValueError("additional recorded development condition differs")
    for index, entry in enumerate(result.model_ledger, 1):
        payload = _json(blobs["payload_" + str(index)])
        if not isinstance(payload, dict):
            raise ValueError("additional actual HTTP payload must be an object")  # noqa: TRY004 - invalid artifact data.
        messages = payload.get("messages")
        if (
            payload.keys()
            != {
                "model",
                "messages",
                "thinking",
                "temperature",
                "max_tokens",
                "response_format",
                "stream",
            }
            or payload.get("model") != request.model.requested_model
            or payload.get("thinking") != {"type": "disabled"}
            or payload.get("temperature") != 0
            or payload.get("max_tokens") != request.model.max_tokens
            or payload.get("response_format") != {"type": "json_object"}
            or payload.get("stream") is not False
            or not isinstance(messages, list)
            or len(messages) != 3
            or any(not isinstance(message, dict) for message in messages)
            or messages[0] != {"role": "system", "content": request.entry_prompt}
            or messages[1].get("role") != "system"
            or messages[2].get("role") != "user"
            or any(
                entry.get(field) != getattr(request.model, field)
                for field in (
                    "requested_model",
                    "published_version",
                    "version_checked_at",
                    "thinking",
                    "temperature",
                    "max_tokens",
                )
            )
        ):
            raise ValueError(
                "additional actual model input differs from the frozen request"
            )
        raw = entry.get("raw_response")
        if isinstance(raw, dict) and (
            raw.get("usage") != entry.get("usage")
            or raw.get("id") != entry.get("request_id")
        ):
            raise ValueError("additional raw provider accounting differs")


def _first_valid_is_terminal(result, blobs):
    """A valid citation/diagnosis result terminates the single logical analysis."""
    registry = _json(blobs["registry"])
    for index, call in enumerate(result.model_ledger[:-1], 1):
        if call.get("parse_status") != "valid":
            continue
        try:
            raw = call["raw_response"]
            choice = raw["choices"][0]
            if choice.get("finish_reason") != "stop" or not raw.get("model"):
                continue
            output = AnalysisOutput.model_validate_json(choice["message"]["content"])
            if output.diagnosis is None:
                continue
            payload = _json(blobs["payload_" + str(index)])
            context = _json(payload["messages"][-1]["content"])
            validate_output_citations(output, context)
            validate_diagnosis(output.diagnosis, registry)
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        raise ValueError("additional analysis continued after a legally valid response")


def _replay(
    manifest,
    blobs,
    paths,
    registration_sha256,
    request_sha256,
    manifest_sha256,
    budget_path,
    mounted_host_budget_path=None,
    recovery_lineage=None,
):
    registration = validate_additional_development_registration(
        _json(blobs["registration"])
    )
    request_data = _json(blobs["request"])
    request = EpochDevelopmentRequest.model_validate(request_data)
    if recovery_lineage is not None:
        from evals.adapters.planning_recovery import validate_recovery_original

        validate_recovery_original(
            recovery_lineage, registration, manifest_sha256, request_sha256
        )
    if (
        canonical_hash(registration) != registration_sha256
        or canonical_hash(request_data) != request_sha256
        or registration["request_sha256"] != request_sha256
        or registration["request"] != request_data
        or manifest.registration_sha256 != registration_sha256
        or manifest.request_sha256 != request_sha256
        or manifest.source_row_id != request.slot_id
        or manifest.case_id != request.case_id
        or sha256(blobs["events"]).hexdigest() != request.agent_sha256
    ):
        raise ValueError("additional registration/request/input binding differs")
    start = AdditionalDevelopmentStarted.model_validate(_json(blobs["started"]))
    attempt = AdditionalDevelopmentAttempt.model_validate(_json(blobs["attempt"]))
    for record in (start, attempt):
        if (
            record.registration_id != registration["registration_id"]
            or record.registration_sha256 != registration_sha256
            or record.request_sha256 != request_sha256
            or record.slot_id != request.slot_id
        ):
            raise ValueError("additional started/terminal registration binding differs")
    if attempt.result_sha256 != sha256(blobs["result"]).hexdigest():
        raise ValueError("additional terminal result binding differs")
    result = AdapterResult.model_validate(_json(blobs["result"]))
    receipt = _json(blobs["source_receipt"])
    if not isinstance(receipt, dict):
        raise ValueError("additional source receipt must be an object")  # noqa: TRY004 - invalid artifact data.
    source_files = receipt.get("files")
    if not isinstance(source_files, dict):
        raise ValueError("additional source receipt file inventory required")  # noqa: TRY004 - invalid artifact data.
    required = {
        "registration",
        "request",
        "started",
        "attempt",
        "result",
        "stdout",
        "seed",
        "registry",
        "events",
        "knowledge",
        "condition",
        "source_receipt",
    }
    required |= {"original_source:" + name for name in source_files}
    required |= {
        prefix + str(index)
        for index in range(1, len(result.model_ledger) + 1)
        for prefix in ("payload_", "body_")
    }
    if blobs.keys() != required:
        raise ValueError("additional analysis artifact inventory differs")
    for name, raw in blobs.items():
        if not name.startswith("original_source:") and name != "events":
            _json(raw)
    for relative in source_files:
        _parts(relative)
    _ledger(
        request,
        result.model_ledger,
        budget_path,
        mounted_host_budget_path,
        recovery_lineage,
    )
    _conditions(request, result, blobs)
    original_receipt = _original_validator_equivalence(manifest, blobs, request, paths)
    anchor = AdditionalAnalysisAnchor(
        schema_version="task13-additional-analysis-anchor-v1",
        source_kind=SOURCE_KIND,
        source_row_id=request.slot_id,
        case_id=request.case_id,
        order_index=0,
        registration_sha256=registration_sha256,
        request_sha256=request_sha256,
        manifest_sha256=manifest_sha256,
    )
    values, provenance = _replay_verified_analysis(
        anchor, manifest, blobs, request, original_receipt, artifact_paths=paths
    )
    _first_valid_is_terminal(result, blobs)
    return values, {
        **provenance,
        "source_kind": SOURCE_KIND,
        "source_registration_sha256": registration_sha256,
        "source_package_manifest_sha256": manifest_sha256,
        "source_package_schema_version": manifest.schema_version,
        "source_package_validation_source_sha256": manifest.validation_source_sha256,
        "source_package_verifier_sha256": manifest.package_verifier_sha256,
        "source_registration_id": registration["registration_id"],
        "source_synthetic": registration["synthetic"],
        "source_core_sha256": request.config_sha256,
        "source_epoch_id": request.epoch_id,
        "source_epoch_manifest_sha256": request.epoch_manifest_sha256,
        "source_model_identity_binding": request.model_identity_binding.model_dump(
            mode="json"
        ),
        "original_manifest_sha256": manifest_sha256,
    }


def _verify(
    root,
    manifest_sha256,
    registration_sha256,
    request_sha256,
    budget_path,
    mounted_host_budget_path=None,
    recovery_lineage=None,
):
    root = _root(root)
    manifest_raw = _resolve(root, "manifest.json").read_bytes()
    if sha256(manifest_raw).hexdigest() != manifest_sha256:
        raise ValueError("additional package manifest hash differs")
    manifest = AdditionalAnalysisManifest.model_validate(_json(manifest_raw))
    if recovery_lineage is None and (
        manifest.validation_source_sha256 != _validation_source_hashes()
        or manifest.package_verifier_sha256
        != sha256(Path(__file__).read_bytes()).hexdigest()
    ):
        raise ValueError("additional replay validator source drift")
    refs = list(manifest.artifacts.values())
    _inventory(root, refs)
    paths, blobs = {}, {}
    for name, ref in manifest.artifacts.items():
        paths[name], blobs[name] = _read_ref(root, ref)
    if recovery_lineage is not None:
        # Preserve the original package byte-for-byte. Only the explicitly
        # changed admission contract, verifier metadata, pure respond guidance
        # and exact timing-v2 dispatch guard may differ. Analysis stays equivalent.
        _validate_recovery_validation_sources(manifest, blobs)
    if "events" not in paths or paths["events"].name != "events.jsonl":
        raise ValueError("additional events must retain the fixed seed filename")
    base = {
        "registration",
        "request",
        "started",
        "attempt",
        "result",
        "stdout",
        "seed",
        "registry",
        "knowledge",
        "condition",
        "source_receipt",
    }
    if not base <= blobs.keys():
        raise ValueError("additional package provenance incomplete")
    values, provenance = _replay(
        manifest,
        blobs,
        paths,
        registration_sha256,
        request_sha256,
        manifest_sha256,
        budget_path,
        mounted_host_budget_path,
        recovery_lineage,
    )
    if recovery_lineage is not None:
        from evals.adapters.planning_recovery import validate_recovery_provenance

        validate_recovery_provenance(recovery_lineage, provenance)
    # Re-read after replay: load_seed and source comparison must consume the same bytes.
    _inventory(root, refs)
    if _resolve(root, "manifest.json").read_bytes() != manifest_raw:
        raise ValueError("additional manifest changed during verification")
    for name, ref in manifest.artifacts.items():
        if _read_ref(root, ref)[1] != blobs[name]:
            raise ValueError("additional artifact changed during verification")
    return values, provenance


def verify_additional_analysis_package(
    root,
    expected_manifest_sha256,
    expected_registration_sha256,
    expected_request_sha256,
    budget_path,
    *,
    mounted_host_budget_path=None,
    recovery_lineage=None,
) -> ImportedAnalysis:
    """Pins and the original account path must come from a trusted controller.

    Only an inspected Linux PID1 worker may supply mounted_host_budget_path to
    bind /app/budget/campaign.sqlite to its independently verified host mount.
    The package and ambient environment never supply this authority argument.
    """
    _pins(
        expected_manifest_sha256, expected_registration_sha256, expected_request_sha256
    )
    args = (
        Path(root),
        expected_manifest_sha256,
        expected_registration_sha256,
        expected_request_sha256,
        Path(budget_path),
        mounted_host_budget_path,
        recovery_lineage,
    )
    values, provenance = _verify(*args)
    return ImportedAnalysis._from_verified_artifacts(
        values, provenance, lambda: _verify(*args)
    )


def export_additional_analysis_package(
    *,
    registration,
    expected_registration_sha256,
    expected_request_sha256,
    artifact_paths,
    artifact_sha256,
    budget_path,
    destination,
) -> dict:
    """Export pinned completed bytes into an exclusive fresh immutable inventory.

    artifact_paths and artifact_sha256 have identical keys: registration, request,
    started, attempt, result, stdout, seed, registry, events, knowledge, condition,
    source_receipt, original_source:<each receipt path>, payload_N and body_N.
    Registration/request pins are canonical JSON hashes; artifact pins are byte
    SHA256s. Result hashes are post-analysis metadata, never prefrozen core input.
    """
    _pins(expected_registration_sha256, expected_request_sha256)
    registration = validate_additional_development_registration(registration)
    if (
        canonical_hash(registration) != expected_registration_sha256
        or registration["request_sha256"] != expected_request_sha256
    ):
        raise ValueError("trusted additional registration/request pins differ")
    if artifact_paths.keys() != artifact_sha256.keys():
        raise ValueError("every export artifact needs an independent byte pin")
    destination = Path(destination)
    if not destination.is_absolute() or ".." in destination.parts:
        raise ValueError("an absolute fresh additional package destination is required")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("additional package destination already exists")
    destination = _root(destination.parent) / destination.name
    paths, blobs, pending, refs = {}, {}, {}, {}
    for name, raw_path in artifact_paths.items():
        _pins(artifact_sha256[name])
        path = Path(raw_path)
        paths[name] = _regular(path, _root(path.parent))
        if destination.is_relative_to(path.parent):
            raise ValueError(
                "additional export must not modify original artifact directories"
            )
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != artifact_sha256[name]:
            raise ValueError("additional export artifact byte pin differs")
        if name.startswith("original_source:"):
            relative = "source/" + name.removeprefix("original_source:")
        elif name == "source_receipt":
            relative = "source/source_receipt.json"
        elif name == "events":
            relative = "artifacts/agent/events.jsonl"
        elif re.fullmatch(r"[a-zA-Z0-9_-]+", name):
            relative = "artifacts/" + name + ".json"
        else:
            raise ValueError("unsupported additional artifact name")
        _parts(relative)
        if relative.casefold() in {p.casefold() for p in pending}:
            raise ValueError("duplicate additional export path")
        blobs[name] = pending[relative] = raw
        refs[name] = Artifact(
            path=relative, size=len(raw), sha256=artifact_sha256[name]
        )
    if "registration" not in blobs or _json(blobs["registration"]) != registration:
        raise ValueError("actual additional registration artifact differs")
    required = {
        "request",
        "started",
        "attempt",
        "result",
        "stdout",
        "seed",
        "registry",
        "events",
        "knowledge",
        "condition",
        "source_receipt",
    }
    if not required <= blobs.keys():
        raise ValueError("additional export provenance incomplete")
    result = AdapterResult.model_validate(_json(blobs["result"]))
    if not result.model_ledger:
        raise ValueError("additional analysis physical ledger required")
    manifest = AdditionalAnalysisManifest(
        schema_version="task13-additional-analysis-package-v1",
        source_kind=SOURCE_KIND,
        order_index=0,
        source_row_id=registration["request"]["slot_id"],
        case_id=registration["raw_case_id"],
        registration_sha256=expected_registration_sha256,
        request_sha256=expected_request_sha256,
        successful_physical_request_id=result.model_ledger[-1]["physical_request_id"],
        validation_source_sha256=_validation_source_hashes(),
        package_verifier_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        artifacts=refs,
    )
    raw_manifest = json.dumps(
        manifest.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2
    ).encode()
    digest = sha256(raw_manifest).hexdigest()
    _replay(
        manifest,
        blobs,
        paths,
        expected_registration_sha256,
        expected_request_sha256,
        digest,
        Path(budget_path),
    )
    for name, path in paths.items():
        if _regular(path, _root(path.parent)).read_bytes() != blobs[name]:
            raise ValueError("additional source changed during export")
    destination.mkdir(exist_ok=False)
    for relative, raw in pending.items():
        path = destination.joinpath(*_parts(relative))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    with (destination / "manifest.json").open("xb") as stream:
        stream.write(raw_manifest)
    imported = verify_additional_analysis_package(
        destination,
        digest,
        expected_registration_sha256,
        expected_request_sha256,
        budget_path,
    )
    return {
        "schema_version": "task13-additional-analysis-export-v1",
        "manifest_sha256": digest,
        "source_identity": imported.source_identity,
        "provenance": imported.provenance,
        "file_count": len(pending) + 1,
        "total_bytes": sum(map(len, pending.values())) + len(raw_manifest),
    }
