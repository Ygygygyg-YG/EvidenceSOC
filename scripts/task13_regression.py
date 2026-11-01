"""Pinned, existing-only formal regression host; importing dispatches nothing.

The existing fixed-matrix library owns requests, accounting and replay refusal.
This entrypoint only verifies independently pinned external admission evidence.
It never creates consent, source epochs, E observations or replacement plans.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from evals.adapters.retained_workflow import resource_fields
from evals.contracts import CallBudget, ModelConfig, SeedPolicy, canonical_hash
from evals.e_timing import _validate_replicate_source, build_e_timing_registration
from evals.remediation import _summary, execute_bundle, prepare_bundle, validate_bundle
from evals.runners.manifest import agent_input
from evals.verification_v2 import observed_six_branch_max
from scripts.task13_e_trial import _bytes, _decode, _path, _read_pin, _write

SCOPE = "Task13supplement176regression-afterE"
INPUTS = {
    "registration",
    "bundle",
    "core_config",
    "runtime_options",
    "source_receipt",
    "final_freeze",
    "e_timing_receipt",
    "rag_receipt",
    "engineering_receipt",
    "model_price_receipt",
    "scope_packet",
    "scope_decision",
}
FROZEN_INPUTS = INPUTS - {"final_freeze", "scope_packet", "scope_decision"}
HOST_ENTRYPOINT = "scripts/task13_regression.py"
HOST_ENTRIES = {
    HOST_ENTRYPOINT,
    "scripts/task13_e_trial.py",
    "scripts/task13_worker_runtime.py",
    "evals/contracts.py",
    "evals/remediation.py",
    "evals/e_planning.py",
    "evals/e_timing.py",
    "evals/verification_v2.py",
    "evals/runners/manifest.py",
    "evals/adapters/epoch_remediation.py",
    "evals/adapters/remediation_worker.py",
    "evals/adapters/remediation_contracts.py",
    "evals/adapters/budget_v2.py",
    "evals/adapters/source_epochs.py",
}
RAG_ENTRIES = {
    "evals/rag_gates.py",
    "evals/adapters/model_client.py",
    "evals/adapters/environment.py",
    "services/backend/src/evidencesoc/rag/retriever.py",
    "services/backend/src/evidencesoc/rag/embeddings.py",
    "services/backend/src/evidencesoc/mcp_server/main.py",
    "services/backend/src/evidencesoc/mcp_server/client.py",
    "services/backend/src/evidencesoc/agents/capabilities.py",
}


def _time(value):
    when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if when.tzinfo is None or when.utcoffset() is None:
        raise ValueError("a timezone-aware actual timestamp is required")
    return when


def _zero(value):
    return type(value) is int and value == 0


@dataclass(frozen=True)
class FreeDependencies:
    """Explicit free fixtures only; a real manifest rejects all injections."""

    worker: Callable
    runtime_validator: Callable
    now: Callable


class RegressionHost:
    """Independent raw pins are caller admission inputs, never self-reported hashes."""

    def __init__(self, manifest_path, manifest_sha256, *, free_dependencies=None):
        self._pin = {"path": str(manifest_path), "sha256": manifest_sha256}
        self._raw = _read_pin(self._pin)
        self._manifest = _decode(self._raw)
        m = self._manifest
        if (
            m.get("schema_version") != "task13-regression-host-v1"
            or type(m.get("synthetic")) is not bool
            or set(m.get("inputs", {})) != INPUTS
            or set(m.get("case_roots", {})) != {"ait", "dedale"}
            or type(m.get("max_evidence_age_seconds")) is not int
            or not 1 <= m["max_evidence_age_seconds"] <= 86400
        ):
            raise ValueError("complete pinned regression host manifest required")
        if free_dependencies is not None and not m["synthetic"]:
            raise PermissionError(
                "only an explicitly synthetic host accepts free dependencies"
            )
        if m["synthetic"] and free_dependencies is None:
            raise PermissionError(
                "synthetic execution requires explicit free dependencies"
            )
        self._free = free_dependencies
        self._now = (
            free_dependencies.now if free_dependencies else lambda: datetime.now(UTC)
        )
        self._root = _path(m["output_dir"])
        _time(m["deadline_at"])
        for path in m["case_roots"].values():
            _path(path)

    def _load(self):
        if _read_pin(self._pin) != self._raw:
            raise PermissionError("frozen regression host manifest changed")
        # Read every future external input before any database or runtime access.
        return {
            key: _decode(_read_pin(pin))
            for key, pin in self._manifest["inputs"].items()
        }

    def _fresh(self, value):
        age = (self._now() - _time(value)).total_seconds()
        if not 0 <= age <= self._manifest["max_evidence_age_seconds"]:
            raise PermissionError(
                "external admission evidence is stale or future dated"
            )

    def _scope(self, data):
        m, packet, record = self._manifest, data["scope_packet"], data["scope_decision"]
        refs = m["inputs"]
        if self._now() >= _time(m["deadline_at"]):
            raise PermissionError("registered regression deadline has passed")
        if (
            packet.get("schema_version") != "task13-regression-scope-v1"
            or packet.get("scope") != SCOPE
            or packet.get("campaign_id") != data["bundle"]["campaign_id"]
            or packet.get("final_freeze_sha256") != refs["final_freeze"]["sha256"]
            or packet.get("bundle_sha256") != data["bundle"]["bundle_sha256"]
            or type(packet.get("registered_rows")) is not int
            or packet["registered_rows"] != 176
            or packet.get("deadline_at") != m["deadline_at"]
            or record.get("schema_version")
            != "task13-regression-user-scope-decision-v1"
            or record.get("role") != "user"
            or record.get("scope") != SCOPE
            or record.get("decision") != "approved"
            or record.get("scope_packet_sha256") != refs["scope_packet"]["sha256"]
            or any(
                not isinstance(record.get(key), str) or not record[key].strip()
                for key in ("record_id", "text")
            )
            or _time(record["decided_at"]) > self._now()
        ):
            raise PermissionError(
                "separate actual user regression scope decision required"
            )

    def _fixed(self, data):
        b, core, freeze, source = (
            data[key]
            for key in ("bundle", "core_config", "final_freeze", "source_receipt")
        )
        validate_bundle(b)
        if (
            b["schema_version"] != "task13-remediation-bundle-v3"
            or b["purpose"] != "regression"
        ):
            raise PermissionError(
                "only the registered epoch-bound 176-row regression is allowed"
            )
        expected = prepare_bundle(
            data["registration"],
            source_commit=b["source_commit"],
            source_sha256=b["source_sha256"],
            config=core,
            epoch_binding={
                key: b[key]
                for key in (
                    "epoch_id",
                    "epoch_manifest_sha256",
                    "model_identity_binding",
                )
                if key in b
            },
        )
        if (
            b != expected
            or core != b["config"]
            or core.get("model") != ModelConfig().model_dump(mode="json")
            or core.get("seed") != SeedPolicy().model_dump(mode="json")
            or core.get("budget") != CallBudget().model_dump(mode="json")
            or "timing_receipt_sha256" in core
            or canonical_hash(source) != b["source_sha256"]
            or source.get("source_commit") != b["source_commit"]
            or freeze.get("schema_version") != "task13-regression-final-freeze-v1"
            or freeze.get("status") != "frozen"
            or freeze.get("synthetic") is not self._manifest["synthetic"]
            or freeze.get("campaign_id") != b["campaign_id"]
            or any(
                freeze.get(key) != b[key]
                for key in (
                    "source_commit",
                    "source_sha256",
                    "config_sha256",
                    "epoch_id",
                    "epoch_manifest_sha256",
                )
            )
            or freeze.get("bindings")
            != {key: self._manifest["inputs"][key]["sha256"] for key in FROZEN_INPUTS}
        ):
            raise PermissionError(
                "final freeze, exact registration or shared E core configuration differs"
            )
        files = freeze.get("source_files")
        actual_host = Path(__file__).resolve()
        actual_hash = sha256(actual_host.read_bytes()).hexdigest()
        if (
            not isinstance(files, dict)
            or not files
            or files.get(str(actual_host)) != actual_hash
            or (
                HOST_ENTRYPOINT in source.get("files", {})
                and source["files"][HOST_ENTRYPOINT] != actual_hash
            )
        ):
            raise PermissionError("actual frozen regression host entrypoint is missing")
        for path, digest in files.items():
            if sha256(_path(path, file=True).read_bytes()).hexdigest() != digest:
                raise PermissionError("frozen E source file changed")
        if not self._manifest["synthetic"]:
            root = actual_host.parents[1]
            required_host_entries = HOST_ENTRIES | (
                {
                    "evals/adapters/model_identity_runtime.py",
                    "evals/adapters/model_identities.py",
                    "evals/adapters/model_client.py",
                    "evals/adapters/e_planning_contracts.py",
                }
                if b.get("model_identity_binding") is not None
                else set()
            )
            for relative in required_host_entries:
                digest = sha256(
                    _path(root / relative, file=True).read_bytes()
                ).hexdigest()
                if files.get(str(root / relative)) != digest or (
                    relative in source["files"] and source["files"][relative] != digest
                ):
                    raise PermissionError(
                        "critical actual host helper source is outside the freeze"
                    )

    def _timing(self, data):
        receipt, freeze, core, bundle = (
            data[key]
            for key in ("e_timing_receipt", "final_freeze", "core_config", "bundle")
        )
        if receipt.get("synthetic") is not self._manifest["synthetic"]:
            raise PermissionError("synthetic E timing cannot admit a real regression")
        if receipt.get("schema_version") in {
            "task13-e-timing-pool-receipt-v1",
            "task13-e-timing-pool-receipt-v2",
        }:
            from evals.timing_pool import validate_pool_receipt

            if not self._manifest["synthetic"]:
                validator = Path(__file__).resolve().parents[1] / "evals/timing_pool.py"
                if (
                    freeze["source_files"].get(str(validator))
                    != sha256(_path(validator, file=True).read_bytes()).hexdigest()
                ):
                    raise PermissionError(
                        "actual timing pool validator is outside freeze"
                    )
            identity = {
                "campaign_id": bundle["campaign_id"],
                "plan_sha256": core["f8_plan_sha256"],
                "source_commit": bundle["source_commit"],
                "source_sha256": canonical_hash(freeze["source_files"]),
                "config_sha256": bundle["config_sha256"],
            }
            expected_binding = {
                key: bundle.get(key)
                for key in (
                    "source_sha256",
                    "epoch_id",
                    "epoch_manifest_sha256",
                    "model_identity_binding",
                )
            }
            if receipt.get("formal_binding") != expected_binding:
                raise PermissionError("timing pool formal epoch/model binding differs")
            validate_pool_receipt(receipt, identity)
            return
        planning = receipt["planning_registration"]
        expected = build_e_timing_registration(
            planning,
            source_files=freeze["source_files"],
            f8_plan_sha256=core["f8_plan_sha256"],
            planning_dispatch_registration_receipt=receipt[
                "planning_dispatch_registration_receipt"
            ],
        )
        if (
            planning["synthetic"] is not self._manifest["synthetic"]
            or planning["core_config"] != core
            or receipt.get("registration_sha256") != canonical_hash(expected)
            or receipt.get("planning_registration_sha256") != canonical_hash(planning)
            or receipt.get("budget_source_receipt_sha256") != bundle["source_sha256"]
            or any(
                planning["epoch_binding"].get(key) != bundle[key]
                for key in (
                    "source_commit",
                    "source_sha256",
                    "epoch_id",
                    "epoch_manifest_sha256",
                )
            )
            or planning["epoch_binding"]["budget_identity"] != core["budget_identity"]
            or planning["epoch_binding"].get("model_identity_binding")
            != bundle.get("model_identity_binding")
            or len(receipt.get("trials", [])) != 3
            or [trial["trial_id"] for trial in receipt["trials"]]
            != [trial["trial_id"] for trial in expected["trials"]]
        ):
            raise PermissionError(
                "actual E timing registration or epoch/config binding differs"
            )
        for actual, registered in zip(
            receipt["trials"], expected["trials"], strict=True
        ):
            source = self._timing_source(data, expected, registered, actual)
            if len(actual["branches"]) != len(registered["branches"]):
                raise PermissionError("E timing branches differ from registered slots")
            for branch, fixed in zip(
                actual["branches"], registered["branches"], strict=True
            ):
                request = branch["request"]
                if any(
                    request.get(key) != fixed[key]
                    for key in ("request_id", "namespace", "verification_enabled")
                ) or (
                    request.get("case_id") != registered["case_id"]
                    or request.get("agent_sha256") != registered["agent_sha256"]
                    or request.get("approved_state") != source["state"]
                    or request.get("source_resources")
                    != resource_fields(source["resources"])
                    or request.get("approval_receipt_sha256")
                    != actual["binding"]["approval_receipt_sha256"]
                ):
                    raise PermissionError(
                        "actual E branch source or registered request binding differs"
                    )
        identity = {
            "campaign_id": bundle["campaign_id"],
            "plan_sha256": core["f8_plan_sha256"],
            "source_commit": bundle["source_commit"],
            "source_sha256": canonical_hash(freeze["source_files"]),
            "config_sha256": bundle["config_sha256"],
        }
        observed = observed_six_branch_max(receipt, identity)
        if receipt.get("observed_max_seconds") != observed:
            raise PermissionError(
                "E timing maximum differs from actual complete observations"
            )

    def _timing_source(self, data, registration, registered, trial):
        """Read original E blobs; never synthesize missing retained source proof."""
        receipt = data["e_timing_receipt"]
        pin = self._manifest["inputs"]["e_timing_receipt"]
        path = _path(pin["path"], file=True)
        if (
            path.parent.name != "timings"
            or path.name != canonical_hash(receipt) + ".json"
            or _decode(_read_pin(pin)) != receipt
        ):
            raise PermissionError(
                "original E timing source journal binding is required"
            )
        binding = trial["binding"]
        digest = binding["source_sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise PermissionError("original E source binding digest is invalid")
        try:
            source_path = _path(
                path.parent.parent / "sources" / (digest + ".json"), file=True
            )
            source = _decode(source_path.read_bytes())
        except (OSError, ValueError) as error:
            raise PermissionError(
                "original E source blob is unavailable or invalid"
            ) from error
        if not isinstance(source, dict) or canonical_hash(source) != digest:
            raise PermissionError("original E source blob hash differs")
        _validate_replicate_source(registration, registered, source)
        expected_source = {
            key: receipt[key]
            for key in (
                "campaign_id",
                "source_commit",
                "source_sha256",
                "config_sha256",
            )
        }
        expected_source.update(
            source_row_id=registered["source_row_id"],
            case_id=registered["case_id"],
            dataset=registered["dataset"],
            analysis_manifest_sha256=registered["manifest_sha256"],
            budget_source_receipt_sha256=registration["budget_source_receipt_sha256"],
        )
        state = source["state"]
        expected_binding = {
            "planning_slot_id": registered["planning_slot_id"],
            "planning_request_sha256": registered["planning_request_sha256"],
            "planning_registration_sha256": registration[
                "planning_registration_sha256"
            ],
            "resources_sha256": source["resources_sha256"],
            "retained_state_sha256": source["retained_state_sha256"],
            "source_incident_id": state["incident_id"],
            "source_run_id": registered["run_id"],
            "approval_id": state["approval"]["approval_id"],
            "approved_plan_sha256": state["approved_plan_sha256"],
            "diagnostic_snapshot_sha256": state["diagnostic_snapshot_sha256"],
        }
        if (
            any(source.get(key) != value for key, value in expected_source.items())
            or any(binding.get(key) != value for key, value in expected_binding.items())
            or not isinstance(binding.get("expires_at"), str)
            or _time(binding["expires_at"])
            != _time(state["response_plan"]["expires_at"])
        ):
            raise PermissionError("actual E source and retained trial binding differ")
        return source

    def _source_binding(self, binding, data):
        if binding.get("git_head") != data["bundle"]["source_commit"]:
            raise PermissionError("gate source commit differs")
        files = binding.get("files_sha256")
        root = Path(__file__).resolve().parents[1]
        if (
            not isinstance(files, dict)
            or not files
            or any(
                data["final_freeze"]["source_files"].get(str(root / path)) != digest
                or (
                    path in data["source_receipt"]["files"]
                    and data["source_receipt"]["files"][path] != digest
                )
                for path, digest in files.items()
            )
        ):
            raise PermissionError("gate source file hashes differ")
        if not self._manifest["synthetic"] and not RAG_ENTRIES <= files.keys():
            raise PermissionError(
                "actual R1/R2 evaluated source coverage is incomplete"
            )

    def _rag(self, data):
        index = data["rag_receipt"]
        if (
            index.get("schema_version") != "task13-rag-gate-index-v2"
            or index.get("status") != "passed"
            or not _zero(index.get("paid_model_requests"))
        ):
            raise PermissionError("fresh zero-paid actual R1/R2 gate index required")
        self._fresh(index["created_at"])
        self._source_binding(index["source"], data)
        for filename, label in (("r1-channel.json", "R1"), ("r2-isolation.json", "R2")):
            gate = _decode(_read_pin(index["gates"][filename]))
            if (
                gate.get("status") != "passed"
                or gate.get("gate") != label
                or not _zero(gate.get("paid_model_requests"))
                or gate.get("cleanup_completed") is not True
                or not _zero(gate.get("nonlocal_connect_attempts"))
                or gate.get("model_config") != data["core_config"]["model"]
                or gate.get("source") != index["source"]
            ):
                raise PermissionError("actual R1/R2 primary receipt failed or differs")
            self._fresh(gate["created_at"])

    def _test_report(self, specification, data):
        report = _decode(_read_pin(specification["evidence"]))
        critical = specification.get("critical_tests")
        allowed_skips = specification.get("noncritical_skips", [])
        records = report.get("tests", [])
        if (
            not _zero(report.get("exit_code"))
            or not _zero(report.get("paid_calls", report.get("paid_model_requests")))
            or (
                report.get("source_unchanged") is not True
                and not report.get("source_files")
            )
            or not isinstance(critical, list)
            or not critical
            or len(set(critical)) != len(critical)
            or not isinstance(allowed_skips, list)
            or set(critical) & set(allowed_skips)
            or not isinstance(records, list)
            or not records
            or any(row.get("outcome") not in {"passed", "skipped"} for row in records)
            or any(
                not any(
                    row.get("nodeid") == node
                    and row.get("when") == "call"
                    and row.get("outcome") == "passed"
                    for row in records
                )
                for node in critical
            )
            or {row["nodeid"] for row in records if row["outcome"] == "skipped"}
            != set(allowed_skips)
        ):
            raise PermissionError(
                "actual test outcomes or critical zero-skip evidence failed"
            )
        if "source_files" in report:
            files = data["source_receipt"]["files"]
            for path, digest in report["source_files"].items():
                target = str(_path(path)) if Path(path).is_absolute() else None
                if (
                    target
                    and data["final_freeze"]["source_files"].get(target) != digest
                ) or (not target and files.get(path) != digest):
                    raise PermissionError("actual test source hashes differ")

    def _engineering(self, data):
        receipt = data["engineering_receipt"]
        if (
            receipt.get("schema_version") != "task13-regression-engineering-v1"
            or receipt.get("status") != "passed"
            or not _zero(receipt.get("critical_skips"))
            or receipt.get("source_commit") != data["bundle"]["source_commit"]
            or receipt.get("source_files_sha256")
            != canonical_hash(data["final_freeze"]["source_files"])
            or not {"backend", "evals"} <= receipt.get("tests", {}).keys()
        ):
            raise PermissionError(
                "tested frozen sources and zero critical skips required"
            )
        for specification in receipt["tests"].values():
            self._test_report(specification, data)
        expected_inputs = {}
        for dataset, count in (("ait", 22), ("dedale", 66)):
            refs = receipt["task12"]
            admission = _decode(_read_pin(refs[dataset + "_receipt"]))
            selection = _decode(_read_pin(refs[dataset + "_selection"]))
            digest = (
                admission.get("selection_sha256")
                if dataset == "ait"
                else admission.get("selection", {}).get("sha256")
            )
            if (
                digest != refs[dataset + "_selection"]["sha256"]
                or selection.get("split") != "test"
                or len(selection.get("cases", [])) != count
            ):
                raise PermissionError("actual Task12 accepted selection differs")
            if dataset == "dedale" and (
                admission.get("task12_accepted") is not True
                or admission.get("status") != "accepted_and_frozen"
            ):
                raise PermissionError(
                    "Task12 DEDALE admission is not accepted and frozen"
                )
            trusted = {
                row["case_id"]: row["artifacts"]
                for row in (
                    admission["test_cases"] if dataset == "ait" else selection["cases"]
                )
            }
            if set(trusted) != {row["case_id"] for row in selection["cases"]}:
                raise PermissionError("Task12 admitted case set differs")
            for case_id, artifacts in trusted.items():
                if not case_id.startswith(dataset + "-"):
                    raise PermissionError("Task12 case belongs to another dataset")
                expected_inputs[case_id] = {
                    name: artifacts["agent/" + name]["current_sha256"]
                    if dataset == "ait"
                    else artifacts["agent/" + name]
                    for name in ("manifest.json", "events.jsonl")
                }
        rows = data["bundle"]["rows"]
        if {row["case_id"] for row in rows} != set(expected_inputs):
            raise PermissionError(
                "registered cases differ from actual accepted 22 AIT / 66 DEDALE"
            )
        for row in rows:
            _, actual = agent_input(
                _path(self._manifest["case_roots"][row["case_id"].split("-", 1)[0]]),
                row["case_id"],
            )
            if (
                actual != expected_inputs[row["case_id"]]
                or actual != row["input_hashes"]
            ):
                raise PermissionError(
                    "actual accepted agent bytes differ from registration"
                )

    def _price(self, data):
        price, core = data["model_price_receipt"], data["core_config"]
        checks = price.get("checks")
        if (
            price.get("schema_version") != "task13-regression-model-price-v1"
            or price.get("status") != "verified"
            or price.get("model") != core["model"]
            or price.get("observed_model_binding")
            != (
                {
                    key: core["model_identity"][key]
                    for key in ("response_model", "fingerprint")
                }
                if core.get("model_identity") is not None
                else core.get("original_observed_model_binding")
            )
            or not isinstance(checks, dict)
            or len(checks) < 8
            or any(value is not True for value in checks.values())
            or _time(price["valid_until"]) <= self._now()
            or not isinstance(price.get("evidence"), list)
            or not price["evidence"]
        ):
            raise PermissionError(
                "fresh external model/version/price comparison required"
            )
        self._fresh(price["checked_at"])
        for ref in price["evidence"]:
            if not _read_pin(ref):
                raise PermissionError("public provider evidence is empty")

    def _runtime(self, data):
        options, bundle, core = (
            data[key] for key in ("runtime_options", "bundle", "core_config")
        )
        budget = _path(Path(options["budget_dir"]) / "campaign.sqlite")
        if (
            options.get("phase") != "formal"
            or options.get("source_commit") != bundle["source_commit"]
            or options.get("budget_identity") != core["budget_identity"]
            or budget != _path(core["active_budget_path"])
            or options.get("model_identity_binding")
            != bundle.get("model_identity_binding")
        ):
            raise PermissionError(
                "formal runtime must retain the original budget/source identity"
            )
        if self._free:
            self._free.runtime_validator(deepcopy(data), deepcopy(self._manifest))
            return
        from evals.adapters.epoch_remediation import (
            EpochRemediationRequest,
            validate_epoch_runtime,
        )
        from evals.adapters.remediation_worker import (
            _budget_snapshot,
            require_existing_budget,
        )
        from scripts.task13_worker_runtime import (
            _validate_source,
            dependency_tree_hash,
            e_planning_runtime_binding,
        )

        source = _path(options["source_dir"])
        _validate_source(source, bundle["source_commit"])
        require_existing_budget(budget, core["budget_identity"])
        request = EpochRemediationRequest.model_validate(bundle["rows"][0]["request"])
        if request.model_identity_binding is not None:
            from evals.adapters.model_identity_runtime import require_dispatch_identity

            manifest = require_dispatch_identity(budget, request)
            if manifest["expected_model"] != core.get("model_identity") or core.get(
                "original_observed_model_binding"
            ) != {
                key: manifest["inherited_global"][key]
                for key in ("response_model", "fingerprint")
            }:
                raise PermissionError("adopted regression model descriptor differs")
        else:
            account, _ = _budget_snapshot(
                budget, core["budget_identity"]["baseline_max_rowid"]
            )
            observed = core.get("original_observed_model_binding")
            if (
                not isinstance(observed, dict)
                or set(observed) != {"response_model", "fingerprint"}
                or any(
                    not isinstance(value, str) or not value.strip()
                    for value in observed.values()
                )
                or account.get("halt")
                or any(account.get(key) != value for key, value in observed.items())
            ):
                raise PermissionError(
                    "existing model account halted or original identity differs"
                )
        dependencies = _path(options["dependencies_dir"])
        dependency_receipt = _decode(
            _path(dependencies / "task13_dependencies.json", file=True).read_bytes()
        )
        if (
            dependency_tree_hash(dependencies) != dependency_receipt["tree_sha256"]
            or dependency_tree_hash(_path(options["knowledge_dir"]))
            != options["knowledge_sha256"]
        ):
            raise PermissionError("actual locked dependency or knowledge tree differs")
        request = EpochRemediationRequest.model_validate(bundle["rows"][0]["request"])
        agent, _ = agent_input(
            _path(self._manifest["case_roots"][request.case_id.split("-", 1)[0]]),
            request.case_id,
        )
        epoch = validate_epoch_runtime(
            request,
            agent,
            source,
            budget,
            e_planning_runtime_binding(options, dependency_receipt),
            bundle["source_commit"],
        )
        if any(
            epoch["entrypoints"].get(relative)
            != data["final_freeze"]["source_files"].get(
                str(Path(__file__).resolve().parents[1] / relative)
            )
            or relative not in epoch["entrypoints"]
            for relative in HOST_ENTRIES
        ):
            raise PermissionError(
                "actual regression host/helper is outside the registered source epoch"
            )
        if any(
            not any(
                path.is_relative_to(_path(root))
                for root in epoch["controller_state_roots"]
            )
            for path in (self._root, _path(options["output_dir"]))
        ):
            raise PermissionError(
                "actual formal output paths are outside registered controller roots"
            )

    def _preflight(self):
        data = self._load()
        if (self._root / "model-runtime-halt.json").exists():
            raise PermissionError("formal model runtime halted; no automatic recovery")
        self._scope(data)
        self._fixed(data)
        self._timing(data)
        self._rag(data)
        self._engineering(data)
        self._price(data)
        self._prior_results(data)
        self._runtime(data)
        return data

    def readiness(self):
        """SELECT/read only. Missing future approvals never initialize runtime or DB."""
        try:
            data = self._preflight()
        except (
            OSError,
            ValueError,
            PermissionError,
            RuntimeError,
            KeyError,
            TypeError,
        ) as error:
            return {"status": "PENDING", "reason": type(error).__name__, "scope": SCOPE}
        return {
            "status": "verified",
            "scope": SCOPE,
            "synthetic": self._manifest["synthetic"],
            "bundle_sha256": data["bundle"]["bundle_sha256"],
        }

    def status(self):
        """Read existing execution receipts without initialization, recovery or dispatch."""
        try:
            data = self._load()
            validate_bundle(data["bundle"])
            return _summary(
                data["bundle"],
                self._root,
                "offline_contract_test" if self._free else "real_execution",
            )
        except (OSError, ValueError, PermissionError, KeyError, TypeError) as error:
            return {"status": "PENDING", "reason": type(error).__name__, "scope": SCOPE}

    def _admit(self, identity):
        data = self._preflight()
        expected = {
            key: data["bundle"][key]
            for key in (
                "bundle_sha256",
                "campaign_id",
                "purpose",
                "source_commit",
                "source_sha256",
                "config_sha256",
                "budget_identity_sha256",
                "epoch_id",
                "epoch_manifest_sha256",
            )
        }
        if identity != expected:
            raise PermissionError(
                "actual execution identity differs from frozen regression"
            )
        return {
            "schema_version": "task13-v3-execution-gate-v1",
            "status": "verified",
            "scope": "offline_contract_test" if self._free else "real_execution",
            **identity,
        }

    @contextmanager
    def _lock(self):
        self._root.mkdir(parents=True, exist_ok=True)
        lock = self._root / "host-writer.lock"
        _write(lock, self._raw)
        try:
            binding = self._root / "host-binding.json"
            if not binding.exists():
                _write(binding, self._raw)
            if binding.read_bytes() != self._raw:
                raise PermissionError("formal output belongs to another frozen host")
            yield
        finally:
            lock.unlink()

    def _received_model_guard(self, data, row, *, persist_halt=True):
        if self._free:
            return
        result_path = self._root / row["slot_id"] / "result.json"
        value = _decode(_path(result_path, file=True).read_bytes())
        core = data["core_config"]
        ledger = value.get("model_ledger", [])
        invalid = not isinstance(ledger, list)
        observed = core["original_observed_model_binding"]
        if data["bundle"].get("model_identity_binding") is not None:
            from evals.adapters.epoch_remediation import EpochRemediationRequest
            from evals.adapters.model_identity_runtime import verify_identity_ledger

            request = EpochRemediationRequest.model_validate(row["request"])
            descriptor = core["model_identity"]
            observed = {
                key: descriptor[key] for key in ("response_model", "fingerprint")
            }
            try:
                manifest = (
                    verify_identity_ledger(
                        _path(core["active_budget_path"], file=True), request, ledger
                    )
                    if ledger
                    else None
                )
                if manifest is not None and manifest["expected_model"] != descriptor:
                    invalid = True
            except (ValueError, RuntimeError):
                invalid = True
        for call in ledger if isinstance(ledger, list) else []:
            if not isinstance(call, dict):
                invalid = True
                continue
            raw = call.get("raw_response")
            if call.get("http_status") != 200 and not isinstance(raw, dict):
                continue
            if (
                call.get("response_model") != observed["response_model"]
                or call.get("system_fingerprint") != observed["fingerprint"]
                or not isinstance(raw, dict)
                or raw.get("model") != observed["response_model"]
                or raw.get("system_fingerprint") != observed["fingerprint"]
            ):
                invalid = True
        if invalid:
            if persist_halt:
                _write(
                    self._root / "model-runtime-halt.json",
                    _bytes(
                        {
                            "schema_version": "task13-regression-model-runtime-halt-v1",
                            "reason": "received_model_identity_differs_or_missing",
                            "expected": observed,
                            "result": {
                                "path": str(result_path),
                                "sha256": sha256(result_path.read_bytes()).hexdigest(),
                            },
                        }
                    ),
                )
            raise PermissionError(
                "actual paid result preserved; received model identity differs"
            )

    def _budget_stopped(self, row):
        value = _decode(
            _path(self._root / row["slot_id"] / "result.json", file=True).read_bytes()
        )
        return any(
            error.get("type") == "BudgetLimit"
            or error.get("error_type") == "BudgetLimit"
            for error in value.get("errors", [])
        )

    def _prior_results(self, data):
        # A crash between the library's durable result and this wrapper's return
        # cannot make a received identity mismatch or budget stop disappear.
        for row in data["bundle"]["rows"]:
            if (self._root / row["slot_id"] / "result.json").exists():
                self._received_model_guard(data, row, persist_halt=False)
                if self._budget_stopped(row):
                    raise PermissionError(
                        "prior original request stopped at the budget limit"
                    )

    def execute(self, *, row_limit=None):
        """Explicit dispatch only. The existing library retains unknown/no-replay rules."""
        if row_limit is not None and (type(row_limit) is not int or row_limit < 1):
            raise ValueError("positive integer row limit required")
        data = self._preflight()
        scope = "offline_contract_test" if self._free else "real_execution"
        with self._lock():
            summary = _summary(data["bundle"], self._root, scope)
            for _ in range(row_limit or 176):
                if summary["counts"]["unknown"]:
                    break
                row = next(
                    (
                        row
                        for row in data["bundle"]["rows"]
                        if not (self._root / row["slot_id"] / "started.json").exists()
                    ),
                    None,
                )
                if row is None:
                    break
                summary = execute_bundle(
                    data["bundle"],
                    self._root,
                    case_roots=self._manifest["case_roots"],
                    admitter=self._admit,
                    runtime_options=data["runtime_options"],
                    offline_worker=self._free.worker if self._free else None,
                    row_limit=1,
                )
                self._received_model_guard(data, row)
                if summary["counts"]["unknown"] or self._budget_stopped(row):
                    break
            return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("operation", choices=("readiness", "status", "execute"))
    parser.add_argument("--row-limit", type=int)
    args = parser.parse_args(argv)
    try:
        host = RegressionHost(args.manifest, args.manifest_sha256)
        result = (
            host.execute(row_limit=args.row_limit)
            if args.operation == "execute"
            else getattr(host, args.operation)()
        )
    except (OSError, ValueError, PermissionError, KeyError, TypeError) as error:
        result = {"status": "PENDING", "reason": type(error).__name__, "scope": SCOPE}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 2 if result.get("status") == "PENDING" else 0


if __name__ == "__main__":
    raise SystemExit(main())
