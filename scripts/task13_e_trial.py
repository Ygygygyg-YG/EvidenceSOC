"""Explicit, existing-only E2 host operations. Importing this module does no work.

Registration and consent are external inputs. No command creates an epoch,
journal, scope decision, plan approval, replacement, or renewal. The only
injectable dependencies are explicitly synthetic, free test dependencies.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import os
import re
from collections.abc import Callable
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from evals.adapters.e_planning_journal import (
    EPlanningAuthority,
    EPlanningDispatchJournal,
)
from evals.adapters.e_planning_review import (
    build_review_request,
    require_review_window,
)
from evals.contracts import canonical_hash
from evals.e_planning import planning_requests, validate_e_planning_registration
from evals.e_timing import (
    ETimingCampaign,
    _validate_replicate_source,
    validate_registration,
)
from evals.worker_lifecycle import HostWorkerLifecycleVerifier

SCOPE = "Task13supplement3engineeringtrials-before176"
INPUTS = {
    "planning_registration",
    "timing_registration",
    "planning_authority",
    "scope_packet",
    "scope_decision",
    "runtime_options",
    "readiness",
}
HOST_ENTRYPOINT = "scripts/task13_e_trial.py"
HOST_READ_ENTRYPOINT = "evals/host_review.py"


def require_host_entrypoints(epoch, timing):
    """Both host implementations must be pinned by the actual registered source."""
    root = Path(__file__).resolve().parents[1]
    for relative in (HOST_ENTRYPOINT, HOST_READ_ENTRYPOINT):
        path = root / relative
        digest = sha256(path.read_bytes()).hexdigest()
        if (
            epoch["entrypoints"].get(relative) != digest
            or timing["source_files"].get(str(path)) != digest
        ):
            raise PermissionError("actual host entrypoint differs from frozen source")


def require_pool_membership(pool, packet, timing):
    """An explicit parent packet authorizes exactly its native child membership."""
    from evals.timing_pool_controller import pool_scope_proposal

    proposal = pool_scope_proposal(pool)
    if packet.get("pool_proposal") != proposal or packet.get(
        "pool_proposal_sha256"
    ) != canonical_hash(proposal):
        raise PermissionError(
            "parent pool proposal hash or complete projection differs"
        )
    members = [child for child in pool["children"] if child["registration"] == timing]
    if len(members) != 1:
        raise PermissionError("native child is not an exact unique parent pool member")
    return members[0]


class PlanningBlocked(PermissionError):
    """A verified no-candidate slot cannot authorize review or timing."""


def _path(value, *, file=False):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute canonical host paths are required")
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise ValueError("host paths cannot contain links or reparse points")
    if file and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError("a single existing regular host file is required")
    return path.resolve()


def _decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON keys are forbidden")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("nonfinite JSON values are forbidden")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def _bytes(value):
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode()


def _read_pin(pin):
    if (
        not isinstance(pin, dict)
        or set(pin) != {"path", "sha256"}
        or re.fullmatch(r"[0-9a-f]{64}", pin.get("sha256", "")) is None
    ):
        raise ValueError("independently supplied file path and SHA256 required")
    path = _path(pin["path"], file=True)
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != pin["sha256"]:
        raise PermissionError("pinned host input bytes differ")
    return raw


def _write(path, raw):
    path = _path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path), "sha256": sha256(raw).hexdigest()}


async def _await(value):
    return await value if inspect.isawaitable(value) else value


@dataclass(frozen=True)
class FreeDependencies:
    """Free fakes only. A real registration categorically rejects this object."""

    plan: Callable
    review: Callable
    verification: Callable
    preflight: Callable
    approval_verifier: Callable
    lifecycle_verifier: Callable
    now: Callable
    monotonic_ns: Callable


class ETrialController:
    """Frozen reusable host entrypoint with no implicit dispatch or paid startup.

    ``manifest_sha256`` is an independent raw-byte pin, not a value read from
    the manifest itself. Each referenced input also carries an independent raw
    SHA256. Inputs and existing registrations are rechecked at every operation.
    """

    def __init__(self, manifest_path, manifest_sha256, *, free_dependencies=None):
        self._manifest_pin = {"path": str(manifest_path), "sha256": manifest_sha256}
        self._manifest_raw = _read_pin(self._manifest_pin)
        manifest = _decode(self._manifest_raw)
        if (
            set(manifest)
            != {
                "schema_version",
                "synthetic",
                "inputs",
                "agent_dir",
                "output_dir",
                "host_termination_dir",
            }
            or manifest["schema_version"] != "task13-e-host-controller-v1"
            or type(manifest["synthetic"]) is not bool
            or set(manifest["inputs"]) not in (INPUTS, INPUTS | {"pool_authority"})
        ):
            raise ValueError("complete frozen host controller manifest required")
        self._manifest = deepcopy(manifest)
        self._inputs = {
            key: _decode(_read_pin(pin)) for key, pin in manifest["inputs"].items()
        }
        self._planning = validate_e_planning_registration(
            self._inputs["planning_registration"]
        )
        self._timing = deepcopy(self._inputs["timing_registration"])
        validate_registration(self._timing)
        if (
            self._timing.get("schema_version") != "task13-e-timing-registration-v2"
            or self._timing["planning_registration"] != self._planning
            or manifest["synthetic"] != self._planning["synthetic"]
        ):
            raise ValueError("host requires exactly its frozen E2 registrations")
        if free_dependencies is not None and not manifest["synthetic"]:
            raise PermissionError("real execution cannot inject test dependencies")
        if manifest["synthetic"] and free_dependencies is None:
            raise PermissionError("synthetic host requires explicit free dependencies")
        self._free = free_dependencies
        self._requests = planning_requests(self._planning)
        observed = self._planning["core_config"].get("original_observed_model_binding")
        if (
            not isinstance(observed, dict)
            or set(observed) != {"response_model", "fingerprint"}
            or any(
                not isinstance(value, str) or not value.strip()
                for value in observed.values()
            )
        ):
            raise PermissionError(
                "explicit frozen original observed model binding required"
            )
        self._observed_model = deepcopy(observed)
        self._root = _path(manifest["output_dir"])
        self._agent = _path(manifest["agent_dir"])
        self._termination = _path(manifest["host_termination_dir"])
        self._now = (
            free_dependencies.now if free_dependencies else lambda: datetime.now(UTC)
        )

    def _request(self, ordinal):
        if type(ordinal) is not int or ordinal not in (1, 2, 3):
            raise ValueError("only frozen ordinals 1, 2, 3 are registered")
        return self._requests[ordinal - 1]

    def _require_pool_phase(self, request, phase):
        if "pool_authority" not in self._inputs:
            return
        from evals.timing_pool_controller import (
            PoolPhaseLease,
            require_pool_phase_lease,
        )

        lease = getattr(self, "_pool_lease", None)
        if not isinstance(lease, PoolPhaseLease):
            raise PermissionError("active parent pool phase lease required")
        pool = self._inputs["pool_authority"]
        members = [
            child for child in pool["children"] if child["registration"] == self._timing
        ]
        if len(members) != 1:
            raise PermissionError("active parent pool lease child differs")
        require_pool_phase_lease(
            pool, members[0]["child_id"], request.trial_id, phase, lease
        )

    def _pool_previous_expiry(self, request):
        if "pool_authority" not in self._inputs or request.ordinal <= 1:
            return False
        self._require_pool_phase(request, "plan")
        from evals.timing_pool_controller import (
            PoolJournal,
            validate_pre_timing_expiry_audit,
        )

        pool = self._inputs["pool_authority"]
        prior = self._requests[request.ordinal - 2].trial_id
        journal = PoolJournal(
            pool["execution_journal_path"], pool_sha256=canonical_hash(pool)
        )
        audits = [
            e["payload"]
            for e in journal._events()
            if e["kind"] == "expiry_audit" and e["payload"]["trial_id"] == prior
        ]
        if len(audits) != 1:
            return False
        proof = audits[0]
        if (
            proof["outcome"] != "ttl_infrastructure_failure"
            or proof["evidence"].get("subtype") != "pre_timing_expired"
            or proof["evidence"]["audit"]["trial_id"] != prior
            or canonical_hash(proof["evidence"]) != proof["evidence_sha256"]
        ):
            raise PermissionError("prior pool expiry audit identity differs")
        validate_pre_timing_expiry_audit(proof["evidence"]["audit"])
        return True

    def _slot(self, request):
        return self._root / "slots" / request.planning_slot_id

    def _options(self, phase, *, verification=False):
        options = deepcopy(self._inputs["runtime_options"])
        options["phase"] = phase
        options.pop("host_termination_dir", None)
        if verification:
            options["host_termination_dir"] = str(self._termination)
        return options

    def _guard(self):
        if _read_pin(self._manifest_pin) != self._manifest_raw:
            raise PermissionError("host manifest changed")
        for key, pin in self._manifest["inputs"].items():
            if _decode(_read_pin(pin)) != self._inputs[key]:
                raise PermissionError("frozen host inputs changed")
        binding = self._root / "host-binding.json"
        if binding.exists() and binding.read_bytes() != self._manifest_raw:
            raise PermissionError("host output belongs to a different frozen manifest")

    def _journal(self):
        dispatch = self._timing["planning_dispatch_registration_receipt"]
        authority = EPlanningAuthority.model_validate(
            self._inputs["planning_authority"]
        )
        if (
            canonical_hash(authority) != dispatch["authority_sha256"]
            or authority.registration_sha256 != canonical_hash(self._planning)
            or authority.synthetic != self._manifest["synthetic"]
            or authority.journal_path != dispatch["journal_path"]
        ):
            raise PermissionError("external authority differs from frozen dispatch")
        return EPlanningDispatchJournal.open_existing(
            _path(dispatch["journal_path"], file=True),
            expected_registration_sha256=canonical_hash(self._planning),
            expected_authority_sha256=dispatch["authority_sha256"],
        )

    def _scope(self):
        refs = self._manifest["inputs"]
        ready, authority, record = (
            self._inputs[key]
            for key in ("readiness", "planning_authority", "scope_decision")
        )
        expected = {
            "schema_version": "task13-e-host-readiness-v1",
            "status": "verified",
            "scope": SCOPE,
            "synthetic": self._manifest["synthetic"],
            "bindings": {
                key: pin["sha256"] for key, pin in refs.items() if key != "readiness"
            },
            **{
                key: self._manifest[key]
                for key in ("agent_dir", "output_dir", "host_termination_dir")
            },
        }
        if ready != expected or canonical_hash(ready) != canonical_hash(expected):
            raise PermissionError("actual pinned external readiness is not verified")
        self._chat(record, kind="scope")
        if (
            record.get("scope_packet_sha256") != refs["scope_packet"]["sha256"]
            or record.get("decision") != "approved"
            or authority["scope_packet_sha256"] != refs["scope_packet"]["sha256"]
            or authority["decision_record_sha256"] != refs["scope_decision"]["sha256"]
        ):
            raise PermissionError("actual scope chat and independent authority differ")
        policy = self._requests[0].participation_policy
        if policy is not None and self._inputs["scope_packet"].get(
            "participation_policy"
        ) != policy.model_dump(mode="json"):
            raise PermissionError("anytime policy differs from its approved new scope")
        packet = self._inputs["scope_packet"]
        if "pool_authority" in self._inputs:
            from evals.timing_pool import validate_pool_structure

            pool = validate_pool_structure(self._inputs["pool_authority"])
            require_pool_membership(pool, packet, self._timing)
            # Both child dispatch authorities still bind their own native planning
            # registration and the same parent scope/actual user decision above.
            root = Path(__file__).resolve().parents[1]
            for relative in (
                "scripts/task13_timing_pool.py",
                "evals/timing_pool_controller.py",
                "evals/timing_pool.py",
            ):
                path = root / relative
                if (
                    self._timing["source_files"].get(str(path))
                    != sha256(path.read_bytes()).hexdigest()
                ):
                    raise PermissionError("pool host implementation is not frozen")
        elif any(
            key in packet
            for key in (
                "pool_registration",
                "pool_registration_sha256",
                "pool_proposal",
                "pool_proposal_sha256",
            )
        ):
            raise PermissionError(
                "parent pool scope requires explicit pool authority mode"
            )
        lineage = self._planning.get("recovery_lineage")
        if lineage is None:
            if {"recovery_lineage", "recovery_lineage_sha256"} & packet.keys():
                raise PermissionError("scope recovery has no registered lineage")
        elif (
            policy is None
            or packet.get("recovery_lineage") != lineage
            or canonical_hash(packet.get("recovery_lineage")) != canonical_hash(lineage)
            or packet.get("recovery_lineage_sha256") != canonical_hash(lineage)
            or lineage["authorization_record_sha256"]
            != policy.authorization_record_sha256
        ):
            raise PermissionError(
                "recovery lineage or actual user authorization differs"
            )
        options = self._inputs["runtime_options"]
        request = self._requests[0]
        if (
            options.get("phase") != "development"
            or options.get("source_commit") != request.source_commit
            or options.get("budget_identity") != request.budget_identity
            or options.get("model_identity_binding")
            != (
                request.model_identity_binding.model_dump(mode="json")
                if request.model_identity_binding is not None
                else None
            )
            or options.get("planning_authority_sha256") != canonical_hash(authority)
            or str(_path(options["import_dispatch_path"])) != authority["journal_path"]
        ):
            raise PermissionError(
                "original host runtime/source/budget/journal binding differs"
            )
        for key in ("source_dir", "output_dir", "budget_dir", "import_source_dir"):
            _path(options[key])

    def _preflight(self, request, *, review=False):
        self._guard()
        self._scope()
        self._model_runtime_guard()
        binding = self._journal().validate_request(request)
        options = self._options("verification" if review else "development")
        if self._free:
            self._free.preflight(request, self._agent, deepcopy(options))
            return binding
        from evals.adapters.source_epochs import require_registered_epoch
        from scripts.task13_worker_runtime import validate_e_planning_host

        dependencies = _path(options["dependencies_dir"])
        receipt = _decode(
            _path(dependencies / "task13_dependencies.json", file=True).read_bytes()
        )
        validate_e_planning_host(request, self._agent, options, receipt, review=review)
        epoch = require_registered_epoch(
            _path(options["budget_dir"]) / "campaign.sqlite",
            request.epoch_id,
            source_sha256=request.source_sha256,
            config_sha256=request.config_sha256,
            budget_identity=request.budget_identity,
            manifest_sha256=request.epoch_manifest_sha256,
            latest=True,
        )
        if epoch["authority"] != {
            "kind": "phase_scope_consent",
            "packet_sha256": self._manifest["inputs"]["scope_packet"]["sha256"],
            "decision_record_sha256": self._manifest["inputs"]["scope_decision"][
                "sha256"
            ],
        }:
            raise PermissionError(
                "actual host entrypoint or registered real phase authority differs"
            )
        require_host_entrypoints(epoch, self._timing)
        roots = [_path(value) for value in epoch["controller_state_roots"]]
        if "pool_authority" in self._inputs:
            pool_path = _path(self._inputs["pool_authority"]["execution_journal_path"])
            if pool_path.name != "pool-journal.jsonl" or not any(
                pool_path.is_relative_to(root) for root in roots
            ):
                raise PermissionError(
                    "pool journal outside actual registered epoch controller roots"
                )
        if any(
            not any(path.is_relative_to(root) for root in roots)
            for path in (self._root, self._termination, _path(options["output_dir"]))
        ):
            raise PermissionError(
                "actual controller state paths are outside the registered epoch"
            )
        return binding

    def _model_runtime_guard(self):
        """Recheck existing account state read-only; never bind/reset the account."""
        if (self._root / "model-runtime-halt.json").exists():
            raise PermissionError(
                "model runtime halted after observed identity rejection"
            )
        options = self._inputs["runtime_options"]
        request = self._requests[0]
        if request.model_identity_binding is not None:
            from evals.adapters.model_identity_runtime import require_dispatch_identity

            manifest = require_dispatch_identity(
                _path(Path(options["budget_dir"]) / "campaign.sqlite", file=True),
                request,
            )
            if manifest["expected_model"] != self._planning["core_config"].get(
                "model_identity"
            ) or self._observed_model != {
                key: manifest["inherited_global"][key]
                for key in ("response_model", "fingerprint")
            }:
                raise PermissionError("adopted model identity descriptor differs")
            return
        from evals.adapters.remediation_worker import _budget_snapshot

        values, _ = _budget_snapshot(
            _path(Path(options["budget_dir"]) / "campaign.sqlite", file=True),
            self._requests[0].budget_identity["baseline_max_rowid"],
        )
        if values.get("halt") or any(
            values.get(key) != expected
            for key, expected in self._observed_model.items()
        ):
            raise PermissionError(
                "model runtime account halted or original binding differs"
            )

    def _verify_model_result(self, value, capture, request=None):
        """Keep every physical result/fee; only matching received identities pass."""
        ledger = value.get("model_ledger")
        invalid = not isinstance(ledger, list)
        request = request or self._requests[0]
        observed = self._observed_model
        if request.model_identity_binding is not None:
            from evals.adapters.model_identity_runtime import verify_identity_ledger

            descriptor = self._planning["core_config"]["model_identity"]
            observed = {
                key: descriptor[key] for key in ("response_model", "fingerprint")
            }
            try:
                manifest = (
                    verify_identity_ledger(
                        _path(
                            Path(self._inputs["runtime_options"]["budget_dir"])
                            / "campaign.sqlite",
                            file=True,
                        ),
                        request,
                        ledger,
                    )
                    if ledger
                    else None
                )
                if manifest is not None and manifest["expected_model"] != descriptor:
                    invalid = True
            except (ValueError, RuntimeError):
                invalid = True
        received = 0
        for call in ledger if isinstance(ledger, list) else []:
            if not isinstance(call, dict):
                invalid = True
                continue
            raw = call.get("raw_response")
            if call.get("http_status") != 200 and not isinstance(raw, dict):
                continue
            received += 1
            if (
                call.get("response_model") != observed["response_model"]
                or call.get("system_fingerprint") != observed["fingerprint"]
                or not isinstance(raw, dict)
                or raw.get("model") != observed["response_model"]
                or raw.get("system_fingerprint") != observed["fingerprint"]
            ):
                invalid = True
        if invalid or (value.get("execution_status") == "completed" and not received):
            _write(
                self._root / "model-runtime-halt.json",
                _bytes(
                    {
                        "schema_version": "task13-e-model-runtime-halt-v1",
                        "reason": "received_model_identity_differs_or_missing",
                        "expected": observed,
                        **capture,
                    }
                ),
            )
            raise PermissionError(
                "model runtime received identity differs or is missing"
            )

    def readiness(self):
        """Read-only admission result; never creates a directory or registration."""
        try:
            for request in self._requests:
                self._preflight(request)
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
            "planning_registration_sha256": canonical_hash(self._planning),
        }

    @contextmanager
    def _lock(self):
        self._root.mkdir(parents=True, exist_ok=True)
        lock = self._root / "host-writer.lock"
        try:
            _write(lock, _bytes({"pid": os.getpid()}))
        except FileExistsError as error:
            raise PermissionError(
                "host writer active or interrupted; explicit reconciliation required"
            ) from error
        try:
            binding = self._root / "host-binding.json"
            if not binding.exists():
                _write(binding, self._manifest_raw)
            self._guard()
            yield
        finally:
            lock.unlink()

    def _save(self, category, raw):
        digest = sha256(raw).hexdigest()
        path = self._root / "artifacts" / category / digest
        if path.exists():
            pin = {"path": str(path), "sha256": digest}
            if _read_pin(pin) != raw:
                raise PermissionError("immutable host artifact differs")
            return pin
        return _write(path, raw)

    def _record(self, path):
        return _decode(_path(path, file=True).read_bytes()) if path.exists() else None

    def _terminal(self, request, operation):
        root = self._slot(request)
        result = self._record(root / (operation + "-terminal.json"))
        started = self._record(root / (operation + "-started.json"))
        if started and started.get("request_sha256") != canonical_hash(request):
            raise PermissionError("host start marker differs from frozen request")
        if result:
            if not started or result.get("start_sha256") != canonical_hash(started):
                raise PermissionError(
                    "host terminal receipt lacks its exact start marker"
                )
            for key in (
                "runtime_result",
                "stdout",
                "retained_state",
                "resources",
                "provenance",
                "chat_record",
                "no_plan_state",
                "payload_index",
                "model_ledger",
                "tool_ledger",
            ):
                if result.get(key):
                    _read_pin(result[key])
            for pair in result.get("no_plan_payloads", []):
                _read_pin(pair["payload"])
                _read_pin(pair["http_body"])
            return result
        return (
            {"status": "unknown", "reason": "started_without_verified_terminal"}
            if started
            else None
        )

    def _finish(self, request, operation, started, **result):
        value = {"start_sha256": canonical_hash(started), **result}
        _write(self._slot(request) / (operation + "-terminal.json"), _bytes(value))
        return value

    def _capture(self, value, options, request, *, capture=None):
        """Preserve actual wrapper return and its exact independent stdout bytes."""
        result_pin = self._save("runtime-result", _bytes(value))
        isolation = value.get("isolation_evidence") or {}
        raw_ref = isolation.get("raw_stdout")
        if not isinstance(raw_ref, dict):
            raise PermissionError("runtime stdout provenance is missing")
        raw_path = _path(raw_ref["path"], file=True)
        if (
            not raw_path.is_relative_to(_path(options["output_dir"]))
            or raw_path.name != "worker-stdout.bin"
            or not raw_path.parent.name.endswith(".controller")
        ):
            raise PermissionError(
                "runtime stdout lies outside its exact output protocol"
            )
        raw = _read_pin({key: raw_ref[key] for key in ("path", "sha256")})
        if raw_ref.get("bytes") != len(raw):
            raise PermissionError("runtime stdout size differs")
        saved = self._save("stdout", raw)
        captured = {"runtime_result": result_pin, "stdout": saved}
        if capture is not None:
            capture.update(captured)
        # Index all actual returns before validating them, including failures.
        self._save(
            "runtime-attempt", _bytes({"runtime_result": result_pin, "stdout": saved})
        )
        nonce = raw_path.parent.name.removesuffix(".controller")
        worker_output = raw_path.parent.with_name(nonce)
        expected_output = (
            _path(options["output_dir"])
            / request.run_id
            / request.case_id
            / request.group
            / nonce
            if request.schema_version == "task13-e-planning-worker-v1"
            else _path(options["output_dir"])
            / "source_review"
            / request.case_id
            / request.request_id
            / nonce
        )
        if (
            isolation.get("status") != "passed"
            or isolation.get("source_commit") != self._requests[0].source_commit
            or (isolation.get("probe") or {}).get("pid") != 1
            or (isolation.get("probe") or {}).get("nonce") != nonce
            or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
            or worker_output != expected_output
            or not (isolation.get("container") or {}).get("container_id")
        ):
            raise PermissionError("actual inspected runtime isolation is not verified")
        original = _decode(raw)
        if any(
            original.get(key) != value.get(key)
            for key in (
                "execution_status",
                "product_status",
                "status",
                "input_sha256",
                "model_ledger",
                "verification",
                "artifact_hashes",
                "errors",
                "diagnosis_status",
                "diagnostic_snapshot",
                "source",
                "approval_packet",
                "approval_receipt",
                "operation",
                "request_id",
                "source_state_sha256",
                "planning_slot_id",
                "registration_sha256",
                "selected_source_lineage_sha256",
                "resources",
                "tool_ledger",
            )
        ):
            raise PermissionError("runtime result differs from original worker stdout")
        return captured, worker_output

    def _blocker(self, request):
        for current in self._requests[: request.ordinal]:
            terminal = self._terminal(current, "plan")
            if terminal and terminal.get("status") == "blocked":
                return terminal
        return None

    def _require_candidate(self, request):
        if self._blocker(request):
            raise PlanningBlocked(
                "planning blocked: model_returned_null; new scope and slots required"
            )

    def _no_plan(self, request, value, out, capture):
        """Independently verify actual portable source, started claim and raw artifacts."""
        from evidencesoc.agents.analysis_import import PlanningAdmission

        from evals.adapters.e_planning_no_plan import verify_no_plan
        from evals.adapters.e_planning_worker import _claim_binding
        from evals.adapters.planning_analysis import verify_planning_analysis

        if (
            value.get("product_status") != "manual_review"
            or value.get("diagnosis_status") != "succeeded"
            or value.get("errors") != []
            or (out / "case-resource.json").exists()
        ):
            raise PermissionError("no-plan execution or cleanup claims differ")
        artifacts = {}
        for key, filename in (
            ("no_plan_state", "investigation-state.json"),
            ("provenance", "import-provenance.json"),
            ("model_ledger", "model-ledger.json"),
            ("tool_ledger", "tool-ledger.json"),
            ("payload_index", "model-payloads.json"),
        ):
            raw = _path(out / filename, file=True).read_bytes()
            capture[key] = self._save(key, raw)
            artifacts[key] = _decode(raw)
        state, provenance = artifacts["no_plan_state"], artifacts["provenance"]
        if (
            value.get("model_ledger") != artifacts["model_ledger"]
            or value.get("tool_ledger") != artifacts["tool_ledger"]
            or value.get("diagnostic_snapshot") != state.get("diagnostic_snapshot")
            or value.get("artifact_hashes")
            != {
                "investigation_state": canonical_hash(state),
                "import_provenance": canonical_hash(provenance),
            }
        ):
            raise PermissionError("no-plan actual artifacts differ from worker stdout")
        source = verify_planning_analysis(
            request,
            _path(self._inputs["runtime_options"]["import_source_dir"]),
            _path(
                Path(self._inputs["runtime_options"]["budget_dir"]) / "campaign.sqlite",
                file=True,
            ),
        )
        journal = self._journal()
        binding = _claim_binding(request, journal.validate_request(request))
        admission = PlanningAdmission._from_existing_claim(
            binding, lambda: _claim_binding(request, journal.validate_request(request))
        )
        expected = admission.provenance_for(source, request.incident_id)
        if provenance != expected:
            raise PermissionError(
                "no-plan actual import provenance differs from current claim"
            )
        verification = verify_no_plan(
            request=request,
            imported=source,
            expected_provenance=expected,
            state=state,
            ledger=artifacts["model_ledger"],
            payloads=artifacts["payload_index"],
            output_root=out,
            budget_path=_path(
                Path(self._inputs["runtime_options"]["budget_dir"]) / "campaign.sqlite",
                file=True,
            ),
        )
        if value.get("verification") != verification:
            raise PermissionError(
                "no-plan verification differs from actual raw response"
            )
        capture["no_plan_payloads"] = []
        for item in artifacts["payload_index"]:
            pair = {}
            for key, index_key in (
                ("payload", "payload_path"),
                ("http_body", "http_body_path"),
            ):
                path = _path(out / item[index_key], file=True)
                if not path.is_relative_to(out):
                    raise PermissionError(
                        "no-plan payload escapes actual worker output"
                    )
                pair[key] = self._save("no-plan-" + key, path.read_bytes())
            capture["no_plan_payloads"].append(pair)
        return verification

    async def plan(self, ordinal):
        """Explicitly dispatch one fixed planning request once; ambiguity consumes it."""
        request = self._request(ordinal)
        self._require_pool_phase(request, "plan")
        binding = self._preflight(request)
        with self._lock():
            prior = self._terminal(request, "plan")
            if prior:
                return prior
            blocked = self._blocker(request)
            if blocked:
                return blocked
            if binding["status"] == "started":
                return {"status": "unknown", "reason": "worker_claim_already_started"}
            if ordinal > 1:
                path = self._root / "timing" / "registration.json"
                if not path.exists():
                    if not self._pool_previous_expiry(request):
                        raise PermissionError(
                            "preceding trial must terminate before a new short-TTL plan"
                        )
                else:
                    campaign = self._campaign()
                    previous = campaign.snapshot()["trials"][ordinal - 2]
                    if previous["status"] not in {
                        "completed",
                        "failed",
                        "expired",
                        "rejected",
                        "not_applicable",
                    } and (
                        previous["status"] != "not_started"
                        or not self._pool_previous_expiry(request)
                    ):
                        raise PermissionError("preceding trial is pending or unknown")
            started = {
                "operation": "plan",
                "request_sha256": canonical_hash(request),
                "request": request.model_dump(mode="json"),
                "manifest_sha256": self._manifest_pin["sha256"],
                "started_at": self._now().isoformat(),
            }
            _write(self._slot(request) / "plan-started.json", _bytes(started))
            capture = {}
            try:
                from scripts.task13_worker_runtime import run_e_planning_container

                options = self._options("development")
                worker = self._free.plan if self._free else run_e_planning_container
                self._require_pool_phase(request, "plan")
                value = await worker(request, self._agent, options)
                capture["runtime_result"] = self._save("runtime-result", _bytes(value))
                try:
                    _, out = self._capture(value, options, request, capture=capture)
                finally:
                    self._verify_model_result(value, capture, request)
                if value.get("execution_status") != "completed":
                    return self._finish(
                        request, "plan", started, status="failed", **capture
                    )
                if (value.get("verification") or {}).get("status") == "no_plan":
                    verification = self._no_plan(request, value, out, capture)
                    return self._finish(
                        request,
                        "plan",
                        started,
                        status="blocked",
                        reason="model_returned_null",
                        no_plan_reason=verification["no_plan_reason"],
                        no_plan_reason_missing=verification["no_plan_reason_missing"],
                        requires_new_scope_and_slots=True,
                        **capture,
                    )
                if value.get("product_status") != "awaiting_approval":
                    raise PermissionError(
                        "planning did not return completed awaiting approval"
                    )
                for key, filename in (
                    ("retained_state", "investigation-state.json"),
                    ("resources", "case-resource.json"),
                    ("provenance", "import-provenance.json"),
                ):
                    raw = _path(out / filename, file=True).read_bytes()
                    capture[key] = self._save(key, raw)
                state, resources, provenance = (
                    _decode(_read_pin(capture[key]))
                    for key in ("retained_state", "resources", "provenance")
                )
                expected_hashes = {
                    "investigation_state": canonical_hash(state),
                    "case_resource": canonical_hash(resources),
                    "import_provenance": canonical_hash(provenance),
                }
                if (
                    value.get("artifact_hashes") != expected_hashes
                    or state.get("analysis_import_provenance") != provenance
                ):
                    raise PermissionError("actual planning artifact hashes differ")
                source = self._source(request, state, state, resources)
                _validate_replicate_source(
                    self._timing, self._timing["trials"][ordinal - 1], source
                )
                return self._finish(
                    request, "plan", started, status="awaiting_approval", **capture
                )
            except Exception as error:  # noqa: BLE001 -- keep every attempt; never leak credentials.
                return self._finish(
                    request,
                    "plan",
                    started,
                    status="unknown",
                    error_type=type(error).__name__,
                    **capture,
                )

    def _retained(self, request):
        self._require_candidate(request)
        plan = self._terminal(request, "plan")
        if not plan or plan["status"] != "awaiting_approval":
            raise PermissionError("verified original pending worker retention required")
        return tuple(
            _decode(_read_pin(plan[key])) for key in ("retained_state", "resources")
        )

    async def _review(
        self,
        request,
        *,
        operation="read_packet",
        packet=None,
        decision=None,
        reason=None,
    ):
        require_review_window(self._now(), request.participation_policy)
        self._preflight(request, review=True)
        retained, resources = self._retained(request)
        review = build_review_request(
            request,
            resources,
            operation=operation,
            packet=packet,
            decision=decision,
            reason=reason,
        )
        options = self._options("verification")
        if operation == "read_packet" and self._free is None:
            from evals.host_review import read_e_planning_host_review

            value = await read_e_planning_host_review(review, self._agent, options)
            receipt = value.get("host_read_receipt") or {}
            if (
                receipt.get("schema_version") != "task13-e-host-review-read-v1"
                or receipt.get("origin") != "host_original_postgresql_read"
                or receipt.get("request_sha256") != canonical_hash(review)
                or receipt.get("state_sha256") != value.get("source_state_sha256")
                or "isolation_evidence" in value
            ):
                raise PermissionError("actual host read receipt binding differs")
            captured = {
                "host_read_result": self._save("host-review-result", _bytes(value)),
                "host_read_receipt": self._save("host-review-read", _bytes(receipt)),
            }
        else:
            from scripts.task13_worker_runtime import run_e_planning_review_container

            worker = (
                self._free.review if self._free else run_e_planning_review_container
            )
            value = await worker(review, self._agent, options)
            self._save("runtime-result", _bytes(value))
            captured, _ = self._capture(value, options, review)
        if (
            value.get("model_ledger")
            or value.get("status") != "completed"
            or value.get("input_sha256") != canonical_hash(review)
            or value.get("request_id") != review.request_id
            or value.get("operation") != operation
            or value.get("planning_slot_id") != request.planning_slot_id
            or value.get("registration_sha256") != request.registration_sha256
            or value.get("selected_source_lineage_sha256")
            != request.selected_source_lineage_sha256
        ):
            raise PermissionError("zero-model dedicated review protocol differs")
        state = value["source"]["state"]
        expected_resources = {
            key: resources[key]
            for key in ("database_name", "index_name", "incident_id", "source_commit")
        }
        if value["source"]["resources"] != expected_resources or value.get(
            "source_state_sha256"
        ) != canonical_hash(state):
            raise PermissionError(
                "review actual retained resources or state hash differ"
            )
        _validate_replicate_source(
            self._timing,
            self._timing["trials"][request.ordinal - 1],
            self._source(request, state, retained, resources),
        )
        from evals.adapters.retained_workflow import build_approval_packet

        expected_packet = build_approval_packet(
            {"case_id": request.case_id, "dataset": request.dataset},
            state,
            now=self._now(),
            participation_policy=request.participation_policy,
        )
        if value.get("approval_packet") != expected_packet:
            raise PermissionError("review packet differs from exact live state")
        if (
            operation == "read_packet"
            and state.get("approval") is None
            and state != retained
        ):
            raise PermissionError(
                "live pending state differs from original retained bytes"
            )
        require_review_window(self._now(), request.participation_policy)
        return value, captured

    async def read(self, ordinal):
        """Read the live zero-model packet and save the actual inspected response."""
        request = self._request(ordinal)
        self._require_pool_phase(request, "read")
        self._require_candidate(request)
        self._preflight(request, review=True)
        with self._lock():
            value, captured = await self._review(request)
            packet = value["approval_packet"]
            return {
                "status": "read",
                "packet": packet,
                "packet_sha256": canonical_hash(packet),
                **captured,
            }

    def _chat(self, record, *, kind, participation_policy=None):
        if (
            record.get("schema_version") != f"task13-e-user-{kind}-decision-v1"
            or record.get("role") != "user"
            or record.get("scope") != SCOPE
            or not isinstance(record.get("record_id"), str)
            or not record["record_id"].strip()
            or not isinstance(record.get("text"), str)
            or not record["text"].strip()
            or not isinstance(record.get("decided_at"), str)
        ):
            raise PermissionError("actual original user chat record is required")
        when = datetime.fromisoformat(record["decided_at"].replace("Z", "+00:00"))
        if when.tzinfo is None or when > self._now():
            raise PermissionError("actual user chat timestamp is invalid")
        if kind == "plan":
            require_review_window(when, participation_policy)

    async def decision(self, ordinal, *, packet_sha256, chat_record):
        """Apply only the supplied actual user's exact current packet decision."""
        request = self._request(ordinal)
        self._require_pool_phase(request, "decision")
        self._require_candidate(request)
        self._preflight(request, review=True)
        with self._lock():
            previous = self._terminal(request, "decision")
            if previous:
                return previous
            raw = _read_pin(chat_record)
            record = _decode(raw)
            self._chat(
                record, kind="plan", participation_policy=request.participation_policy
            )
            live, _ = await self._review(request)
            packet = live["approval_packet"]
            if (
                canonical_hash(packet) != packet_sha256
                or record.get("packet_sha256") != packet_sha256
                or record.get("case_id") != request.case_id
                or record.get("incident_id") != request.incident_id
                or record.get("decision") not in {"approved", "rejected"}
                or not isinstance(record.get("reason"), str)
                or not record["reason"].strip()
                or packet.get("status") != "pending"
            ):
                raise PermissionError(
                    "actual user decision does not bind the exact live packet"
                )
            started = {
                "operation": "decision",
                "request_sha256": canonical_hash(request),
                "packet_sha256": packet_sha256,
                "chat_record": deepcopy(chat_record),
                "decision": record["decision"],
                "reason": record["reason"],
            }
            _write(self._slot(request) / "decision-started.json", _bytes(started))
            capture = {"chat_record": self._save("user-chat-record", raw)}
            try:
                value, captured = await self._review(
                    request,
                    operation="decision",
                    packet=packet,
                    decision=record["decision"],
                    reason=record["reason"],
                )
                capture.update(captured)
                state = value["source"]["state"]
                approval = state.get("approval") or {}
                if any(
                    approval.get(key) != expected
                    for key, expected in (
                        ("decided_by", "user"),
                        ("decision", record["decision"]),
                        ("reason", record["reason"]),
                    )
                ):
                    raise PermissionError(
                        "product decision differs from actual user record"
                    )
                if record["decision"] == "approved":
                    self._receipt(value.get("approval_receipt"), state)
                return self._finish(
                    request, "decision", started, status=record["decision"], **capture
                )
            except Exception as error:  # noqa: BLE001 -- a sent decision may have persisted.
                return self._finish(
                    request,
                    "decision",
                    started,
                    status="unknown",
                    error_type=type(error).__name__,
                    **capture,
                )

    @staticmethod
    def _receipt(receipt, state):
        expected = {
            "status": "verified",
            "source": "original_product_database",
            "state_sha256": canonical_hash(state),
            "approval_sha256": canonical_hash(state.get("approval")),
            "plan_sha256": state.get("approved_plan_sha256"),
            "plan_version": state.get("approved_plan_version"),
        }
        if not isinstance(receipt, dict) or any(
            receipt.get(key) != value for key, value in expected.items()
        ):
            raise PermissionError(
                "actual persisted product approval receipt is not bound to state"
            )
        return deepcopy(receipt)

    def _source(self, request, state, retained, resources):
        return {
            "campaign_id": self._timing["campaign_id"],
            "source_commit": self._timing["source_commit"],
            "source_sha256": canonical_hash(self._timing["source_files"]),
            "config_sha256": canonical_hash(self._timing["core_config"]),
            "source_row_id": request.source_row_id,
            "case_id": request.case_id,
            "dataset": request.dataset,
            "analysis_manifest_sha256": request.original_manifest_sha256,
            "budget_source_receipt_sha256": request.budget_source_receipt_sha256,
            "planning_request": request.model_dump(mode="json"),
            "state": deepcopy(state),
            "retained_state": deepcopy(retained),
            "retained_state_sha256": canonical_hash(retained),
            "resources": deepcopy(resources),
            "resources_sha256": canonical_hash(resources),
        }

    def _gate(self, identity):
        self._preflight(self._requests[0], review=True)
        for path, digest in self._timing["source_files"].items():
            if sha256(_path(path, file=True).read_bytes()).hexdigest() != digest:
                raise PermissionError("actual frozen timing execution source differs")
        expected = {
            "campaign_id": self._timing["campaign_id"],
            "plan_sha256": self._timing["f8_plan_sha256"],
            "source_commit": self._timing["source_commit"],
            "source_sha256": canonical_hash(self._timing["source_files"]),
            "config_sha256": canonical_hash(self._timing["core_config"]),
        }
        if identity != expected:
            raise PermissionError(
                "execution gate identity differs from frozen registration"
            )
        return {
            "schema_version": "task13-v2-execution-gate-v1",
            "status": "verified",
            "scope": SCOPE,
            "synthetic": self._manifest["synthetic"],
            **identity,
        }

    def _campaign(self, *, approval_verifier=None, now=None):
        return ETimingCampaign(
            self._timing,
            self._root / "timing",
            execution_admitter=self._gate,
            approval_verifier=approval_verifier,
            worker_lifecycle_verifier=(
                self._free.lifecycle_verifier
                if self._free
                else HostWorkerLifecycleVerifier(self._termination)
            ),
            now=now if now is not None else self._now,
            monotonic_ns=self._free.monotonic_ns if self._free else None,
        )

    async def trial(self, ordinal):
        """Explicit timing v2 trial; six requests and lifecycle policy remain in ETimingCampaign."""
        request = self._request(ordinal)
        self._require_pool_phase(request, "trial")
        self._require_candidate(request)
        self._preflight(request, review=True)
        with self._lock():
            decided = self._terminal(request, "decision")
            if not decided or decided["status"] != "approved":
                raise PermissionError(
                    "actual exact-packet approved product decision required"
                )
            actual = _decode(_read_pin(decided["runtime_result"]))
            retained, resources = self._retained(request)
            source = self._source(
                request, actual["source"]["state"], retained, resources
            )
            self._receipt(actual.get("approval_receipt"), source["state"])

            async def verify(current):
                if current != source:
                    raise PermissionError(
                        "timing approved source differs from verified decision"
                    )
                live, _ = await self._review(request)
                if live["source"]["state"] != current["state"]:
                    raise PermissionError("actual live approved checkpoint changed")
                from evals.verification import verify_source_approval

                verifier = (
                    self._free.approval_verifier
                    if self._free
                    else verify_source_approval
                )
                fresh = await _await(verifier(deepcopy(current)))
                self._receipt(fresh, current["state"])
                if fresh != actual["approval_receipt"]:
                    raise PermissionError(
                        "fresh actual product DB approval differs from decision receipt"
                    )
                self._save("fresh-product-approval", _bytes(fresh))
                return fresh

            from scripts.task13_worker_runtime import run_verification_container

            worker = (
                self._free.verification if self._free else run_verification_container
            )

            admission_clock = None
            if "pool_authority" in self._inputs:
                from evals.timing_pool_controller import FirstDispatchClock, PoolJournal

                pool = self._inputs["pool_authority"]
                journal = PoolJournal(
                    pool["execution_journal_path"], pool_sha256=canonical_hash(pool)
                )
                admission_clock = FirstDispatchClock(
                    self._now,
                    expires_at=datetime.fromisoformat(
                        source["state"]["response_plan"]["expires_at"]
                    ),
                    shared_max=journal.status()["observed_max_seconds"],
                )

            async def run_worker(branch):
                self._require_pool_phase(request, "trial")
                if admission_clock is not None and not admission_clock.admitted:
                    admission_clock.admit()
                self._preflight(request, review=True)
                return await worker(
                    branch,
                    self._agent,
                    self._options("verification", verification=True),
                )

            return await self._campaign(
                approval_verifier=verify, now=admission_clock
            ).run_trial(request.trial_id, source, run_worker=run_worker)

    def status(self):
        """Read-only status. Started or worker-claimed ambiguity remains unknown."""
        self._guard()
        slots = []
        try:
            journal = self._journal()
        except (OSError, ValueError, PermissionError):
            journal = None
        for request in self._requests:
            planning = self._terminal(request, "plan")
            if (
                planning is None
                and journal
                and journal.validate_request(request)["status"] == "started"
            ):
                planning = {
                    "status": "unknown",
                    "reason": "worker_claim_already_started",
                }
            decision = self._terminal(request, "decision")
            slots.append(
                {
                    "ordinal": request.ordinal,
                    "planning_slot_id": request.planning_slot_id,
                    "trial_id": request.trial_id,
                    "planning_status": (planning or {}).get("status", "not_started"),
                    "planning": planning,
                    "decision": decision,
                }
            )
        timing = None
        if (self._root / "timing" / "registration.json").exists():
            from evals.e_timing import read_timing_journal

            timing = read_timing_journal(self._root / "timing")
        return {
            "synthetic": self._manifest["synthetic"],
            "scope": SCOPE,
            "slots": slots,
            "timing": timing,
            "formal_admissible": False,
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument(
        "operation",
        choices=("readiness", "status", "plan", "read", "decision", "trial"),
    )
    parser.add_argument("--ordinal", type=int)
    parser.add_argument("--packet-sha256")
    parser.add_argument("--chat-record")
    parser.add_argument("--chat-record-sha256")
    args = parser.parse_args(argv)
    try:
        host = ETrialController(args.manifest, args.manifest_sha256)
        if args.operation in {"status", "readiness"}:
            result = getattr(host, args.operation)()
        elif args.operation == "decision":
            result = asyncio.run(
                host.decision(
                    args.ordinal,
                    packet_sha256=args.packet_sha256,
                    chat_record={
                        "path": args.chat_record,
                        "sha256": args.chat_record_sha256,
                    },
                )
            )
        else:
            result = asyncio.run(getattr(host, args.operation)(args.ordinal))
    except PlanningBlocked:
        result = {
            "status": "blocked",
            "reason": "model_returned_null",
            "requires_new_scope_and_slots": True,
            "scope": SCOPE,
        }
    except (OSError, ValueError, PermissionError, KeyError, TypeError) as error:
        result = {"status": "PENDING", "reason": type(error).__name__, "scope": SCOPE}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return (
        3
        if result.get("status") == "blocked"
        else 2
        if result.get("status") == "PENDING"
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
