"""Host-only manual quarantine audit, independent of native settlement and TTL.

This module grants no source adoption, provider dispatch or approval authority.
The original unknown prefix and all native evidence remain untouched.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import sqlite3
import subprocess
from contextlib import ExitStack, contextmanager
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from pathlib import Path

from evals.adapters.source_epochs import _ACTIVE_CONTROLLER_LOCKS
from evals.contracts import canonical_hash
from evals.timing_pool_controller import PoolJournal, require_plain_path

FROZEN = {
    "pool_host_manifest": "296222a174956c76a95da46858e5f965b6921fc134f84ab4f737bea374eb076a",
    "stop_evidence": "62b6b27f72dbb63c484bd58634d40c4535f51fcf58598909b309d8f08a28a660",
    "fee_audit": "81a44cd0b6cccdb1115e387a1b31b4ffdb1a0cda70a0b3fa5b6d21d76bc9e56e",
    "journal_head": "68a42b853ae3ba98b9fc0605e0cf7e635f63ece6212d78d9883cda31fad7f4d9",
    "pool_sha256": "8b9027f60b0ad132121ddc45718dbbb3e07f99efdd0915cf540d307f007f57fc",
}
TRIAL_ID = "ea3b7efc1a10d86f2fece87f82c6396a"
PACKET_SHA256 = "a0ae783b364cfa06438760e5aaa9b5b4f19247a195855f0285f33c4e03148f87"
APPROVAL_SHA256 = "a79c826a7f12500b9524572bbf7c4a5f841f6c45cd73db99116d46892330dc2e"
PLAN_ID = "RP-1289880e3f8d8352367001fb"

_ACTIVE_LEASES = {}


def _pin(ref):
    if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
        raise PermissionError("complete raw evidence pin required")
    path = require_plain_path(ref["path"], file=True)
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != ref["sha256"]:
        raise PermissionError("raw evidence pin differs")
    return json.loads(raw)


def _spec(spec):
    if (
        isinstance(spec, dict)
        and spec.get("schema_version") == "task13-manual-startup-recovery-lock-spec-v1"
    ):
        from evals.timing_pool_startup_recovery import validate_startup_spec

        return validate_startup_spec(spec)
    required = {
        "schema_version",
        "pool_host_manifest",
        "expected_scope",
        "stop_evidence",
        "fee_audit",
        "controller_state_roots",
    }
    if (
        not isinstance(spec, dict)
        or set(spec) not in (required, required | {"target_pool_registration"})
        or spec["schema_version"] != "task13-manual-recovery-lock-spec-v1"
    ):
        raise PermissionError("complete manual recovery lock spec required")
    for name in ("pool_host_manifest", "stop_evidence", "fee_audit"):
        if spec[name].get("sha256") != FROZEN[name]:
            raise PermissionError("only the exact frozen old prefix is eligible")
        _pin(spec[name])
    _pin(spec["expected_scope"])
    roots = spec["controller_state_roots"]
    if (
        not isinstance(roots, list)
        or not roots
        or len(set(roots)) != len(roots)
        or any(
            str(require_plain_path(p).resolve()) != p or not Path(p).is_dir()
            for p in roots
        )
    ):
        raise PermissionError("canonical original controller roots required")
    host, stop = _pin(spec["pool_host_manifest"]), _pin(spec["stop_evidence"])
    journal = require_plain_path(host["journal_path"], file=True)
    if (
        journal.name != "pool-journal.jsonl"
        or stop["pool_journal"]["path"] != str(journal)
        or sha256(journal.read_bytes()).hexdigest() != stop["pool_journal"]["sha256"]
        or stop["journal_head"] != FROZEN["journal_head"]
        or not any(journal.is_relative_to(Path(p)) for p in roots)
    ):
        raise PermissionError("frozen parent journal pin or roots differ")
    if "target_pool_registration" in spec:
        _target_registration(spec)
    return json.loads(json.dumps(spec, allow_nan=False))


def _target_registration(spec):
    """Admit one independently pinned target, never a self-declared policy."""
    from evals.timing_pool import (
        RECOVERY_REGISTRATION_SCHEMA,
        STARTUP_RECOVERY_REGISTRATION_SCHEMA,
        validate_recovery_bindings,
    )

    startup = spec["schema_version"] == "task13-manual-startup-recovery-lock-spec-v1"
    if startup:
        from evals.timing_pool_startup_recovery import STARTUP_FROZEN
    frozen = STARTUP_FROZEN if startup else FROZEN
    expected_schema = (
        STARTUP_RECOVERY_REGISTRATION_SCHEMA
        if startup
        else RECOVERY_REGISTRATION_SCHEMA
    )
    count = 4 if startup else 5
    target = _pin(spec["target_pool_registration"])
    old_host = _pin(spec["pool_host_manifest"])
    stop = _pin(spec["stop_evidence"])
    try:
        path = require_plain_path(target["execution_journal_path"])
        predecessor = target["quarantined_predecessor"]
        grant = validate_recovery_bindings(
            target["migration_grant"], predecessor, pool_schema=expected_schema
        )
        order = [entry["trial_id"] for entry in target["attempt_order"]]
        if (
            target["schema_version"] != expected_schema
            or target["future_logical_limit"] != count
            or target["future_physical_limit"] != count * 3
            or len(order) != count
            or len(set(order)) != count
            or len(target["imported_observations"]) != 1
            or path.name != "pool-journal.jsonl"
            or str(path) == stop["pool_journal"]["path"]
            or not any(
                path.is_relative_to(Path(root))
                for root in spec["controller_state_roots"]
            )
            or canonical_hash(grant) != target["migration_grant_sha256"]
            or target["recovery_plan"] != spec["expected_scope"]
            or grant["recovery_plan_sha256"] != spec["expected_scope"]["sha256"]
            or predecessor["pool_registration"] != old_host["pool_registration"]
            or predecessor["pool_journal"] != stop["pool_journal"]
            or predecessor["pool_head_sha256"] != frozen["journal_head"]
            or predecessor["quarantine_record"] != target["quarantine_record"]
        ):
            raise ValueError("target identity or predecessor")
        _pin(target["quarantine_record"])
        return target
    except (KeyError, ValueError, TypeError) as error:
        raise PermissionError(
            "pinned manual recovery target registration differs"
        ) from error


def _require_target_genesis(journal, target):
    from scripts.task13_pool_prepare import initial_pool_spent

    events = journal._events()
    state = journal.status()
    if len(events) != 1 or state["attempted"] or state["pending"] or state["stopped"]:
        raise PermissionError(
            "manual recovery target must remain exact single prepare genesis"
        )
    payload = events[0]["payload"]
    if (
        set(payload)
        != {
            "attempts",
            "imported_trial_id",
            "initial_spent_yuan",
            "imported_max_seconds",
            "policy",
            "migration_grant",
            "quarantined_predecessor",
        }
        or payload["attempts"]
        != [entry["trial_id"] for entry in target["attempt_order"]]
        or payload["imported_trial_id"]
        != target["imported_observations"][0]["trial_id"]
        or payload["policy"] != target["schema_version"]
        or payload["migration_grant"] != target["migration_grant"]
        or payload["quarantined_predecessor"] != target["quarantined_predecessor"]
        or payload["initial_spent_yuan"] != initial_pool_spent(target)
        or payload["imported_max_seconds"] != 384.562
    ):
        raise PermissionError("pinned manual recovery target genesis differs")


class RecoveryLease:
    """A live outer fence capability. Construction alone confers no ownership."""

    def __init__(self, spec, nonce, owned, journals):
        self.spec = spec
        self.nonce = nonce
        self.owned = owned
        self.journals = journals
        self.native = None
        self.evidence = None
        self.expected_target = None
        self._expected_target_sha256 = None
        self._spec_sha256 = canonical_hash(spec)

    def locked_audit(
        self, inputs=None, expected_evidence=None, *, expected_target=None
    ):
        """Return the strengthening callback used inside native registration."""
        spec = self.spec if inputs is None else inputs
        if expected_target is not None:
            from evals.timing_pool_startup_recovery import bind_expected_target

            bind_expected_target(self, expected_target)

        def check(*, db, controller_state_roots, owned_locks):
            _require_lease(self)
            require_native_lock_ownership(controller_state_roots, owned_locks)
            if not db.in_transaction or set(controller_state_roots) != set(
                self.spec["controller_state_roots"]
            ):
                raise PermissionError(
                    "native transaction or locked root coverage differs"
                )
            self.native = (controller_state_roots, owned_locks, db)
            try:
                value = audit_old_pool_locked(spec, lease=self)
                if expected_evidence is not None:
                    validate_quarantine_evidence(
                        expected_evidence, expected_scope=spec["expected_scope"]
                    )
                    if value != expected_evidence:
                        raise PermissionError("fresh quarantine audit differs")
                self.evidence = value
            finally:
                self.native = None

        return check


def _require_lease(lease):
    if (
        not isinstance(lease, RecoveryLease)
        or _ACTIVE_LEASES.get(id(lease)) is not lease
    ):
        raise PermissionError("live manual recovery lease required")
    if canonical_hash(lease.spec) != lease._spec_sha256:
        raise PermissionError("manual recovery lease spec changed")
    if (
        lease.expected_target is not None
        and canonical_hash(lease.expected_target) != lease._expected_target_sha256
    ):
        raise PermissionError("manual recovery target material changed")
    for path, owner in lease.owned.items():
        _require_owned_lock(path, owner)
    for journal, owner in lease.journals:
        if json.loads(journal.lock_path.read_bytes()) != owner:
            raise PermissionError("manual recovery lease pool ownership differs")


def _require_owned_lock(path, owner):
    try:
        require_plain_path(path, file=isinstance(owner, bytes))
        if isinstance(owner, tuple):
            valid = (
                path.is_dir()
                and (path.stat().st_dev, path.stat().st_ino) == owner
                and not any(path.iterdir())
            )
        else:
            valid = path.read_bytes() == owner
        if not valid:
            raise PermissionError("manual recovery lease lock ownership differs")
    except OSError as error:
        raise PermissionError("manual recovery lease lock ownership differs") from error


def _release_owned_lock(path, owner):
    _require_owned_lock(path, owner)
    path.rmdir() if isinstance(owner, tuple) else path.unlink()


def _sealed_additional_outputs(roots, spec, target):
    """Authenticate immutable worker outputs before choosing transient writes."""
    from evals.adapters.source_epochs import _additional_terminal

    sealed, entries = set(), set()
    for root in roots:
        for path in root.rglob("*"):
            require_plain_path(path, file=path.is_file())
            entries.add(path)
    for path in sorted(entries):
        if path.name in {
            ".pool-adoption-fence",
            "host-writer.lock",
            "pool-journal.jsonl.lock",
            ".writer-lock",
            ".analysis36-campaign-lock",
            ".rolling-adoption-lock",
        }:
            raise PermissionError(
                "manual recovery active or stale lock requires reconciliation"
            )
        if path.name == "started.json":
            start = json.loads(path.read_bytes())
            if any(
                key in start
                for key in ("schema_version", "registration_id", "registration_sha256")
            ):
                _additional_terminal(path.parent, start)
                sealed.add(path.parent)
    control_roots = set()
    for predecessor in _closed_predecessors(spec):
        host = _pin(predecessor["host"])
        control_roots.add(Path(host["journal_path"]).parent)
        for pin in host["hosts"].values():
            child_host = _pin(pin)
            if child_host.get("schema_version") != "task13-e-host-controller-v1":
                raise PermissionError("pinned predecessor host schema differs")
            control_roots.add(require_plain_path(child_host["output_dir"]))
    if target is not None:
        control_roots.add(Path(target["execution_journal_path"]).parent)
        control_roots.update(
            require_plain_path(child["evidence_root"]).parent
            for child in target["children"]
        )
    if not control_roots <= set(roots) or any(
        root.is_relative_to(output) for root in control_roots for output in sealed
    ):
        raise PermissionError(
            "pinned host or pool root coverage conflicts with sealed output"
        )
    if any(
        path.name in {"host-binding.json", "pool-journal.jsonl"}
        and any(path.is_relative_to(output) for output in sealed)
        for path in entries
    ):
        raise PermissionError(
            "host or pool control evidence conflicts with sealed output"
        )
    return sealed


def _closed_predecessors(spec):
    if spec["schema_version"] == "task13-manual-startup-recovery-lock-spec-v1":
        from evals.timing_pool_startup_recovery import closed_predecessors

        return closed_predecessors(spec)
    stop = _pin(spec["stop_evidence"])
    return [
        {
            "host": spec["pool_host_manifest"],
            "journal": stop["pool_journal"],
            "head": FROZEN["journal_head"],
            "pool_sha256": FROZEN["pool_sha256"],
            "schema": "task13-e-timing-pool-registration-v1",
        }
    ]


@contextmanager
def manual_recovery_quiescence(spec):
    """Hold all old host/pool locks; native locks remain owned by registration."""
    if os.getpid() == 1 or os.environ.get("TASK13_WORKER_NONCE"):
        raise PermissionError("manual recovery quarantine is host-only")
    spec = _spec(spec)
    nonce = secrets.token_hex(32)
    raw = json.dumps({"pid": os.getpid(), "nonce": nonce}).encode()
    owned, journals = {}, []
    roots = [Path(p) for p in spec["controller_state_roots"]]
    predecessors = {p["journal"]["path"]: p for p in _closed_predecessors(spec)}
    target = _target_registration(spec) if "target_pool_registration" in spec else None
    sealed = _sealed_additional_outputs(roots, spec, target)
    with ExitStack() as stack:
        for root in sorted(roots):
            fence = root / ".pool-adoption-fence"
            try:
                fence.mkdir()
            except FileExistsError as error:
                raise PermissionError(
                    "manual recovery adoption fence active or stale"
                ) from error
            identity = (fence.stat().st_dev, fence.stat().st_ino)
            stack.callback(_release_owned_lock, fence, identity)
            owned[fence] = identity
        for root in sorted(roots):
            if any(root.is_relative_to(output) for output in sealed):
                continue
            lock = root / "host-writer.lock"
            try:
                with lock.open("xb") as stream:
                    stream.write(raw)
            except FileExistsError as error:
                raise PermissionError(
                    "manual recovery host writer active or stale"
                ) from error
            stack.callback(_release_owned_lock, lock, raw)
            owned[lock] = raw
        found = set()
        for root in roots:
            for path in root.rglob("*"):
                require_plain_path(path, file=path.is_file())
                if path.name == "pool-journal.jsonl":
                    found.add(path)
        if not {Path(p) for p in predecessors} <= found:
            raise PermissionError("frozen pool omitted from locked roots")
        for path in sorted(found):
            if str(path) in predecessors:
                from evals.timing_pool import pool_policy

                predecessor = predecessors[str(path)]
                journal = PoolJournal(
                    path,
                    pool_sha256=predecessor["pool_sha256"],
                    policy=pool_policy(predecessor["schema"]),
                )
            elif target is not None and str(path) == target["execution_journal_path"]:
                from evals.timing_pool import pool_policy

                journal = PoolJournal(
                    path, pool_sha256=canonical_hash(target), policy=pool_policy(target)
                )
            else:
                raise PermissionError("unlisted or pending pool blocks manual recovery")
            owner = stack.enter_context(journal.lock(_adoption=True))
            journals.append((journal, owner))
            state = journal.status()
            if str(path) in predecessors:
                predecessor = predecessors[str(path)]
                expected_stop = (
                    "native_unknown"
                    if predecessor["schema"] == "task13-e-timing-pool-registration-v2"
                    else "unknown_native_execution"
                )
                if (
                    state["journal_head"] != predecessor["head"]
                    or state["pool_sha256"] != predecessor["pool_sha256"]
                    or sha256(path.read_bytes()).hexdigest()
                    != predecessor["journal"]["sha256"]
                    or not state["pending"]
                    or state["stopped"] != expected_stop
                ):
                    raise PermissionError("frozen unknown parent prefix differs")
            else:
                _require_target_genesis(journal, target)
        lease = RecoveryLease(spec, nonce, owned, journals)
        _ACTIVE_LEASES[id(lease)] = lease
        stack.callback(_ACTIVE_LEASES.pop, id(lease))
        _spec(spec)
        yield lease


def require_native_lock_ownership(controller_state_roots, owned_locks):
    active = _ACTIVE_CONTROLLER_LOCKS.get(id(owned_locks))
    if (
        active is None
        or active[0] is not owned_locks
        or active[1] != frozenset(controller_state_roots)
        or not all(
            path.is_dir()
            and not path.is_symlink()
            and not path.is_junction()
            and (path.stat().st_dev, path.stat().st_ino) == active[2].get(path)
            for path in owned_locks
        )
    ):
        raise PermissionError("live original native lock capability required")


def audit_old_pool_locked(inputs, *, lease):
    _require_lease(lease)
    if os.getpid() == 1 or os.environ.get("TASK13_WORKER_NONCE"):
        raise PermissionError("manual recovery audit is host-only")
    if lease.native is None:
        raise PermissionError("live original native lock capability required")
    require_native_lock_ownership(*lease.native[:2])
    if not lease.native[2].in_transaction:
        raise PermissionError("native immediate transaction required")
    spec = _spec(inputs)
    if spec != lease.spec:
        raise PermissionError("manual recovery lease spec differs")
    before = _tree_snapshot(spec["controller_state_roots"])
    try:
        if spec["schema_version"] == "task13-manual-startup-recovery-lock-spec-v1":
            from evals.timing_pool_startup_recovery import audit_startup_prefix

            evidence = audit_startup_prefix(spec, lease)
        else:
            evidence = _audit_prefix(spec, lease)
    except PermissionError:
        raise
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as error:
        raise PermissionError("manual quarantine evidence closure failed") from error
    _require_lease(lease)
    require_native_lock_ownership(*lease.native[:2])
    if before != _tree_snapshot(spec["controller_state_roots"]):
        raise PermissionError("old native raw evidence changed during quarantine audit")
    original_roots = [Path(p) for p in evidence["old_controller_state_roots"]]
    preserved = {
        name: digest
        for name, digest in before.items()
        if any(Path(name).is_relative_to(root) for root in original_roots)
    }
    evidence["preserved_files_sha256"] = canonical_hash(preserved)
    evidence["preserved_files"] = preserved
    return validate_quarantine_evidence(evidence, expected_scope=spec["expected_scope"])


def _tree_snapshot(roots):
    result = {}
    for root in roots:
        for path in Path(root).rglob("*"):
            require_plain_path(path, file=path.is_file())
            if path.is_file() and path.name not in {
                "host-writer.lock",
                "pool-journal.jsonl.lock",
            }:
                if path.parent.name == ".pool-adoption-fence":
                    continue
                result[str(path)] = sha256(path.read_bytes()).hexdigest()
    return result


def _check_preserved_files(files, digest):
    if not isinstance(files, dict) or not files or canonical_hash(files) != digest:
        raise PermissionError("complete preserved raw file map required")
    for name, expected in files.items():
        try:
            path = require_plain_path(name, file=True)
            if sha256(path.read_bytes()).hexdigest() != expected:
                raise PermissionError("preserved old raw bytes changed")
        except OSError as error:
            raise PermissionError("preserved old raw file missing") from error


def _native_untouched(view):
    if (
        len(view.events) != 1
        or len(view.trials) != 3
        or len(view.records) != 18
        or any(
            row.get("status") != "not_started" or row.get("binding")
            for row in view.trials.values()
        )
        or any(
            row.get("status") != "not_started"
            or row.get("review_pending")
            or any(
                row.get(k)
                for k in (
                    "input_sha256",
                    "output_sha256",
                    "started_at",
                    "completed_at",
                    "worker_nonce",
                    "binding",
                )
            )
            for row in view.records.values()
        )
    ):
        raise PermissionError(
            "manual quarantine requires untouched native trials and branches"
        )
    return {"trials": 3, "branches": 18, "events": 1}


def _require_original_budget_transaction(db, path):
    databases = db.execute("PRAGMA database_list").fetchall()
    main = [row[2] for row in databases if row[1] == "main"]
    if (
        not db.in_transaction
        or len(main) != 1
        or not main[0]
        or Path(main[0]).resolve() != path.resolve()
    ):
        raise PermissionError(
            "native audit transaction requires the original budget file"
        )


def _container_absent(container):
    if (
        not isinstance(container, str)
        or re.fullmatch("[0-9a-f]{64}", container) is None
    ):
        raise PermissionError("owned container identity required")
    argv = [
        "docker",
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        "id=" + container,
        "--format",
        "{{.ID}}",
    ]
    try:
        result = subprocess.run(argv, capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PermissionError("fresh owned worker absence is unknown") from error
    if result.returncode != 0 or result.stdout.strip() or result.stderr.strip():
        raise PermissionError(
            "owned worker absence is unknown or worker remains active"
        )
    return {
        "argv": argv,
        "returncode": 0,
        "stdout_sha256": sha256(result.stdout).hexdigest(),
        "stderr_sha256": sha256(result.stderr).hexdigest(),
    }


def _audit_prefix(spec, lease):
    from evals.adapters.e_planning_review import (
        build_review_request,
        validate_review_state,
    )
    from evals.adapters.e_planning_worker import _claim_binding
    from evals.timing_pool import (
        _archive_context,
        _json,
        _load_host_inputs,
        _validate_approval_semantics,
        _validate_host_semantics,
        _validate_runtime_capture,
        _validate_source_semantics,
        _view,
        validate_migration_marker,
        validate_pool_registration,
    )
    from evals.timing_pool_controller import validate_pool_journal_evidence
    from evals.timing_pool_evidence import _ledger, _native_read_matches

    manifest = _pin(spec["pool_host_manifest"])
    stop, fee = _pin(spec["stop_evidence"]), _pin(spec["fee_audit"])
    pool = validate_pool_registration(_pin(manifest["pool_registration"]))
    if canonical_hash(pool) != FROZEN["pool_sha256"]:
        raise PermissionError("original pool registration identity differs")
    parent = {**stop["pool_journal"], "head_sha256": FROZEN["journal_head"]}
    transcript = validate_pool_journal_evidence({"pool_journal": parent}, pool)
    events, state = transcript["events"], transcript["state"]
    expected = [
        ("prepare", None),
        ("begin", None),
        ("phase_claim", "plan"),
        ("phase_finish", "plan"),
        ("phase_claim", "read"),
        ("phase_finish", "read"),
        ("phase_claim", "decision"),
        ("phase_finish", "decision"),
        ("phase_claim", "trial"),
        ("stop", None),
    ]
    if (
        [(e["kind"], e["payload"].get("phase")) for e in events] != expected
        or state["pending"] != TRIAL_ID
        or state["stopped"] != "unknown_native_execution"
        or state["qualified"] != 1
        or state["attempted"] != 1
        or transcript["settlements"]
        or any(e["payload"].get("trial_id", TRIAL_ID) != TRIAL_ID for e in events)
        or events[6]["payload"]["packet_sha256"] != PACKET_SHA256
        or events[6]["payload"]["chat_record"] != stop["actual_plan_approval"]
        or stop["actual_plan_approval"]["sha256"] != APPROVAL_SHA256
    ):
        raise PermissionError(
            "only the exact frozen unknown parent prefix may be quarantined"
        )
    contexts, natives = {}, []
    parent_packets, parent_decisions = [], []
    for child in pool["children"]:
        host = _pin(manifest["hosts"][child["child_id"]])
        view = _view(child["evidence_root"])
        inputs = _load_host_inputs(view, host)
        if (
            view.registration != child["registration"]
            or inputs["pool_authority"] != pool
        ):
            raise PermissionError("original native child membership differs")
        counts = _native_untouched(view)
        context = _validate_host_semantics(view, host, inputs)
        if not set(context["epoch"]["controller_state_roots"]) <= set(
            spec["controller_state_roots"]
        ):
            raise PermissionError("manual quarantine omitted an original native root")
        contexts[child["child_id"]] = (context, view)
        natives.append(
            {
                "root": str(view.root),
                "registration_sha256": canonical_hash(view.registration),
                **counts,
            }
        )
        parent_packets.append(host["inputs"]["scope_packet"])
        parent_decisions.append(host["inputs"]["scope_decision"])
    if (
        len({canonical_hash(p) for p in parent_packets}) != 1
        or len({canonical_hash(p) for p in parent_decisions}) != 1
    ):
        raise PermissionError(
            "original children lack one exact original scope decision"
        )
    validate_migration_marker(
        _pin(manifest["migration_marker"]), pool, parent_packets[0], parent_decisions[0]
    )
    context, view = contexts[pool["attempt_order"][0]["child_id"]]
    _require_original_budget_transaction(lease.native[2], context["budget_path"])
    request = next(r for r in context["reader"]._requests if r.trial_id == TRIAL_ID)
    if context["claims"][TRIAL_ID]["status"] != "started":
        raise PermissionError("original planning append claim missing")
    for other, _ in contexts.values():
        for candidate in other["reader"]._requests:
            slot = other["reader"]._root / "slots" / candidate.planning_slot_id
            if candidate.trial_id != TRIAL_ID and (
                other["claims"][candidate.trial_id]["status"] != "unclaimed"
                or slot.exists()
                and any(slot.iterdir())
            ):
                raise PermissionError("later native planning work exists")
    root = context["reader"]._root
    slot = root / "slots" / request.planning_slot_id
    plan, started = (
        _json(slot / "plan-terminal.json"),
        _json(slot / "plan-started.json"),
    )
    decision, decided_start = (
        _json(slot / "decision-terminal.json"),
        _json(slot / "decision-started.json"),
    )
    if (
        plan["status"] != "awaiting_approval"
        or decision["status"] != "approved"
        or plan["start_sha256"] != canonical_hash(started)
        or started["request"] != request.model_dump(mode="json")
        or started["request_sha256"] != canonical_hash(request)
        or started["manifest_sha256"]
        != sha256((root / "host-binding.json").read_bytes()).hexdigest()
        or decision["start_sha256"] != canonical_hash(decided_start)
        or (slot / "trial-started.json").exists()
        or (slot / "trial-terminal.json").exists()
    ):
        raise PermissionError(
            "original planning/decision origin or zero dispatch differs"
        )
    runtime, resources, retained = (
        _pin(plan[k]) for k in ("runtime_result", "resources", "retained_state")
    )
    _validate_runtime_capture(
        runtime, plan, context["reader"]._inputs["runtime_options"], request
    )
    rows = _ledger(context, request, runtime)
    if (
        len(rows) != 3
        or _pin(plan["provenance"]) != retained["analysis_import_provenance"]
    ):
        raise PermissionError(
            "original three physical planning attempts or provenance differs"
        )
    decided, chat = _pin(decision["runtime_result"]), _pin(decision["chat_record"])
    if chat != _pin(stop["actual_plan_approval"]):
        raise PermissionError("original actual plan approval differs")
    source = context["reader"]._source(
        request, decided["source"]["state"], retained, resources
    )
    _validate_source_semantics(view, view.trials[TRIAL_ID], source)
    review = build_review_request(request, resources, operation="read_packet")
    validate_review_state(
        review,
        source["state"],
        context["imported"],
        _claim_binding(request, context["claims"][TRIAL_ID]),
    )
    _validate_approval_semantics(
        context,
        view.trials[TRIAL_ID],
        source,
        chat,
        decided_start,
        decided,
        _archive_context({}),
        approved_before=events[8]["payload"]["quiescence"]["inspected_at"],
        historical_direct_capture=stop["actual_plan_approval"],
    )
    if source["state"]["response_plan"][
        "response_plan_id"
    ] != PLAN_ID or not _native_read_matches(
        context, request, events[5]["payload"]["result_sha256"]
    ):
        raise PermissionError("original plan/read packet closure differs")
    for terminal, finish_index in ((plan, 3), (decision, 7)):
        if canonical_hash(terminal) != events[finish_index]["payload"]["result_sha256"]:
            raise PermissionError("original parent/native phase finish differs")
    fresh = _fresh_retained_state(review)
    if (
        fresh["state"] != source["state"]
        or fresh["approval_receipt"] != decided["approval_receipt"]
    ):
        raise PermissionError("fresh actual approval/checkpoint state drifted")
    workers = _workers_absent(contexts, runtime, decided)
    fees = _fees(contexts, manifest, fee, rows, request)
    return {
        "schema_version": "task13-manual-pool-quarantine-v1",
        "status": "quarantined_unknown_prefix",
        "authority": False,
        "timing_credit": 0,
        "expected_scope": spec["expected_scope"],
        "pool_host_manifest": spec["pool_host_manifest"],
        "stop_evidence": spec["stop_evidence"],
        "fee_audit": spec["fee_audit"],
        "parent_journal": {**parent, "event_count": 10},
        "native_journals": natives,
        "old_controller_state_roots": context["epoch"]["controller_state_roots"],
        "legacy_identity": {
            "epoch_id": request.epoch_id,
            "epoch_manifest_sha256": request.epoch_manifest_sha256,
            "model_epoch_id": request.model_identity_binding.model_epoch_id,
            "model_identity_sha256": request.model_identity_binding.model_identity_sha256,
        },
        "planning": {
            "trial_id": TRIAL_ID,
            "plan_id": PLAN_ID,
            "packet_sha256": PACKET_SHA256,
            "actual_approval_sha256": APPROVAL_SHA256,
            "actual_cny": str(sum((r["actual"] for r in rows), Decimal(0))),
            "reservation_ids": [r["reservation_id"] for r in rows],
            "approved_state_sha256": canonical_hash(source["state"]),
        },
        "fees": fees,
        "workers": workers,
    }


def _fresh_retained_state(review):
    from evals.host_review import read_retained_review_state

    return asyncio.run(read_retained_review_state(review))


def _workers_absent(contexts, planning_runtime, decision_runtime):
    workers = []
    for phase, runtime in (("plan", planning_runtime), ("decision", decision_runtime)):
        container = runtime["isolation_evidence"]["container"]["container_id"]
        workers.append(
            {
                "phase": phase,
                "container_id": container,
                "runtime_sha256": canonical_hash(runtime),
                "inspection": _container_absent(container),
            }
        )
    known = {w["container_id"] for w in workers}
    for context, _ in contexts.values():
        for path in sorted(context["reader"]._termination.glob("*/*.json")):
            value = _pin(
                {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}
            )
            if (
                value.get("status") != "verified"
                or value.get("host_process_exited") is not True
                or value.get("container_absent") is not True
            ):
                raise PermissionError("unknown original native worker lifecycle")
            container = value["container_id"]
            if container not in known:
                workers.append(
                    {
                        "phase": "native_termination",
                        "container_id": container,
                        "runtime_sha256": canonical_hash(value),
                        "inspection": _container_absent(container),
                    }
                )
                known.add(container)
    return workers


def _fees(contexts, manifest, fee, rows, request):
    from scripts.task13_timing_pool import NativePoolController

    budgets = {str(c["budget_path"]) for c, _ in contexts.values()}
    if len(budgets) != 1:
        raise PermissionError("manual quarantine split the original budget")
    path = Path(next(iter(budgets)))
    checker = object.__new__(NativePoolController)
    checker.budget_path, checker.manifest = path, manifest
    checker.budget()  # Existing original config, global unknown and settled-only guards.
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        physical = db.execute(
            "SELECT s.*,r.actual,r.settled,e.epoch_id,m.model_epoch_id,m.identity_manifest_sha256 FROM supplement_requests s JOIN reservations r ON s.reservation_id=r.id LEFT JOIN supplement_request_epochs e ON e.reservation_id=s.reservation_id LEFT JOIN supplement_request_models m ON m.reservation_id=s.reservation_id ORDER BY s.reservation_id"
        ).fetchall()
        actual = db.execute(
            "SELECT s.reservation_id,r.actual,s.request_id,s.role,s.purpose,r.settled FROM supplement_requests s JOIN reservations r ON s.reservation_id=r.id ORDER BY s.reservation_id"
        ).fetchall()
        original = db.execute(
            "SELECT rowid,* FROM reservations ORDER BY rowid"
        ).fetchall()
        config = db.execute("SELECT key,value FROM config ORDER BY key").fetchall()
        epoch_rows = db.execute(
            "SELECT s.reservation_id FROM supplement_requests s JOIN supplement_request_epochs e ON e.reservation_id=s.reservation_id WHERE e.epoch_id=? AND s.purpose='development'",
            (request.epoch_id,),
        ).fetchall()
    if (
        len(actual) != 77
        or any(r[1] is None or r[5] != 1 for r in actual)
        or {r[0] for r in epoch_rows} != {r["reservation_id"] for r in rows}
    ):
        raise PermissionError(
            "unknown, in-flight or unreported supplement physical attempts"
        )
    total = sum((Decimal(str(r[1])) for r in actual), Decimal(0))
    expected = {r["reservation_id"]: r for r in fee["last_three_reservations"]}
    if (
        str(total) != fee["total_supplement_actual_cny"]
        or total != Decimal("0.7273648000000000039")
        or fee["supplement_row_count"] != 77
        or fee["settled_supplement_rows"] != 77
        or fee["unknown_or_inflight_supplement_rows"] != 0
        or fee["legacy_original_unknown_count"] != 2
        or set(expected) != {r["reservation_id"] for r in rows}
        or sum((r["actual"] for r in rows), Decimal(0)) != Decimal("0.04363624")
    ):
        raise PermissionError("frozen original supplement fee audit differs")
    for row in actual:
        if row[0] in expected:
            item = expected[row[0]]
            if (
                Decimal(str(item["actual_cny"])) != Decimal(str(row[1]))
                or (item["request_id"], item["role"], item["purpose"], item["settled"])
                != row[2:]
            ):
                raise PermissionError(
                    "last three original physical fee attribution differs"
                )
    return {
        "row_count": 77,
        "total_actual_cny": str(total),
        "legacy_unknown_count": 2,
        "config_sha256": canonical_hash(config),
        "reservations_sha256": canonical_hash(original),
        "physical_rows_sha256": canonical_hash(physical),
        "reservation_ids": [r[0] for r in actual],
        "original_reservation_count": len(original),
        "original_reservation_max_rowid": original[-1][0],
    }


def _validate_worker_inspections(workers):
    try:
        phases = [w["phase"] for w in workers]
        if phases.count("plan") != 1 or phases.count("decision") != 1:
            raise ValueError("owned phases")
        for worker in workers:
            if (
                set(worker) != {"phase", "container_id", "runtime_sha256", "inspection"}
                or worker["phase"] not in {"plan", "decision", "native_termination"}
                or re.fullmatch("[0-9a-f]{64}", worker["container_id"]) is None
                or re.fullmatch("[0-9a-f]{64}", worker["runtime_sha256"]) is None
                or worker["inspection"]
                != {
                    "argv": [
                        "docker",
                        "container",
                        "ls",
                        "--all",
                        "--no-trunc",
                        "--filter",
                        "id=" + worker["container_id"],
                        "--format",
                        "{{.ID}}",
                    ],
                    "returncode": 0,
                    "stdout_sha256": sha256(b"").hexdigest(),
                    "stderr_sha256": sha256(b"").hexdigest(),
                }
            ):
                raise ValueError("absence record")
    except (KeyError, ValueError, TypeError) as error:
        raise PermissionError("invalid original owned worker absence proof") from error


def _validate_preserved_raw(evidence):
    """Historical baseline only: new-epoch paid rows may append after adoption."""
    from evals.timing_pool import _json, _view

    manifest = _pin(evidence["pool_host_manifest"])
    pool = _pin(manifest["pool_registration"])
    parent = evidence["parent_journal"]
    if (
        parent["path"] != pool["execution_journal_path"]
        or sha256(
            require_plain_path(parent["path"], file=True).read_bytes()
        ).hexdigest()
        != parent["sha256"]
    ):
        raise PermissionError("original quarantined parent raw bytes changed")
    journal = PoolJournal(parent["path"], pool_sha256=FROZEN["pool_sha256"])
    if journal._events()[-1]["sha256"] != FROZEN["journal_head"]:
        raise PermissionError("original quarantined parent head changed")
    expected_native = []
    for child in pool["children"]:
        view = _view(child["evidence_root"])
        if view.registration != child["registration"]:
            raise PermissionError("original quarantined native registration changed")
        expected_native.append(
            {
                "root": str(view.root),
                "registration_sha256": canonical_hash(view.registration),
                **_native_untouched(view),
            }
        )
    if evidence["native_journals"] != expected_native:
        raise PermissionError("original quarantined native baseline differs")
    formal = pool["formal_binding"]
    expected = {
        "epoch_id": formal["epoch_id"],
        "epoch_manifest_sha256": formal["epoch_manifest_sha256"],
        **formal["model_identity_binding"],
    }
    if evidence["legacy_identity"] != expected:
        raise PermissionError("original source/model identity differs")
    child = next(
        c
        for c in pool["children"]
        if c["child_id"] == pool["attempt_order"][0]["child_id"]
    )
    host = _pin(manifest["hosts"][child["child_id"]])
    inputs = {key: _pin(value) for key, value in host["inputs"].items()}
    from evals.e_planning import planning_requests

    request = next(
        r
        for r in planning_requests(inputs["planning_registration"])
        if r.trial_id == TRIAL_ID
    )
    slot = Path(host["output_dir"]) / "slots" / request.planning_slot_id
    for phase in ("plan", "decision"):
        runtime = _pin(_json(slot / (phase + "-terminal.json"))["runtime_result"])
        worker = next(w for w in evidence["workers"] if w["phase"] == phase)
        if worker["container_id"] != runtime["isolation_evidence"]["container"][
            "container_id"
        ] or worker["runtime_sha256"] != canonical_hash(runtime):
            raise PermissionError("original owned worker identity differs")
    path = Path(inputs["runtime_options"]["budget_dir"]) / "campaign.sqlite"
    from evals.adapters.source_epochs import require_registered_epoch

    old_epoch = require_registered_epoch(
        path,
        request.epoch_id,
        source_sha256=request.source_sha256,
        config_sha256=request.config_sha256,
        manifest_sha256=request.epoch_manifest_sha256,
        latest=False,
    )
    if evidence["old_controller_state_roots"] != old_epoch["controller_state_roots"]:
        raise PermissionError("original native controller root set changed")
    if any(
        not any(
            Path(name).is_relative_to(Path(root))
            for root in old_epoch["controller_state_roots"]
        )
        for name in evidence["preserved_files"]
    ):
        raise PermissionError("preserved file outside original native roots")
    _check_fee_baseline(
        path, evidence["fees"], legacy_identity=evidence["legacy_identity"]
    )


def _check_fee_baseline(path, fees, *, legacy_identity=None):
    """Keep exact old rows while allowing independently authorized new appends."""
    ids = fees["reservation_ids"]
    if len(ids) != 77 or len(set(ids)) != 77:
        raise PermissionError("complete original physical baseline required")
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        config = db.execute("SELECT key,value FROM config ORDER BY key").fetchall()
        physical = db.execute(
            "SELECT s.*,r.actual,r.settled,e.epoch_id,m.model_epoch_id,m.identity_manifest_sha256 FROM supplement_requests s JOIN reservations r ON s.reservation_id=r.id LEFT JOIN supplement_request_epochs e ON e.reservation_id=s.reservation_id LEFT JOIN supplement_request_models m ON m.reservation_id=s.reservation_id WHERE s.reservation_id IN ("
            + ",".join("?" for _ in ids)
            + ") ORDER BY s.reservation_id",
            ids,
        ).fetchall()
        original = db.execute(
            "SELECT rowid,* FROM reservations WHERE rowid<=? ORDER BY rowid",
            (fees["original_reservation_max_rowid"],),
        ).fetchall()
        added = db.execute(
            "SELECT s.reservation_id,r.actual,r.settled,e.epoch_id,m.model_epoch_id,m.identity_manifest_sha256,s.source_sha256,s.config_sha256,s.purpose FROM supplement_requests s JOIN reservations r ON s.reservation_id=r.id LEFT JOIN supplement_request_epochs e ON e.reservation_id=s.reservation_id LEFT JOIN supplement_request_models m ON m.reservation_id=s.reservation_id WHERE s.reservation_id NOT IN ("
            + ",".join("?" for _ in ids)
            + ") ORDER BY s.reservation_id",
            ids,
        ).fetchall()
        _validate_new_fee_rows(db, added, legacy_identity)
    if (
        canonical_hash(config) != fees["config_sha256"]
        or canonical_hash(physical) != fees["physical_rows_sha256"]
        or len(original) != fees["original_reservation_count"]
        or canonical_hash(original) != fees["reservations_sha256"]
    ):
        raise PermissionError("original physical/config/reservation baseline changed")


def _validate_new_fee_rows(db, rows, legacy_identity):
    """Reject all historical identities using native verified registry chains."""
    if not rows:
        return
    from evals.adapters.model_identities import _chain as model_chain
    from evals.adapters.source_epochs import _chain as source_chain

    try:
        sources, _ = source_chain(db)
        models, _ = model_chain(db)
        sources = {m["epoch_id"]: m for m in sources}
        models = {m["model_epoch_id"]: m for m in models}
        original_source = sources[legacy_identity["epoch_id"]]
        original_model = models[legacy_identity["model_epoch_id"]]
        if (
            canonical_hash(original_source) != legacy_identity["epoch_manifest_sha256"]
            or canonical_hash(original_model)
            != legacy_identity["model_identity_sha256"]
            or original_model["epoch_id"] != original_source["epoch_id"]
        ):
            raise ValueError("original registry boundary differs")
        for (
            reservation,
            actual,
            settled,
            epoch_id,
            model_id,
            model_sha,
            source_sha,
            config_sha,
            purpose,
        ) in rows:
            source, model = sources[epoch_id], models[model_id]
            amount = Decimal(str(actual))
            if (
                not reservation
                or settled != 1
                or not amount.is_finite()
                or amount < 0
                or source["epoch_number"] <= original_source["epoch_number"]
                or model["model_epoch_number"] <= original_model["model_epoch_number"]
                or model["epoch_id"] != epoch_id
                or canonical_hash(model) != model_sha
                or model["source_manifest_sha256"] != canonical_hash(source)
                or (source["source_sha256"], source["config_sha256"])
                != (source_sha, config_sha)
                or purpose not in model["purposes"]
            ):
                raise ValueError("new fee source/model/settlement differs")
    except (KeyError, ValueError, TypeError, sqlite3.Error, InvalidOperation) as error:
        raise PermissionError(
            "new fee rows require new registered source/model identities and settled cost"
        ) from error


def fresh_quarantine_workers_absent(evidence):
    """Fresh read-only daemon guard; async callers must use asyncio.to_thread."""
    value = validate_quarantine_evidence(
        evidence, expected_scope=evidence["expected_scope"]
    )
    if value.get("schema_version") == "task13-manual-startup-pool-quarantine-v1":
        from evals.timing_pool_startup_recovery import fresh_startup_workers_absent

        startup = fresh_startup_workers_absent(_pin(value["stop_evidence"]))
        older = fresh_quarantine_workers_absent(_pin(value["older_quarantine"]))
        return {
            "schema_version": "task13-startup-quarantine-worker-absence-v1",
            "status": "verified",
            "startup": startup,
            "older": older,
        }
    return {
        "schema_version": "task13-manual-quarantine-worker-absence-v1",
        "status": "verified",
        "workers": [
            {
                "container_id": worker["container_id"],
                "inspection": _container_absent(worker["container_id"]),
            }
            for worker in value["workers"]
        ],
    }


def validate_quarantine_evidence(evidence, *, expected_scope):
    """Validate the independent proof schema; never infer adoption or TTL credit."""
    if (
        isinstance(evidence, dict)
        and evidence.get("schema_version") == "task13-manual-startup-pool-quarantine-v1"
    ):
        from evals.timing_pool_startup_recovery import validate_startup_quarantine

        try:
            return validate_startup_quarantine(evidence, expected_scope=expected_scope)
        except (
            ValueError,
            KeyError,
            TypeError,
            OSError,
            sqlite3.Error,
            InvalidOperation,
        ) as error:
            raise PermissionError(
                "invalid independent startup quarantine evidence"
            ) from error
    required = {
        "schema_version",
        "status",
        "authority",
        "timing_credit",
        "expected_scope",
        "pool_host_manifest",
        "stop_evidence",
        "fee_audit",
        "parent_journal",
        "native_journals",
        "old_controller_state_roots",
        "legacy_identity",
        "planning",
        "fees",
        "workers",
        "preserved_files_sha256",
        "preserved_files",
    }
    try:
        if (
            set(evidence) != required
            or evidence["schema_version"] != "task13-manual-pool-quarantine-v1"
            or evidence["status"] != "quarantined_unknown_prefix"
            or evidence["authority"] is not False
            or type(evidence["timing_credit"]) is not int
            or evidence["timing_credit"] != 0
            or evidence["expected_scope"] != expected_scope
        ):
            raise ValueError("schema or scope")
        _pin(expected_scope)
        for name in ("pool_host_manifest", "stop_evidence", "fee_audit"):
            if evidence[name]["sha256"] != FROZEN[name]:
                raise ValueError("frozen proof anchor")
            _pin(evidence[name])
        if (
            evidence["parent_journal"]["head_sha256"] != FROZEN["journal_head"]
            or evidence["parent_journal"]["event_count"] != 10
            or len(evidence["native_journals"]) != 2
            or any(
                any(
                    n[k] != v
                    for k, v in (("trials", 3), ("branches", 18), ("events", 1))
                )
                for n in evidence["native_journals"]
            )
            or evidence["planning"]["trial_id"] != TRIAL_ID
            or evidence["planning"]["plan_id"] != PLAN_ID
            or evidence["planning"]["packet_sha256"] != PACKET_SHA256
            or evidence["planning"]["actual_approval_sha256"] != APPROVAL_SHA256
            or Decimal(evidence["planning"]["actual_cny"]) != Decimal("0.04363624")
            or len(set(evidence["planning"]["reservation_ids"])) != 3
            or evidence["fees"]["row_count"] != 77
            or evidence["fees"]["legacy_unknown_count"] != 2
            or Decimal(evidence["fees"]["total_actual_cny"])
            != Decimal("0.7273648000000000039")
            or len(evidence["workers"]) < 2
            or not {"plan", "decision"} <= {w["phase"] for w in evidence["workers"]}
        ):
            raise ValueError("frozen quarantine facts")
        json.dumps(evidence, allow_nan=False)
        _validate_worker_inspections(evidence["workers"])
        _check_preserved_files(
            evidence["preserved_files"], evidence["preserved_files_sha256"]
        )
        _validate_preserved_raw(evidence)
        return json.loads(json.dumps(evidence))
    except (
        ValueError,
        KeyError,
        TypeError,
        OSError,
        sqlite3.Error,
        InvalidOperation,
    ) as error:
        raise PermissionError(
            "invalid independent manual quarantine evidence"
        ) from error
