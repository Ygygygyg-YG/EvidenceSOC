"""Closed host-only audit of the one frozen pre-GO startup-unknown predecessor.

No source adoption, native execution, fee settlement, TTL or approval credit is
conferred by this module. Both unknown parents remain immutable.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sqlite3
import subprocess
from collections import Counter
from hashlib import sha256
from pathlib import Path

from evals.contracts import canonical_hash

STARTUP_FROZEN = {
    "pool_host_manifest": "3fd4cda4f984ee7c9df876886d413702f1b65f0d306aeaa15fde711d0293ea1b",
    "stop_evidence": "8e081d52624c26b411d50d400e15cdfabb7d1a363c6ec7c347c4bbcd089514e0",
    "fee_audit": "a9f7d61d50d2c4e832eb1af631135ef8d0bb93950de0fa3e0b5f58cc86ff3b3c",
    "journal_head": "39be936e93a21e627e33deb4d8b8cbc215379b3629454cefb697fe1f454b0bf5",
    "pool_sha256": "d5987cec9dc8b89e711a9ccd5832dba3780f031a4d168eb1016bb5a857cc7b69",
    "materialization": "f5827abd166748c5bbe0c9f00bb16a959cdb99e9db83c8ada68b4a74f4aa4127",
    "preparation": "1d1b4574d886978a7bfa5366a214d23b46eb57fd33485722db1b14992a30e330",
}
STARTUP_TRIAL = "36c027576170c1e4f6f971261a7085f6"
ROWID_BASELINE_SHA256 = (
    "883abb64f1babc0374ab6a731e1d06074aac9d0aa5e1bc997b096a79cc5512a7"
)
STARTUP_QUARANTINE_SCHEMA = "task13-manual-startup-pool-quarantine-v1"
STARTUP_LOCK_SCHEMA = "task13-manual-startup-recovery-lock-spec-v1"


def _require(value, message):
    if not value:
        raise PermissionError(message)


def validate_startup_shape(stop, pool, events, started, terminal, failure):
    """Derive the consumed attempt from immutable v2 policy and exact five events."""
    from evals.timing_pool import RECOVERY_REGISTRATION_SCHEMA, pool_policy

    policy = pool_policy(pool)
    grant = pool["migration_grant"]
    _require(
        policy.registration_schema == RECOVERY_REGISTRATION_SCHEMA
        and grant["consumed_logical"] == 8
        and grant["consumed_physical"] == 24
        and grant["remaining_logical"] == 5
        and grant["remaining_physical"] == 15
        and policy.future_logical_limit == 5
        and policy.future_physical_limit == 15
        and len(pool["attempt_order"]) == 5
        and stop["trial_id"] == STARTUP_TRIAL
        and pool["attempt_order"][0]["trial_id"] == STARTUP_TRIAL
        and [(e["kind"], e["payload"].get("phase")) for e in events]
        == [
            ("prepare", None),
            ("begin", None),
            ("phase_claim", "plan"),
            ("phase_finish", "plan"),
            ("stop", None),
        ]
        and all(
            e["payload"].get("trial_id", STARTUP_TRIAL) == STARTUP_TRIAL for e in events
        )
        and events[-1]["payload"] == {"reason": "native_unknown"}
        and terminal
        == {
            "status": "unknown",
            "error_type": "WorkerInfrastructureError",
            "start_sha256": canonical_hash(started),
        }
        and events[3]["payload"]["result_sha256"] == canonical_hash(terminal)
        and started["operation"] == "plan"
        and started["request"]["trial_id"] == STARTUP_TRIAL
        and started["request_sha256"] == canonical_hash(started["request"])
        and failure["schema_version"] == "task13-worker-startup-failure-v1"
        and failure["go_authorized"] is False
        and failure["error_type"] == "WorkerInfrastructureError"
        and failure["stage"] == "waiting_probe"
        and failure["worker_failure"]
        == {
            "stage": "worker_probe",
            "category": "infrastructure",
            "error_type": "OSError",
        }
        and failure["request_sha256"] == started["request_sha256"]
        and failure["container_name"]
        == "task13-worker-85a13281a9f14d1191c105f2fa758655"
        and stop["unknown_preserved"] is True
        and stop["no_actual_plan_or_trial_approval"] is True,
        "only the exact frozen pre-GO startup-unknown prefix is eligible",
    )
    remaining = policy.future_logical_limit - 1
    return {
        "original_consumed_logical": grant["consumed_logical"],
        "original_consumed_physical": grant["consumed_physical"],
        "failed_attempts": 1,
        "failed_attempt_physical_upper_bound": 3,
        "consumed_logical": grant["consumed_logical"] + 1,
        "consumed_physical": grant["consumed_physical"] + 3,
        "remaining_logical": remaining,
        "remaining_physical": remaining * 3,
        "charged_requests": 0,
        "actual_cny": "0",
    }


def connection_snapshot(db):
    """Full native SQL state including rowids, using SELECT statements only."""
    schema = db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ).fetchall()
    tables, rowids = {}, {}
    for kind, name, _, definition in schema:
        if kind != "table":
            continue
        quoted = '"' + name.replace('"', '""') + '"'
        encode = lambda row: json.dumps(row, default=lambda value: {"hex": value.hex()})
        tables[name] = sorted(map(encode, db.execute("SELECT * FROM " + quoted)))
        if "WITHOUT ROWID" not in (definition or "").upper():
            rowids[name] = sorted(
                map(encode, db.execute("SELECT rowid,* FROM " + quoted))
            )
    return {"schema": [list(row) for row in schema], "tables": tables, "rowids": rowids}


def validate_sql_prefix(db, baseline, *, expected_target=None):
    """Keep every old row and rowid; permit only exact compiled source/model appends."""
    allowed = {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
        sqlite3.SQLITE_RECURSIVE,
    }
    changes = db.total_changes
    db.set_authorizer(
        lambda action, *_: (
            sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY
        )
    )
    try:
        current = connection_snapshot(db)
    finally:
        db.set_authorizer(None)
    _require(
        db.total_changes == changes, "startup SQL audit mutated the native transaction"
    )
    _require(current["schema"] == baseline["schema"], "original SQL schema changed")
    if expected_target is None:
        _require(current == baseline, "original SQL rows or rowids changed")
        return (False, False)
    from scripts.task13_pool_prepare import validate_epoch_prefix

    prefix = validate_epoch_prefix(
        {key: baseline[key] for key in ("schema", "tables")},
        {key: current[key] for key in ("schema", "tables")},
        expected_target,
    )
    _require(
        current["rowids"].keys() == baseline["rowids"].keys(),
        "original SQL rowid tables changed",
    )
    for name, old in baseline["rowids"].items():
        now = current["rowids"][name]
        _require(
            not Counter(old) - Counter(now), "original SQL rowid changed or removed"
        )
        extra = list((Counter(now) - Counter(old)).elements())
        if extra:
            _require(
                name in {"supplement_source_epochs", "supplement_model_epochs"}
                and len(extra) == 1,
                "unrelated original SQL rowid appended",
            )
            expected = max((json.loads(row)[0] for row in old), default=0) + 1
            _require(json.loads(extra[0])[0] == expected, "new metadata rowid differs")
    return prefix


def _rowid_baseline(fee):
    from evals.timing_pool_recovery import _pin

    path = Path(fee["budget_baseline_sql"]["path"]).with_name(
        "startup-budget-baseline-rowids.json"
    )
    value = _pin({"path": str(path), "sha256": ROWID_BASELINE_SHA256})
    _require(
        value["budget_path"] == fee["budget_path"]
        and value["budget_raw_sha256"] == fee["budget_raw_sha256"],
        "original rowid baseline identity differs",
    )
    baseline = value["snapshot"]
    _require(
        {key: baseline[key] for key in ("schema", "tables")}
        == _pin(fee["budget_baseline_sql"]),
        "original rowid baseline differs from frozen SQL baseline",
    )
    return baseline


def bind_expected_target(lease, target):
    """Seal exact root-compiled material once; never accept a table whitelist."""
    from evals.timing_pool_recovery import _pin, _require_lease

    _require_lease(lease)
    _require(
        lease.spec["schema_version"] == STARTUP_LOCK_SCHEMA,
        "target SQL append capability is restricted to startup v3",
    )
    value = json.loads(json.dumps(target, allow_nan=False))
    preparation = _pin(value["preparation"])
    _require(
        preparation["schema_version"] == "task13-manual-startup-recovery-preparation-v1"
        and preparation["recovery_plan"] == lease.spec["expected_scope"]
        and preparation["scope_packet"] == value["scope_packet"]
        and value["source"]["epoch_number"] == 12
        and value["model"]["model_epoch_number"] == 9,
        "target material does not join the exact startup recovery plan",
    )
    source = json.loads(json.dumps(value["source"]))
    source["authority"] = preparation["source"]["authority"]
    model = json.loads(json.dumps(value["model"]))
    model["source_manifest_sha256"] = model["adoption_decision_sha256"] = None
    _require(
        source == preparation["source"] and model == preparation["model"],
        "target material differs from independently prepared templates",
    )
    digest = canonical_hash(value)
    _require(
        lease._expected_target_sha256 in (None, digest),
        "sealed target material differs",
    )
    lease.expected_target, lease._expected_target_sha256 = value, digest


def validate_startup_spec(spec):
    from evals.timing_pool_controller import require_plain_path
    from evals.timing_pool_recovery import _pin, _target_registration
    from scripts.task13_manual_recovery import STARTUP_COUNTS

    required = {
        "schema_version",
        "pool_host_manifest",
        "expected_scope",
        "stop_evidence",
        "fee_audit",
        "controller_state_roots",
    }
    _require(
        isinstance(spec, dict)
        and set(spec) in (required, required | {"target_pool_registration"})
        and spec["schema_version"] == STARTUP_LOCK_SCHEMA,
        "complete closed startup recovery lock spec required",
    )
    for name in ("pool_host_manifest", "stop_evidence", "fee_audit"):
        _require(
            spec[name].get("sha256") == STARTUP_FROZEN[name],
            "only the frozen startup predecessor is eligible",
        )
        _pin(spec[name])
    plan = _pin(spec["expected_scope"])
    identity = plan.get("recovery_id")
    _require(
        isinstance(identity, str)
        and re.fullmatch("[0-9a-f]{32}", identity) is not None,
        "fixed startup recovery identity required",
    )
    _require(
        plan["schema_version"] == "task13-manual-startup-recovery-plan-v1"
        and canonical_hash(plan["quota"]) == canonical_hash(STARTUP_COUNTS)
        and plan["predecessor_pool_host"] == spec["pool_host_manifest"]
        and plan["predecessor_head_sha256"] == STARTUP_FROZEN["journal_head"],
        "startup recovery scope differs",
    )
    _require(
        plan["deadline"] == "2026-11-02T23:59:59+08:00"
        and type(plan["development_cap_cny"]) is int
        and plan["development_cap_cny"] == 6
        and plan["temporary_roots"]
        == [f"D:/传智杯/.tmp/t13v3-{identity[:12]}-{i}" for i in (1, 2)]
        and plan["actual_authority"] is None
        and type(plan["provider_requests"]) is int
        and plan["provider_requests"] == 0
        and type(plan["timing_credit"]) is int
        and plan["timing_credit"] == 0,
        "startup deadline, staging roots or inert plan authority differs",
    )
    _require(
        plan["predecessor_materialization"]["sha256"]
        == STARTUP_FROZEN["materialization"]
        and plan["predecessor_preparation"]["sha256"] == STARTUP_FROZEN["preparation"],
        "exact startup materialization and preparation pins required",
    )
    _pin(plan["predecessor_materialization"])
    _pin(plan["predecessor_preparation"])
    roots = spec["controller_state_roots"]
    _require(
        isinstance(roots, list)
        and roots
        and len(set(roots)) == len(roots)
        and all(
            str(require_plain_path(p).resolve()) == p and Path(p).is_dir()
            for p in roots
        ),
        "canonical original controller roots required",
    )
    stop = _pin(spec["stop_evidence"])
    host = _pin(spec["pool_host_manifest"])
    journal = require_plain_path(host["journal_path"], file=True)
    _require(
        str(journal) == stop["pool_journal"]["path"]
        and journal.name == "pool-journal.jsonl"
        and sha256(journal.read_bytes()).hexdigest() == stop["pool_journal"]["sha256"]
        and stop["journal_head"] == STARTUP_FROZEN["journal_head"]
        and any(journal.is_relative_to(Path(root)) for root in roots),
        "frozen startup parent or roots differ",
    )
    if "target_pool_registration" in spec:
        _target_registration(spec)
    return json.loads(json.dumps(spec, allow_nan=False))


def closed_predecessors(spec):
    """No caller whitelist: the older pool comes only from the frozen old proof."""
    from evals.timing_pool_recovery import FROZEN, _pin

    stop = _pin(spec["stop_evidence"])
    old = _pin(stop["old_quarantine_record"])
    return [
        {
            "host": spec["pool_host_manifest"],
            "journal": stop["pool_journal"],
            "head": STARTUP_FROZEN["journal_head"],
            "pool_sha256": STARTUP_FROZEN["pool_sha256"],
            "schema": "task13-e-timing-pool-registration-v2",
        },
        {
            "host": old["pool_host_manifest"],
            "journal": {k: old["parent_journal"][k] for k in ("path", "sha256")},
            "head": FROZEN["journal_head"],
            "pool_sha256": FROZEN["pool_sha256"],
            "schema": "task13-e-timing-pool-registration-v1",
        },
    ]


def _raw_refs(stop):
    from scripts.task13_pool_prepare import raw, refs

    for ref in refs(stop):
        raw(ref)


def fresh_startup_workers_absent(stop):
    """Kernel PID/creation identity and exact owned Docker name; errors are unknown."""
    from evals.timing_pool_recovery import _pin
    from scripts.task13_pool_prepare import raw

    recorded = _pin(stop["owned_worker_absence"])
    launch = _pin(stop["bridge_launch_receipt"])
    _require(
        recorded["launch_receipt"] == stop["bridge_launch_receipt"]
        and recorded["bridge_helper"] == launch["bridge"]
        and recorded["bridge"]["expected"] == launch["process"],
        "frozen owned bridge identity differs",
    )
    raw(launch["bridge"])
    module_spec = importlib.util.spec_from_file_location(
        "task13_frozen_startup_bridge_absence", launch["bridge"]["path"]
    )
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    process = module.inspect_original_process(launch["process"])
    _require(
        process.get("known") is True and process.get("original_process_absent") is True,
        "owned bridge absence is unknown or bridge is active",
    )
    argv = [
        "docker",
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        "name=^/task13-worker-85a13281a9f14d1191c105f2fa758655$",
        "--format",
        "{{.ID}}",
    ]
    try:
        result = subprocess.run(argv, capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PermissionError("fresh startup container absence is unknown") from error
    _require(
        result.returncode == 0
        and not result.stdout.strip()
        and not result.stderr.strip(),
        "startup container absence is unknown or worker remains active",
    )
    return {
        "schema_version": "task13-startup-owned-worker-absence-v1",
        "status": "verified",
        "bridge": process,
        "container": {
            "argv": argv,
            "returncode": 0,
            "stdout_sha256": sha256(result.stdout).hexdigest(),
            "stderr_sha256": sha256(result.stderr).hexdigest(),
        },
    }


def validate_startup_absence(absence, quarantine, *, inspected_at):
    """Validate the exact two-generation boundary proof without running a probe."""
    from datetime import datetime

    from evals.timing_pool_recovery import _pin

    try:
        stop = _pin(quarantine["stop_evidence"])
        launch = _pin(stop["bridge_launch_receipt"])
        older = _pin(quarantine["older_quarantine"])
        _require(
            set(absence) == {"schema_version", "status", "startup", "older"}
            and absence["schema_version"]
            == "task13-startup-quarantine-worker-absence-v1"
            and absence["status"] == "verified",
            "startup predecessor absence schema differs",
        )
        startup = absence["startup"]
        _require(
            set(startup) == {"schema_version", "status", "bridge", "container"}
            and startup["schema_version"] == "task13-startup-owned-worker-absence-v1"
            and startup["status"] == "verified",
            "startup owned worker absence schema differs",
        )
        process = startup["bridge"]
        _require(
            process["known"] is True
            and process["original_process_absent"] is True
            and process["expected"] == launch["process"],
            "owned startup bridge identity or absence differs",
        )
        if "error_code" in process:
            _require(
                set(process)
                == {
                    "known",
                    "original_process_absent",
                    "reason",
                    "error_code",
                    "expected",
                    "inspected_at",
                }
                and type(process["error_code"]) is int
                and process["error_code"] == 87
                and process["reason"] == "kernel_invalid_pid",
                "kernel absence is unknown",
            )
        else:
            _require(
                set(process)
                == {
                    "known",
                    "original_process_absent",
                    "actual",
                    "expected",
                    "inspected_at",
                },
                "kernel identity inspection differs",
            )
            actual = process["actual"]
            _require(
                set(actual) == {"creation_filetime", "running", "exit_code"}
                and type(actual["creation_filetime"]) is int
                and type(actual["running"]) is bool
                and type(actual["exit_code"]) is int
                and (
                    actual["creation_filetime"]
                    != launch["process"]["creation_filetime"]
                    or actual["running"] is False
                ),
                "original bridge process remains active or unknown",
            )
        clock = process["inspected_at"]
        _require(
            set(clock) == {"utc", "monotonic_ns", "wall_time_ns"}
            and all(
                type(clock[k]) is int and clock[k] > 0
                for k in ("monotonic_ns", "wall_time_ns")
            ),
            "kernel inspection clock differs",
        )
        when, checked = (
            datetime.fromisoformat(inspected_at),
            datetime.fromisoformat(clock["utc"]),
        )
        _require(
            when.tzinfo is not None and checked.tzinfo is not None and checked <= when,
            "kernel inspection follows the recorded recovery boundary",
        )
        empty = sha256(b"").hexdigest()
        _require(
            startup["container"]
            == {
                "argv": [
                    "docker",
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--filter",
                    "name=^/task13-worker-85a13281a9f14d1191c105f2fa758655$",
                    "--format",
                    "{{.ID}}",
                ],
                "returncode": 0,
                "stdout_sha256": empty,
                "stderr_sha256": empty,
            },
            "exact owned startup container absence differs",
        )
        expected_workers = [
            {
                "container_id": w["container_id"],
                "inspection": {
                    "argv": [
                        "docker",
                        "container",
                        "ls",
                        "--all",
                        "--no-trunc",
                        "--filter",
                        "id=" + w["container_id"],
                        "--format",
                        "{{.ID}}",
                    ],
                    "returncode": 0,
                    "stdout_sha256": empty,
                    "stderr_sha256": empty,
                },
            }
            for w in older["workers"]
        ]
        _require(
            absence["older"]
            == {
                "schema_version": "task13-manual-quarantine-worker-absence-v1",
                "status": "verified",
                "workers": expected_workers,
            },
            "older quarantine owned worker absence differs",
        )
    except (KeyError, TypeError, ValueError) as error:
        raise PermissionError(
            "fresh quarantine predecessor startup worker absence differs"
        ) from error


def _owned_transient_paths(spec):
    """Ignore only writer files authenticated by the matching live outer lease."""
    from evals.timing_pool_recovery import _ACTIVE_LEASES, _require_lease

    owned = set()
    for lease in _ACTIVE_LEASES.values():
        if any(
            lease.spec.get(k) != spec.get(k)
            for k in (
                "expected_scope",
                "pool_host_manifest",
                "stop_evidence",
                "fee_audit",
            )
        ):
            continue
        _require_lease(lease)
        roots = {Path(p) for p in lease.spec["controller_state_roots"]}
        _require(
            {Path(p) for p in spec["controller_state_roots"]} <= roots,
            "live startup lease root coverage differs",
        )
        raw = json.dumps({"pid": os.getpid(), "nonce": lease.nonce}).encode()
        for path, owner in lease.owned.items():
            if isinstance(owner, tuple):
                continue
            _require(
                path in {root / "host-writer.lock" for root in roots} and owner == raw,
                "live startup writer path or nonce owner differs",
            )
            owned.add(path)
    return owned


def _facts(spec):
    from evals.adapters.e_planning_journal import _read
    from evals.adapters.model_identities import require_registered_model_identity
    from evals.adapters.source_epochs import require_registered_epoch
    from evals.timing_pool import _load_host_inputs, _view, pool_policy
    from evals.timing_pool_controller import validate_pool_journal_evidence
    from evals.timing_pool_recovery import (
        _native_untouched,
        _pin,
        validate_quarantine_evidence,
    )

    host, stop, fee = (
        _pin(spec[k]) for k in ("pool_host_manifest", "stop_evidence", "fee_audit")
    )
    materialization = _pin(
        {
            "path": str(
                Path(spec["pool_host_manifest"]["path"]).with_name(
                    "materialization.json"
                )
            ),
            "sha256": STARTUP_FROZEN["materialization"],
        }
    )
    _require(
        materialization["pool_host_manifest"] == spec["pool_host_manifest"]
        and materialization["preparation"]["sha256"] == STARTUP_FROZEN["preparation"],
        "original startup materialization differs",
    )
    _pin(materialization["preparation"])
    _raw_refs(stop)
    pool = _pin(host["pool_registration"])
    _require(
        canonical_hash(pool) == STARTUP_FROZEN["pool_sha256"]
        and host["pool_registration"] == stop["pool_registration"]
        and pool_policy(pool).future_logical_limit == 5,
        "original startup registration differs",
    )
    parent = {**stop["pool_journal"], "head_sha256": STARTUP_FROZEN["journal_head"]}
    transcript = validate_pool_journal_evidence({"pool_journal": parent}, pool)
    started, terminal, failure = (
        _pin(stop[k])
        for k in ("native_plan_started", "native_plan_terminal", "startup_failure")
    )
    accounting = validate_startup_shape(
        stop, pool, transcript["events"], started, terminal, failure
    )
    _require(
        transcript["state"]["pending"] == STARTUP_TRIAL
        and transcript["state"]["attempted"] == 1
        and transcript["state"]["stopped"] == "native_unknown"
        and not transcript["settlements"],
        "startup parent unknown state differs",
    )
    old = _pin(stop["old_quarantine_record"])
    _require(
        pool["quarantine_record"] == stop["old_quarantine_record"]
        and fee["legacy_quarantine"] == stop["old_quarantine_record"],
        "older quarantine binding differs",
    )
    validate_quarantine_evidence(old, expected_scope=old["expected_scope"])
    transients = _owned_transient_paths(spec)
    natives, source = [], None
    for child, native in zip(pool["children"], fee["native_children"], strict=True):
        child_host = _pin(host["hosts"][child["child_id"]])
        view = _view(child["evidence_root"])
        inputs = _load_host_inputs(view, child_host)
        _require(
            view.registration == child["registration"]
            and inputs["pool_authority"] == pool,
            "original startup native child membership differs",
        )
        counts = _native_untouched(view)
        authority = inputs["planning_authority"]
        _require(
            native["journal"]["path"] == authority["journal_path"]
            and native["authority_sha256"] == canonical_hash(authority),
            "startup native authority differs",
        )
        _pin_journal(native["journal"])
        with sqlite3.connect(
            Path(authority["journal_path"]).resolve().as_uri() + "?mode=ro", uri=True
        ) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            _read(
                db,
                canonical_hash(inputs["planning_registration"]),
                canonical_hash(authority),
            )
            _require(
                db.execute(
                    "SELECT count(*) FROM analysis_import_planning_claims"
                ).fetchone()[0]
                == 0,
                "startup native child slot was claimed",
            )
        from evals.e_planning import planning_requests

        requests = planning_requests(inputs["planning_registration"])
        budget = Path(inputs["runtime_options"]["budget_dir"]) / "campaign.sqlite"
        q = requests[0]
        current_source = require_registered_epoch(
            budget,
            q.epoch_id,
            source_sha256=q.source_sha256,
            config_sha256=q.config_sha256,
            manifest_sha256=q.epoch_manifest_sha256,
            latest=False,
        )
        require_registered_model_identity(
            budget,
            q.model_identity_binding.model_epoch_id,
            epoch_id=q.epoch_id,
            source_sha256=q.source_sha256,
            config_sha256=q.config_sha256,
            purpose=q.purpose,
            manifest_sha256=q.model_identity_binding.model_identity_sha256,
            latest=False,
        )
        _require(
            source is None or source == current_source,
            "startup native source identities differ",
        )
        source = current_source
        _require(
            str(budget) == fee["budget_path"] and source["epoch_number"] == 11,
            "startup genuine budget/source identity differs",
        )
        worker_root = Path(inputs["runtime_options"]["output_dir"])
        worker_files = {
            p for p in worker_root.rglob("*") if p.is_file() and p not in transients
        }
        expected_worker_files = (
            {Path(stop["startup_failure"]["path"])}
            if child["child_id"] == pool["attempt_order"][0]["child_id"]
            else set()
        )
        _require(
            worker_files == expected_worker_files
            and not any(
                p.is_file() and p not in transients
                for p in Path(child_host["host_termination_dir"]).rglob("*")
            ),
            "unexpected native worker or termination output exists",
        )
        for q in requests:
            slot = Path(child_host["output_dir"]) / "slots" / q.planning_slot_id
            if q.trial_id == STARTUP_TRIAL:
                _require(
                    slot / "plan-started.json"
                    == Path(stop["native_plan_started"]["path"])
                    and {p.name for p in slot.iterdir()}
                    == {"plan-started.json", "plan-terminal.json"}
                    and started["request"] == q.model_dump(mode="json")
                    and started["manifest_sha256"]
                    == sha256(
                        (
                            Path(child_host["output_dir"]) / "host-binding.json"
                        ).read_bytes()
                    ).hexdigest(),
                    "startup plan origin or later native work differs",
                )
            else:
                _require(
                    not slot.exists() or not any(slot.iterdir()),
                    "later native planning work exists",
                )
        natives.append(
            {
                "root": str(view.root),
                "registration_sha256": canonical_hash(view.registration),
                **counts,
            }
        )
    _require(
        set(source["controller_state_roots"]) <= set(spec["controller_state_roots"]),
        "startup recovery omitted an original controller root",
    )
    _require(
        source == materialization["source"],
        "original startup source materialization changed",
    )
    _require(
        fee["new_provider_requests"] == 0
        and fee["new_fee_cny"] == "0"
        and fee["legacy_fee_baseline"] == old["fees"],
        "startup original fee baseline differs",
    )
    return host, stop, fee, parent, accounting, natives, source, old


def _pin_journal(ref):
    from evals.timing_pool_controller import require_plain_path

    _require(
        sha256(require_plain_path(ref["path"], file=True).read_bytes()).hexdigest()
        == ref["sha256"],
        "original native planning journal bytes changed",
    )


def audit_startup_prefix(spec, lease):
    from evals.timing_pool_recovery import (
        _require_original_budget_transaction,
        fresh_quarantine_workers_absent,
    )

    host, stop, fee, parent, accounting, natives, source, old = _facts(spec)
    db = lease.native[2]
    _require_original_budget_transaction(db, Path(fee["budget_path"]))
    validate_sql_prefix(db, _rowid_baseline(fee), expected_target=lease.expected_target)
    workers = fresh_startup_workers_absent(stop)
    fresh_quarantine_workers_absent(old)
    # Current absence is a gate, while the proof itself stays byte-stable across
    # exact native source/model callbacks and metadata-only resumption.
    _require(workers["status"] == "verified", "startup workers absence unknown")
    return {
        "schema_version": STARTUP_QUARANTINE_SCHEMA,
        "status": "quarantined_startup_unknown_prefix",
        "authority": False,
        "timing_credit": 0,
        "expected_scope": spec["expected_scope"],
        **{k: spec[k] for k in ("pool_host_manifest", "stop_evidence", "fee_audit")},
        "parent_journal": {**parent, "event_count": 5},
        "native_journals": natives,
        "old_controller_state_roots": source["controller_state_roots"],
        "legacy_identity": {
            "epoch_id": source["epoch_id"],
            "epoch_manifest_sha256": canonical_hash(source),
            **pool_identity(host),
        },
        "planning": accounting,
        "fees": fee["legacy_fee_baseline"],
        "workers": stop["owned_worker_absence"],
        "older_quarantine": stop["old_quarantine_record"],
        "budget_rowid_baseline_sha256": ROWID_BASELINE_SHA256,
    }


def pool_identity(host):
    from evals.timing_pool_recovery import _pin

    return _pin(host["pool_registration"])["formal_binding"]["model_identity_binding"]


def validate_startup_quarantine(evidence, *, expected_scope):
    from evals.timing_pool_recovery import (
        _check_fee_baseline,
        _check_preserved_files,
        _pin,
    )

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
        "older_quarantine",
        "budget_rowid_baseline_sha256",
        "preserved_files",
        "preserved_files_sha256",
    }
    _require(
        set(evidence) == required
        and evidence["schema_version"] == STARTUP_QUARANTINE_SCHEMA
        and evidence["status"] == "quarantined_startup_unknown_prefix"
        and evidence["authority"] is False
        and type(evidence["timing_credit"]) is int
        and evidence["timing_credit"] == 0
        and evidence["expected_scope"] == expected_scope,
        "invalid independent startup quarantine schema or scope",
    )
    _pin(expected_scope)
    for name in ("pool_host_manifest", "stop_evidence", "fee_audit"):
        _require(
            evidence[name]["sha256"] == STARTUP_FROZEN[name],
            "startup quarantine anchor differs",
        )
    spec = {
        k: evidence[k]
        for k in ("pool_host_manifest", "stop_evidence", "fee_audit", "expected_scope")
    }
    spec["controller_state_roots"] = evidence["old_controller_state_roots"]
    spec["schema_version"] = STARTUP_LOCK_SCHEMA
    validate_startup_spec(spec)
    host, stop, fee, parent, accounting, natives, source, _old = _facts(spec)
    _require(
        evidence["parent_journal"] == {**parent, "event_count": 5}
        and evidence["planning"] == accounting
        and evidence["native_journals"] == natives
        and evidence["old_controller_state_roots"] == source["controller_state_roots"]
        and evidence["fees"] == fee["legacy_fee_baseline"]
        and evidence["workers"] == stop["owned_worker_absence"]
        and evidence["older_quarantine"] == stop["old_quarantine_record"]
        and evidence["budget_rowid_baseline_sha256"] == ROWID_BASELINE_SHA256
        and evidence["legacy_identity"]
        == {
            "epoch_id": source["epoch_id"],
            "epoch_manifest_sha256": canonical_hash(source),
            **pool_identity(host),
        },
        "frozen startup quarantine facts differ",
    )
    _rowid_baseline(fee)
    _check_preserved_files(
        evidence["preserved_files"], evidence["preserved_files_sha256"]
    )
    _require(
        all(
            any(
                Path(name).is_relative_to(Path(root))
                for root in source["controller_state_roots"]
            )
            for name in evidence["preserved_files"]
        ),
        "startup preserved file map escapes original roots",
    )
    _check_fee_baseline(
        Path(fee["budget_path"]),
        evidence["fees"],
        legacy_identity=evidence["legacy_identity"],
    )
    return json.loads(json.dumps(evidence, allow_nan=False))
