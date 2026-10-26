"""Host-registered source epochs on the original budget, without dispatch authority.

The independent manifest/authority hashes must come from the trusted host. This
module never creates a consent record. Workers only read existing registration;
runtime integration must still verify mounted source, config, image and inputs.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import ExitStack
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath, PureWindowsPath

from evals.adapters.budget_v2 import (
    CAMPAIGN_ID,
    HELD_CONTINGENCY,
    PURPOSE_LIMITS,
    SUPPLEMENT_LIMIT,
    _identity,
    _sha256,
)
from evals.contracts import canonical_hash

LIMITS = {
    "total": 100,
    "development": 15,
    "supplement": SUPPLEMENT_LIMIT,
    "purposes": dict(PURPOSE_LIMITS),
    "held": HELD_CONTINGENCY,
}
_FIELDS = {
    "schema_version",
    "campaign_id",
    "epoch_id",
    "epoch_number",
    "predecessor_epoch_id",
    "source_commit",
    "source_sha256",
    "config_sha256",
    "entrypoints",
    "entrypoints_sha256",
    "runtime_binding",
    "budget_identity",
    "budget_limits",
    "budget_path",
    "controller_state_roots",
    "authority",
}


def _absolute_path(value):
    # Manifests retain the host path when inspected inside a Linux worker.
    return isinstance(value, str) and (
        PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()
    )


def _validate_manifest(value):
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError("complete source epoch manifest is required")
    number = value["epoch_number"]
    if (
        value["schema_version"] != "task13-supplement-source-epoch-v1"
        or value["campaign_id"] != CAMPAIGN_ID
        or not _identity(value["epoch_id"])
        or type(number) is not int
        or number < 0
        or (number == 0 and value["predecessor_epoch_id"] is not None)
        or (number > 0 and not _identity(value["predecessor_epoch_id"]))
        or not isinstance(value["source_commit"], str)
        or re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]) is None
        or any(
            not _sha256(value[key])
            for key in ("source_sha256", "config_sha256", "entrypoints_sha256")
        )
        or value["budget_limits"] != LIMITS
        or not _absolute_path(value["budget_path"])
    ):
        raise ValueError("invalid source epoch manifest binding or limits")
    entries = value["entrypoints"]
    required = {
        "scripts/task13_worker_runtime.py",
        "evals/remediation.py",
        "evals/adapters/budget_v2.py",
    }
    if (
        not isinstance(entries, dict)
        or not required <= set(entries)
        or any(
            not isinstance(key, str)
            or "\\" in key
            or ":" in key
            or PurePosixPath(key).is_absolute()
            or ".." in PurePosixPath(key).parts
            or str(PurePosixPath(key)) != key
            or not _sha256(digest)
            for key, digest in entries.items()
        )
        or canonical_hash(entries) != value["entrypoints_sha256"]
    ):
        raise ValueError("invalid source epoch entrypoint manifest")
    runtime = value["runtime_binding"]
    if (
        not isinstance(runtime, dict)
        or set(runtime)
        != {
            "image_id",
            "dependencies_lock_sha256",
            "dependencies_tree_sha256",
            "knowledge_sha256",
            "controller_manifest_sha256",
        }
        or not isinstance(runtime["image_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", runtime["image_id"]) is None
        or any(not _sha256(v) for k, v in runtime.items() if k != "image_id")
    ):
        raise ValueError("invalid source epoch runtime binding")
    roots = value["controller_state_roots"]
    if (
        not isinstance(roots, list)
        or not roots
        or any(not _absolute_path(v) for v in roots)
        or len(set(roots)) != len(roots)
    ):
        raise ValueError("host-bound controller state roots are required")
    authority = value["authority"]
    if (
        not isinstance(authority, dict)
        or set(authority) != {"kind", "packet_sha256", "decision_record_sha256"}
        or authority["kind"]
        != ("legacy_source_attestation" if number == 0 else "phase_scope_consent")
        or not _sha256(authority["packet_sha256"])
        or not _sha256(authority["decision_record_sha256"])
    ):
        raise ValueError("external source epoch authority binding is required")
    return value


def _require_budget(db, identity):
    fields = {
        "schema_version",
        "baseline_count",
        "baseline_max_rowid",
        "baseline_sha256",
    }
    if (
        not isinstance(identity, dict)
        or set(identity) != fields
        or identity["schema_version"] != "task13-original-budget-identity-v1"
        or type(identity["baseline_count"]) is not int
        or type(identity["baseline_max_rowid"]) is not int
        or not 0 < identity["baseline_count"] <= identity["baseline_max_rowid"]
        or not _sha256(identity["baseline_sha256"])
    ):
        raise ValueError("frozen original budget identity is required")
    config = dict(db.execute("SELECT key,value FROM config"))
    if config.get("total") not in {"100", "100.0"} or config.get("development") not in {
        "15",
        "15.0",
    }:
        raise ValueError("original budget limits must remain 100/15")
    rows = db.execute(
        "SELECT rowid,id,request_key,phase,upper,actual,settled FROM reservations "
        "WHERE rowid<=? ORDER BY rowid",
        (identity["baseline_max_rowid"],),
    ).fetchall()
    if (
        len(rows) != identity["baseline_count"]
        or not rows
        or rows[-1][0] != identity["baseline_max_rowid"]
        or canonical_hash(rows) != identity["baseline_sha256"]
    ):
        raise ValueError("original budget identity differs from frozen history")


def _campaign(db):
    row = db.execute(
        "SELECT frozen_config FROM supplement_campaigns WHERE campaign_id=?",
        (CAMPAIGN_ID,),
    ).fetchone()
    if row is None:
        raise ValueError("source epochs require an existing supplement campaign")
    value = json.loads(row[0])
    if (
        set(value)
        != {
            "source_sha256",
            "config_sha256",
            "supplement_cny",
            "purpose_limits_cny",
            "held_contingency_cny",
        }
        or value["supplement_cny"] != SUPPLEMENT_LIMIT
        or value["purpose_limits_cny"] != dict(PURPOSE_LIMITS)
        or value["held_contingency_cny"] != HELD_CONTINGENCY
    ):
        raise ValueError("frozen supplement campaign limits differ")
    return value


def _existing_path(path):
    path = Path(path)
    if not path.is_file() or any(
        part.is_symlink() or part.is_junction() for part in (path, *path.parents)
    ):
        raise ValueError("source epochs require the existing original budget")
    return path


def _schema(db):
    db.execute(
        "CREATE TABLE IF NOT EXISTS supplement_source_epochs ("
        "epoch_id TEXT PRIMARY KEY,campaign_id TEXT NOT NULL,epoch_number INTEGER NOT NULL,"
        "predecessor_epoch_id TEXT,manifest_json TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,"
        "authority_sha256 TEXT NOT NULL,registered_at TEXT NOT NULL,chain_sha256 TEXT NOT NULL,"
        "UNIQUE(campaign_id,epoch_number),UNIQUE(predecessor_epoch_id))"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS supplement_request_epochs ("
        "reservation_id TEXT PRIMARY KEY REFERENCES supplement_requests(reservation_id),"
        "epoch_id TEXT NOT NULL REFERENCES supplement_source_epochs(epoch_id))"
    )
    for table in ("supplement_source_epochs", "supplement_request_epochs"):
        for operation in ("UPDATE", "DELETE"):
            db.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()} "
                f"BEFORE {operation} ON {table} BEGIN "
                "SELECT RAISE(ABORT,'source epoch records are append-only'); END"
            )


def _chain(db):
    frozen = _campaign(db)
    manifests, previous = [], None
    for row in db.execute(
        "SELECT epoch_id,campaign_id,epoch_number,predecessor_epoch_id,manifest_json,"
        "manifest_sha256,authority_sha256,registered_at,chain_sha256 "
        "FROM supplement_source_epochs ORDER BY epoch_number"
    ):
        manifest = _validate_manifest(json.loads(row[4]))
        _require_budget(db, manifest["budget_identity"])
        if (
            tuple(row[:4])
            != (
                manifest["epoch_id"],
                CAMPAIGN_ID,
                len(manifests),
                previous[0] if previous else None,
            )
            or manifest["epoch_number"] != row[2]
            or manifest["predecessor_epoch_id"] != row[3]
            or canonical_hash(manifest) != row[5]
            or not _sha256(row[6])
            or canonical_hash([previous[8] if previous else None, *row[:4], *row[5:8]])
            != row[8]
            or (
                not previous
                and any(
                    manifest[key] != frozen[key]
                    for key in ("source_sha256", "config_sha256")
                )
            )
            or (
                manifests
                and not set(manifests[-1]["controller_state_roots"])
                <= set(manifest["controller_state_roots"])
            )
            or (
                manifests
                and manifest["budget_identity"] != manifests[0]["budget_identity"]
            )
            or (manifests and manifest["budget_path"] != manifests[0]["budget_path"])
        ):
            raise ValueError("registered source epoch chain or manifest was altered")
        manifests.append(manifest)
        previous = row
    return manifests, previous


def require_epoch_in_transaction(
    db,
    epoch_id,
    *,
    source_sha256,
    config_sha256,
    budget_identity=None,
    manifest_sha256=None,
    latest=False,
):
    """SELECT only; caller owns the transaction used for reservation/settlement."""
    try:
        manifests, _ = _chain(db)
    except (sqlite3.Error, json.JSONDecodeError, TypeError, KeyError) as exc:
        raise ValueError(
            "registered source epoch schema or manifest is unavailable"
        ) from exc
    matches = [m for m in manifests if m["epoch_id"] == epoch_id]
    if not matches:
        raise ValueError("explicit host-registered source epoch is required")
    value = matches[0]
    if (
        value["source_sha256"] != source_sha256
        or value["config_sha256"] != config_sha256
        or (budget_identity is not None and value["budget_identity"] != budget_identity)
        or (manifest_sha256 is not None and canonical_hash(value) != manifest_sha256)
        or (latest and value != manifests[-1])
    ):
        raise ValueError("registered source epoch binding differs or epoch is retired")
    return value


def require_legacy_dispatch_in_transaction(db):
    """A new source version retires new-code legacy dispatch, never settlement."""
    manifests, _ = _chain(db)
    if len(manifests) > 1:
        raise ValueError("legacy source epoch is retired for new reservations")


def require_registered_epoch(path, epoch_id, **bindings):
    """Read-only lookup; never creates campaign, schema, epoch or reservation."""
    path = _existing_path(path)
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        manifest = require_epoch_in_transaction(db, epoch_id, **bindings)
        # The container wrapper separately verifies the original host mount.
        # Outside a worker, even a same-prefix cloned DB has the wrong path.
        if (
            not os.environ.get("TASK13_WORKER_NONCE")
            and Path(manifest["budget_path"]).resolve() != path.resolve()
        ):
            raise ValueError("registered epoch requires its original host budget path")
        return manifest


def _lock_controller_roots(roots, stack):
    owned_locks = set()
    for root in sorted(roots):
        path = Path(root)
        if (
            not path.is_dir()
            or path.is_symlink()
            or path.is_junction()
            or str(path.resolve()) != root
        ):
            raise ValueError("host controller state root is unavailable or linked")
        if (path / "bundle.json").is_file() and str(path.parent.resolve()) not in roots:
            raise PermissionError(
                "analysis capsule parent must be included in controller roots"
            )
        for name in (".writer-lock", ".analysis36-campaign-lock"):
            lock = path / name
            try:
                lock.mkdir()
            except FileExistsError:
                raise PermissionError(
                    "controller active or stale writer lock requires reconciliation"
                ) from None
            owned_locks.add(lock)
            stack.callback(lock.rmdir)
    # Acquire every writer lock before reading any of their journals. Nested
    # registered roots share these owned locks and must not reject each other.
    journal_roots = set()
    for root in sorted(roots):
        path = Path(root)
        for entry in path.rglob("*"):
            if entry.is_symlink() or entry.is_junction():
                raise ValueError("controller state contains links")
            if (
                entry.name in {".writer-lock", ".analysis36-campaign-lock"}
                and entry not in owned_locks
            ):
                raise PermissionError("controller contains an active writer lock")
            if entry.name == "registration.json":
                journal_roots.add(entry.parent)
            if (
                entry.is_dir()
                and entry.name == "events"
                and any(entry.glob("*.json"))
                and not (entry.parent / "registration.json").is_file()
            ):
                raise PermissionError(
                    "unrecognized controller journal requires reconciliation"
                )
            if entry.name == "started.json":
                attempt_path = entry.parent / "attempt.json"
                result_path = entry.parent / "result.json"
                if not attempt_path.is_file() or not result_path.is_file():
                    raise PermissionError("controller dispatch is not quiescent")
                start = json.loads(entry.read_text(encoding="utf-8"))
                attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
                if (
                    attempt.get("status") not in {"completed", "failed"}
                    or not _sha256(start.get("bundle_sha256"))
                    or attempt.get("bundle_sha256") != start["bundle_sha256"]
                    or attempt.get("slot_id") != start.get("slot_id")
                    or attempt.get("result_sha256")
                    != sha256(result_path.read_bytes()).hexdigest()
                ):
                    raise PermissionError(
                        "controller terminal receipt requires reconciliation"
                    )
    for root in sorted(journal_roots):
        if root.resolve() not in {Path(value).resolve() for value in roots}:
            raise PermissionError(
                "every discovered journal root must be registered and locked"
            )
        try:
            registration = json.loads(
                (root / "registration.json").read_text(encoding="utf-8")
            )
            if registration.get("schema_version") == "task13-e-timing-registration-v1":
                from evals.e_timing import read_timing_journal

                state = read_timing_journal(root)
            elif (
                registration.get("plan", {}).get("schema_version")
                == "task13-v2-f8-candidate-registration-v1"
            ):
                from evals.verification_v2 import read_campaign_journal

                state = read_campaign_journal(root)
            else:
                raise ValueError("unrecognized controller registration")
            allowed = {
                "not_started",
                "completed",
                "failed",
                "expired",
                "rejected",
                "not_applicable",
                "budget_stopped",
                "deadline_stopped",
            }
            if any(
                row.get("status") not in allowed or row.get("review_pending")
                for row in [*state["cases"].values(), *state["records"].values()]
            ):
                raise PermissionError(
                    "controller journal is not quiescent or approval is pending"
                )
        except PermissionError:
            raise
        except (KeyError, TypeError, ValueError, OSError) as error:
            raise PermissionError(
                "controller journal requires reconciliation"
            ) from error


def register_source_epoch(
    path,
    manifest,
    *,
    expected_manifest_sha256,
    budget_identity,
    authority,
    expected_authority_sha256,
):
    """Append on a trusted host after independent concrete authority verification.

    The supplied hashes are admission inputs, never inferred from worker data.
    Controller roots are covered by the pinned manifest and cannot be dropped in
    a successor. This function shares the controller's existing writer locks.
    """
    if os.getpid() == 1 or os.environ.get("TASK13_WORKER_NONCE"):
        raise PermissionError("source epoch registration is host-only")
    path = _existing_path(path)
    manifest = _validate_manifest(json.loads(json.dumps(manifest, allow_nan=False)))
    if (
        not _sha256(expected_manifest_sha256)
        or canonical_hash(manifest) != expected_manifest_sha256
    ):
        raise ValueError("independently pinned source epoch manifest hash differs")
    if Path(manifest["budget_path"]).resolve() != path.resolve():
        raise ValueError("host source epoch requires the original bound budget path")
    if manifest["budget_identity"] != budget_identity:
        raise ValueError("source epoch original budget identity differs")
    expected_authority = {
        "schema_version": "task13-source-epoch-authority-v1",
        **manifest["authority"],
        "campaign_id": CAMPAIGN_ID,
        "epoch_id": manifest["epoch_id"],
        "manifest_sha256": expected_manifest_sha256,
        "budget_identity_sha256": canonical_hash(budget_identity),
        "decision": "attested" if manifest["epoch_number"] == 0 else "approved",
    }
    if (
        authority != expected_authority
        or not _sha256(expected_authority_sha256)
        or canonical_hash(authority) != expected_authority_sha256
    ):
        raise PermissionError("independently pinned external authority record differs")
    with ExitStack() as stack:
        _lock_controller_roots(manifest["controller_state_roots"], stack)
        with sqlite3.connect(path, timeout=30) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            _require_budget(db, budget_identity)
            _campaign(db)
            if db.execute(
                "SELECT 1 FROM reservations WHERE settled=0 LIMIT 1"
            ).fetchone():
                raise PermissionError(
                    "budget has in-flight requests; epoch registration refused"
                )
            _schema(db)
            manifests, previous = _chain(db)
            if (
                manifest["epoch_number"] != len(manifests)
                or manifest["predecessor_epoch_id"]
                != (previous[0] if previous else None)
                or (
                    manifests
                    and manifest["budget_identity"] != manifests[0]["budget_identity"]
                )
                or (
                    manifests and manifest["budget_path"] != manifests[0]["budget_path"]
                )
                or (
                    manifests
                    and not set(manifests[-1]["controller_state_roots"])
                    <= set(manifest["controller_state_roots"])
                )
            ):
                raise ValueError(
                    "source epoch predecessor, number, roots or identity differs"
                )
            frozen = _campaign(db)
            if not manifests and any(
                manifest[key] != frozen[key]
                for key in ("source_sha256", "config_sha256")
            ):
                raise ValueError(
                    "legacy epoch must attest the existing frozen source/config"
                )
            registered_at = datetime.now(UTC).isoformat()
            columns = [
                manifest["epoch_id"],
                CAMPAIGN_ID,
                len(manifests),
                manifest["predecessor_epoch_id"],
            ]
            digests = [
                expected_manifest_sha256,
                expected_authority_sha256,
                registered_at,
            ]
            chain = canonical_hash(
                [previous[8] if previous else None, *columns, *digests]
            )
            db.execute(
                "INSERT INTO supplement_source_epochs VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    *columns,
                    json.dumps(manifest, sort_keys=True, allow_nan=False),
                    *digests,
                    chain,
                ),
            )
            return {
                "epoch_id": manifest["epoch_id"],
                "manifest_sha256": expected_manifest_sha256,
                "chain_sha256": chain,
            }
