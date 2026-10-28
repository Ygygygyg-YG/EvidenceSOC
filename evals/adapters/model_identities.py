"""Explicit host-pinned model identity registration on the original budget."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path

from evals.adapters.budget_v2 import CAMPAIGN_ID, PURPOSE_LIMITS, _identity, _sha256
from evals.contracts import canonical_hash

IDENTITY_HALT = "observable model version changed"
FIELDS = {
    "schema_version",
    "campaign_id",
    "model_epoch_id",
    "model_epoch_number",
    "predecessor_model_epoch_id",
    "epoch_id",
    "source_manifest_sha256",
    "source_sha256",
    "config_sha256",
    "budget_identity",
    "budget_limits",
    "budget_path",
    "controller_state_roots",
    "expected_model",
    "purposes",
    "inherited_global",
    "halt_evidence_sha256",
    "adoption_decision_sha256",
    "authority_identity",
}
AUTH_FIELDS = {
    "schema_version",
    "kind",
    "decision",
    "manifest_sha256",
    "adoption_decision_sha256",
    "authority_identity",
    "confirmation_sha256",
}
TABLES = (
    "supplement_model_epochs",
    "supplement_request_models",
    "supplement_model_halts",
    "budget_halt_events",
)


def _validate_manifest(m):
    from evals.adapters.source_epochs import LIMITS, _absolute_path

    if not isinstance(m, dict) or set(m) != FIELDS:
        raise ValueError("complete model identity manifest required")
    n = m["model_epoch_number"]
    model, inherited = m["expected_model"], m["inherited_global"]
    if (
        m["schema_version"] != "task13-model-identity-v1"
        or m["campaign_id"] != CAMPAIGN_ID
        or not _identity(m["model_epoch_id"])
        or type(n) is not int
        or n < 0
        or (n == 0 and m["predecessor_model_epoch_id"] is not None)
        or (n > 0 and not _identity(m["predecessor_model_epoch_id"]))
        or not _identity(m["epoch_id"])
        or any(
            not _sha256(m[k])
            for k in (
                "source_manifest_sha256",
                "source_sha256",
                "config_sha256",
                "adoption_decision_sha256",
            )
        )
        or m["budget_limits"] != LIMITS
        or not _absolute_path(m["budget_path"])
        or not isinstance(m["controller_state_roots"], list)
        or not m["controller_state_roots"]
        or any(not _absolute_path(x) for x in m["controller_state_roots"])
        or len(set(m["controller_state_roots"])) != len(m["controller_state_roots"])
        or not isinstance(model, dict)
        or set(model) != {"id", "response_model", "fingerprint"}
        or model["id"] != m["model_epoch_id"]
        or not _identity(model["response_model"])
        or not _identity(model["fingerprint"])
        or not isinstance(m["purposes"], list)
        or not m["purposes"]
        or len(set(m["purposes"])) != len(m["purposes"])
        or any(x not in PURPOSE_LIMITS for x in m["purposes"])
        or not isinstance(inherited, dict)
        or set(inherited) != {"response_model", "fingerprint", "halt"}
        or not _identity(inherited["response_model"])
        or not _identity(inherited["fingerprint"])
        or inherited["halt"] != IDENTITY_HALT
        or not isinstance(m["halt_evidence_sha256"], list)
        or len(m["halt_evidence_sha256"]) != 2
        or any(not _sha256(x) for x in m["halt_evidence_sha256"])
        or not _identity(m["authority_identity"])
    ):
        raise ValueError("invalid model identity manifest")
    return m


def _authority(m, a, digest):
    if (
        not isinstance(a, dict)
        or set(a) != AUTH_FIELDS
        or a["schema_version"] != "task13-model-identity-authority-v1"
        or a["kind"] != "runtime_model_adoption"
        or a["decision"] != "approved"
        or a["manifest_sha256"] != canonical_hash(m)
        or a["adoption_decision_sha256"] != m["adoption_decision_sha256"]
        or a["authority_identity"] != m["authority_identity"]
        or not _sha256(a["confirmation_sha256"])
        or not _sha256(digest)
        or canonical_hash(a) != digest
    ):
        raise PermissionError(
            "independently pinned external model adoption authority required"
        )


CONFLICT_PREDICATES = {
    "supplement_model_epochs": "model_epoch_id=NEW.model_epoch_id OR (campaign_id=NEW.campaign_id AND model_epoch_number=NEW.model_epoch_number) OR (NEW.predecessor_model_epoch_id IS NOT NULL AND predecessor_model_epoch_id=NEW.predecessor_model_epoch_id)",
    "supplement_request_models": "reservation_id=NEW.reservation_id",
    "supplement_model_halts": "event_id=NEW.event_id",
    "budget_halt_events": "event_id=NEW.event_id",
}


def _conflict_trigger(table):
    name = f"{table}_no_replace"
    return f"CREATE TRIGGER {name} BEFORE INSERT ON {table} WHEN EXISTS (SELECT 1 FROM {table} WHERE {CONFLICT_PREDICATES[table]}) BEGIN SELECT RAISE(ABORT,'model identity records are append-only'); END"


def _schema(db):
    db.execute(
        "CREATE TABLE IF NOT EXISTS supplement_model_epochs (model_epoch_id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, model_epoch_number INTEGER NOT NULL, predecessor_model_epoch_id TEXT, manifest_json TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, authority_json TEXT NOT NULL, authority_sha256 TEXT NOT NULL, registered_at TEXT NOT NULL, chain_sha256 TEXT NOT NULL, UNIQUE(campaign_id,model_epoch_number), UNIQUE(predecessor_model_epoch_id))"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS supplement_request_models (reservation_id TEXT PRIMARY KEY REFERENCES supplement_requests(reservation_id), model_epoch_id TEXT NOT NULL REFERENCES supplement_model_epochs(model_epoch_id), identity_manifest_sha256 TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS supplement_model_halts (event_id TEXT PRIMARY KEY, model_epoch_id TEXT NOT NULL REFERENCES supplement_model_epochs(model_epoch_id), reservation_id TEXT, reason TEXT NOT NULL, observed_model TEXT, observed_fingerprint TEXT, evidence_sha256 TEXT NOT NULL, created_at TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS budget_halt_events (event_id INTEGER PRIMARY KEY, reason TEXT NOT NULL)"
    )
    for table in TABLES:
        for op in ("UPDATE", "DELETE"):
            db.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{op.lower()} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'model identity records are append-only'); END"
            )
    for table in TABLES:
        db.execute(
            _conflict_trigger(table).replace(
                "CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1
            )
        )
    for op in ("INSERT", "UPDATE"):
        db.execute(
            f"CREATE TRIGGER IF NOT EXISTS budget_capture_halt_{op.lower()} AFTER {op} ON config WHEN NEW.key='halt' AND NEW.value<>'observable model version changed' BEGIN INSERT INTO budget_halt_events(reason) VALUES (NEW.value); END"
        )


def _check_schema(db):
    expected = {}
    for table in TABLES:
        if not db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone():
            raise ValueError("model identity schema unavailable")
        for op in ("UPDATE", "DELETE"):
            name = f"{table}_no_{op.lower()}"
            expected[name] = (
                f"CREATE TRIGGER {name} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'model identity records are append-only'); END"
            )
    for table in TABLES:
        expected[f"{table}_no_replace"] = _conflict_trigger(table)
    for op in ("INSERT", "UPDATE"):
        name = f"budget_capture_halt_{op.lower()}"
        expected[name] = (
            f"CREATE TRIGGER {name} AFTER {op} ON config WHEN NEW.key='halt' AND NEW.value<>'observable model version changed' BEGIN INSERT INTO budget_halt_events(reason) VALUES (NEW.value); END"
        )
    for name, sql in expected.items():
        row = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
        ).fetchone()
        if not row or " ".join(row[0].split()) != " ".join(sql.split()):
            raise ValueError("model identity protection trigger differs")


def _chain(db):
    from evals.adapters.source_epochs import (
        _require_budget,
        require_epoch_in_transaction,
    )

    _check_schema(db)
    values, previous = [], None
    for row in db.execute(
        "SELECT model_epoch_id,campaign_id,model_epoch_number,predecessor_model_epoch_id,manifest_json,manifest_sha256,authority_json,authority_sha256,registered_at,chain_sha256 FROM supplement_model_epochs ORDER BY model_epoch_number"
    ):
        m = _validate_manifest(json.loads(row[4]))
        a = json.loads(row[6])
        _authority(m, a, row[7])
        _require_budget(db, m["budget_identity"])
        source = require_epoch_in_transaction(
            db,
            m["epoch_id"],
            source_sha256=m["source_sha256"],
            config_sha256=m["config_sha256"],
            manifest_sha256=m["source_manifest_sha256"],
            budget_identity=m["budget_identity"],
        )
        if (
            tuple(row[:4])
            != (
                m["model_epoch_id"],
                CAMPAIGN_ID,
                len(values),
                previous[0] if previous else None,
            )
            or m["model_epoch_number"] != row[2]
            or m["predecessor_model_epoch_id"] != row[3]
            or canonical_hash(m) != row[5]
            or canonical_hash(
                [previous[9] if previous else None, *row[:4], row[5], row[7], row[8]]
            )
            != row[9]
            or m["budget_path"] != source["budget_path"]
            or m["controller_state_roots"] != source["controller_state_roots"]
        ):
            raise ValueError("model identity chain altered")
        values.append(m)
        previous = row
    ids = {m["model_epoch_id"] for m in values}
    for (
        event_id,
        model_id,
        reservation,
        reason,
        observed,
        fingerprint,
        evidence,
        created_at,
    ) in db.execute(
        "SELECT event_id,model_epoch_id,reservation_id,reason,observed_model,observed_fingerprint,evidence_sha256,created_at FROM supplement_model_halts"
    ):
        if (
            model_id not in ids
            or reason != "response_identity_mismatch"
            or evidence
            != canonical_hash(
                [
                    event_id,
                    model_id,
                    reservation,
                    reason,
                    observed,
                    fingerprint,
                    created_at,
                ]
            )
        ):
            raise ValueError("model halt evidence altered")
    return values, previous


def require_model_identity_in_transaction(
    db,
    model_epoch_id,
    *,
    epoch_id,
    source_sha256,
    config_sha256,
    purpose,
    manifest_sha256=None,
    latest=False,
):
    try:
        values, _ = _chain(db)
        match = next((m for m in values if m["model_epoch_id"] == model_epoch_id), None)
        if (
            match is None
            or match["epoch_id"] != epoch_id
            or match["source_sha256"] != source_sha256
            or match["config_sha256"] != config_sha256
            or purpose not in match["purposes"]
            or (
                manifest_sha256 is not None and canonical_hash(match) != manifest_sha256
            )
            or (latest and match != values[-1])
        ):
            raise ValueError(
                "model identity binding differs, purpose forbidden or identity retired"
            )
        return match
    except (
        sqlite3.Error,
        json.JSONDecodeError,
        TypeError,
        KeyError,
        PermissionError,
    ) as exc:
        raise ValueError("model identity schema or chain unavailable") from exc


def require_registered_model_identity(path, model_epoch_id, **bindings):
    from evals.adapters.source_epochs import _existing_path

    path = _existing_path(path)
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        m = require_model_identity_in_transaction(db, model_epoch_id, **bindings)
        if (
            not os.environ.get("TASK13_WORKER_NONCE")
            and Path(m["budget_path"]).resolve() != path.resolve()
        ):
            raise ValueError("model identity requires original budget path")
        return m


def register_model_identity(
    path,
    manifest,
    *,
    expected_manifest_sha256,
    budget_identity,
    authority,
    expected_authority_sha256,
):
    from evals.adapters.source_epochs import (
        _existing_path,
        _lock_controller_roots,
        _require_budget,
        require_epoch_in_transaction,
    )

    if os.getpid() == 1 or os.environ.get("TASK13_WORKER_NONCE"):
        raise PermissionError("model registration is host-only")
    path = _existing_path(path)
    m = _validate_manifest(json.loads(json.dumps(manifest, allow_nan=False)))
    if (
        not _sha256(expected_manifest_sha256)
        or canonical_hash(m) != expected_manifest_sha256
    ):
        raise ValueError("model identity manifest pin differs")
    _authority(m, authority, expected_authority_sha256)
    if (
        m["budget_identity"] != budget_identity
        or Path(m["budget_path"]).resolve() != path.resolve()
    ):
        raise ValueError("original budget binding differs")
    with ExitStack() as stack:
        _lock_controller_roots(m["controller_state_roots"], stack)
        with sqlite3.connect(path, timeout=30) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            _require_budget(db, budget_identity)
            source = require_epoch_in_transaction(
                db,
                m["epoch_id"],
                source_sha256=m["source_sha256"],
                config_sha256=m["config_sha256"],
                manifest_sha256=m["source_manifest_sha256"],
                budget_identity=budget_identity,
                latest=True,
            )
            if (
                m["controller_state_roots"] != source["controller_state_roots"]
                or m["budget_path"] != source["budget_path"]
            ):
                raise ValueError("source host binding differs")
            if db.execute(
                "SELECT 1 FROM reservations WHERE settled=0 LIMIT 1"
            ).fetchone():
                raise PermissionError("budget has in-flight requests")
            config = dict(db.execute("SELECT key,value FROM config"))
            if any(config.get(k) != v for k, v in m["inherited_global"].items()):
                raise ValueError("inherited global identity or halt differs")
            exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='supplement_model_epochs'"
            ).fetchone()
            if exists:
                values, previous = _chain(db)
            else:
                _schema(db)
                values, previous = _chain(db)
            if db.execute("SELECT 1 FROM budget_halt_events LIMIT 1").fetchone():
                raise RuntimeError("global budget blocker recorded")
            if m["model_epoch_number"] != len(values) or m[
                "predecessor_model_epoch_id"
            ] != (previous[0] if previous else None):
                raise ValueError("model identity predecessor differs")
            at = datetime.now(UTC).isoformat()
            head = (
                m["model_epoch_id"],
                CAMPAIGN_ID,
                m["model_epoch_number"],
                m["predecessor_model_epoch_id"],
            )
            chain = canonical_hash(
                [
                    previous[9] if previous else None,
                    *head,
                    expected_manifest_sha256,
                    expected_authority_sha256,
                    at,
                ]
            )
            db.execute(
                "INSERT INTO supplement_model_epochs VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    *head,
                    json.dumps(m, sort_keys=True),
                    expected_manifest_sha256,
                    json.dumps(authority, sort_keys=True),
                    expected_authority_sha256,
                    at,
                    chain,
                ),
            )
    return m
