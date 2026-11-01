"""Host-preregistered E2 dispatch slots, separate from legacy source admission.

Authority and both expected hashes are independent trusted-host admission inputs.
Nothing here infers consent, registers a source epoch, spends budget, approves a
plan, or verifies source artifacts. Inspected workers must do those other checks.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from evals.adapters.e_planning_contracts import EPlanningRequest
from evals.adapters.remediation_contracts import CAMPAIGN
from evals.contracts import SHA256, Contract, canonical_hash
from evals.e_planning import planning_requests, validate_e_planning_registration

TABLES = {
    "e_planning_registration": "e_planning_registration",
    "analysis_import_planning_slots": "e_planning_slots",
    "analysis_import_planning_claims": "e_planning_claims",
}


class EPlanningAuthority(Contract):
    schema_version: Literal["task13-e-planning-authority-v1"]
    campaign_id: Literal["task13-repair-202610-v2"]
    registration_sha256: str = Field(pattern=SHA256)
    journal_path: str
    scope_packet_sha256: str = Field(pattern=SHA256)
    decision_record_sha256: str = Field(pattern=SHA256)
    decision: Literal["approved"]
    decided_by: Literal["user"]
    decided_at: str
    purpose: Literal["development"]
    synthetic: bool = Field(strict=True)
    request_sha256s: list[str] = Field(min_length=3, max_length=3)

    @model_validator(mode="after")
    def explicit_external_decision(self) -> Self:
        when = datetime.fromisoformat(self.decided_at.replace("Z", "+00:00"))
        if when.tzinfo is None or when.utcoffset() is None:
            raise ValueError("external scope decision needs an actual zoned timestamp")
        if len(set(self.request_sha256s)) != 3:
            raise ValueError("three independently bound planning requests required")
        if not self.synthetic and (
            self.scope_packet_sha256 == "0" * 64
            or self.decision_record_sha256 == "0" * 64
        ):
            raise ValueError(
                "real authority requires nonempty external artifact hashes"
            )
        return self


def _validate_request_partition(requests, authorized, denied):
    if (
        len(set(requests)) != 3
        or len(set(authorized)) != len(authorized)
        or len(set(denied)) != len(denied)
        or set(authorized) & set(denied)
        or set(authorized) | set(denied) != set(requests)
        or authorized != [digest for digest in requests if digest in authorized]
        or denied != [digest for digest in requests if digest in denied]
    ):
        raise ValueError(
            "authorized and denied requests must partition the frozen three"
        )


class ManualRecoveryChildGrant(Contract):
    registration_sha256: str = Field(pattern=SHA256)
    journal_path: str
    request_sha256s: list[Annotated[str, Field(pattern=SHA256)]] = Field(
        min_length=3, max_length=3
    )
    authorized_request_sha256s: list[Annotated[str, Field(pattern=SHA256)]] = Field(
        min_length=1, max_length=3
    )
    denied_request_sha256s: list[Annotated[str, Field(pattern=SHA256)]] = Field(
        min_length=0, max_length=2
    )

    @model_validator(mode="after")
    def fixed_partition(self) -> Self:
        _validate_request_partition(
            self.request_sha256s,
            self.authorized_request_sha256s,
            self.denied_request_sha256s,
        )
        return self


class ManualRecoveryGrant(Contract):
    """Frozen migration scope; parsing does not consume or create authority."""

    schema_version: Literal["task13-manual-recovery-grant-v1"]
    recovery_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    recovery_plan_sha256: str = Field(pattern=SHA256)
    quarantine_record_sha256: str = Field(pattern=SHA256)
    predecessor_pool_registration_sha256: str = Field(pattern=SHA256)
    predecessor_pool_journal_sha256: str = Field(pattern=SHA256)
    predecessor_pool_head_sha256: str = Field(pattern=SHA256)
    scope_packet_sha256: str = Field(pattern=SHA256)
    decision_record_sha256: str = Field(pattern=SHA256)
    consumed_logical: Literal[8]
    consumed_physical: Literal[24]
    remaining_logical: Literal[5]
    remaining_physical: Literal[15]
    total_logical_limit: Literal[13]
    total_physical_limit: Literal[39]
    analysis_inclusive_limit: Literal[40]
    development_cap_yuan: Literal["6"]
    deadline: Literal["2026-11-02T23:59:59+08:00"]
    children: list[ManualRecoveryChildGrant] = Field(min_length=2, max_length=2)

    @model_validator(mode="before")
    @classmethod
    def strict_budget_types(cls, value):
        if isinstance(value, dict) and any(
            type(value.get(key)) is not int
            for key in (
                "consumed_logical",
                "consumed_physical",
                "remaining_logical",
                "remaining_physical",
                "total_logical_limit",
                "total_physical_limit",
                "analysis_inclusive_limit",
            )
        ):
            raise ValueError("migration budgets require exact integer values")
        return value

    @model_validator(mode="after")
    def exact_remaining_grant(self) -> Self:
        if (
            [len(child.authorized_request_sha256s) for child in self.children] != [3, 2]
            or len({child.registration_sha256 for child in self.children}) != 2
            or len({child.journal_path for child in self.children}) != 2
            or len(
                {digest for child in self.children for digest in child.request_sha256s}
            )
            != 6
            or any(
                getattr(self, key) == "0" * 64
                for key in (
                    "recovery_plan_sha256",
                    "quarantine_record_sha256",
                    "predecessor_pool_registration_sha256",
                    "predecessor_pool_journal_sha256",
                    "predecessor_pool_head_sha256",
                    "scope_packet_sha256",
                    "decision_record_sha256",
                )
            )
        ):
            raise ValueError(
                "migration requires exact distinct three-plus-two grants and pins"
            )
        return self


class LimitedEPlanningAuthority(Contract):
    """Explicit subset of a three-slot native registration under one migration."""

    schema_version: Literal["task13-e-planning-authority-v2"]
    campaign_id: Literal["task13-repair-202610-v2"]
    registration_sha256: str = Field(pattern=SHA256)
    journal_path: str
    scope_packet_sha256: str = Field(pattern=SHA256)
    decision_record_sha256: str = Field(pattern=SHA256)
    decision: Literal["approved"]
    decided_by: Literal["user"]
    decided_at: str
    purpose: Literal["development"]
    synthetic: bool = Field(strict=True)
    request_sha256s: list[Annotated[str, Field(pattern=SHA256)]] = Field(
        min_length=3, max_length=3
    )
    authorized_request_sha256s: list[Annotated[str, Field(pattern=SHA256)]] = Field(
        min_length=1, max_length=3
    )
    denied_request_sha256s: list[Annotated[str, Field(pattern=SHA256)]] = Field(
        min_length=0, max_length=2
    )
    migration_grant: ManualRecoveryGrant
    migration_grant_sha256: str = Field(pattern=SHA256)

    @model_validator(mode="after")
    def exact_migration_child(self) -> Self:
        legacy = {key: getattr(self, key) for key in EPlanningAuthority.model_fields}
        legacy["schema_version"] = "task13-e-planning-authority-v1"
        EPlanningAuthority.model_validate(legacy)
        _validate_request_partition(
            self.request_sha256s,
            self.authorized_request_sha256s,
            self.denied_request_sha256s,
        )
        grant = self.migration_grant
        child = {
            key: getattr(self, key) for key in ManualRecoveryChildGrant.model_fields
        }
        if (
            canonical_hash(grant) != self.migration_grant_sha256
            or grant.scope_packet_sha256 != self.scope_packet_sha256
            or grant.decision_record_sha256 != self.decision_record_sha256
            or sum(
                candidate.model_dump(mode="json") == child
                for candidate in grant.children
            )
            != 1
        ):
            raise ValueError(
                "limited authority differs from exact migration child grant"
            )
        return self


def parse_authority(value) -> EPlanningAuthority | LimitedEPlanningAuthority:
    """Parse an explicit version without changing legacy canonical values."""
    if not isinstance(value, dict):
        raise ValueError("an explicit versioned planning authority is required")  # noqa: TRY004 - invalid external authority.
    if value.get("schema_version") == "task13-e-planning-authority-v1":
        return EPlanningAuthority.model_validate(value)
    if value.get("schema_version") == "task13-e-planning-authority-v2":
        return LimitedEPlanningAuthority.model_validate(value)
    raise ValueError("unsupported planning authority version")


def _require_authorized_request(authority, request):
    if (
        authority["schema_version"] == "task13-e-planning-authority-v2"
        and canonical_hash(request) not in authority["authorized_request_sha256s"]
    ):
        raise PermissionError("planning request is not authorized by its limited grant")


def _path(value, *, exists):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("an absolute regular planning journal path is required")
    for part in (path, *path.parents):
        if not part.exists() and not part.is_symlink():
            continue
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("planning journal path contains a link/reparse point")
    if exists and not path.is_file():
        raise ValueError("an existing planning journal is required")
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError("planning journal must be a single regular file")
    if not path.parent.is_dir():
        raise ValueError("registered journal parent must already exist")
    return path.resolve(strict=exists)


@contextmanager
def _connect(path, *, readonly=False):
    # mode=rw/ro never creates a missing file, including after a worker crash.
    mode = "ro" if readonly else "rw"
    db = sqlite3.connect(path.as_uri() + "?mode=" + mode, uri=True, timeout=30)
    try:
        db.execute("PRAGMA foreign_keys=ON")
        with db:
            yield db
    finally:
        db.close()


def _require_mounted_path(path, authority, mounted_host_journal_path):
    if str(path) == authority["journal_path"] and mounted_host_journal_path is None:
        return
    if (
        os.getpid() != 1
        or not os.environ.get("TASK13_WORKER_NONCE")
        or path != Path("/app/import-dispatch/e-planning.sqlite")
        or mounted_host_journal_path != authority["journal_path"]
    ):
        raise ValueError("registered journal path or inspected host mount differs")


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


def _authority(
    value, registration, expected_registration_sha256, expected_authority_sha256
):
    r = validate_e_planning_registration(registration)
    a = parse_authority(value).model_dump(mode="json")
    if (
        canonical_hash(r) != expected_registration_sha256
        or canonical_hash(a) != expected_authority_sha256
        or a["registration_sha256"] != expected_registration_sha256
        or a["synthetic"] != r["synthetic"]
        or a["request_sha256s"] != [canonical_hash(q) for q in planning_requests(r)]
    ):
        raise PermissionError(
            "independently pinned external planning authority differs"
        )
    return r, a


def _schema(db):
    db.execute(
        "CREATE TABLE e_planning_registration (singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
        "registration_json TEXT NOT NULL,registration_sha256 TEXT NOT NULL,"
        "authority_json TEXT NOT NULL,authority_sha256 TEXT NOT NULL,receipt_json TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE analysis_import_planning_slots (planning_slot_id TEXT PRIMARY KEY,"
        "ordinal INTEGER UNIQUE NOT NULL CHECK(ordinal BETWEEN 1 AND 3),"
        "source_identity TEXT NOT NULL,analysis_output_sha256 TEXT NOT NULL,"
        "request_sha256 TEXT UNIQUE NOT NULL,incident_id TEXT UNIQUE NOT NULL,"
        "request_json TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE analysis_import_planning_claims (planning_slot_id TEXT PRIMARY KEY "
        "REFERENCES analysis_import_planning_slots(planning_slot_id),"
        "request_sha256 TEXT UNIQUE NOT NULL,incident_id TEXT UNIQUE NOT NULL,"
        "status TEXT NOT NULL CHECK(status='started'))"
    )
    for table, prefix in TABLES.items():
        for operation in ("update", "delete"):
            db.execute(
                f"CREATE TRIGGER {prefix}_no_{operation} BEFORE {operation.upper()} ON {table} "
                "BEGIN SELECT RAISE(ABORT,'immutable E planning dispatch'); END"
            )


def _read(db, expected_registration_sha256, expected_authority_sha256):
    try:
        tables = {
            r[0]
            for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        triggers = {
            r[0]
            for r in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        }
        required_triggers = {
            prefix + "_no_" + operation
            for prefix in TABLES.values()
            for operation in ("update", "delete")
        }
        if tables != set(TABLES) or triggers != required_triggers:
            raise ValueError("registered planning schema or immutable guards differ")
        rows = db.execute("SELECT * FROM e_planning_registration").fetchall()
        if len(rows) != 1 or rows[0][0] != 1:
            raise ValueError("exactly one host planning registration required")
        row = rows[0]
        r, a = _authority(
            json.loads(row[3]),
            json.loads(row[1]),
            expected_registration_sha256,
            expected_authority_sha256,
        )
        requests = planning_requests(r)
        receipt = {
            "schema_version": "task13-e-planning-dispatch-registration-v1",
            "campaign_id": CAMPAIGN,
            "registration_sha256": expected_registration_sha256,
            "authority_sha256": expected_authority_sha256,
            "journal_path": a["journal_path"],
            "synthetic": r["synthetic"],
            "planning_slot_ids": [q.planning_slot_id for q in requests],
        }
        if (row[2], row[4], json.loads(row[5])) != (
            expected_registration_sha256,
            expected_authority_sha256,
            receipt,
        ):
            raise ValueError("registered planning receipt differs")
        expected = [
            (
                q.planning_slot_id,
                q.ordinal,
                q.source_identity,
                q.analysis_output_sha256,
                canonical_hash(q),
                q.incident_id,
                q.model_dump(mode="json"),
            )
            for q in requests
        ]
        observed = [
            (*slot[:6], json.loads(slot[6]))
            for slot in db.execute(
                "SELECT * FROM analysis_import_planning_slots ORDER BY ordinal"
            )
        ]
        if observed != expected:
            raise ValueError("registered planning slot/request/source binding differs")
        by_slot = {q.planning_slot_id: q for q in requests}
        for slot, digest, incident, status in db.execute(
            "SELECT * FROM analysis_import_planning_claims"
        ):
            q = by_slot.get(slot)
            if q is None or (digest, incident, status) != (
                canonical_hash(q),
                q.incident_id,
                "started",
            ):
                raise ValueError("registered planning claim binding differs")
            _require_authorized_request(a, q)
        return r, a, receipt
    except (sqlite3.DatabaseError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError(
            "registered planning journal is unavailable or malformed"
        ) from error


def register_planning_slots(
    path,
    registration,
    *,
    expected_registration_sha256,
    authority,
    expected_authority_sha256,
) -> dict:
    """Host-only, externally pinned registration; no authority defaults exist.

    The caller must obtain the actual scope record and its independently pinned
    hashes before calling. Supplying data here is not proof of a human decision.
    """
    if os.getpid() == 1 or os.environ.get("TASK13_WORKER_NONCE"):
        raise PermissionError("planning slot registration is host-only")
    r, a = _authority(
        authority, registration, expected_registration_sha256, expected_authority_sha256
    )
    path = _path(path, exists=False)
    if a["journal_path"] != str(path):
        raise PermissionError("external authority requires its original journal path")
    if path.exists():
        with _connect(path, readonly=True) as db:
            return _read(db, expected_registration_sha256, expected_authority_sha256)[2]
    # Exclusive creation makes an existing/unknown journal fail closed, never reset.
    try:
        with path.open("xb"):
            pass
    except FileExistsError:
        with _connect(_path(path, exists=True), readonly=True) as db:
            return _read(db, expected_registration_sha256, expected_authority_sha256)[2]
    requests = planning_requests(r)
    receipt = {
        "schema_version": "task13-e-planning-dispatch-registration-v1",
        "campaign_id": CAMPAIGN,
        "registration_sha256": expected_registration_sha256,
        "authority_sha256": expected_authority_sha256,
        "journal_path": str(path),
        "synthetic": r["synthetic"],
        "planning_slot_ids": [q.planning_slot_id for q in requests],
    }
    with _connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        _schema(db)
        db.execute(
            "INSERT INTO e_planning_registration VALUES (1,?,?,?,?,?)",
            (
                _json(r),
                expected_registration_sha256,
                _json(a),
                expected_authority_sha256,
                _json(receipt),
            ),
        )
        db.executemany(
            "INSERT INTO analysis_import_planning_slots VALUES (?,?,?,?,?,?,?)",
            [
                (
                    q.planning_slot_id,
                    q.ordinal,
                    q.source_identity,
                    q.analysis_output_sha256,
                    canonical_hash(q),
                    q.incident_id,
                    _json(q.model_dump(mode="json")),
                )
                for q in requests
            ],
        )
    return receipt


class EPlanningDispatchJournal:
    """Existing-only worker admission. Started/unknown slots can never replay."""

    def __init__(self, *args, **kwargs):
        raise TypeError("use the existing-only EPlanningDispatchJournal.open_existing")

    @classmethod
    def open_existing(
        cls,
        path,
        *,
        expected_registration_sha256,
        expected_authority_sha256,
        mounted_host_journal_path=None,
    ):
        """Worker remapping requires the runtime's independently inspected source.

        This parameter does not inspect Docker. The runtime must establish that
        the one RW mount is this exact registered host file before GO.
        """
        path = _path(path, exists=True)
        try:
            with _connect(path, readonly=True) as db:
                _, authority, _ = _read(
                    db, expected_registration_sha256, expected_authority_sha256
                )
                _require_mounted_path(path, authority, mounted_host_journal_path)
        except PermissionError as error:
            raise ValueError("registered planning authority differs") from error
        instance = object.__new__(cls)
        instance.path = path
        instance.registration_sha256 = expected_registration_sha256
        instance.authority_sha256 = expected_authority_sha256
        instance.mounted_host_journal_path = mounted_host_journal_path
        return instance

    def validate_request(self, request: EPlanningRequest) -> dict:
        """Read registered identity and claim state without admitting execution."""
        request = EPlanningRequest.model_validate(request.model_dump(mode="json"))
        path = _path(self.path, exists=True)
        with _connect(path, readonly=True) as db:
            db.execute("BEGIN")
            registration, authority, _ = _read(
                db, self.registration_sha256, self.authority_sha256
            )
            _require_mounted_path(path, authority, self.mounted_host_journal_path)
            registered = planning_requests(registration)[request.ordinal - 1]
            if canonical_hash(registered) != canonical_hash(request):
                raise PermissionError(
                    "request differs from the registered planning slot"
                )
            _require_authorized_request(authority, request)
            claim = db.execute(
                "SELECT request_sha256,incident_id,status FROM analysis_import_planning_claims "
                "WHERE planning_slot_id=?",
                (request.planning_slot_id,),
            ).fetchone()
            if claim is not None and tuple(claim) != (
                canonical_hash(request),
                request.incident_id,
                "started",
            ):
                raise PermissionError("planning claim differs from registered request")
        return {
            "status": "started" if claim else "unclaimed",
            "planning_slot_id": request.planning_slot_id,
            "request_sha256": canonical_hash(request),
            "registration_sha256": self.registration_sha256,
            "authority_sha256": self.authority_sha256,
            "source_identity": request.source_identity,
            "analysis_output_sha256": request.analysis_output_sha256,
            "incident_id": request.incident_id,
        }

    def claim_planning_slot(self, request: EPlanningRequest) -> dict:
        request = EPlanningRequest.model_validate(request.model_dump(mode="json"))
        path = _path(self.path, exists=True)
        with _connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            registration, authority, _ = _read(
                db, self.registration_sha256, self.authority_sha256
            )
            _require_mounted_path(path, authority, self.mounted_host_journal_path)
            registered = planning_requests(registration)[request.ordinal - 1]
            if (
                canonical_hash(registered) != canonical_hash(request)
                or request.registration_sha256 != self.registration_sha256
            ):
                raise PermissionError(
                    "request differs from the registered planning slot"
                )
            _require_authorized_request(authority, request)
            try:
                db.execute(
                    "INSERT INTO analysis_import_planning_claims VALUES (?,?,?,'started')",
                    (
                        request.planning_slot_id,
                        canonical_hash(request),
                        request.incident_id,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise PermissionError(
                    "planning slot already started; automatic replay refused"
                ) from error
        return {
            "status": "started",
            "planning_slot_id": request.planning_slot_id,
            "request_sha256": canonical_hash(request),
            "registration_sha256": self.registration_sha256,
            "authority_sha256": self.authority_sha256,
            "source_identity": request.source_identity,
            "analysis_output_sha256": request.analysis_output_sha256,
            "incident_id": request.incident_id,
        }
