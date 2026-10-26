"""Restricted, immutable analysis-import payload; no evaluation dependencies.

Artifact verification is an adapter responsibility. This type is created only by
that verifier, not by initial_state or JSON deserialization. Product entry checks
the artifacts again and independently hydrates the incident's persisted evidence.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


def _digest(value):
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


@dataclass(frozen=True, init=False)
class ImportedAnalysis:
    _values: bytes
    _provenance: bytes
    _check: Callable

    def __init__(self, *args, **kwargs):
        raise TypeError("ImportedAnalysis requires the artifact verifier")

    @classmethod
    def _from_verified_artifacts(cls, values, provenance, check):
        instance = object.__new__(cls)
        object.__setattr__(
            instance,
            "_values",
            json.dumps(values, sort_keys=True, allow_nan=False).encode(),
        )
        object.__setattr__(
            instance,
            "_provenance",
            json.dumps(provenance, sort_keys=True, allow_nan=False).encode(),
        )
        object.__setattr__(instance, "_check", check)
        return instance

    @property
    def provenance(self):
        return json.loads(self._provenance)

    @property
    def source_identity(self):
        p = self.provenance
        return _digest([p["case_id"], p["source_row_id"], p["request_sha256"]])

    def product_values(self):
        return {
            **json.loads(self._values),
            "analysis_import_provenance": self.provenance,
        }

    def revalidate(self):
        values, provenance = self._check()
        if values != json.loads(self._values) or provenance != self.provenance:
            raise ValueError("verified analysis source changed")


class ImportDispatchJournal:
    """Append-only admission: a crash after claim never enables automatic replay.

    This is dispatch metadata, never a model budget or approval database. Runtime
    integration must mount the one registered journal; this class does not grant
    worker or paid-call authority.
    """

    def __init__(self, path: Path):
        path = Path(path)
        if (
            not path.is_absolute()
            or path.is_symlink()
            or (path.exists() and path.stat().st_nlink != 1)
        ):
            raise ValueError("an absolute regular dispatch journal is required")
        self.path = path
        with sqlite3.connect(path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS analysis_import_dispatch (source_identity TEXT PRIMARY KEY, incident_id TEXT UNIQUE NOT NULL, status TEXT NOT NULL CHECK(status='started'))"
            )
            db.execute(
                "CREATE TRIGGER IF NOT EXISTS analysis_import_no_update BEFORE UPDATE ON analysis_import_dispatch BEGIN SELECT RAISE(ABORT, 'immutable import dispatch'); END"
            )
            db.execute(
                "CREATE TRIGGER IF NOT EXISTS analysis_import_no_delete BEFORE DELETE ON analysis_import_dispatch BEGIN SELECT RAISE(ABORT, 'immutable import dispatch'); END"
            )

    def claim(self, source_identity, incident_id):
        try:
            with sqlite3.connect(self.path) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO analysis_import_dispatch VALUES (?, ?, 'started')",
                    (source_identity, incident_id),
                )
        except sqlite3.IntegrityError as error:
            raise PermissionError(
                "source or incident already started; automatic replay refused"
            ) from error


@dataclass(frozen=True, init=False)
class PlanningAdmission:
    """Immutable, rechecked receipt for one already claimed planning slot.

    Only the adapter that opened the externally registered journal creates this
    type. It carries no authority to create, register or claim another slot.
    """

    _binding: bytes
    _check: Callable

    def __init__(self, *args, **kwargs):
        raise TypeError("PlanningAdmission requires an existing journal claim")

    @classmethod
    def _from_existing_claim(cls, binding, check):
        if check() != binding or binding.get("status") != "started":
            raise PermissionError("registered planning claim differs")
        instance = object.__new__(cls)
        object.__setattr__(
            instance,
            "_binding",
            json.dumps(binding, sort_keys=True, allow_nan=False).encode(),
        )
        object.__setattr__(instance, "_check", check)
        return instance

    @property
    def binding(self):
        return json.loads(self._binding)

    def provenance_for(self, source, incident_id):
        binding = self.binding
        source.revalidate()
        if self._check() != binding or incident_id != binding["incident_id"]:
            raise PermissionError("registered planning claim or incident differs")
        provenance = source.provenance
        source_fields = {
            "analysis_output_sha256": "analysis_output_sha256",
            "imported_values_sha256": "imported_values_sha256",
            "source_package_manifest_sha256": "source_package_manifest_sha256",
            "original_request_sha256": "request_sha256",
            "original_manifest_sha256": "manifest_sha256",
        }
        if source.source_identity != binding["source_identity"] or any(
            binding[key] != provenance.get(source_key)
            for key, source_key in source_fields.items()
        ):
            raise PermissionError("registered planning source lineage differs")
        return {
            **provenance,
            "planning_admission": {
                key: value for key, value in binding.items() if key != "status"
            },
        }
