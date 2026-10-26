"""Bound Task13 supplement accounting; creates no provider or controller authority.

Use the existing campaign.sqlite, never a fresh budget DB for a live supplement.
The caller must supply a trusted, frozen run binding before constructing a model.
Historical reservations are deliberately neither migrated nor inferred.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from evals.adapters.model_client import BudgetAccount, BudgetLimit
from evals.contracts import canonical_hash

CAMPAIGN_ID = "task13-repair-202610-v2"
PURPOSE_LIMITS = MappingProxyType({"development": 6.0, "regression": 16.0, "f8": 6.0})
PURPOSE_PHASES = MappingProxyType(
    {"development": "development", "regression": "formal", "f8": "verification"}
)
SUPPLEMENT_LIMIT = 30.0
HELD_CONTINGENCY = 2.0
_START_FIELDS = frozenset(
    {
        "role",
        "request_id",
        "requested_at",
        "logical_call_id",
        "physical_attempt",
        "request_sha256",
    }
)
_END_FIELDS = frozenset(
    {
        "request_id",
        "finished_at",
        "usage",
        "provider_request_id",
        "parse_status",
        "error_type",
        "usage_missing_reason",
        "duration_ms",
    }
)


def _identity(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value) is not None
    )


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _timestamp(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid request metadata timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("request metadata timestamp must include timezone")
    return parsed


@dataclass(frozen=True)
class _Binding:
    campaign_id: str
    case_id: str
    group: str
    attempt: int
    purpose: str
    source_sha256: str
    config_sha256: str


class SupplementBudgetAccount(BudgetAccount):
    """Global, development, campaign and purpose caps share one SQLite transaction.

    The 2 CNY contingency is held, has no dispatch purpose, and cannot be
    automatically moved to an exhausted purpose. Unknown and in-flight requests
    retain their own reserved upper bound in every applicable scope.
    """

    def __init__(
        self,
        path: Path,
        *,
        campaign_id: str,
        case_id: str,
        group: str,
        attempt: int,
        purpose: str,
        source_sha256: str,
        config_sha256: str,
        total_cny: float = 100,
        dev_cny: float = 15,
        epoch_id: str | None = None,
    ):
        if (
            campaign_id != CAMPAIGN_ID
            or not _identity(case_id)
            or not _identity(group)
            or type(attempt) is not int
            or attempt < 1
            or not isinstance(purpose, str)
            or purpose not in PURPOSE_LIMITS
            or not _sha256(source_sha256)
            or not _sha256(config_sha256)
        ):
            raise ValueError("explicit valid supplement binding is required")
        self._binding = _Binding(
            campaign_id, case_id, group, attempt, purpose, source_sha256, config_sha256
        )
        self._stable_keys: dict[str, tuple[str, int]] = {}
        self._epoch_id = epoch_id
        if epoch_id is not None:
            from evals.adapters.source_epochs import require_registered_epoch

            if (
                not _identity(epoch_id)
                or isinstance(total_cny, bool)
                or isinstance(dev_cny, bool)
                or total_cny != 100
                or dev_cny != 15
            ):
                raise ValueError(
                    "registered epoch requires the unchanged 100/15 budget"
                )
            # A worker may only read registration. In particular, do not invoke
            # the legacy constructor which can create a DB/campaign/schema.
            self.path = Path(path)
            manifest = require_registered_epoch(
                self.path,
                epoch_id,
                source_sha256=source_sha256,
                config_sha256=config_sha256,
            )
            self._epoch_manifest_sha256 = canonical_hash(manifest)
            self._epoch_budget_identity = manifest["budget_identity"]
            return
        super().__init__(path, total_cny=total_cny, dev_cny=dev_cny)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "CREATE TABLE IF NOT EXISTS supplement_campaigns ("
                "campaign_id TEXT PRIMARY KEY, frozen_config TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS supplement_requests ("
                "reservation_id TEXT PRIMARY KEY REFERENCES reservations(id), "
                "campaign_id TEXT NOT NULL REFERENCES supplement_campaigns(campaign_id), "
                "case_id TEXT NOT NULL, group_name TEXT NOT NULL, attempt INTEGER NOT NULL, "
                "purpose TEXT NOT NULL, source_sha256 TEXT NOT NULL, config_sha256 TEXT NOT NULL, "
                "role TEXT NOT NULL, request_id TEXT UNIQUE NOT NULL, requested_at TEXT NOT NULL, "
                "logical_call_id TEXT NOT NULL, physical_attempt INTEGER NOT NULL, "
                "request_sha256 TEXT NOT NULL, finished_at TEXT, usage_json TEXT, "
                "provider_request_id TEXT, parse_status TEXT, error_type TEXT, "
                "usage_missing_reason TEXT, duration_ms INTEGER)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS supplement_requests_scope "
                "ON supplement_requests(campaign_id,purpose)"
            )
            frozen = json.dumps(
                {
                    "source_sha256": source_sha256,
                    "config_sha256": config_sha256,
                    "supplement_cny": SUPPLEMENT_LIMIT,
                    "purpose_limits_cny": dict(PURPOSE_LIMITS),
                    "held_contingency_cny": HELD_CONTINGENCY,
                },
                sort_keys=True,
            )
            previous = db.execute(
                "SELECT frozen_config FROM supplement_campaigns WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
            if previous and previous[0] != frozen:
                raise ValueError("frozen supplement source/config/limits cannot change")
            db.execute(
                "INSERT OR IGNORE INTO supplement_campaigns VALUES (?,?)",
                (campaign_id, frozen),
            )

    def request_binding(self) -> dict[str, Any]:
        value = asdict(self._binding)
        if self._epoch_id is not None:
            value["epoch_id"] = self._epoch_id
        return value

    def _require_epoch(self, db, *, latest=False):
        if self._epoch_id is not None:
            from evals.adapters.source_epochs import require_epoch_in_transaction

            return require_epoch_in_transaction(
                db,
                self._epoch_id,
                source_sha256=self._binding.source_sha256,
                config_sha256=self._binding.config_sha256,
                budget_identity=self._epoch_budget_identity,
                manifest_sha256=self._epoch_manifest_sha256,
                latest=latest,
            )
        if (
            latest
            and db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='supplement_source_epochs'"
            ).fetchone()
        ):
            from evals.adapters.source_epochs import (
                require_legacy_dispatch_in_transaction,
            )

            require_legacy_dispatch_in_transaction(db)
        return None

    def physical_request_key(
        self, logical_key: str, physical_attempt: int, *, explicit_call_id: Any
    ) -> str:
        # A crash/reopen must not turn an already dispatched call into a fresh UUID.
        # A stable call ID is supplied by the trusted controller, never inferred.
        if not _identity(explicit_call_id):
            raise ValueError("supplement requires an explicit stable model call ID")
        key = canonical_hash([self.request_binding(), logical_key, physical_attempt])
        # The legacy alias also needs this hint after epoch zero is registered:
        # TrackedModel's persisted logical_call_id is random on reopen.
        self._stable_keys[key] = (logical_key, physical_attempt)
        return key

    def _reject_stable_replay(self, db, request_key, metadata):
        stable = self._stable_keys.get(request_key)
        if stable is None:
            return
        if not db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='supplement_request_epochs'"
        ).fetchone():
            # Preserve legacy-to-legacy behavior before any explicit epoch.
            return
        logical_key, physical = stable
        if (
            physical != metadata["physical_attempt"]
            or metadata["request_id"] != request_key
        ):
            raise ValueError("physical request metadata differs from its stable key")
        binding = self._binding
        candidates = db.execute(
            "SELECT s.source_sha256,s.config_sha256,e.epoch_id,r.request_key "
            "FROM supplement_requests s JOIN reservations r ON r.id=s.reservation_id "
            "LEFT JOIN supplement_request_epochs e ON e.reservation_id=s.reservation_id "
            "WHERE s.campaign_id=? AND s.case_id=? AND s.group_name=? AND s.attempt=? "
            "AND s.purpose=? AND s.role=? AND s.physical_attempt=?",
            (
                binding.campaign_id,
                binding.case_id,
                binding.group,
                binding.attempt,
                binding.purpose,
                metadata["role"],
                physical,
            ),
        )
        for source, config, epoch, old_key in candidates:
            old_binding = {
                **asdict(binding),
                "source_sha256": source,
                "config_sha256": config,
            }
            if epoch is not None:
                old_binding["epoch_id"] = epoch
            if canonical_hash([old_binding, logical_key, physical]) == old_key:
                raise BudgetLimit(
                    "stable physical request already reserved; source epoch replay refused"
                )

    def _reserve_in_transaction(
        self, db, reservation, request_key, upper_cny, phase, metadata
    ) -> None:
        binding = self._binding
        if phase != PURPOSE_PHASES[binding.purpose]:
            raise ValueError(
                "reservation phase does not match bound supplement purpose"
            )
        if not isinstance(metadata, dict) or set(metadata) != _START_FIELDS:
            raise ValueError("complete physical request metadata is required")
        if (
            not _identity(metadata["role"])
            or not _identity(metadata["request_id"])
            or not _identity(metadata["logical_call_id"])
            or type(metadata["physical_attempt"]) is not int
            or not 1 <= metadata["physical_attempt"] <= 3
            or not _sha256(metadata["request_sha256"])
        ):
            raise ValueError("invalid physical request metadata")
        _timestamp(metadata["requested_at"])
        self._require_epoch(db, latest=True)
        if db.execute(
            "SELECT 1 FROM supplement_requests WHERE request_id=?",
            (metadata["request_id"],),
        ).fetchone():
            raise BudgetLimit("physical request ID already reserved; duplicate refused")
        self._reject_stable_replay(db, request_key, metadata)
        mapped = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='supplement_request_epochs'"
        ).fetchone()
        if self._epoch_id is not None or mapped:
            replay = db.execute(
                "SELECT s.reservation_id FROM supplement_requests s "
                "WHERE s.campaign_id=? AND s.case_id=? AND s.group_name=? AND s.attempt=? "
                "AND s.purpose=? AND s.role=? AND s.logical_call_id=? AND s.physical_attempt=?"
                + (
                    " AND EXISTS (SELECT 1 FROM supplement_request_epochs e "
                    "WHERE e.reservation_id=s.reservation_id)"
                    if self._epoch_id is None
                    else ""
                )
                + " LIMIT 1",
                (
                    binding.campaign_id,
                    binding.case_id,
                    binding.group,
                    binding.attempt,
                    binding.purpose,
                    metadata["role"],
                    metadata["logical_call_id"],
                    metadata["physical_attempt"],
                ),
            ).fetchone()
            if replay:
                raise BudgetLimit(
                    "semantic physical request already reserved; cross-epoch replay refused"
                )
        campaign_amount, purpose_amount = db.execute(
            "SELECT COALESCE(SUM(COALESCE(r.actual,r.upper)),0), "
            "COALESCE(SUM(CASE WHEN s.purpose=? THEN COALESCE(r.actual,r.upper) ELSE 0 END),0) "
            "FROM supplement_requests s JOIN reservations r ON r.id=s.reservation_id "
            "WHERE s.campaign_id=?",
            (binding.purpose, binding.campaign_id),
        ).fetchone()
        if campaign_amount + upper_cny > SUPPLEMENT_LIMIT + 1e-12:
            raise BudgetLimit(
                "supplement campaign budget exhausted including in-flight requests"
            )
        if purpose_amount + upper_cny > PURPOSE_LIMITS[binding.purpose] + 1e-12:
            raise BudgetLimit(f"{binding.purpose} supplement purpose budget exhausted")
        db.execute(
            "INSERT INTO supplement_requests ("
            "reservation_id,campaign_id,case_id,group_name,attempt,purpose,source_sha256,config_sha256,"
            "role,request_id,requested_at,logical_call_id,physical_attempt,request_sha256) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                reservation,
                binding.campaign_id,
                binding.case_id,
                binding.group,
                binding.attempt,
                binding.purpose,
                binding.source_sha256,
                binding.config_sha256,
                metadata["role"],
                metadata["request_id"],
                metadata["requested_at"],
                metadata["logical_call_id"],
                metadata["physical_attempt"],
                metadata["request_sha256"],
            ),
        )
        if self._epoch_id is not None:
            db.execute(
                "INSERT INTO supplement_request_epochs (reservation_id,epoch_id) VALUES (?,?)",
                (reservation, self._epoch_id),
            )

    def _settle_in_transaction(self, db, reservation, actual, metadata) -> None:
        if not isinstance(metadata, dict) or set(metadata) != _END_FIELDS:
            raise ValueError("complete physical settlement metadata is required")
        row = db.execute(
            "SELECT campaign_id,case_id,group_name,attempt,purpose,source_sha256,config_sha256,"
            "request_id,requested_at FROM supplement_requests WHERE reservation_id=?",
            (reservation,),
        ).fetchone()
        if row is None or tuple(row[:7]) != tuple(asdict(self._binding).values()):
            raise ValueError("settlement does not match the bound supplement binding")
        self._require_epoch(db)
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='supplement_request_epochs'"
        ).fetchone():
            epoch = db.execute(
                "SELECT epoch_id FROM supplement_request_epochs WHERE reservation_id=?",
                (reservation,),
            ).fetchone()
            if (epoch[0] if epoch else None) != self._epoch_id:
                raise ValueError(
                    "settlement does not match the original source epoch mapping"
                )
        elif self._epoch_id is not None:
            raise ValueError("settlement source epoch mapping is unavailable")
        if metadata["request_id"] != row[7]:
            raise ValueError("settlement request ID does not match reservation")
        if _timestamp(metadata["finished_at"]) < _timestamp(row[8]):
            raise ValueError("settlement metadata end precedes start")
        if (
            type(metadata["duration_ms"]) is not int
            or metadata["duration_ms"] < 0
            or not isinstance(metadata["parse_status"], str)
            or metadata["parse_status"]
            not in {"not_received", "valid", "schema_error", "incomplete"}
            or (
                metadata["provider_request_id"] is not None
                and not _identity(metadata["provider_request_id"])
            )
            or (
                metadata["error_type"] is not None
                and not _identity(metadata["error_type"])
            )
            or (actual is None and not _identity(metadata["usage_missing_reason"]))
            or (actual is not None and metadata["usage_missing_reason"] is not None)
        ):
            raise ValueError("invalid physical settlement metadata")
        try:
            usage_json = json.dumps(metadata["usage"], allow_nan=False, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid usage metadata JSON") from exc
        db.execute(
            "UPDATE supplement_requests SET finished_at=?,usage_json=?,provider_request_id=?,"
            "parse_status=?,error_type=?,usage_missing_reason=?,duration_ms=? WHERE reservation_id=?",
            (
                metadata["finished_at"],
                usage_json,
                metadata["provider_request_id"],
                metadata["parse_status"],
                metadata["error_type"],
                metadata["usage_missing_reason"],
                metadata["duration_ms"],
                reservation,
            ),
        )

    def supplement_summary(self) -> dict[str, Any]:
        with self._db() as db:
            db.execute("BEGIN")
            rows = db.execute(
                "SELECT s.purpose,COALESCE(SUM(COALESCE(r.actual,r.upper)),0),"
                "COALESCE(SUM(r.actual),0),SUM(r.settled=1 AND r.actual IS NULL),SUM(r.settled=0),"
                "SUM(CASE WHEN r.settled=1 AND r.actual IS NULL THEN r.upper ELSE 0 END),"
                "SUM(CASE WHEN r.settled=0 THEN r.upper ELSE 0 END) "
                "FROM supplement_requests s JOIN reservations r ON r.id=s.reservation_id "
                "WHERE s.campaign_id=? GROUP BY s.purpose",
                (self._binding.campaign_id,),
            ).fetchall()
            config = dict(db.execute("SELECT key,value FROM config").fetchall())
            total, dev = db.execute(
                "SELECT COALESCE(SUM(COALESCE(actual,upper)),0),"
                "COALESCE(SUM(CASE WHEN phase='development' THEN COALESCE(actual,upper) ELSE 0 END),0) "
                "FROM reservations"
            ).fetchone()
        total_available = max(0, float(config["total"]) - total)
        dev_available = max(0, float(config["development"]) - dev)
        purposes = {
            purpose: {
                "limit_cny": limit,
                "accounted_cny": 0.0,
                "known_cny": 0.0,
                "unknown_count": 0,
                "in_flight": 0,
                "unknown_reserved_cny": 0.0,
                "in_flight_reserved_cny": 0.0,
                "remaining_cny": limit,
            }
            for purpose, limit in PURPOSE_LIMITS.items()
        }
        for (
            purpose,
            amount,
            known,
            unknown,
            in_flight,
            unknown_upper,
            inflight_upper,
        ) in rows:
            purposes[purpose].update(
                accounted_cny=amount,
                known_cny=known,
                unknown_count=unknown,
                in_flight=in_flight,
                unknown_reserved_cny=unknown_upper,
                in_flight_reserved_cny=inflight_upper,
                remaining_cny=PURPOSE_LIMITS[purpose] - amount,
            )
        amount = sum(item["accounted_cny"] for item in purposes.values())
        purpose_available = sum(
            min(max(0, item["remaining_cny"]), dev_available)
            if purpose == "development"
            else max(0, item["remaining_cny"])
            for purpose, item in purposes.items()
        )
        return {
            "campaign_id": self._binding.campaign_id,
            "limit_cny": SUPPLEMENT_LIMIT,
            "accounted_cny": amount,
            "known_cny": sum(item["known_cny"] for item in purposes.values()),
            "unknown_count": sum(item["unknown_count"] for item in purposes.values()),
            "in_flight": sum(item["in_flight"] for item in purposes.values()),
            "unknown_reserved_cny": sum(
                item["unknown_reserved_cny"] for item in purposes.values()
            ),
            "in_flight_reserved_cny": sum(
                item["in_flight_reserved_cny"] for item in purposes.values()
            ),
            "remaining_cny": SUPPLEMENT_LIMIT - amount,
            "held_contingency_cny": HELD_CONTINGENCY,
            "halted": bool(config.get("halt")),
            "dispatchable_cny": 0
            if config.get("halt")
            else min(
                total_available,
                max(0, SUPPLEMENT_LIMIT - HELD_CONTINGENCY - amount),
                purpose_available,
            ),
            "purposes": purposes,
        }

    def requests(self) -> list[dict[str, Any]]:
        """All new-campaign physical requests, including unfinished/unknown attempts."""
        with self._db() as db:
            cursor = db.execute(
                "SELECT s.*,r.phase,r.upper AS reserved_cny,r.actual AS cost_cny,r.settled "
                "FROM supplement_requests s JOIN reservations r ON r.id=s.reservation_id "
                "WHERE s.campaign_id=? ORDER BY s.requested_at,s.reservation_id",
                (self._binding.campaign_id,),
            )
            names = [column[0] for column in cursor.description]
            result = [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]
        for record in result:
            record["group"] = record.pop("group_name")
            usage = record.pop("usage_json")
            record["usage"] = json.loads(usage) if usage is not None else None
        return result
