"""Independent controller-only rolling F8 journal; no model or approval creation.

The caller supplies the new B3 source, actual persisted-approval verifier and
isolated worker. Timing admission consumes complete E trial receipts, never a
claimed duration. Registration is not execution authorization. This library has
no CLI, automatic renewal, legacy manual-review repair, or automatic redispatch.
"""

from __future__ import annotations

import inspect
import json
import math
import os
import re
import uuid
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from evals.adapters.retained_workflow import build_approval_packet, resource_fields
from evals.adapters.verification_worker import (
    ObservationPair,
    VerificationWorkerRequest,
)
from evals.contracts import canonical_hash
from evals.verification import (
    _eligibility,
    _measurements,
    validate_verification_plan,
)
from evals.verification import (
    _validated_worker_result as _legacy_validated_worker_result,
)

CAMPAIGN = "task13-repair-202610-v2"
TERMINAL = {
    "completed",
    "rejected",
    "expired",
    "failed",
    "not_applicable",
    "budget_stopped",
    "deadline_stopped",
}
STATUSES = TERMINAL | {"not_started", "dispatched", "unknown"}


def file_sha256(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _time(value):
    value = datetime.fromisoformat(value) if isinstance(value, str) else value
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("an aware timestamp is required")
    return value


def _validated_worker_result(value, request, plan, used_resources):
    """Reject malformed JSON objects before invoking the unchanged v1 checks."""
    if not isinstance(value, dict):
        raise TypeError("worker receipt must be an object")
    isolation = value.get("isolation_evidence")
    resource = value.get("resource_receipt")
    if not isinstance(isolation, dict) or not isinstance(resource, dict):
        raise TypeError("worker isolation and resource receipts must be objects")
    probe, container = isolation.get("probe"), isolation.get("container")
    if not isinstance(probe, dict) or not isinstance(container, dict):
        raise TypeError("worker probe and container receipts must be objects")
    boundaries = probe.get("boundaries")
    if not isinstance(boundaries, dict) or any(
        not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
        for rows in boundaries.values()
    ):
        raise TypeError("worker boundaries must contain lists of object receipts")
    if value.get("validation_result") is not None and not isinstance(
        value["validation_result"], dict
    ):
        raise TypeError("worker validation result must be an object or null")
    return _legacy_validated_worker_result(value, request, plan, used_resources)


def validate_registration(plan):
    """Validate the *entire* v2 registration without mutating its frozen bytes."""
    if (
        plan.get("schema_version") != "task13-v2-f8-candidate-registration-v1"
        or plan.get("campaign_id") != CAMPAIGN
        or plan.get("plan_ttl_minutes") != 30
        or plan.get("one_pending_approval_max") != 1
    ):
        raise ValueError("the independent v2 campaign registration is required")
    legacy_shape = {**plan, "schema_version": "task13-verification-plan-v1"}
    validate_verification_plan(legacy_shape)
    order = [
        (
            slot["case_id"],
            slot["condition"],
            [branch["branch"] for branch in slot["branches"]],
        )
        for slot in plan["slots"]
    ]
    if canonical_hash(order) != plan.get("order_sha256"):
        raise ValueError("registration order hash differs")
    branch_ids = []
    for index, slot in enumerate(plan["slots"]):
        if (
            slot.get("sequence") != index + 1
            or slot.get("case_order") != index // 3 + 1
            or slot.get("status") != "not_started"
            or any(
                slot.get(key) is not None
                for key in ("plan_id", "plan_sha256", "approval_id")
            )
        ):
            raise ValueError("registration initial slot/order differs")
        if not re.fullmatch(r"[0-9a-f]{64}", slot.get("agent_sha256", "")):
            raise ValueError("registered agent hash is required")
        for branch in slot["branches"]:
            if (
                branch.get("status") != "not_started"
                or re.fullmatch(r"f8-branch-[0-9a-f]{24}", branch.get("branch_id", ""))
                is None
                or branch.get("dispatched_at") is not None
                or branch.get("output_sha256") is not None
            ):
                raise ValueError("v2 registration must retain every unstarted branch")
            branch_ids.append(branch["branch_id"])
    if len(set(branch_ids)) != 528:
        raise ValueError("all 528 branch identities must be unique")


def observed_six_branch_max(receipt, identity):
    """E admission interface: derive maximum from >=3 complete bound trial logs.

    A contract check cannot establish the external origin of evidence. Production
    callers must supply the actual E artifacts; synthetic test fixtures are not
    proof of measured trials or human approval.
    """
    try:
        if not isinstance(receipt, dict) or any(
            receipt.get(key) != value for key, value in identity.items()
        ):
            raise ValueError("timing binding differs")
        if receipt.get("schema_version") != "task13-v2-six-branch-timing-v1":
            raise ValueError("timing schema differs")
        trials = receipt["trials"]
        if len(trials) < 3:
            raise ValueError("three complete timing trials are required")
        durations, trial_ids, approval_ids, used_resources = [], set(), set(), set()
        request_ids, namespaces = set(), set()
        for trial in trials:
            trial_id = trial["trial_id"]
            if trial_id in trial_ids or not re.fullmatch(r"[0-9a-f]{32}", trial_id):
                raise ValueError("timing trial identity reused")
            trial_ids.add(trial_id)
            rows = trial["branches"]
            if len(rows) != 6:
                raise ValueError("six complete branches are required")
            bound, flags, start, end = None, [], None, None
            previous_observations = None
            for branch_index, row in enumerate(rows):
                request = VerificationWorkerRequest.model_validate(row["request"])
                value = row["result"]
                _validated_worker_result(value, request, identity, used_resources)
                if request.request_id in request_ids or request.namespace in namespaces:
                    raise ValueError("timing branch reused")
                request_ids.add(request.request_id)
                namespaces.add(request.namespace)
                state = request.approved_state
                if state["approval"].get("decided_by") != "user":
                    raise ValueError("actual user approval is required")
                current = (
                    request.case_id,
                    request.source_state_sha256,
                    request.approved_plan_sha256,
                    request.approval_receipt_sha256,
                )
                if bound is not None and bound != current:
                    raise ValueError("timing branches mix approved plans")
                bound = current
                flags.append(request.verification_enabled)
                observed_at = next(
                    iter(request.observations.values())
                ).before.observed_at
                expected_observations = {
                    key: ObservationPair.model_validate(value).model_dump(mode="json")
                    for key, value in _measurements(
                        state,
                        ("success", "failure", "no_change")[branch_index // 2],
                        observed_at,
                    ).items()
                }
                serialized_observations = request.model_dump(mode="json")[
                    "observations"
                ]
                if canonical_hash(serialized_observations) != canonical_hash(
                    expected_observations
                ):
                    raise ValueError(
                        "timing must contain each of the three condition pairs"
                    )
                if (
                    branch_index % 2
                    and canonical_hash(serialized_observations) != previous_observations
                ):
                    raise ValueError("timing pair observations differ")
                previous_observations = canonical_hash(serialized_observations)
                dispatched, completed = (
                    _time(row["dispatched_at"]),
                    _time(row["completed_at"]),
                )
                if completed < dispatched or (end is not None and dispatched < end):
                    raise ValueError("timing timestamps are not sequential")
                plan = state["response_plan"]
                created, expires = _time(plan["created_at"]), _time(plan["expires_at"])
                if (
                    expires - created != timedelta(minutes=30)
                    or completed >= expires
                    or dispatched < created
                    or _time(state["approval"]["decided_at"]) > dispatched
                ):
                    raise ValueError("timing trial expired")
                start, end = start or dispatched, completed
            if flags != [True, False] * 3:
                raise ValueError("timing six-branch order differs")
            approval_id = state["approval"]["approval_id"]
            if approval_id in approval_ids:
                raise ValueError("development approvals must be independent")
            approval_ids.add(approval_id)
            seconds = (end - start).total_seconds()
            if not math.isfinite(seconds) or seconds <= 0:
                raise ValueError("timing duration must be observed and positive")
            durations.append(seconds)
        return max(durations)
    except (KeyError, TypeError, ValueError, PermissionError) as error:
        raise PermissionError(
            "valid actual three-trial six-branch timing evidence is required"
        ) from error


def observed_timing_max(receipt, identity):
    """Explicit schema dispatch; native historical evidence is never relabelled."""
    if (
        isinstance(receipt, dict)
        and receipt.get("schema_version") == "task13-e-timing-pool-receipt-v1"
    ):
        from evals.timing_pool import validate_pool_receipt

        return validate_pool_receipt(receipt, identity)
    return observed_six_branch_max(receipt, identity)


def _json_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _immutable(path, value):
    """Atomic non-replacing publication; reuse only identical existing content."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _json_bytes(value)
    if path.exists():
        if path.read_bytes() != data:
            raise PermissionError("immutable artifact drift")
        return
    temporary = path.parent / (".pending-" + uuid.uuid4().hex)
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != data:
                raise PermissionError("immutable artifact drift") from None
    finally:
        temporary.unlink(missing_ok=True)


def read_campaign_journal(output_dir):
    """Read verified current journal state without initialization or recovery.

    The host caller must already hold the writer lock. This creates no files,
    applies no recovery transitions and does not trust the mutable projection.
    """
    root = Path(output_dir)
    registration = json.loads((root / "registration.json").read_text(encoding="utf-8"))
    validate_registration(registration["plan"])
    view = object.__new__(VerificationCampaign)
    view.root = root
    view._registration = deepcopy(registration)
    view._registration_written = True
    view.plan = deepcopy(registration["plan"])
    view.identity = deepcopy(registration["identity"])
    view.source_files = deepcopy(registration["source_files"])
    view.config = deepcopy(registration["config"])
    view._guard()
    view._load()
    if not view.events:
        raise PermissionError("campaign journal origin is missing")
    return {"cases": deepcopy(view.cases), "records": deepcopy(view.records)}


class VerificationCampaign:
    """Single-writer append-only campaign, with a disposable atomic projection.

    ``source_files`` is the frozen runtime manifest, checked before every entry
    and dispatch. A writer lock is never silently stolen; a process-kill stale
    lock requires operator reconciliation before reopening the same journal.
    """

    def __init__(
        self,
        plan,
        output_dir,
        *,
        source_commit,
        source_files,
        config,
        execution_admitter=None,
    ):
        validate_registration(plan)
        if not re.fullmatch(r"[0-9a-f]{40}", source_commit) or not source_files:
            raise ValueError("frozen source commit and file manifest are required")
        self.plan, self.root = deepcopy(plan), Path(output_dir)
        self.source_files = deepcopy(source_files)
        self.config = deepcopy(config)
        self.execution_admitter = execution_admitter
        self.identity = {
            "campaign_id": CAMPAIGN,
            "plan_sha256": canonical_hash(plan),
            "source_commit": source_commit,
            "source_sha256": canonical_hash(source_files),
            "config_sha256": canonical_hash(config),
        }
        self._registration = {
            "identity": deepcopy(self.identity),
            "plan": deepcopy(self.plan),
            "source_files": deepcopy(source_files),
            "config": deepcopy(config),
        }
        self._registration_written = False
        self.root.mkdir(parents=True, exist_ok=True)
        with self._lock():
            self._guard()
            _immutable(self.root / "registration.json", self._registration)
            self._registration_written = True
            self._load()
            if not self.events:
                self._append({"identity": self.identity})
            self._recover()
            self._project()

    @contextmanager
    def _lock(self):
        lock = self.root / ".writer-lock"
        try:
            lock.mkdir()
        except FileExistsError:
            raise PermissionError(
                "campaign writer is active or needs stale-lock reconciliation"
            ) from None
        try:
            yield
        finally:
            lock.rmdir()

    def _guard(self):
        registered = self.root / "registration.json"
        if (self._registration_written and not registered.exists()) or (
            registered.exists()
            and registered.read_bytes() != _json_bytes(self._registration)
        ):
            raise PermissionError("immutable registration drift")
        if self.identity != self._registration["identity"]:
            raise PermissionError("frozen identity drift")
        if canonical_hash(self.plan) != self.identity["plan_sha256"]:
            raise PermissionError("registration plan drift")
        if canonical_hash(self.config) != self.identity["config_sha256"]:
            raise PermissionError("configuration drift")
        if canonical_hash(self.source_files) != self.identity["source_sha256"]:
            raise PermissionError("source manifest drift")
        for path, expected in self.source_files.items():
            if file_sha256(path) != expected:
                raise PermissionError("frozen source file drift")

    def _load(self):
        self.records, self.cases, self.events = {}, {}, []
        self.control = {"stop": None}
        for slot in self.plan["slots"]:
            case_id = slot["case_id"]
            self.cases.setdefault(
                case_id, {"status": "not_started", "reason": None, "binding": None}
            )
            for branch in slot["branches"]:
                self.records[branch["request_id"]] = {
                    **{
                        key: slot[key]
                        for key in (
                            "case_id",
                            "dataset",
                            "pair_id",
                            "condition_id",
                            "condition",
                            "agent_sha256",
                        )
                    },
                    **deepcopy(branch),
                    "status": "not_started",
                    "reason": None,
                    "input_sha256": None,
                    "output_sha256": None,
                    "outcome": None,
                }
        previous = None
        for index, path in enumerate(sorted((self.root / "events").glob("*.json"))):
            try:
                event = json.loads(path.read_text(encoding="utf-8"))
                digest = canonical_hash(event)
                if (
                    event["sequence"] != index
                    or event["previous_sha256"] != previous
                    or path.name != f"{index:08d}-{digest}.json"
                    or event["identity_sha256"] != canonical_hash(self.identity)
                ):
                    raise ValueError("journal chain differs")
                payload = event["payload"]
                if index == 0 and payload != {"identity": self.identity}:
                    raise ValueError("journal origin differs")
                case_id = payload.get("case_id")
                for key, patch in payload.get("case_patches", {}).items():
                    self.cases[key].update(deepcopy(patch))
                self.control.update(deepcopy(payload.get("control_patch", {})))
                if case_id:
                    self.cases[case_id].update(deepcopy(payload.get("case_patch", {})))
                for request_id, patch in payload.get("branches", {}).items():
                    current = self.records[request_id]
                    if patch.get("status", current["status"]) not in STATUSES:
                        raise ValueError("invalid journal status")
                    if current["status"] in TERMINAL and any(
                        current.get(key) != value for key, value in patch.items()
                    ):
                        raise ValueError("terminal journal record changed")
                    current.update(deepcopy(patch))
                self.events.append(event)
                previous = digest
            except (ValueError, KeyError, TypeError) as error:
                raise PermissionError(
                    "journal hash or transition is invalid"
                ) from error

    def _append(self, payload):
        previous = canonical_hash(self.events[-1]) if self.events else None
        event = {
            "sequence": len(self.events),
            "previous_sha256": previous,
            "identity_sha256": canonical_hash(self.identity),
            "recorded_at": datetime.now(UTC).isoformat(),
            "payload": deepcopy(payload),
        }
        _immutable(
            self.root
            / "events"
            / f"{len(self.events):08d}-{canonical_hash(event)}.json",
            event,
        )
        self._load()
        self._project()

    def _snapshot(self):
        records = list(deepcopy(self.records).values())
        pair_counts, complete_cases = Counter(), Counter()
        for slot in self.plan["slots"]:
            if all(
                self.records[branch["request_id"]]["status"] == "completed"
                for branch in slot["branches"]
            ):
                pair_counts[slot["case_id"]] += 1
        for case_id, pairs in pair_counts.items():
            if pairs == 3 and self.cases[case_id]["status"] == "completed":
                complete_cases[case_id.split("-", 1)[0]] += 1
        approved = sum(
            case["status"] == "completed" and bool(case["binding"])
            for case in self.cases.values()
        )
        return {
            "schema_version": "task13-v2-f8-results-v1",
            **self.identity,
            "planned_cases": 88,
            "planned_pairs": 264,
            "planned_branches": 528,
            "planned_slots": deepcopy(self.plan["slots"]),
            "records": records,
            "cases": deepcopy(self.cases),
            "control": deepcopy(self.control),
            "journal_head_sha256": canonical_hash(self.events[-1])
            if self.events
            else None,
            "coverage": {
                "complete_ait_cases": complete_cases["ait"],
                "complete_dedale_cases": complete_cases["dedale"],
                "complete_pairs": sum(pair_counts.values()),
                "approved_cases": approved,
                "minimum_met": complete_cases["ait"] >= 4
                and complete_cases["dedale"] >= 4
                and sum(pair_counts.values()) >= 24
                and approved >= 8,
                "minimum_required": {
                    "ait_cases": 4,
                    "dedale_cases": 4,
                    "pairs": 24,
                    "real_approvals": 8,
                },
            },
        }

    def _project(self):
        temporary = self.root / (".projection-" + uuid.uuid4().hex)
        try:
            with temporary.open("xb") as stream:
                stream.write(_json_bytes(self._snapshot()))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.root / "projection.json")
        finally:
            temporary.unlink(missing_ok=True)

    def snapshot(self):
        with self._lock():
            self._guard()
            self._load()
            self._project()
            return self._snapshot()

    def stop_remaining(self, reason, *, detail):
        """Preserve untouched slots on a real budget/deadline stop; never replay."""
        if (
            reason not in {"budget_stopped", "deadline_stopped"}
            or not isinstance(detail, str)
            or not detail.strip()
        ):
            raise ValueError("an explicit budget/deadline stop and reason are required")
        stop = {"reason": reason, "detail": detail}
        with self._lock():
            self._guard()
            self._load()
            self._recover()
            if self.control["stop"]:
                if self.control["stop"] != stop:
                    raise PermissionError("campaign stop is immutable")
                return self._snapshot()
            patch = {"status": reason, "reason": detail}
            self._append(
                {
                    "control_patch": {"stop": stop},
                    "branches": {
                        key: patch
                        for key, row in self.records.items()
                        if row["status"] == "not_started"
                    },
                    "case_patches": {
                        key: patch
                        for key, case in self.cases.items()
                        if case["status"]
                        in {"not_started", "pending_approval", "running"}
                    },
                }
            )
            return self._snapshot()

    def _source(self, case_id, source):
        if case_id not in self.cases:
            raise ValueError("unregistered case")
        expected = {
            **{
                key: self.identity[key]
                for key in (
                    "campaign_id",
                    "source_commit",
                    "source_sha256",
                    "config_sha256",
                )
            },
            "case_id": case_id,
            "dataset": case_id.split("-", 1)[0],
        }
        if not isinstance(source, dict) or any(
            source.get(key) != value for key, value in expected.items()
        ):
            raise PermissionError(
                "source must be bound to the new v2 campaign and frozen source/config"
            )
        if self.cases[case_id]["binding"] and self.cases[case_id]["binding"][
            "source_sha256"
        ] != canonical_hash(source):
            raise PermissionError(
                "case source binding changed; approval renewal cannot stitch results"
            )

    def _case_rows(self, case_id):
        return [row for row in self.records.values() if row["case_id"] == case_id]

    def _pending_guard(self, case_id):
        if any(
            key != case_id and value["status"] == "pending_approval"
            for key, value in self.cases.items()
        ):
            raise PermissionError("only one human approval may be pending")

    def prepare_approval(self, case_id, source, *, now=None):
        """Prepare the actual product packet; never approve or renew a plan."""
        current = _time(now or datetime.now(UTC))
        if current.astimezone(timezone(timedelta(hours=8))).hour < 19:
            raise PermissionError("review window is 19:00-00:00 Asia/Shanghai")
        with self._lock():
            self._guard()
            self._load()
            self._source(case_id, source)
            self._pending_guard(case_id)
            case = self.cases[case_id]
            if case["binding"] or case["status"] in TERMINAL:
                raise PermissionError("case already bound or terminal")
            row = self._case_rows(case_id)[0]
            packet = {
                "campaign_id": CAMPAIGN,
                "registration_sha256": self.identity["plan_sha256"],
                "source_sha256": canonical_hash(source),
                "packet": build_approval_packet(
                    row, deepcopy(source["state"]), now=current
                ),
            }
            if case.get("review_packet") == packet:
                return deepcopy(packet)
            if case["status"] == "pending_approval":
                raise PermissionError("pending review source drift")
            _immutable(
                self.root / "reviews" / (canonical_hash(packet) + ".json"), packet
            )
            self._append(
                {
                    "case_id": case_id,
                    "case_patch": {
                        "status": "pending_approval",
                        "review_packet": packet,
                    },
                }
            )
            return deepcopy(packet)

    def _used_resources(self):
        used = set()
        # Validate accepted completions first. An invalid duplicate receipt from
        # an earlier registration slot must not shadow a previously accepted run.
        rows = sorted(
            self.records.values(), key=lambda row: row["status"] != "completed"
        )
        for row in rows:
            if row.get("output_sha256"):
                request = self._request(row["request_id"])
                value = self._blob("outputs", row["output_sha256"])
                try:
                    # Execution consumed these resources even if its valid receipt
                    # arrived after TTL. Scoring status cannot authorize reuse.
                    _validated_worker_result(value, request, self.identity, used)
                except (ValueError, PermissionError, TypeError, KeyError):
                    if row["status"] == "completed":
                        raise
                    # Invalid receipts do not establish trustworthy identities.
                    # Their original failed/expired status remains unchanged.
        return used

    def _blob(self, category, digest):
        value = json.loads(
            (self.root / category / (digest + ".json")).read_text(encoding="utf-8")
        )
        if canonical_hash(value) != digest:
            raise PermissionError("immutable artifact hash differs")
        return value

    def _request(self, request_id):
        return VerificationWorkerRequest.model_validate(
            self._blob("inputs", self.records[request_id]["input_sha256"])
        )

    def _recover(self):
        for row in list(self.records.values()):
            if row["status"] == "dispatched":
                receipt_path = self.root / "receipts" / (row["request_id"] + ".json")
                if receipt_path.exists():
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    self._accept(
                        row["request_id"],
                        self._blob("outputs", receipt["output_sha256"]),
                        _time(receipt["received_at"]),
                    )
                else:
                    self._append(
                        {
                            "case_id": row["case_id"],
                            "case_patch": {
                                "status": "unknown",
                                "reason": "dispatched_without_determinate_receipt",
                            },
                            "branches": {
                                row["request_id"]: {
                                    "status": "unknown",
                                    "reason": "dispatched_without_determinate_receipt",
                                }
                            },
                        }
                    )
        self._refresh_cases()

    def _refresh_cases(self):
        changes = {}
        for case_id, case in self.cases.items():
            if case["status"] not in {"running", "unknown"} or not case["binding"]:
                continue
            rows = self._case_rows(case_id)
            if len(rows) == 6 and all(row["status"] == "completed" for row in rows):
                changes[case_id] = {"status": "completed", "reason": None}
            elif any(row["status"] in {"failed", "expired"} for row in rows):
                status = (
                    "expired"
                    if any(row["status"] == "expired" for row in rows)
                    else "failed"
                )
                changes[case_id] = {"status": status, "reason": "case_incomplete"}
        if changes:
            self._append({"case_patches": changes})

    def _accept(self, request_id, value, current):
        self._guard()
        row = self.records[request_id]
        digest = canonical_hash(value)
        if row["status"] in TERMINAL:
            if row["output_sha256"] == digest:
                return
            raise PermissionError("terminal branch cannot be replaced")
        if row["status"] not in {"dispatched", "unknown"}:
            raise PermissionError(
                "only a previously dispatched request may receive a result"
            )
        request = self._request(request_id)
        _immutable(self.root / "outputs" / (digest + ".json"), value)
        receipt_path = self.root / "receipts" / (request_id + ".json")
        if receipt_path.exists():
            durable = json.loads(receipt_path.read_text(encoding="utf-8"))
            if durable["output_sha256"] != digest or durable[
                "input_sha256"
            ] != canonical_hash(request):
                raise PermissionError("immutable worker receipt drift")
            current = _time(durable["received_at"])
        else:
            _immutable(
                receipt_path,
                {
                    "input_sha256": canonical_hash(request),
                    "output_sha256": digest,
                    "received_at": current.isoformat(),
                },
            )
        patch = {"output_sha256": digest, "completed_at": current.isoformat()}
        try:
            outcome = _validated_worker_result(
                value, request, self.identity, self._used_resources()
            )
            patch.update(
                resource_receipt=value["resource_receipt"],
                isolation_evidence=value["isolation_evidence"],
            )
            expires = _time(request.approved_state["response_plan"]["expires_at"])
            if current >= expires:
                patch.update(
                    status="expired", reason="receipt_after_plan_expiry", outcome=None
                )
            else:
                patch.update(
                    status="completed",
                    reason=None,
                    outcome=outcome,
                    resource_receipt=value["resource_receipt"],
                    isolation_evidence=value["isolation_evidence"],
                )
        except (ValueError, PermissionError, TypeError, KeyError):
            patch.update(status="failed", reason="worker_receipt_invalid", outcome=None)
        self._append({"case_id": row["case_id"], "branches": {request_id: patch}})

    def merge_result(self, request_id, value, *, now=None):
        """Merge a determinate late receipt without issuing any worker request."""
        with self._lock():
            self._guard()
            self._load()
            self._accept(request_id, value, _time(now or datetime.now(UTC)))
            self._refresh_cases()
            return self._snapshot()

    async def run_case(
        self,
        case_id,
        source,
        *,
        worker,
        timing_receipt,
        approval_verifier=None,
        now=None,
        admission_deadline=None,
    ):
        """Handle one registered case; bound interrupted cases are never replayed."""
        clock = now or (lambda: datetime.now(UTC))
        source = deepcopy(source)
        with self._lock():
            self._guard()
            self._load()
            self._recover()
            self._source(case_id, source)
            self._pending_guard(case_id)
            case = self.cases[case_id]
            if case["binding"] or case["status"] in TERMINAL:
                return self._snapshot()
            current = _time(clock())
            status, reason = _eligibility(source, current)
            if status is not None:
                mapped = (
                    "not_applicable"
                    if reason in {"not_applicable", "no_response_plan"}
                    else "expired"
                    if reason == "plan_expired"
                    else status
                    if status in TERMINAL
                    else "not_started"
                )
                patch = {"status": mapped, "reason": reason}
                case_patch = (
                    {**patch, "status": "pending_approval"}
                    if case["status"] == "pending_approval"
                    and reason == "approval_pending"
                    else patch
                )
                self._append(
                    {
                        "case_id": case_id,
                        "case_patch": case_patch,
                        "branches": {
                            row["request_id"]: patch for row in self._case_rows(case_id)
                        },
                    }
                )
                return self._snapshot()
            if approval_verifier is None:
                raise PermissionError("actual persisted approval verifier is required")
            if self.execution_admitter is None:
                raise PermissionError(
                    "verified v2 execution gate is required; registration is not authorization"
                )
            gate = self.execution_admitter(deepcopy(self.identity))
            gate = await gate if inspect.isawaitable(gate) else gate
            if (
                not isinstance(gate, dict)
                or gate.get("schema_version") != "task13-v2-execution-gate-v1"
                or gate.get("status") != "verified"
                or any(gate.get(key) != value for key, value in self.identity.items())
            ):
                raise PermissionError("verified v2 execution gate binding differs")
            if gate.get("deadline_at") is not None:
                gate_deadline = _time(gate["deadline_at"])
                if (
                    admission_deadline is not None
                    and _time(admission_deadline) != gate_deadline
                ):
                    raise PermissionError(
                        "F8 admission deadline differs from approved gate"
                    )
                admission_deadline = gate_deadline
            _immutable(self.root / "gates" / (canonical_hash(gate) + ".json"), gate)
            receipt = approval_verifier(deepcopy(source))
            receipt = await receipt if inspect.isawaitable(receipt) else receipt
            state = source["state"]
            if state["approval"].get("decided_by") != "user":
                raise PermissionError("actual user approval is required")
            response_plan = state["response_plan"]
            expires, created = (
                _time(response_plan["expires_at"]),
                _time(response_plan["created_at"]),
            )
            if expires - created != timedelta(minutes=30):
                raise PermissionError("plan TTL must remain exactly 30 minutes")
            maximum = observed_timing_max(timing_receipt, self.identity)
            # Re-read the clock after all admission work, immediately before binding.
            current = _time(clock())
            if admission_deadline is not None and current >= _time(admission_deadline):
                raise PermissionError("F8 admission deadline has passed")
            if (expires - current).total_seconds() <= 1.5 * maximum + 300:
                raise PermissionError(
                    "remaining TTL must exceed 1.5 * observed maximum + 300 seconds"
                )
            requests = []
            for slot in self.plan["slots"]:
                if slot["case_id"] != case_id:
                    continue
                observations = _measurements(state, slot["condition"], current)
                for branch in slot["branches"]:
                    request = VerificationWorkerRequest(
                        request_id=branch["request_id"],
                        namespace=branch["namespace"],
                        case_id=case_id,
                        agent_sha256=slot["agent_sha256"],
                        source_state_sha256=canonical_hash(state),
                        approved_plan_sha256=state["approved_plan_sha256"],
                        approval_receipt=receipt,
                        approval_receipt_sha256=canonical_hash(receipt),
                        approved_state=state,
                        source_resources=resource_fields(source["resources"]),
                        verification_enabled=branch["branch"] == "enabled",
                        observations=observations,
                    )
                    _immutable(
                        self.root / "inputs" / (canonical_hash(request) + ".json"),
                        request.model_dump(mode="json"),
                    )
                    requests.append(request)
            binding = {
                "source_sha256": canonical_hash(source),
                "state_sha256": canonical_hash(state),
                "approved_plan_sha256": state["approved_plan_sha256"],
                "approved_plan_version": state["approved_plan_version"],
                "approval_receipt_sha256": canonical_hash(receipt),
                "approval_id": state["approval"]["approval_id"],
                "diagnostic_snapshot_sha256": state["diagnostic_snapshot_sha256"],
                "expires_at": expires.isoformat(),
                "timing_receipt_sha256": canonical_hash(timing_receipt),
                "execution_gate_sha256": canonical_hash(gate),
            }
            _immutable(
                self.root / "sources" / (canonical_hash(source) + ".json"), source
            )
            _immutable(
                self.root / "timings" / (canonical_hash(timing_receipt) + ".json"),
                timing_receipt,
            )
            _immutable(
                self.root / "approvals" / (canonical_hash(receipt) + ".json"), receipt
            )
            if admission_deadline is not None:
                # Publication may itself be slow. Admission happens only after
                # every required input is durable; already bound cases may finish.
                current = _time(clock())
                if current >= _time(admission_deadline):
                    raise PermissionError("F8 admission deadline has passed")
                if (expires - current).total_seconds() <= 1.5 * maximum + 300:
                    raise PermissionError(
                        "remaining TTL must exceed 1.5 * observed maximum + 300 seconds"
                    )
            self._append(
                {
                    "case_id": case_id,
                    "case_patch": {
                        "status": "running",
                        "reason": None,
                        "binding": binding,
                    },
                }
            )
            for request in requests:
                self._guard()
                current = _time(clock())
                if current >= expires:
                    break
                self._append(
                    {
                        "case_id": case_id,
                        "branches": {
                            request.request_id: {
                                "status": "dispatched",
                                "dispatched_at": current.isoformat(),
                                "input_sha256": canonical_hash(request),
                            }
                        },
                    }
                )
                try:
                    value = await worker(request)
                except Exception as error:  # noqa: BLE001 -- dispatch may have happened; never retry.
                    self._append(
                        {
                            "case_id": case_id,
                            "case_patch": {
                                "status": "unknown",
                                "reason": "worker_interrupted",
                            },
                            "branches": {
                                request.request_id: {
                                    "status": "unknown",
                                    "reason": "worker_interrupted",
                                    "error_type": type(error).__name__,
                                }
                            },
                        }
                    )
                    return self._snapshot()
                self._accept(request.request_id, value, _time(clock()))
                if self.records[request.request_id]["status"] != "completed":
                    break
            rows = self._case_rows(case_id)
            if all(row["status"] == "completed" for row in rows):
                case_patch = {"status": "completed", "reason": None}
                branches = {}
            else:
                expired = _time(clock()) >= expires
                case_patch = {
                    "status": "expired" if expired else "failed",
                    "reason": "plan_expired_during_case"
                    if expired
                    else "case_incomplete",
                }
                branches = (
                    {
                        row["request_id"]: {
                            "status": "expired",
                            "reason": "plan_expired_during_case",
                        }
                        for row in rows
                        if row["status"] == "not_started"
                    }
                    if expired
                    else {}
                )
            self._append(
                {"case_id": case_id, "case_patch": case_patch, "branches": branches}
            )
            return self._snapshot()
