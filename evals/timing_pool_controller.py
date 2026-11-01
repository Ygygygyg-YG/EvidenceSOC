"""Append-only bounded pool coordinator. Native evidence remains authoritative.

The journal is not an approval, timing receipt, or budget authority. Its reservation
is a pessimistic upper bound until independently verified native settlement.
"""

from __future__ import annotations

import json
import math
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path

DEADLINE = datetime.fromisoformat("2026-11-02T23:59:59+08:00")


class PoolStopped(PermissionError):
    pass


def _raw(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _money(value):
    amount = Decimal(str(value))
    if not amount.is_finite() or amount < 0:
        raise PoolStopped("unknown cost")
    return amount


def _digest(value):
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise PoolStopped("invalid evidence hash")
    return value


class PoolJournal:
    def __init__(self, path, *, pool_sha256):
        self.path = Path(path).absolute()
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self.pool_sha256 = _digest(pool_sha256)
        for parent in (self.path, *self.path.parents):
            if parent.is_symlink() or parent.is_junction():
                raise PoolStopped("journal links forbidden")

    @classmethod
    def prepare(
        cls,
        path,
        *,
        pool_sha256,
        attempts,
        imported_trial_id,
        now,
        initial_spent_yuan="0",
        imported_max_seconds=0,
    ):
        if (
            len(attempts) != 6
            or len(set(attempts)) != 6
            or imported_trial_id in attempts
        ):
            raise PoolStopped("six unique future attempts required")
        if now.tzinfo is None or now >= DEADLINE:
            raise PoolStopped("deadline expired")
        j = cls(path, pool_sha256=pool_sha256)
        with j.lock():
            if j.path.exists():
                raise PoolStopped("journal already exists; never reset")
            payload = {
                "attempts": attempts,
                "imported_trial_id": imported_trial_id,
                "initial_spent_yuan": str(_money(initial_spent_yuan)),
                "imported_max_seconds": imported_max_seconds,
            }
            j._append("prepare", payload, [])
        return j

    @contextmanager
    def lock(self, *, _adoption=False):
        import secrets

        require_plain_path(self.path)
        require_plain_path(self.lock_path)
        if not _adoption:
            _require_unfenced(self.path)
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise PoolStopped("pool lock exists; audit crash before recovery") from exc
        try:
            owner = {"pid": os.getpid(), "nonce": secrets.token_hex(32)}
            os.write(fd, _raw(owner))
            os.fsync(fd)
            if not _adoption:
                _require_unfenced(self.path)
            yield owner
        finally:
            os.close(fd)
            self.lock_path.unlink()

    def _events(self):
        require_plain_path(self.path, file=True)
        raw = self.path.read_bytes()
        if not raw.endswith(b"\n") or self.path.stat().st_nlink != 1:
            raise PoolStopped("torn or linked journal")
        result = []
        previous = "0" * 64
        for line in raw.splitlines():
            try:
                event = json.loads(line)
                digest = event.pop("sha256")
                if (
                    event["previous"] != previous
                    or event["sequence"] != len(result)
                    or event["pool_sha256"] != self.pool_sha256
                    or sha256(_raw(event)).hexdigest() != digest
                ):
                    raise ValueError()
            except (ValueError, KeyError, TypeError) as exc:
                raise PoolStopped("journal hash chain invalid") from exc
            event["sha256"] = digest
            previous = digest
            result.append(event)
        if not result or result[0]["kind"] != "prepare":
            raise PoolStopped("journal genesis missing")
        return result

    def _append(self, kind, payload, events):
        require_plain_path(self.path, file=bool(events))
        event = {
            "kind": kind,
            "payload": payload,
            "sequence": len(events),
            "pool_sha256": self.pool_sha256,
            "previous": events[-1]["sha256"] if events else "0" * 64,
        }
        event["sha256"] = sha256(_raw(event)).hexdigest()
        with self.path.open("ab" if events else "xb") as stream:
            stream.write(_raw(event) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    def status(self):
        events = self._events()
        genesis = events[0]["payload"]
        state = {
            "qualified": 1,
            "attempted": 0,
            "pending": None,
            "stopped": None,
            "spent_yuan": genesis["initial_spent_yuan"],
            "reserved_yuan": "0",
            "observed_max_seconds": genesis["imported_max_seconds"],
            "evidence": [],
        }
        for event in events[1:]:
            p = event["payload"]
            kind = event["kind"]
            if kind == "begin":
                state.update(pending=p["trial_id"], reserved_yuan=p["reserved_yuan"])
                state["attempted"] += 1
            elif kind in {"settle", "expiry_audit"}:
                state["spent_yuan"] = str(
                    _money(state["spent_yuan"]) + _money(p["actual_yuan"])
                )
                state.update(pending=None, reserved_yuan="0")
                state["observed_max_seconds"] = max(
                    state["observed_max_seconds"], p["observed_max_seconds"]
                )
                state["evidence"].append(p["evidence_sha256"])
                if p["outcome"] == "qualified":
                    state["qualified"] += 1
                else:
                    state["stopped"] = p["outcome"]
            elif kind in {"phase_claim", "phase_finish", "guard_review"}:
                pass
            elif kind == "stop":
                state["stopped"] = p["reason"]
            elif kind == "resume":
                state["stopped"] = None
            else:
                raise PoolStopped("unknown journal event")
        state.update(
            consumed_logical=7 + state["attempted"],
            physical_upper_bound=21 + 3 * state["attempted"],
            analysis_inclusive_upper_bound=22 + 3 * state["attempted"],
            pool_sha256=self.pool_sha256,
            journal_head=events[-1]["sha256"],
        )
        return state

    def begin(self, trial_id, *, now, quiescent, reserved_yuan, before_claim=None):
        with self.lock():
            s = self.status()
            events = self._events()
            if s["pending"]:
                raise PoolStopped("pending or unknown attempt; no replay")
            if s["stopped"]:
                raise PoolStopped("STOP: " + s["stopped"])
            if s["qualified"] >= 3:
                raise PoolStopped("target reached")
            if s["attempted"] >= 6:
                raise PoolStopped("pool exhausted")
            if trial_id != events[0]["payload"]["attempts"][s["attempted"]]:
                raise PoolStopped("sequence mismatch")
            if not quiescent:
                raise PoolStopped("quiescence not verified")
            if now.tzinfo is None or now >= DEADLINE:
                raise PoolStopped("deadline expired")
            if s["observed_max_seconds"] > 800:
                require_current_guard_review(
                    events, self.pool_sha256, now, s["observed_max_seconds"]
                )
            if _money(s["spent_yuan"]) + _money(reserved_yuan) > 6:
                raise PoolStopped("development budget exceeded")
            if before_claim is not None:
                before_claim()
            self._append(
                "begin",
                {
                    "trial_id": trial_id,
                    "reserved_yuan": str(_money(reserved_yuan)),
                    "started_at": now.isoformat(),
                    "guard_review_sha256": events[-1]["sha256"]
                    if s["observed_max_seconds"] > 800
                    else None,
                },
                events,
            )

    def settle(
        self,
        trial_id,
        *,
        outcome,
        actual_yuan,
        quiescent,
        observed_max_seconds,
        evidence_sha256,
        evidence=None,
    ):
        with self.lock():
            s = self.status()
            if s["pending"] != trial_id or s["stopped"]:
                raise PoolStopped("settlement has no pending claim or is hard stopped")
            if not quiescent:
                raise PoolStopped("unknown execution; quiescence required")
            if outcome not in {"qualified", "ttl_infrastructure_failure"}:
                raise PoolStopped("hard outcome requires STOP")
            if not math.isfinite(observed_max_seconds) or observed_max_seconds < 0:
                raise PoolStopped("invalid timing")
            if _money(actual_yuan) > _money(s["reserved_yuan"]):
                raise PoolStopped("cost exceeds reservation; hard STOP")
            if _digest(evidence_sha256) in s["evidence"]:
                raise PoolStopped("duplicate evidence claim")
            self._append(
                "settle",
                {
                    "trial_id": trial_id,
                    "outcome": outcome,
                    "actual_yuan": str(_money(actual_yuan)),
                    "observed_max_seconds": observed_max_seconds,
                    "evidence_sha256": evidence_sha256,
                    **({"evidence": evidence} if evidence is not None else {}),
                },
                self._events(),
            )

    def stop(self, reason):
        with self.lock():
            if reason == "ttl_infrastructure_failure":
                raise PoolStopped("TTL STOP requires a verified settled native failure")
            self._append("stop", {"reason": reason}, self._events())

    def resume(
        self, *, quiescent, fresh_guard_sha256, guard_cost_yuan, guard_evidence=None
    ):
        with self.lock():
            s = self.status()
            if s["pending"] or s["stopped"] != "ttl_infrastructure_failure":
                raise PoolStopped("hard STOP cannot resume")
            if not quiescent or _money(guard_cost_yuan) != 0:
                raise PoolStopped("fresh free quiescent guard required")
            self._append(
                "resume",
                {
                    "fresh_guard_sha256": _digest(fresh_guard_sha256),
                    **(
                        {"guard_evidence": guard_evidence}
                        if guard_evidence is not None
                        else {}
                    ),
                },
                self._events(),
            )


def pool_scope_proposal(pool):
    """Concrete pre-consent projection with exactly three future authority pins.

    Child IDs, slots, source/config/lineage, account and model IDs stay exact.
    Native builders regenerate all hashes derived from these future pins; the
    actual native epoch and dispatch guards must verify their eventual values.
    No arbitrary hash keys or nested historical lineage are stripped.
    """
    from copy import deepcopy

    from evals.contracts import canonical_hash
    from evals.e_timing import build_e_timing_registration, validate_registration

    proposal = deepcopy(pool)
    for child in proposal["children"]:
        timing = child["registration"]
        validate_registration(timing)
        planning = deepcopy(timing["planning_registration"])
        planning["epoch_binding"]["epoch_manifest_sha256"] = "0" * 64
        model = planning["epoch_binding"].get("model_identity_binding")
        if model is not None:
            model["model_identity_sha256"] = "0" * 64
        dispatch = deepcopy(timing["planning_dispatch_registration_receipt"])
        dispatch["authority_sha256"] = "0" * 64
        dispatch["registration_sha256"] = canonical_hash(planning)
        child["registration"] = build_e_timing_registration(
            planning,
            source_files=timing["source_files"],
            f8_plan_sha256=timing["f8_plan_sha256"],
            planning_dispatch_registration_receipt=dispatch,
        )
    # This repeats the same native epoch fields outside the child registration.
    # Normalize only their future authority digests, retaining all fixed IDs.
    formal = proposal.get("formal_binding")
    if formal is not None:
        formal["epoch_manifest_sha256"] = "0" * 64
        if formal.get("model_identity_binding") is not None:
            formal["model_identity_binding"]["model_identity_sha256"] = "0" * 64
    return proposal


def validate_pool_journal_evidence(evidence, pool):
    """Verify a pinned controller transcript; never infer actual user consent.

    Callers additionally verify its native authority, account and worker evidence.
    This function rejects semantically impossible but correctly rehashed logs.
    """
    from evals.contracts import canonical_hash

    pin = evidence["pool_journal"]
    journal = PoolJournal(pin["path"], pool_sha256=canonical_hash(pool))
    if sha256(journal.path.read_bytes()).hexdigest() != _digest(pin["sha256"]):
        raise PoolStopped("pool journal raw pin differs")
    events = journal._events()
    if events[-1]["sha256"] != pin["head_sha256"]:
        raise PoolStopped("pool journal head differs")
    genesis = events[0]["payload"]
    order = [a["trial_id"] for a in pool["attempt_order"]]
    if (
        len(order) != 6
        or len(set(order)) != 6
        or genesis["attempts"] != order
        or genesis["imported_trial_id"] != pool["imported_observations"][0]["trial_id"]
    ):
        raise PoolStopped("pool identity or attempt sequence differs")
    pending = None
    attempted = 0
    qualified = 1
    stopped = None
    spent = _money(genesis["initial_spent_yuan"])
    reserved = Decimal(0)
    claims = {}
    finishes = {}
    settlements = []
    used = set()
    maximum = genesis["imported_max_seconds"]
    for event in events[1:]:
        p = event["payload"]
        kind = event["kind"]
        if kind == "begin":
            if (
                pending
                or stopped
                or attempted >= 6
                or qualified >= 3
                or p["trial_id"] != order[attempted]
            ):
                raise PoolStopped("invalid pending or attempt sequence transition")
            if maximum > 800:
                require_current_guard_review(
                    events[: events.index(event)],
                    journal.pool_sha256,
                    datetime.fromisoformat(p["started_at"]),
                    maximum,
                )
            expected_review = (
                events[events.index(event) - 1]["sha256"] if maximum > 800 else None
            )
            if p.get("guard_review_sha256") != expected_review:
                raise PoolStopped("begin guard review binding differs")
            reserved = _money(p["reserved_yuan"])
            if spent + reserved > 6:
                raise PoolStopped("pool budget reservation exceeds cap")
            started = datetime.fromisoformat(p["started_at"])
            if started.tzinfo is None or started >= DEADLINE:
                raise PoolStopped("attempt exceeds engineering deadline")
            pending = p["trial_id"]
            attempted += 1
            claims = {}
            finishes = {}
        elif kind == "phase_claim":
            phase = p["phase"]
            if (
                stopped
                or p["trial_id"] != pending
                or phase not in {"plan", "read", "decision", "trial"}
            ):
                raise PoolStopped("phase has no active pool attempt")
            if claims.get(phase, 0) and (
                phase != "read" or claims[phase] != finishes.get(phase, 0)
            ):
                raise PoolStopped("unknown or repeated phase claim")
            if phase != "plan" and not finishes.get("plan"):
                raise PoolStopped("native phase precedes completed planning")
            if phase == "decision" and (
                not finishes.get("read")
                or not p.get("chat_record")
                or not p.get("packet_sha256")
            ):
                raise PoolStopped("decision lacks actual read and pinned chat")
            if phase == "trial" and not finishes.get("decision"):
                raise PoolStopped("trial precedes actual decision")
            claims[phase] = claims.get(phase, 0) + 1
        elif kind == "phase_finish":
            phase = p["phase"]
            if (
                p["trial_id"] != pending
                or claims.get(phase, 0) != finishes.get(phase, 0) + 1
            ):
                raise PoolStopped("phase finish has no unique claim")
            _digest(p["result_sha256"])
            finishes[phase] = finishes.get(phase, 0) + 1
        elif kind in {"settle", "expiry_audit"}:
            if kind == "expiry_audit":
                if (
                    p["trial_id"] != pending
                    or not finishes.get("plan")
                    or stopped
                    not in (None, "unknown_native_execution", "native_unknown")
                ):
                    raise PoolStopped(
                        "expiry reconciliation lacks completed planning or is hard stopped"
                    )
                if p["evidence"].get("subtype") != "pre_timing_expired":
                    raise PoolStopped("expiry reconciliation subtype differs")
                validate_pre_timing_expiry_audit(p["evidence"]["audit"])
            elif p["trial_id"] != pending or not finishes.get("trial") or stopped:
                raise PoolStopped("settlement lacks completed native phase")
            if p["outcome"] not in {"qualified", "ttl_infrastructure_failure"}:
                raise PoolStopped("unknown settlement outcome")
            if (
                canonical_hash(p["evidence"]) != p["evidence_sha256"]
                or p["evidence_sha256"] in used
            ):
                raise PoolStopped("settlement evidence changed or double claimed")
            used.add(p["evidence_sha256"])
            cost = _money(p["actual_yuan"])
            if cost > reserved:
                raise PoolStopped("settled cost exceeds reserved bound")
            spent += cost
            pending = None
            if p["outcome"] == "qualified":
                qualified += 1
            else:
                stopped = p["outcome"]
            maximum = max(maximum, p["observed_max_seconds"])
            settlements.append(p)
        elif kind == "guard_review":
            if pending or stopped:
                raise PoolStopped("guard review requires a closed unstopped prefix")
            validate_guard_review(
                p,
                journal.pool_sha256,
                events[: events.index(event)],
                datetime.fromisoformat(p["checked_at"]),
                maximum,
            )
        elif kind == "stop":
            if p["reason"] == "ttl_infrastructure_failure":
                raise PoolStopped("TTL STOP requires native settlement")
            stopped = p["reason"]
        elif kind == "resume":
            if pending or stopped != "ttl_infrastructure_failure":
                raise PoolStopped("hard or unknown STOP cannot resume")
            _digest(p["fresh_guard_sha256"])
            if canonical_hash(p["guard_evidence"]) != p["fresh_guard_sha256"]:
                raise PoolStopped("fresh free guard proof differs")
            stopped = None
        else:
            raise PoolStopped("unknown controller event")
    return {"state": journal.status(), "events": events, "settlements": settlements}


def require_plain_path(path, *, file=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise PoolStopped("absolute canonical pool path required")
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise PoolStopped("pool path links forbidden")
    if file and (not path.is_file() or path.stat().st_nlink != 1):
        raise PoolStopped("single-link pool file required")
    return path


def _require_unfenced(path):
    for root in (Path(path).parent, *Path(path).parents):
        if (root / ".pool-adoption-fence").exists() or (
            root / ".pool-adoption-fence"
        ).is_symlink():
            raise PoolStopped("pool source adoption fence is held")


@dataclass(frozen=True)
class PoolPhaseLease:
    journal_path: Path
    nonce: str
    claim_sha256: str
    child_id: str
    trial_id: str
    phase: str


def require_pool_phase_lease(pool, child_id, trial_id, phase, lease):
    from evals.contracts import canonical_hash

    if not isinstance(lease, PoolPhaseLease):
        raise PoolStopped("active parent pool phase lease required")
    path = require_plain_path(pool["execution_journal_path"], file=True)
    if path.name != "pool-journal.jsonl" or path != lease.journal_path:
        raise PoolStopped("phase journal differs from approved pool path")
    _require_unfenced(path)
    journal = PoolJournal(path, pool_sha256=canonical_hash(pool))
    owner = json.loads(require_plain_path(journal.lock_path, file=True).read_bytes())
    if owner != {"pid": os.getpid(), "nonce": lease.nonce}:
        raise PoolStopped("parent phase lock is not owned by current process")
    events = journal._events()
    state = journal.status()
    claim = events[-1]
    if (
        (lease.child_id, lease.trial_id, lease.phase) != (child_id, trial_id, phase)
        or claim["kind"] != "phase_claim"
        or claim["sha256"] != lease.claim_sha256
        or any(
            claim["payload"].get(k) != v
            for k, v in {
                "child_id": child_id,
                "trial_id": trial_id,
                "phase": phase,
            }.items()
        )
        or state["pending"] != trial_id
        or state["stopped"]
        or state["qualified"] >= 3
        or not 1 <= state["attempted"] <= 6
    ):
        raise PoolStopped("parent phase claim stale, mismatched or outside pool caps")
    expected = events[0]["payload"]["attempts"][state["attempted"] - 1]
    if expected != trial_id:
        raise PoolStopped("parent phase attempt order differs")
    children = [c for c in pool["children"] if c["child_id"] == child_id]
    if len(children) != 1 or trial_id not in {
        t["trial_id"] for t in children[0]["registration"]["trials"]
    }:
        raise PoolStopped("parent phase child membership differs")


class FirstDispatchClock:
    """Return exact real clock values; never admit a first dispatch after cutoff."""

    def __init__(self, now, *, expires_at=None, shared_max=0):
        self.now = now
        self.expires_at = expires_at
        self.required_remaining = shared_remaining_threshold(shared_max)
        self.admitted = False
        self.last = None

    def __call__(self):
        value = self.now()
        if not self.admitted and (value.tzinfo is None or value >= DEADLINE):
            raise PoolStopped("first native dispatch exceeds engineering deadline")
        if (
            not self.admitted
            and self.expires_at is not None
            and (self.expires_at - value).total_seconds() <= self.required_remaining
        ):
            raise PoolStopped("shared M first dispatch remaining TTL insufficient")
        self.last = value
        return value

    def admit(self):
        if self.last is None or self.last >= DEADLINE:
            raise PoolStopped("first native dispatch has no valid deadline sample")
        self.admitted = True


@contextmanager
def pool_quiescence(controllers, roots):
    """Hold pool fences AND locks while caller composes original native guards.

    Required for any source/model epoch adoption involving these registered roots;
    native source_epochs does not interpret this companion's JSONL journal.
    """
    from contextlib import ExitStack

    roots = [require_plain_path(root) for root in roots]
    supplied = {
        require_plain_path(
            (c.journal if hasattr(c, "journal") else c).path, file=True
        ): (c.journal if hasattr(c, "journal") else c)
        for c in controllers
    }
    if any(
        p.name != "pool-journal.jsonl" or not any(p.is_relative_to(r) for r in roots)
        for p in supplied
    ):
        raise PoolStopped("pool journal outside registered roots or fixed filename")
    with ExitStack() as stack:
        for root in sorted(roots):
            fence = root / ".pool-adoption-fence"
            try:
                fence.mkdir()
            except FileExistsError as error:
                raise PoolStopped("pool adoption fence active or stale") from error
            stack.callback(fence.rmdir)
        found = set()
        for root in roots:
            for path in root.rglob("*"):
                require_plain_path(path)
                if path.name == "pool-journal.jsonl":
                    found.add(require_plain_path(path, file=True))
        if found != set(supplied):
            raise PoolStopped(
                "unlisted or missing pool journal requires companion audit"
            )
        heads = {}
        for path, journal in sorted(supplied.items()):
            stack.enter_context(journal.lock(_adoption=True))
            state = journal.status()
            if state["pending"]:
                raise PoolStopped("pending or unknown pool attempt blocks adoption")
            heads[str(path)] = state["journal_head"]
        yield {
            "schema_version": "task13-pool-quiescence-v1",
            "status": "verified",
            "pool_heads": heads,
            "native_journals_require_separate_native_locks": True,
        }


def validate_pre_timing_expiry_audit(audit):
    """Read-only expiry predicate; native provenance/SQL reads are supplied by auditor."""
    from evals.contracts import canonical_hash

    try:
        if audit["schema_version"] != "task13-pool-pre-timing-expiry-v1":
            raise PoolStopped("invalid expiry audit schema")
        state = audit["host_review_result"]["source"]["state"]
        live = audit["host_review_result"]
        receipt = live["host_read_receipt"]
        checked = datetime.fromisoformat(audit["checked_at"])
        expires = datetime.fromisoformat(state["response_plan"]["expires_at"])
        if (
            checked.tzinfo is None
            or expires.tzinfo is None
            or checked < expires
            or canonical_hash(state) != canonical_hash(audit["retained_state"])
            or state.get("approval") is not None
            or not (
                state.get("simulation") is None
                or type(state.get("simulation")) is list
                and state["simulation"] == []
            )
            or state.get("simulation_execution") is not None
            or live.get("approval_receipt") is not None
        ):
            raise PoolStopped(
                "expiry requires unchanged expired plan without persisted approval or simulation"
            )
        if (
            live["status"] != "completed"
            or live["operation"] != "read_packet"
            or live.get("model_ledger")
            or live["input_sha256"] != canonical_hash(audit["review_request"])
            or live["source_state_sha256"] != canonical_hash(state)
            or receipt["origin"] != "host_original_postgresql_read"
            or receipt["request_sha256"] != canonical_hash(audit["review_request"])
            or receipt["state_sha256"] != canonical_hash(state)
            or any(
                receipt.get(k) != "on"
                for k in (
                    "checkpoint_transaction_read_only",
                    "business_transaction_read_only",
                )
            )
            or any(
                receipt.get(k) != 0
                for k in (
                    "provider_calls",
                    "model_calls",
                    "mcp_calls",
                    "decisions_written",
                )
            )
        ):
            raise PoolStopped("expiry checkpoint read or zero-write provenance unknown")
        if any(
            item["record"].get("decision") != "approved"
            for item in audit["decision_records"]
        ):
            raise PoolStopped(
                "actual rejection or unknown user decision cannot become expiry"
            )
        trials = [
            t
            for t in audit["native_snapshot"]["trials"]
            if t["trial_id"] == audit["trial_id"]
        ]
        if (
            len(trials) != 1
            or trials[0]["status"] != "not_started"
            or trials[0].get("binding")
        ):
            raise PoolStopped("expiry native trial already started or unknown")
        if any(
            r.get("trial_id") == audit["trial_id"]
            and (
                r.get("status") != "not_started"
                or any(
                    r.get(k)
                    for k in (
                        "input_sha256",
                        "output_sha256",
                        "host_receipt_sha256",
                        "dispatched_at",
                        "dispatched_monotonic_ns",
                    )
                )
            )
            for r in audit["native_snapshot"]["records"]
        ):
            raise PoolStopped("expiry native branch activity exists")
        rows = audit["planning_ledger_rows"]
        if not 1 <= len(rows) <= 3 or any(
            r["settled"] != 1
            or r["actual"] is None
            or _money(r["actual"]) != _money(r["expected_cost"])
            for r in rows
        ):
            raise PoolStopped("expiry planning cost unsettled or unknown")
        if _money(audit["budget_before_yuan"]) != _money(audit["budget_after_yuan"]):
            raise PoolStopped("expiry audit changed account spend")
    except (KeyError, TypeError, ValueError) as error:
        raise PoolStopped("invalid expiry audit evidence") from error


def close_pre_timing_expiry(journal, trial_id, evidence, *, _owner=None):
    """Reconcile only a proved never-started expired plan; keep native state intact."""
    from evals.contracts import canonical_hash

    audit = evidence["audit"]
    validate_pre_timing_expiry_audit(audit)
    if evidence.get("subtype") != "pre_timing_expired" or audit["trial_id"] != trial_id:
        raise PoolStopped("expiry audit trial differs")
    from contextlib import nullcontext

    if _owner is not None:
        actual = json.loads(
            require_plain_path(journal.lock_path, file=True).read_bytes()
        )
        if actual != _owner or actual["pid"] != os.getpid():
            raise PoolStopped("expiry lock ownership differs")
    with nullcontext() if _owner is not None else journal.lock():
        state = journal.status()
        if state["pending"] != trial_id or state["stopped"] not in (
            None,
            "unknown_native_execution",
            "native_unknown",
        ):
            raise PoolStopped("hard STOP cannot be relabelled as audited expiry")
        cost = _money(audit["budget_after_yuan"]) - _money(state["spent_yuan"])
        actual = sum(
            (_money(row["actual"]) for row in audit["planning_ledger_rows"]), Decimal(0)
        )
        if cost != actual or cost > _money(state["reserved_yuan"]):
            raise PoolStopped(
                "expiry ledger attribution differs from parent reservation"
            )
        payload = {
            "trial_id": trial_id,
            "outcome": "ttl_infrastructure_failure",
            "actual_yuan": str(cost),
            "observed_max_seconds": 0,
            "evidence_sha256": canonical_hash(evidence),
            "evidence": evidence,
        }
        journal._append("expiry_audit", payload, journal._events())
        return journal.status()


GUARD_FORMULA = "remaining-strict-max-1500-1.5M-plus300-v1"


def shared_remaining_threshold(maximum):
    if not math.isfinite(maximum) or maximum < 0:
        raise PoolStopped("invalid shared M")
    if maximum >= 1000:
        raise PoolStopped(
            "shared M requires at least 1800 seconds: admission impossible"
        )
    return max(1500.0, 1.5 * maximum + 300)


def validate_guard_review(proof, pool_digest, prefix, now, maximum):
    """Check exact prefix closure; native facts are independently read by consumer."""
    threshold = shared_remaining_threshold(maximum)
    checked = datetime.fromisoformat(proof["checked_at"])
    if (
        checked.tzinfo is None
        or now.tzinfo is None
        or not 0 <= (now - checked).total_seconds() <= 300
    ):
        raise PoolStopped("guard review must be fresh")
    settled = [e["payload"] for e in prefix if e["kind"] in {"settle", "expiry_audit"}]
    ids = [prefix[0]["payload"]["imported_trial_id"]] + [
        p["trial_id"] for p in settled if p["outcome"] == "qualified"
    ]
    observations = proof["observations"]
    measured = max(
        max(o["duration_wall_seconds"], o["duration_monotonic_seconds"])
        for o in observations
    )
    if (
        proof["schema_version"] != "task13-pool-guard-review-v1"
        or proof["pool_registration_sha256"] != pool_digest
        or proof["journal_head_sha256"] != prefix[-1]["sha256"]
        or proof["formula_version"] != GUARD_FORMULA
        or [o["trial_id"] for o in observations] != ids
        or proof["settlement_evidence_sha256"]
        != [p["evidence_sha256"] for p in settled]
        or proof["observed_max_seconds"] != maximum
        or measured != maximum
    ):
        raise PoolStopped("guard review differs from exact pool evidence prefix")
    return threshold


def require_current_guard_review(events, pool_digest, now, maximum):
    shared_remaining_threshold(maximum)
    if not events or events[-1]["kind"] != "guard_review":
        raise PoolStopped("shared M requires guard review")
    return validate_guard_review(
        events[-1]["payload"], pool_digest, events[:-1], now, maximum
    )
