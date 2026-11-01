"""Durable outer scheduling for the original 176 rows and whole-case F8.

A claim precedes every external operation. Interrupted claims are never replayed
or stolen: the operator must reconcile original native evidence first. No model
or product action occurs at import or construction.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import stat
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from evals.contracts import canonical_hash

DEADLINE = "2026-11-05T23:59:59+08:00"


def _plain_rolling(path, *, file=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise PermissionError("rolling evidence requires an absolute non-relative path")
    for entry in (path, *path.parents):
        if entry.is_symlink() or entry.is_junction():
            raise PermissionError("rolling evidence link or junction forbidden")
        if entry.exists():
            info = entry.lstat()
            if entry == path and stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise PermissionError("rolling evidence hardlink forbidden")
            elif not stat.S_ISDIR(info.st_mode):
                raise PermissionError(
                    "rolling evidence ancestor or entry is not regular"
                )
    if file and (not path.is_file() or path.stat().st_nlink != 1):
        raise PermissionError("single-link regular rolling evidence file required")
    return path


def _read_rolling(path):
    path = _plain_rolling(path, file=True)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read()
        after = os.fstat(stream.fileno())
    current = _plain_rolling(path, file=True).stat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_nlink,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_nlink,
    ) or (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
        current.st_nlink,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, 1):
        raise PermissionError("rolling evidence changed during read")
    return raw


def _write_rolling(path, raw):
    path = _plain_rolling(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _plain_rolling(path.parent)
    with path.open("xb") as stream:
        if os.fstat(stream.fileno()).st_nlink != 1:
            raise PermissionError("rolling evidence write target is linked")
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if _read_rolling(path) != raw:
        raise PermissionError("rolling evidence publication differs")


def _raw_json(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False
    ).encode("utf-8")


async def _await(value):
    return await value if inspect.isawaitable(value) else value


class RollingController:
    def __init__(
        self, root, rows, operations, *, scope_sha256, synthetic=False, clock=None
    ):
        if not synthetic and clock is not None:
            raise PermissionError("real controller requires the actual clock")
        self.root, self.ops = _plain_rolling(root), operations
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.rows = [
            {
                k: r.get(k, r.get("request", {}).get(k))
                for k in ("slot_id", "case_id", "group")
            }
            for r in rows
        ]
        if (
            len(self.rows) != 176
            or len({r["slot_id"] for r in self.rows}) != 176
            or len({r["case_id"] for r in self.rows}) != 88
            or sum(r["case_id"].startswith("ait-") for r in self.rows) != 44
            or any(
                a["case_id"] != b["case_id"] or {a["group"], b["group"]} != {"B2", "B3"}
                for a, b in zip(self.rows[::2], self.rows[1::2])
            )
        ):
            raise ValueError("complete original adjacent 176-row matrix required")
        if not re.fullmatch("[0-9a-f]{64}", scope_sha256):
            raise ValueError("actual scope pin required")
        if synthetic is not getattr(operations, "synthetic", None):
            raise PermissionError("synthetic operations cannot grant real authority")
        if not synthetic and type(operations) is not NativeRollingOperations:
            raise PermissionError("real rolling requires the native composition")
        self.identity = {
            "schema_version": "task13-rolling-controller-v1",
            "rows_sha256": canonical_hash(self.rows),
            "scope_sha256": scope_sha256,
            "synthetic": synthetic,
            "deadline_at": DEADLINE,
        }
        if not synthetic:
            operations.bind_controller(self.identity, self.rows, self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        with self._lock():
            self._load()
            if not self.events:
                self._append("registered", identity=self.identity)
            if self.events[0]["payload"].get("identity") != self.identity:
                raise PermissionError("rolling immutable registration differs")

    @contextmanager
    def _lock(self):
        _plain_rolling(self.root)
        lock = _plain_rolling(self.root / ".writer-lock")
        adoption = _plain_rolling(self.root / ".rolling-adoption-lock")
        if adoption.exists():
            raise PermissionError(
                "rolling source adoption is active or requires reconciliation"
            )
        if any(
            p.is_symlink() or p.is_junction() for p in (self.root, *self.root.parents)
        ):
            raise PermissionError("rolling journal link forbidden")
        try:
            lock.mkdir()
        except FileExistsError as exc:
            raise PermissionError(
                "rolling writer lock requires reconciliation"
            ) from exc
        try:
            if adoption.exists():
                raise PermissionError(
                    "rolling source adoption acquired during writer admission"
                )
            yield
        finally:
            lock.rmdir()

    def _load(self):
        self.events = []
        directory = _plain_rolling(self.root / "rolling-events")
        directory.mkdir(exist_ok=True)
        for index, path in enumerate(sorted(directory.iterdir())):
            try:
                event = json.loads(_read_rolling(path))
                digest = event.pop("sha256")
                if (
                    path.name != f"{index:06d}.json"
                    or event["sequence"] != index
                    or event["previous"]
                    != (self.events[-1]["sha256"] if self.events else None)
                    or canonical_hash(event) != digest
                ):
                    raise ValueError("chain differs")
                self.events.append({**event, "sha256": digest})
            except (ValueError, KeyError, TypeError, OSError) as exc:
                raise PermissionError(
                    "rolling journal chain invalid; reconcile before dispatch"
                ) from exc
        head_path = _plain_rolling(self.root / "head.json")
        expected_head = (
            {"count": len(self.events), "sha256": self.events[-1]["sha256"]}
            if self.events
            else None
        )
        try:
            head = json.loads(_read_rolling(head_path)) if head_path.exists() else None
            if head != expected_head:
                raise ValueError("head differs")
        except (ValueError, OSError) as exc:
            raise PermissionError(
                "rolling journal head differs; reconcile interrupted publication or truncation"
            ) from exc
        if self.events and self.events[0]["payload"].get("identity") != self.identity:
            raise PermissionError("rolling registration changed")

    def _append(self, kind, **payload):
        from uuid import uuid4

        previous = self.events[-1]["sha256"] if self.events else None
        self._load()
        if previous != (self.events[-1]["sha256"] if self.events else None):
            raise PermissionError("rolling journal changed before append")
        event = {
            "sequence": len(self.events),
            "previous": previous,
            "at": self.clock().isoformat(),
            "payload": {"kind": kind, **deepcopy(payload)},
        }
        event["sha256"] = canonical_hash(event)
        path = self.root / "rolling-events" / f"{len(self.events):06d}.json"
        _write_rolling(path, _raw_json(event))
        temporary = self.root / (".head-" + uuid4().hex)
        _write_rolling(
            temporary,
            _raw_json({"count": len(self.events) + 1, "sha256": event["sha256"]}),
        )
        head_path = _plain_rolling(self.root / "head.json")
        expected_head = (
            {"count": len(self.events), "sha256": previous} if self.events else None
        )
        actual_head = (
            json.loads(_read_rolling(head_path)) if head_path.exists() else None
        )
        if actual_head != expected_head:
            raise PermissionError(
                "rolling journal head changed during append publication"
            )
        os.replace(temporary, head_path)
        _plain_rolling(self.root / "head.json", file=True)
        self.events.append(event)

    def _artifact(self, category, raw):
        digest = sha256(raw).hexdigest()
        path = self.root / "rolling-evidence" / category / (digest + ".json")
        if path.exists():
            if _read_rolling(path) != raw:
                raise PermissionError("immutable rolling evidence changed")
        else:
            _write_rolling(path, raw)
        return {"path": str(path), "sha256": digest}

    def _pin(self, pin):
        if not isinstance(pin, dict) or set(pin) != {"path", "sha256"}:
            raise PermissionError("exact raw evidence pin required")
        raw = _read_rolling(pin["path"])
        if sha256(raw).hexdigest() != pin["sha256"]:
            raise PermissionError("raw rolling evidence pin differs")
        return raw, json.loads(raw)

    def _capture_time(self, value):
        if (
            not isinstance(value, str)
            or re.search(r"\.\d{6}(?:Z|[+-]\d{2}:\d{2})$", value) is None
        ):
            raise PermissionError(
                "actual capture requires a high-resolution zoned timestamp"
            )
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if when.tzinfo is None or when > self.clock():
            raise PermissionError("actual capture timestamp is future or naive")
        return when

    def _prepared_question(self, case, source, packet):
        from uuid import uuid4

        question = {
            "schema_version": "task13-rolling-prepared-question-v1",
            "record_kind": "prepared_question_not_user_consent",
            "prepared_id": uuid4().hex,
            "case_id": case,
            "incident_id": packet["incident_id"],
            "packet_sha256": canonical_hash(packet),
            "source_sha256": canonical_hash(source),
            "plan_sha256": packet["plan_sha256"],
            "created_at": self.clock().isoformat(timespec="microseconds"),
            "title": "Task13 F8 plan approval: "
            + case
            + " / "
            + canonical_hash(packet),
            "question": "Packet SHA256: "
            + canonical_hash(packet)
            + "\nReview this exact saved plan. Approve or reject only this plan; no renewal or reanalysis is authorized.\n"
            + _raw_json(packet).decode("utf-8"),
            "approved_answer": "Approve this exact displayed plan.",
            "rejected_answer": "Reject this exact displayed plan.",
            "automatic_approval": False,
            "synthetic_control_fixture": False,
        }
        return self._artifact("prepared-questions", _raw_json(question))

    def bind_question_delivery(self, actual_delivery_record):
        """Capture the actual tool call ID after displaying the prepared question.

        The generated prepared_id is not an app questionItemId. The producer
        records the real request_user_input_async call metadata without editing
        the displayed title/question or selecting an answer. Use
        delivery_observed_at with observation_source=actual_tool_call when call
        metadata is available. If learned from the incoming reply, use
        observation_source=actual_question_reply plus its canonical
        actual_question_reply_sha256; this is an observation time, not an
        invented UI-render time. Raw chat captured_at is the local receipt
        capture time, not the human click time or product approval time.
        """
        with self._lock():
            self._load()
            _, claim = self._state()
            if (
                self.identity["synthetic"]
                or not claim
                or claim["kind"] != "pending"
                or claim.get("delivery")
            ):
                raise PermissionError("one real undelivered pending question required")
            raw, delivery = self._pin(actual_delivery_record)
            _, question = self._pin(claim["presentation"]["prepared_question"])
            try:
                item = json.loads(delivery["question_item_id"])
                if (
                    delivery.get("schema_version")
                    != "task13-rolling-question-delivery-v1"
                    or delivery.get("record_kind") != "actual_tool_question_delivery"
                    or delivery.get("tool_name") != "request_user_input_async"
                    or not isinstance(delivery.get("tool_call_id"), str)
                    or not delivery["tool_call_id"].startswith("call_")
                    or item != ["request_user_input_async", delivery["tool_call_id"], 0]
                    or delivery.get("synthetic_control_fixture") is not False
                    or delivery.get("automatic_approval") is not False
                    or delivery.get("prepared_question")
                    != claim["presentation"]["prepared_question"]
                    or any(
                        delivery.get(k) != question[k] for k in ("title", "question")
                    )
                    or delivery.get("observation_source")
                    not in {"actual_tool_call", "actual_question_reply"}
                    or self._capture_time(delivery["delivery_observed_at"])
                    < self._capture_time(question["created_at"])
                ):
                    raise PermissionError(
                        "actual delivered question differs from immutable preparation"
                    )
            except (KeyError, TypeError, ValueError) as error:
                raise PermissionError(
                    "actual delivered question metadata required"
                ) from error
            copied = self._artifact("question-deliveries", raw)
            patch = {k: deepcopy(v) for k, v in claim.items() if k != "kind"}
            patch.update(
                delivery=deepcopy(actual_delivery_record), delivery_capture=copied
            )
            self._append("pending", **patch)
            return copied

    def _actual_reply(self, claim, actual_chat_record):
        if not claim.get("delivery"):
            raise PermissionError(
                "actual tool delivery must be bound before a user reply"
            )
        raw, record = self._pin(actual_chat_record)
        _, question = self._pin(claim["presentation"]["prepared_question"])
        _, delivery = self._pin(claim["delivery"])
        # Re-check both raw original capture and archived copy on every resume.
        if self._pin(claim["delivery_capture"])[1] != delivery:
            raise PermissionError("original delivered question changed")
        try:
            replies = record["actual_question_reply"]
            if not isinstance(replies, list) or len(replies) != 1:
                raise PermissionError("one exact actual question reply required")
            reply = replies[0]
            answer = reply["answer"]
            choices = {
                question["approved_answer"]: "approved",
                question["rejected_answer"]: "rejected",
            }
            if (
                record.get("schema_version") != "task13-rolling-actual-user-reply-v1"
                or record.get("record_kind") != "actual_tool_user_response"
                or record.get("role") != "user"
                or record.get("origin") != "actual_user"
                or record.get("synthetic_control_fixture") is not False
                or record.get("automatic_approval") is not False
                or not isinstance(record.get("record_id"), str)
                or not record["record_id"].strip()
                or record.get("prepared_question")
                != claim["presentation"]["prepared_question"]
                or record.get("question_delivery") != claim["delivery"]
                or any(
                    record.get(k) != question[k]
                    for k in (
                        "case_id",
                        "incident_id",
                        "packet_sha256",
                        "source_sha256",
                        "plan_sha256",
                    )
                )
                or question["source_sha256"] != canonical_hash(claim["source"])
                or question["packet_sha256"] != canonical_hash(claim["packet"])
                or reply.get("questionItemId") != delivery["question_item_id"]
                or any(reply.get(k) != question[k] for k in ("title", "question"))
                or answer not in choices
                or record.get("text") != answer
                or record.get("reason") != answer
                or record.get("decision") != choices[answer]
                or record.get("decided_at") != record.get("captured_at")
                or self._capture_time(record["captured_at"])
                < self._capture_time(question["created_at"])
            ):
                raise PermissionError(
                    "raw actual user reply does not match current delivered plan question"
                )
        except (KeyError, TypeError, ValueError) as error:
            raise PermissionError("complete raw actual user reply required") from error
        observed = self._capture_time(delivery["delivery_observed_at"])
        captured_time = self._capture_time(record["captured_at"])
        if (
            delivery["observation_source"] == "actual_tool_call"
            and observed > captured_time
        ) or (
            delivery["observation_source"] == "actual_question_reply"
            and (
                observed < captured_time
                or delivery.get("actual_question_reply_sha256")
                != canonical_hash(replies)
            )
        ):
            raise PermissionError(
                "actual delivery observation does not bind the captured reply"
            )
        captured = self._artifact("actual-user-replies", raw)
        return {
            "question_id": delivery["question_item_id"],
            "decision": record["decision"],
            "reason": record["reason"],
            "packet_sha256": record["packet_sha256"],
            "decided_at": record["decided_at"],
            "reviewer": record["role"],
            "actual_chat_record": deepcopy(actual_chat_record),
            "actual_chat_capture": captured,
            "prepared_question": claim["presentation"]["prepared_question"],
            "question_delivery": claim["delivery"],
            "record_id": record["record_id"],
        }

    def _state(self):
        finished = set()
        claim = None
        for event in self.events:
            p = event["payload"]
            if p["kind"] == "case_finished":
                finished.add(p["case_id"])
                claim = None
            elif p["kind"] in {
                "prepare_started",
                "pending",
                "decision_started",
                "decision_received",
                "f8_started",
            }:
                claim = p
        return finished, claim

    def _deadline(self):
        now = self.clock()
        if now.tzinfo is None:
            raise ValueError("aware real clock required")
        return now >= datetime.fromisoformat(DEADLINE)

    def _statuses(self):
        summary = self.ops.status()
        rows = summary.get("rows", [])
        if [(r["slot_id"], r["case_id"]) for r in rows] != [
            (r["slot_id"], r["case_id"]) for r in self.rows
        ]:
            raise PermissionError("original row order or status binding differs")
        if any(r["status"] not in {"completed", "failed", "not_started"} for r in rows):
            raise PermissionError(
                "unknown or in-flight formal row requires reconciliation"
            )
        seen_unstarted = False
        for row in rows:
            if row["status"] == "not_started":
                seen_unstarted = True
            elif seen_unstarted:
                raise PermissionError(
                    "formal terminal rows are not an original-order prefix"
                )
        return rows

    async def _finish(self, case, outcome):
        receipt = await _await(self.ops.reconcile())
        if not isinstance(receipt, dict) or receipt.get("status") != "verified":
            raise PermissionError("actual cost and unknown reconciliation required")
        self._append(
            "case_finished", case_id=case, outcome=outcome, reconciliation=receipt
        )
        return outcome

    async def advance(self):
        with self._lock():
            self._load()
            finished, claim = self._state()
            if claim:
                if claim["kind"] == "pending":
                    return deepcopy(claim["presentation"])
                raise PermissionError(
                    "uncertain interrupted operation requires original evidence reconciliation"
                )
            if self._deadline():
                return {"status": "deadline_stopped"}
            await _await(self.ops.guard())
            statuses = self._statuses()
            case = next(
                (r["case_id"] for r in self.rows[::2] if r["case_id"] not in finished),
                None,
            )
            if case is None:
                return {"status": "all_candidates_processed", "processed": 88}
            pair = [r for r in statuses if r["case_id"] == case]
            remaining = sum(r["status"] == "not_started" for r in pair)
            if remaining:
                # Native host rechecks its deadline before each admitted row.
                await _await(self.ops.execute(row_limit=remaining))
                pair = [r for r in self._statuses() if r["case_id"] == case]
            if any(r["status"] == "not_started" for r in pair):
                return {"status": "bounded_stop", "case_id": case}
            if self._deadline():
                return {"status": "deadline_stopped", "case_id": case}
            self._append("prepare_started", case_id=case)
            prepared = await self.ops.prepare(case)
            if "gap" in prepared:
                return await self._finish(
                    case, {"status": "gap", "case_id": case, "reason": prepared["gap"]}
                )
            packet = prepared["packet"]
            if (
                packet.get("case_id") != case
                or packet.get("review_window") != "anytime"
            ):
                raise PermissionError("fresh anytime case-bound packet required")
            presentation = {
                "status": "pending_approval",
                "case_id": case,
                "packet": packet,
                "packet_sha256": canonical_hash(packet),
            }
            if not self.identity["synthetic"]:
                presentation["prepared_question"] = self._prepared_question(
                    case, prepared["source"], packet
                )
            self._append(
                "pending",
                case_id=case,
                source=prepared["source"],
                packet=packet,
                presentation=presentation,
            )
            return deepcopy(presentation)

    async def decide(
        self,
        *,
        question_id=None,
        decision=None,
        reason=None,
        packet_sha256=None,
        actual_chat_record=None,
    ):
        with self._lock():
            self._load()
            _, claim = self._state()
            if not claim or claim["kind"] != "pending":
                raise PermissionError("one actual pending claim required")
            if not self.identity["synthetic"]:
                if actual_chat_record is None or any(
                    v is not None
                    for v in (question_id, decision, reason, packet_sha256)
                ):
                    raise PermissionError(
                        "real decisions require only the pinned raw actual user chat record"
                    )
                actual = self._actual_reply(claim, actual_chat_record)
                question_id, decision, reason, packet_sha256 = (
                    actual[k]
                    for k in ("question_id", "decision", "reason", "packet_sha256")
                )
            else:
                if actual_chat_record is not None:
                    raise PermissionError(
                        "synthetic convenience cannot consume actual chat authority"
                    )
                actual = {
                    "question_id": question_id,
                    "decision": decision,
                    "reason": reason,
                    "packet_sha256": packet_sha256,
                    "decided_at": self.clock().isoformat(),
                    "reviewer": "user",
                    "synthetic_control_fixture": True,
                }
            if (
                not isinstance(question_id, str)
                or not question_id.strip()
                or decision not in {"approved", "rejected"}
                or not isinstance(reason, str)
                or not reason.strip()
                or canonical_hash(claim["packet"]) != packet_sha256
            ):
                raise PermissionError(
                    "exact real question, packet and explicit user decision required"
                )
            if self._deadline():
                return await self._finish(
                    claim["case_id"],
                    {
                        "status": "gap",
                        "reason": "deadline_stopped",
                        "case_id": claim["case_id"],
                    },
                )
            await _await(self.ops.guard())
            self._append(
                "decision_started", case_id=claim["case_id"], claim=claim, actual=actual
            )
            result = await self.ops.decide(claim, actual)
            self._append(
                "decision_received",
                case_id=claim["case_id"],
                claim=claim,
                actual=actual,
                result=result,
            )
            if "gap" in result:
                return await self._finish(
                    claim["case_id"],
                    {
                        "status": "gap",
                        "case_id": claim["case_id"],
                        "reason": result["gap"],
                    },
                )
            await self.ops.verify(claim, result)
            if decision == "rejected":
                return await self._finish(
                    claim["case_id"],
                    {
                        "status": "gap",
                        "reason": "user_rejected",
                        "case_id": claim["case_id"],
                    },
                )
            if self._deadline():
                return await self._finish(
                    claim["case_id"],
                    {
                        "status": "gap",
                        "reason": "deadline_stopped",
                        "case_id": claim["case_id"],
                    },
                )
            self._append("f8_started", case_id=claim["case_id"], result=result)
            outcome = await self.ops.run_f8(claim["case_id"], result)
            return await self._finish(claim["case_id"], outcome)


@contextmanager
def rolling_quiescence(controllers, roots):
    """Hold outer-admission fences while the caller locks/adopts native roots.

    This companion is mandatory for future source adoption involving rolling
    journals. The unchanged native parser does not understand rolling-events.
    Keep this context open around the native epoch operation: it supplies the
    ordinary native writer locks and validates its own journal formats.
    """
    from contextlib import ExitStack

    supplied = {c.root.resolve(): c for c in controllers}
    discovered = set()
    for root in roots:
        base = Path(root)
        for directory in base.rglob("rolling-events"):
            if directory.is_symlink() or directory.is_junction():
                raise PermissionError("linked rolling journal cannot be reconciled")
            if directory.is_dir():
                discovered.add(directory.parent.resolve())
    if discovered != set(supplied):
        raise PermissionError(
            "unlisted or missing rolling journal requires explicit companion audit"
        )
    with ExitStack() as stack:
        for root in sorted(supplied):
            fence = root / ".rolling-adoption-lock"
            try:
                fence.mkdir()
            except FileExistsError as error:
                raise PermissionError(
                    "rolling adoption fence requires reconciliation"
                ) from error
            stack.callback(fence.rmdir)
        heads = {}
        for root, controller in supplied.items():
            lock = root / ".writer-lock"
            try:
                lock.mkdir()
            except FileExistsError as error:
                raise PermissionError(
                    "rolling writer active or stale during quiescence"
                ) from error
            try:
                controller._load()
                _, claim = controller._state()
                if claim is not None:
                    raise PermissionError(
                        "pending or uncertain rolling operation prevents source adoption"
                    )
                controller._statuses()
                heads[str(root)] = controller.events[-1]["sha256"]
            finally:
                lock.rmdir()
        yield {
            "schema_version": "task13-rolling-quiescence-v1",
            "status": "verified",
            "rolling_heads": heads,
            "native_journals_require_separate_native_locks": True,
        }


def require_runtime_equivalence(verification, formal, binding, measured, core):
    """Only phase/output locations differ; every execution option stays frozen."""
    mutable_locations = {"phase", "output_dir", "temporary_root"}
    if (
        {k: v for k, v in verification.items() if k not in mutable_locations}
        != {k: v for k, v in formal.items() if k not in mutable_locations}
        or verification.get("phase") != "verification"
        or formal.get("phase") != "formal"
    ):
        raise PermissionError(
            "verification runtime differs from complete registered formal runtime"
        )
    keys = (
        "image_id",
        "dependencies_lock_sha256",
        "dependencies_tree_sha256",
        "knowledge_sha256",
    )
    if (
        any(measured.get(k) != binding.get(k) or binding.get(k) is None for k in keys)
        or any(
            verification.get(k) != binding.get(k)
            for k in keys
            if k != "dependencies_tree_sha256"
        )
        or measured.get("received_model")
        != {k: core["model_identity"][k] for k in ("response_model", "fingerprint")}
    ):
        raise PermissionError(
            "runtime/model differs from actual measured timing family"
        )


def require_rolling_source_files(source_files):
    """Freeze the added control plane without changing the 117 worker files."""
    root = Path(__file__).resolve().parents[1]
    for relative in (
        "evals/task13_rolling.py",
        "evals/timing_pool.py",
        "evals/verification_v2.py",
        "scripts/task13_regression.py",
    ):
        path = root / relative
        if (
            any(p.is_symlink() or p.is_junction() for p in (path, *path.parents))
            or source_files.get(str(path)) != sha256(path.read_bytes()).hexdigest()
        ):
            raise PermissionError(
                "actual rolling control plane file is outside final freeze"
            )


def regression_host_proposal(manifest):
    """Only future approval pins are omitted; all concrete execution inputs stay."""
    proposal = deepcopy(manifest)
    if proposal.get("schema_version") != "task13-regression-host-v1":
        raise PermissionError("native regression host proposal required")
    proposal["inputs"] = {
        k: v
        for k, v in proposal["inputs"].items()
        if k not in {"scope_packet", "scope_decision"}
    }
    return proposal


def materialize_regression_scope(
    proposal, joint_scope, joint_scope_sha256, joint_decision, joint_decision_sha256
):
    """Derive native envelopes from one real reply; publish with _bytes unchanged.

    The proposal can be prepared before a reply exists. This function never
    records a decision itself, and accepts no pending/default approval.
    """
    from scripts.task13_e_trial import _bytes
    from scripts.task13_regression import SCOPE

    if (
        canonical_hash(proposal) != joint_scope.get("regression_host_proposal_sha256")
        or "scope_packet" in proposal["inputs"]
        or "scope_decision" in proposal["inputs"]
        or joint_decision.get("schema_version")
        != "task13-rolling-joint-user-decision-v1"
        or joint_decision.get("role") != "user"
        or joint_decision.get("decision") != "approved"
        or joint_decision.get("scope_packet_sha256") != joint_scope_sha256
        or any(
            not isinstance(joint_decision.get(k), str) or not joint_decision[k].strip()
            for k in ("record_id", "text", "decided_at")
        )
        or not all(
            re.fullmatch("[0-9a-f]{64}", pin)
            for pin in (joint_scope_sha256, joint_decision_sha256)
        )
    ):
        raise PermissionError(
            "actual joint reply and unchanged concrete proposal required"
        )
    packet = {
        "schema_version": "task13-regression-scope-v1",
        "scope": SCOPE,
        **{
            k: joint_scope[k]
            for k in (
                "campaign_id",
                "final_freeze_sha256",
                "bundle_sha256",
                "registered_rows",
                "deadline_at",
            )
        },
        "joint_scope_sha256": joint_scope_sha256,
    }
    record = {
        "schema_version": "task13-regression-user-scope-decision-v1",
        "scope": SCOPE,
        **{
            k: joint_decision[k]
            for k in ("role", "decision", "record_id", "text", "decided_at")
        },
        "scope_packet_sha256": sha256(_bytes(packet)).hexdigest(),
        "joint_scope_sha256": joint_scope_sha256,
        "joint_decision_sha256": joint_decision_sha256,
    }
    return packet, record


class NativeRollingOperations:
    """Production composition of pinned RegressionHost and VerificationCampaign.

    The caller passes the two real native objects and independently approved raw
    scope/decision pins. No worker/verifier/gate callback is accepted here. The
    scope supplies pinned verification runtime options and participation policy;
    their hashes, full F8 registration and the host manifest are approved together.
    """

    synthetic = False

    def __init__(self, host, campaign, *, joint_scope_pin, joint_decision_pin):
        from evals.verification_v2 import VerificationCampaign
        from scripts.task13_e_trial import _decode, _read_pin
        from scripts.task13_regression import RegressionHost

        if (
            type(host) is not RegressionHost
            or host._free
            or host._manifest["synthetic"]
        ):
            raise PermissionError("actual native regression host required")
        if type(campaign) is not VerificationCampaign:
            raise PermissionError("actual complete native F8 campaign required")
        self.host, self.campaign = host, campaign
        self.scope_pin, self.decision_pin = (
            deepcopy(joint_scope_pin),
            deepcopy(joint_decision_pin),
        )
        self.scope = _decode(_read_pin(self.scope_pin))
        self.decision = _decode(_read_pin(self.decision_pin))
        self.options = _decode(_read_pin(self.scope["verification_runtime_options"]))
        self.policy = _decode(_read_pin(self.scope["participation_policy"]))
        self.identity = deepcopy(campaign.identity)
        self.data = host._load()
        self.rows = deepcopy(self.data["bundle"]["rows"])
        self.agents = {
            r["case_id"]: Path(host._manifest["case_roots"][r["case_id"].split("-")[0]])
            / r["case_id"]
            / "agent"
            for r in self.rows
        }
        self.audit_dir = campaign.root / "rolling-native-audit"
        self._check_scope()
        # Complete the expensive provenance audit before a fresh B3 is admitted.
        host._timing(self.data)
        campaign.execution_admitter = self._admit_f8

    def _check_frozen_scope(self):
        """Read-only frozen bindings and actual reply, also usable after deadline.

        Execution always adds the original registered epoch/runtime checks in
        _check_scope. This method performs no admission, journal or DB writes.
        """
        from evals.adapters.e_participation import EParticipationPolicy
        from evals.verification_v2 import validate_registration
        from scripts.task13_e_trial import _decode, _read_pin

        scope, decision = self.scope, self.decision
        if (
            _decode(_read_pin(self.scope_pin)) != scope
            or _decode(_read_pin(self.decision_pin)) != decision
        ):
            raise PermissionError("joint scope or actual decision changed")
        if (
            _decode(_read_pin(scope["verification_runtime_options"])) != self.options
            or _decode(_read_pin(scope["participation_policy"])) != self.policy
        ):
            raise PermissionError("joint runtime or anytime participation changed")
        EParticipationPolicy.model_validate(self.policy)
        auth = _decode(_read_pin(scope["participation_authorization"]))
        if self.policy["authorization_record_sha256"] != canonical_hash(auth):
            raise PermissionError("actual anytime policy authorization differs")
        data = self.host._load()
        bundle = data["bundle"]
        core = data["core_config"]
        require_rolling_source_files(data["final_freeze"]["source_files"])
        validate_registration(self.campaign.plan)
        expected = {
            "schema_version": "task13-rolling-joint-scope-v1",
            "regression_host_proposal_sha256": canonical_hash(
                regression_host_proposal(self.host._manifest)
            ),
            "campaign_id": bundle["campaign_id"],
            "bundle_sha256": bundle["bundle_sha256"],
            "final_freeze_sha256": self.host._manifest["inputs"]["final_freeze"][
                "sha256"
            ],
            "timing_receipt_sha256": self.host._manifest["inputs"]["e_timing_receipt"][
                "sha256"
            ],
            "f8_registration_sha256": canonical_hash(self.campaign._registration),
            "f8_output_dir": str(self.campaign.root.resolve()),
            "deadline_at": DEADLINE,
            "admitted_operation_may_finish": True,
            "registered_rows": 176,
            "registered_cases": 88,
            "registered_pairs": 264,
            "registered_branches": 528,
            "formal_order_sha256": canonical_hash(
                [(r["case_id"], r["request"]["group"]) for r in self.rows]
            ),
            "f8_cross_case_order": "formal-seed42-arrival",
            "per_plan_approval": "individual-user-decision-v1",
            "f8_model_calls": 0,
            "logical_calls_per_row": 16,
            "physical_attempts_per_logical": 3,
            "budgets": {
                "original_total": 100,
                "original_development": 15,
                "supplement": 30,
                "development": 6,
                "regression": 16,
                "f8": 6,
                "held": 2,
            },
        }
        if any(scope.get(k) != v for k, v in expected.items()):
            raise PermissionError("actual full rolling joint scope binding differs")
        if (
            decision.get("schema_version") != "task13-rolling-joint-user-decision-v1"
            or decision.get("role") != "user"
            or decision.get("decision") != "approved"
            or decision.get("scope_packet_sha256") != self.scope_pin["sha256"]
            or any(
                not isinstance(decision.get(k), str) or not decision[k].strip()
                for k in ("record_id", "text", "decided_at")
            )
            or datetime.fromisoformat(decision["decided_at"])
            > datetime.now(timezone.utc)
        ):
            raise PermissionError("actual joint user scope approval required")
        identity = {
            "campaign_id": bundle["campaign_id"],
            "source_commit": bundle["source_commit"],
            "source_sha256": canonical_hash(data["final_freeze"]["source_files"]),
            "config_sha256": bundle["config_sha256"],
            "plan_sha256": core["f8_plan_sha256"],
        }
        formal_options = data["runtime_options"]
        if (
            identity != self.identity
            or self.campaign.config != core
            or self.campaign.source_files != data["final_freeze"]["source_files"]
            or self.host._manifest["deadline_at"] != DEADLINE
            or self.options.get("phase") != "verification"
            or any(
                self.options.get(k) != formal_options.get(k)
                for k in (
                    "source_commit",
                    "source_dir",
                    "dependencies_dir",
                    "knowledge_dir",
                    "knowledge_sha256",
                    "budget_dir",
                    "budget_identity",
                    "model_identity_binding",
                )
            )
            or {r["case_id"] for r in self.rows}
            != {s["case_id"] for s in self.campaign.plan["slots"]}
        ):
            raise PermissionError(
                "rolling native source/config/runtime/complete-case bridge differs"
            )
        proposal = regression_host_proposal(self.host._manifest)
        native_packet, native_decision = materialize_regression_scope(
            proposal,
            scope,
            self.scope_pin["sha256"],
            decision,
            self.decision_pin["sha256"],
        )
        if (
            data["scope_packet"] != native_packet
            or data["scope_decision"] != native_decision
        ):
            raise PermissionError(
                "native formal authority is not derived from the original joint user reply"
            )
        self.data = data
        return data

    def _check_scope(self):
        data = self._check_frozen_scope()
        core, bundle, scope = data["core_config"], data["bundle"], self.scope
        formal_options = data["runtime_options"]
        from evals.adapters.source_epochs import require_registered_epoch
        from scripts.task13_e_trial import _decode, _path

        epoch = require_registered_epoch(
            Path(core["active_budget_path"]),
            bundle["epoch_id"],
            source_sha256=bundle["source_sha256"],
            config_sha256=bundle["config_sha256"],
            manifest_sha256=bundle["epoch_manifest_sha256"],
            latest=True,
        )
        from scripts.task13_worker_runtime import e_planning_runtime_binding

        dependencies = _decode(
            _read_rolling(
                Path(self.options["dependencies_dir"]) / "task13_dependencies.json"
            )
        )
        runtime = e_planning_runtime_binding(self.options, dependencies)
        if runtime != epoch["runtime_binding"]:
            raise PermissionError(
                "verification runtime differs from registered source epoch"
            )
        measured = data["e_timing_receipt"]["pool_registration"]["condition_identity"][
            "actual_conditions"
        ]
        require_runtime_equivalence(
            self.options, formal_options, runtime, measured, core
        )
        for path in (
            self.campaign.root,
            Path(scope["rolling_output_dir"]),
            Path(self.options["output_dir"]),
        ):
            if not any(
                _path(path).is_relative_to(_path(root))
                for root in epoch["controller_state_roots"]
            ):
                raise PermissionError(
                    "rolling output path is outside actual registered controller roots"
                )
        self.data = data

    def bind_controller(self, identity, rows, root):
        self._check_scope()
        if Path(root).resolve() != Path(self.scope["rolling_output_dir"]).resolve():
            raise PermissionError("outer journal root differs from actual joint scope")
        expected = [
            {k: r.get(k, r["request"].get(k)) for k in ("slot_id", "case_id", "group")}
            for r in self.rows
        ]
        if identity["scope_sha256"] != self.scope_pin["sha256"] or rows != expected:
            raise PermissionError(
                "outer controller does not bind actual joint scope/order"
            )

    def guard(self):
        self._check_scope()
        self.data = self.host._preflight()
        self.reconcile()

    def status(self):
        from scripts.task13_e_trial import _decode, _path

        summary = self.host.status()
        for row in summary.get("rows", []):
            if row["status"] not in {"completed", "failed"}:
                continue
            value = _decode(
                _path(
                    self.host._root / row["slot_id"] / "result.json", file=True
                ).read_bytes()
            )
            if value.get("isolation_evidence", {}).get("status") != "passed":
                raise PermissionError("formal isolation failure requires systemic halt")
        return summary

    def execute(self, row_limit):
        return self.host.execute(row_limit=row_limit)

    def _save(self, category, value):
        from evals.verification_v2 import _immutable

        digest = canonical_hash(value)
        path = self.audit_dir / category / (digest + ".json")
        _immutable(path, value)
        return {
            "path": str(path.resolve()),
            "sha256": sha256(path.read_bytes()).hexdigest(),
        }

    def _source(self, case):
        """Use only the sealed original B3 result and its retained state artifact."""
        from scripts.task13_e_trial import _decode, _path

        row = next(
            r
            for r in self.rows
            if r["case_id"] == case and r["request"]["group"] == "B3"
        )
        status = next(
            r for r in self.host.status()["rows"] if r["slot_id"] == row["slot_id"]
        )
        if status["status"] != "completed":
            return {"gap": "b3_" + status["status"]}
        value = _decode(
            _path(
                self.host._root / row["slot_id"] / "result.json", file=True
            ).read_bytes()
        )
        reference = (value.get("verification") or {}).get("case_reference")
        if not reference:
            return {"gap": "no_retained_executable_b3_plan"}
        evidence = value.get("isolation_evidence") or {}
        if evidence.get("status") != "passed":
            raise PermissionError("original B3 isolation failed")
        nonce = (
            evidence["probe"]["nonce"]
            if "nonce" in evidence["probe"]
            else evidence["probe"]["worker_nonce"]
        )
        if not re.fullmatch("[0-9a-f]{32}", nonce):
            raise PermissionError("original worker nonce invalid")
        state_path = (
            Path(self.data["runtime_options"]["output_dir"])
            / row["request"]["run_id"]
            / case
            / "B3"
            / nonce
            / "investigation-state.json"
        )
        state = _decode(_path(state_path, file=True).read_bytes())
        if (
            canonical_hash(state)
            != value.get("artifact_hashes", {}).get("investigation_state")
            or reference.get("plan_sha256")
            != canonical_hash(state.get("response_plan"))
            or reference.get("snapshot_sha256")
            != state.get("diagnostic_snapshot_sha256")
            or reference.get("source_commit") != self.identity["source_commit"]
        ):
            raise PermissionError("original B3 retained artifact binding differs")
        return {
            **{k: v for k, v in self.identity.items() if k != "plan_sha256"},
            "case_id": case,
            "dataset": case.split("-")[0],
            "state": state,
            "resources": reference,
        }

    async def _review(
        self, source, operation, *, packet=None, decision=None, reason=None
    ):
        from uuid import uuid4

        from evals.adapters.retained_workflow import resource_fields
        from evals.adapters.verification_worker import SourceReviewRequest
        from scripts.task13_worker_runtime import run_source_review_container

        row = next(
            r
            for r in self.rows
            if r["case_id"] == source["case_id"]
            and r.get("group", r["request"].get("group")) == "B3"
        )
        request = SourceReviewRequest(
            request_id=uuid4().hex,
            namespace=uuid4().hex,
            case_id=source["case_id"],
            dataset=source["dataset"],
            agent_sha256=row["request"]["agent_sha256"],
            source_commit=self.identity["source_commit"],
            source_resources=resource_fields(source["resources"]),
            incident_id=source["state"]["incident_id"],
            operation=operation,
            packet=packet,
            decision=decision,
            reason=reason,
        )
        self._save("review-inputs", request.model_dump(mode="json"))
        value = await run_source_review_container(
            request, self.agents[source["case_id"]], self.options
        )
        self._save("review-results", value)
        if (
            value.get("status") != "completed"
            or value.get("model_ledger") != []
            or value.get("request_id") != request.request_id
            or value.get("input_sha256") != canonical_hash(request)
            or value.get("isolation_evidence", {}).get("status") != "passed"
        ):
            raise PermissionError(
                "generic source review failed or made model calls; preserve uncertain claim"
            )
        return value

    async def prepare(self, case):
        from evals.adapters.retained_workflow import build_approval_packet
        from evals.verification import _eligibility

        source = self._source(case)
        if "gap" in source:
            return source
        status, reason = _eligibility(source, datetime.now(timezone.utc))
        if status is not None and reason != "approval_pending":
            return {"gap": reason}
        live = await self._review(source, "read_packet")
        if live["source"]["state"] != source["state"]:
            raise PermissionError("fresh original B3 state differs from sealed state")
        packet = build_approval_packet(
            {"case_id": case, "dataset": source["dataset"]},
            source["state"],
            participation_policy=self.policy,
        )
        if packet["status"] != "pending":
            return {"gap": "plan_expired"}
        return {"source": source, "packet": packet}

    async def decide(self, claim, actual):
        source = claim["source"]
        expires = datetime.fromisoformat(source["state"]["response_plan"]["expires_at"])
        if datetime.now(timezone.utc) >= expires:
            return {"gap": "plan_expired"}
        # The real product matches the packet to the live state before writing.
        value = await self._review(
            source,
            "decision",
            packet=claim["packet"],
            decision=actual["decision"],
            reason=actual["reason"],
        )
        approved = {**source, "state": value["source"]["state"]}
        return {
            "source": approved,
            "receipt": value.get("approval_receipt"),
            "decision": actual["decision"],
        }

    async def verify(self, claim, result):
        from evals.verification import verify_source_approval

        source = result["source"]
        live = await self._review(source, "read_packet")
        if live["source"]["state"] != source["state"]:
            raise PermissionError("fresh decision checkpoint changed")
        if result.get("decision") == "rejected":
            if source["state"].get("approval", {}).get("decision") != "rejected":
                raise PermissionError("actual rejection is not persisted in checkpoint")
            return
        actual = verify_source_approval(source)
        self._save("persisted-approval", actual)
        if actual != result["receipt"]:
            raise PermissionError(
                "fresh original product approval differs from decision"
            )

    def _admit_f8(self, identity):
        if identity != self.identity:
            raise PermissionError("F8 admission identity differs")
        self.guard()
        return {
            "schema_version": "task13-v2-execution-gate-v1",
            "status": "verified",
            **identity,
            "deadline_at": DEADLINE,
            "joint_scope_sha256": self.scope_pin["sha256"],
            "joint_decision_sha256": self.decision_pin["sha256"],
        }

    async def run_f8(self, case, result):
        from evals.verification import _eligibility, verify_source_approval
        from evals.verification_v2 import observed_timing_max
        from scripts.task13_worker_runtime import run_verification_container

        source = result["source"]
        now = datetime.now(timezone.utc)
        status, reason = _eligibility(source, now)
        if status is not None:
            return {"status": "gap", "case_id": case, "reason": reason}
        maximum = observed_timing_max(self.data["e_timing_receipt"], self.identity)
        if (
            datetime.fromisoformat(source["state"]["response_plan"]["expires_at"]) - now
        ).total_seconds() <= 1.5 * maximum + 300:
            return {
                "status": "gap",
                "case_id": case,
                "reason": "insufficient_original_plan_ttl",
            }

        async def worker(request):
            value = await run_verification_container(
                request, self.agents[case], self.options
            )
            self._save("verification-results", value)
            if value.get("model_ledger") != []:
                raise PermissionError("F8 must make zero model calls")
            return value

        def verifier(current):
            if current != source:
                raise PermissionError("F8 source differs from actual decision")
            receipt = verify_source_approval(current)
            if receipt != result["receipt"]:
                raise PermissionError("F8 persisted approval changed")
            return receipt

        try:
            snapshot = await self.campaign.run_case(
                case,
                source,
                worker=worker,
                timing_receipt=self.data["e_timing_receipt"],
                approval_verifier=verifier,
                admission_deadline=DEADLINE,
            )
        except PermissionError as error:
            expected = {
                "remaining TTL must exceed 1.5 * observed maximum + 300 seconds": "insufficient_original_plan_ttl",
                "registered regression deadline has passed": "deadline_stopped",
                "F8 admission deadline has passed": "deadline_stopped",
            }
            if str(error) not in expected:
                raise
            snapshot = self.campaign.snapshot()
            rows = [r for r in snapshot["records"] if r["case_id"] == case]
            if (
                snapshot["cases"][case]["binding"] is not None
                or len(rows) != 6
                or any(r["status"] != "not_started" for r in rows)
            ):
                raise
            self._save(
                "f8-admission-gap",
                {"reason": expected[str(error)], "snapshot": snapshot},
            )
            return {"status": "gap", "case_id": case, "reason": expected[str(error)]}
        self._save("f8-snapshots", snapshot)
        records = snapshot["records"] if "records" in snapshot else snapshot["rows"]
        rows = [
            r
            for r in (records.values() if isinstance(records, dict) else records)
            if r["case_id"] == case
        ]
        if len(rows) != 6 or any(
            r["status"] in {"unknown", "dispatched"} for r in rows
        ):
            raise PermissionError(
                "F8 uncertain or incomplete evidence requires reconciliation"
            )
        if any(r["status"] == "failed" for r in rows):
            raise PermissionError(
                "F8 failed receipt or execution requires systemic failure reconciliation"
            )
        return {
            "status": "completed"
            if all(r["status"] == "completed" for r in rows)
            else "gap",
            "case_id": case,
            "branches": rows,
            "snapshot_sha256": canonical_hash(snapshot),
        }

    def reconcile(self):
        """Read original ledger conservatively; no account construction or DB writes."""
        import math
        import sqlite3

        from evals.adapters.remediation_worker import require_existing_budget

        core = self.data["core_config"]
        path = Path(core["active_budget_path"])
        require_existing_budget(path, core["budget_identity"])
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
            db.execute("BEGIN")
            rows = db.execute(
                "SELECT rowid,phase,upper,actual,settled FROM reservations ORDER BY rowid"
            ).fetchall()
            supplements = db.execute(
                "SELECT s.purpose,r.upper,r.actual,r.settled FROM supplement_requests s JOIN reservations r ON r.id=s.reservation_id WHERE s.campaign_id=?",
                (self.identity["campaign_id"],),
            ).fetchall()
        if any(
            not math.isfinite(float(v)) or float(v) < 0
            for r in rows
            for v in (r[2], r[3])
            if v is not None
        ):
            raise PermissionError("non-finite or negative original accounting")
        totals = {p: 0.0 for p in ("development", "regression", "f8")}
        for purpose, upper, actual, settled in supplements:
            if purpose not in totals or not settled or actual is None:
                raise PermissionError(
                    "supplement unknown or in-flight costs prohibit progress"
                )
            totals[purpose] += actual
        total = sum(
            actual if actual is not None else upper for _, _, upper, actual, _ in rows
        )
        dev = sum(
            actual if actual is not None else upper
            for _, phase, upper, actual, _ in rows
            if phase == "development"
        )
        if (
            total + 2 > 100
            or dev > 15
            or sum(totals.values()) + 2 > 30
            or any(
                totals[p] > cap
                for p, cap in [("development", 6), ("regression", 16), ("f8", 6)]
            )
            or any(not settled for _, _, _, _, settled in rows)
        ):
            raise PermissionError(
                "original caps or unresolved in-flight accounting prohibit progress"
            )
        receipt = {
            "status": "verified",
            "original_total_accounted_cny": total,
            "original_development_accounted_cny": dev,
            "purposes_cny": totals,
            "held_cny": 2,
            "original_unknown_count": sum(
                actual is None for _, _, _, actual, settled in rows if settled
            ),
            "ledger_rows_sha256": canonical_hash(rows),
            "supplement_rows_sha256": canonical_hash(supplements),
        }
        self._save("cost-reconciliation", receipt)
        return receipt
