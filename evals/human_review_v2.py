"""Host-only sixteen-slot review bridge; never creates a human judgment.

Persist prepare_reviews() with write_immutable_json. Present each record in its
registered order without distributing the control mapping. Capture actual UI
delivery and actual user reply as separate raw pinned JSON records. Reply.text
is the user's JSON {claims: [...], relevance: {...]}; parsing never infers a
judgment from response approval. Captured wall times measure receipt times only.
Optional same-session monotonic_ns observations measure presentation-to-receipt
elapsed time, not active reading time. Missing observations remain null.
"""

import json
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256

from evals.contracts import canonical_hash
from evals.review import report_citations, report_claims
from evals.task13_rolling import _read_rolling

PLAN_SHA256 = "af9c8444012be08252fdfafecfa6cc846476c13b8508db425363553ee4db07fe"
ORDER_SHA256 = "0397985ccc72aef8fe6b101630d76f7c486c9c67938b09f9977c31716bd193e4"


def _blind(value):
    if isinstance(value, dict):
        return {
            k: _blind(v)
            for k, v in value.items()
            if k
            not in {
                "group",
                "group_id",
                "case_id",
                "dataset",
                "gold",
                "selection_stratum",
                "mapping",
            }
        }
    if isinstance(value, list):
        return [_blind(v) for v in value]
    return value


def read_pin(pin):
    raw = _read_rolling(pin["path"])
    if sha256(raw).hexdigest() != pin["sha256"]:
        raise ValueError("raw artifact pin changed")
    return json.loads(raw)


def _time(value):
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None or stamp > datetime.now(UTC):
        raise ValueError("actual capture must be aware and nonfuture")
    return stamp


def review_question(prepared_pin, slot_id):
    """Exact blind UI content; actual tool question ID is captured after delivery."""
    prepared = read_pin(prepared_pin)
    record = next(r for r in prepared["records"] if r["slot_id"] == slot_id)
    return {
        "title": f"{record['display_code']} factual review {prepared_pin['sha256']}",
        "question": json.dumps(record, ensure_ascii=False, sort_keys=True),
    }


def prepare_reviews(plan_pin, order_pin, rows):
    if plan_pin["sha256"] != PLAN_SHA256 or order_pin["sha256"] != ORDER_SHA256:
        raise ValueError("original sixteen-slot registration required")
    plan, order = read_pin(plan_pin), read_pin(order_pin)
    slots = plan["slots"]
    if len(slots) != 16 or [(s["sequence"], s["slot_id"]) for s in slots] != [
        (s["sequence"], s["slot_id"]) for s in order["slots"]
    ]:
        raise ValueError("registered presentation order differs")
    lookup = {r["slot_id"]: r for r in rows}
    if len(lookup) != len(rows):
        raise ValueError("duplicate regression rows")
    records = []
    for slot, display in zip(slots, order["slots"], strict=True):
        row = lookup[slot["regression_slot_id"]]
        if row["case_id"] != slot["case_id"] or row["group"] != slot["group"]:
            raise ValueError("actual new row binding differs")
        report = (row.get("result") or {}).get("diagnostic_snapshot") or {}
        claims = report_claims(report)
        reason = (
            "missing_output"
            if row.get("result") is None
            else "no_report"
            if not report
            else "no_factual_claims"
            if not claims
            else None
        )
        records.append(
            {
                "slot_id": slot["slot_id"],
                "sequence": slot["sequence"],
                "display_code": display["display_code"],
                "output_sha256": row["output_sha256"],
                "report_sha256": canonical_hash(report),
                "claims": claims,
                "evidence_ids": list(dict.fromkeys(report_citations(report)))[:5],
                "evidence_registry": _blind(
                    (row.get("result") or {}).get("evidence_registry", {})
                ),
                "unavailable_reason": reason,
            }
        )
    return {
        "schema_version": "task13-human-review-prepared-v2",
        "human_plan": plan_pin,
        "presentation_order": order_pin,
        "records": records,
    }


def validate_reviews(prepared_pin, captures, rows):
    """Return scorer dictionaries keyed by NEW regression slot, all sixteen kept.

    captures is [{presentation: rawpin, reply: rawpin}], in completed slot order.
    Both records bind prepared_sha256, slot_id, question_item_id, title/question.
    Presentation origin=actual_tool_question; reply origin=actual_user, role=user.
    Every record carries synthetic_control_fixture=false and automatic_approval=false.
    This validates retained provenance, not the honesty of a fabricated local file;
    the operator must retain the actual incoming UI records, never author consent.
    """
    prepared = read_pin(prepared_pin)
    expected = prepare_reviews(
        prepared["human_plan"], prepared["presentation_order"], rows
    )
    if prepared != expected:
        raise ValueError("prepared reports no longer match actual sealed output")
    plan = read_pin(prepared["human_plan"])
    records = {r["slot_id"]: r for r in prepared["records"]}
    results = {
        s["regression_slot_id"]: {
            "reviewed": False,
            "slot_id": s["slot_id"],
            "reason": records[s["slot_id"]]["unavailable_reason"] or "not_reviewed",
            "measured_duration_seconds": None,
        }
        for s in plan["slots"]
    }
    slots = {s["slot_id"]: s for s in plan["slots"]}
    previous = 0
    seen_ids = set()
    seen_questions = set()
    previous_capture = None
    available = [
        r["slot_id"] for r in prepared["records"] if not r["unavailable_reason"]
    ]
    for pins in captures:
        start, reply = read_pin(pins["presentation"]), read_pin(pins["reply"])
        slot = slots[reply["slot_id"]]
        record = records[slot["slot_id"]]
        if not available or available.pop(0) != slot["slot_id"]:
            raise ValueError(
                "reviewable slots must retain original presentation prefix"
            )
        if slot["sequence"] <= previous or record["unavailable_reason"]:
            raise ValueError("duplicate/reordered/unavailable review")
        previous = slot["sequence"]
        for item in (start, reply):
            if (
                item.get("synthetic_control_fixture") is not False
                or item.get("automatic_approval") is not False
                or item.get("prepared_sha256") != prepared_pin["sha256"]
                or item.get("slot_id") != slot["slot_id"]
            ):
                raise ValueError("actual review capture binding required")
        if (
            start.get("origin") != "actual_tool_question"
            or reply.get("origin") != "actual_user"
            or reply.get("role") != "user"
            or not reply.get("record_id")
            or reply["record_id"] in seen_ids
        ):
            raise ValueError("fresh actual user capture required")
        seen_ids.add(reply["record_id"])
        qid = json.loads(reply["question_item_id"])
        if (
            len(qid) != 3
            or qid[0] != "request_user_input_async"
            or not isinstance(qid[1], str)
            or not qid[1].startswith("call_")
            or qid[2] != 0
        ):
            raise ValueError("actual tool question identity required")
        identity = tuple(qid)
        if identity in seen_questions:
            raise ValueError(
                "actual question delivery cannot serve multiple review slots"
            )
        seen_questions.add(identity)
        title = f"{record['display_code']} factual review {prepared_pin['sha256']}"
        question = json.dumps(record, ensure_ascii=False, sort_keys=True)
        if any(
            start.get(k) != reply.get(k)
            for k in ("question_item_id", "title", "question")
        ) or (reply.get("title") != title or reply.get("question") != question):
            raise ValueError("reply differs from actual blinded presentation")
        started, ended = _time(start["captured_at"]), _time(reply["captured_at"])
        if ended < started or (previous_capture and started < previous_capture):
            raise ValueError("actual captures out of order")
        previous_capture = ended
        local = ended.astimezone(timezone(timedelta(hours=8)))
        if local.hour < 19:
            raise ValueError(
                "registered human review window is 19:00-00:00 Asia/Shanghai"
            )
        judgment = json.loads(reply["text"])
        claims = judgment["claims"]
        if len(claims) != len(record["claims"]) or {c["claim_id"] for c in claims} != {
            c["claim_id"] for c in record["claims"]
        }:
            raise ValueError("each actual claim must be reviewed exactly once")
        if any(
            c.get("judgment")
            not in {"supported", "unsupported", "uncertain", "undetermined"}
            or not isinstance(c.get("basis"), str)
            or not c["basis"].strip()
            for c in claims
        ):
            raise ValueError("human claim judgment and source basis required")
        relevance = judgment["relevance"]
        if set(relevance) != set(record["evidence_ids"]) or any(
            v
            not in {
                "supported",
                "relevant",
                "uncertain",
                "undetermined",
                "irrelevant",
                "unsupported",
            }
            for v in relevance.values()
        ):
            raise ValueError("each actual top-five citation requires human judgment")
        duration = None
        if "monotonic_ns" in start or "monotonic_ns" in reply:
            if (
                not start.get("clock_session_id")
                or start["clock_session_id"] != reply.get("clock_session_id")
                or type(start.get("monotonic_ns")) is not int
                or type(reply.get("monotonic_ns")) is not int
                or start["monotonic_ns"] < 0
                or reply["monotonic_ns"] < start["monotonic_ns"]
            ):
                raise ValueError(
                    "elapsed duration requires actual same-session monotonic observations"
                )
            duration = (reply["monotonic_ns"] - start["monotonic_ns"]) / 1e9
        results[slot["regression_slot_id"]] = {
            "reviewed": True,
            "reviewer": "user",
            "reviewed_at": reply["captured_at"],
            "claims": claims,
            "relevance": relevance,
            "slot_id": slot["slot_id"],
            "underlying_case": slot["case_id"],
            "capture_pins": pins,
            "measured_duration_seconds": duration,
            "duration_scope": "presentation-to-receipt elapsed; not active reading time",
        }
    return results
