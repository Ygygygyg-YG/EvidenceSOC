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
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256

from evals.contracts import canonical_hash
from evals.review import report_citations, report_claims
from evals.task13_rolling import _read_rolling

PLAN_SHA256 = "af9c8444012be08252fdfafecfa6cc846476c13b8508db425363553ee4db07fe"
ORDER_SHA256 = "0397985ccc72aef8fe6b101630d76f7c486c9c67938b09f9977c31716bd193e4"
ANYTIME_AUTHORIZATION_SHA256 = (
    "decdef181118f852fbde86758f8ee2660a6fb2f0d556364df25b125d1cec4035"
)


def _strict_pin(pin):
    if (
        not isinstance(pin, dict)
        or set(pin) != {"path", "sha256"}
        or not isinstance(pin["path"], str)
        or not pin["path"].strip()
        or not isinstance(pin["sha256"], str)
        or not re.fullmatch("[0-9a-f]{64}", pin["sha256"])
    ):
        raise ValueError("exact raw artifact pin required")
    return read_pin(pin)


def validate_human_participation(joint_scope_pin, joint_decision_pin):
    """Read-only successor authority; callers independently choose both raw pins.

    This checks the human subsection, not native execution authority. The native
    scorer additionally audits the sealed formal host and complete joint scope.
    No historical deadline limits offline human submission.
    """
    scope, decision = _strict_pin(joint_scope_pin), _strict_pin(joint_decision_pin)
    if (
        not isinstance(scope, dict)
        or scope.get("schema_version") != "task13-rolling-joint-scope-v1"
        or not isinstance(scope.get("campaign_id"), str)
        or not scope["campaign_id"].strip()
        or not isinstance(scope.get("bundle_sha256"), str)
        or not re.fullmatch("[0-9a-f]{64}", scope["bundle_sha256"])
    ):
        raise ValueError("actual new formal joint scope identity required")
    policy = scope.get("human_review_participation")
    literals = {
        "schema_version": "task13-human16-participation-v1",
        "review_window": "anytime",
        "reviewer": "user",
        "applies_to": "new-registered-sixteen-slot-sample-only",
        "judgment_mode": "individual-actual-user",
        "campaign_id": scope["campaign_id"],
        "bundle_sha256": scope["bundle_sha256"],
    }
    pinned = {
        "human_plan": PLAN_SHA256,
        "presentation_order": ORDER_SHA256,
        "anytime_authorization": ANYTIME_AUTHORIZATION_SHA256,
    }
    if (
        not isinstance(policy, dict)
        or set(policy) != set(literals) | set(pinned)
        or any(policy[k] != v for k, v in literals.items())
    ):
        raise ValueError("explicit exact human16 anytime participation required")
    for key, digest in pinned.items():
        value = _strict_pin(policy[key])
        if policy[key]["sha256"] != digest:
            raise ValueError(
                "original human registration/actual anytime instruction required"
            )
        if key == "anytime_authorization" and (
            value.get("schema_version")
            != "task13-startup-recovery-actual-user-instructions-v1"
            or value.get("role") != "user"
            or value.get("source") != "actual_user_messages_in_current_chat"
            or value.get("dispatch_window") != "anytime"
            or value.get("user_presence_required") is not False
            or value.get("plan_approval_credit") != 0
            or value.get("formal176_or_f8_sending_approval_credit") is not False
            or "remove time-window and continuous-presence restriction"
            not in value.get("scope_delta", [])
        ):
            raise ValueError(
                "retained actual-user anytime instruction provenance required"
            )
    if (
        not isinstance(decision, dict)
        or decision.get("schema_version") != "task13-rolling-joint-user-decision-v1"
        or decision.get("role") != "user"
        or decision.get("decision") != "approved"
        or decision.get("scope_packet_sha256") != joint_scope_pin["sha256"]
        or decision.get("synthetic_control_fixture", False) is not False
        or decision.get("automatic_approval", False) is not False
        or any(
            not isinstance(decision.get(k), str) or not decision[k].strip()
            for k in ("record_id", "text", "decided_at")
        )
    ):
        raise ValueError("actual joint human16 scope approval required")
    return deepcopy(policy), _time(decision["decided_at"])


def _authority_pair(joint_scope_pin, joint_decision_pin):
    if (joint_scope_pin is None) != (joint_decision_pin is None):
        raise ValueError("both external joint scope and actual decision pins required")
    return joint_scope_pin is not None


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


def prepare_reviews(
    plan_pin, order_pin, rows, *, joint_scope_pin=None, joint_decision_pin=None
):
    successor = _authority_pair(joint_scope_pin, joint_decision_pin)
    policy = None
    if successor:
        policy, _ = validate_human_participation(joint_scope_pin, joint_decision_pin)
        if (
            policy["human_plan"] != plan_pin
            or policy["presentation_order"] != order_pin
        ):
            raise ValueError("human16 policy registration pins differ from preparation")
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
    prepared = {
        "schema_version": "task13-human-review-prepared-v2",
        "human_plan": plan_pin,
        "presentation_order": order_pin,
        "records": records,
    }
    if successor:
        prepared.update(
            schema_version="task13-human-review-prepared-v3",
            joint_scope=deepcopy(joint_scope_pin),
            joint_decision=deepcopy(joint_decision_pin),
            human_review_participation=policy,
        )
    return prepared


def validate_reviews(
    prepared_pin, captures, rows, *, joint_scope_pin=None, joint_decision_pin=None
):
    """Return scorer dictionaries keyed by NEW regression slot, all sixteen kept.

    captures is [{presentation: rawpin, reply: rawpin}], in completed slot order.
    Both records bind prepared_sha256, slot_id, question_item_id, title/question.
    Presentation origin=actual_tool_question; reply origin=actual_user, role=user.
    Every record carries synthetic_control_fixture=false and automatic_approval=false.
    This validates retained provenance, not the honesty of a fabricated local file;
    the operator must retain the actual incoming UI records, never author consent.
    """
    supplied = _authority_pair(joint_scope_pin, joint_decision_pin)
    prepared = read_pin(prepared_pin)
    schema = prepared.get("schema_version")
    successor = schema == "task13-human-review-prepared-v3"
    if schema not in {
        "task13-human-review-prepared-v2",
        "task13-human-review-prepared-v3",
    }:
        raise ValueError("unknown human prepared schema")
    authority = {}
    activation = None
    if successor:
        if (
            not supplied
            or prepared.get("joint_scope") != joint_scope_pin
            or prepared.get("joint_decision") != joint_decision_pin
        ):
            raise ValueError(
                "successor requires exact external joint scope/decision pins"
            )
        _, activation = validate_human_participation(
            joint_scope_pin, joint_decision_pin
        )
        authority = {
            "joint_scope_pin": joint_scope_pin,
            "joint_decision_pin": joint_decision_pin,
        }
    expected = prepare_reviews(
        prepared["human_plan"], prepared["presentation_order"], rows, **authority
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
        if successor and (started < activation or ended < activation):
            raise ValueError(
                "human16 successor capture predates actual joint activation"
            )
        if ended < started or (previous_capture and started < previous_capture):
            raise ValueError("actual captures out of order")
        previous_capture = ended
        local = ended.astimezone(timezone(timedelta(hours=8)))
        if not successor and local.hour < 19:
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
