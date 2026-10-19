"""Controller/scoring-only Task13 metrics over normalized immutable rows."""
from collections import Counter
from math import ceil, floor

from .attack_chain import score_attack_chain
from .classification import prediction, ratio, score_classification
from .evidence import score_evidence
from .verification import score_verification as score_verification


def _quantile(values, q):
    if not values:
        return None
    values = sorted(values)
    point = (len(values) - 1) * q
    lower, upper = floor(point), ceil(point)
    return values[lower] + (values[upper] - values[lower]) * (point - lower)


def score_resources(rows):
    result = {key: None for key in ("input_tokens", "output_tokens", "cost")}
    result["known_subtotals"] = {}
    for key in result.copy():
        if key == "known_subtotals":
            continue
        values = [(row.get("usage") or {}).get(key) for row in rows]
        known = [value for value in values if isinstance(value, (float, int)) and not isinstance(value, bool)]
        result[key] = sum(known) if len(known) == len(rows) and rows else None
        result["known_subtotals"][key] = sum(known) if known else None
        result[key + "_missing_count"] = len(rows) - len(known)
    latencies = [row["latency_ms"] for row in rows if isinstance(row.get("latency_ms"), (int, float))]
    tool_complete = [row.get("tool_ledger_complete", isinstance(row.get("tool_calls"), list)) is True
                     for row in rows]
    actual_tools = [call for row in rows for call in (row.get("tool_calls") or [])
                    if call.get("charged") is not False and not call.get("source_call_id")]
    tool_counts = {"tool_logical_calls": len(actual_tools),
                   "tool_physical_attempts": sum(call.get("physical_attempts", call.get("attempts", 1)) for call in actual_tools)}
    for key, value in tool_counts.items():
        result[key] = value if rows and all(tool_complete) else None
        result["known_subtotals"][key] = value if any(tool_complete) or actual_tools else None
    result.update({"usage_missing_count": sum(not row.get("usage") for row in rows),
                   "latency_p50_ms": _quantile(latencies, .5), "latency_p95_ms": _quantile(latencies, .95),
                   "latency_observed_n": len(latencies), "latency_missing_n": len(rows) - len(latencies),
                   "missing_reason": "Missing usage/tool ledgers remain null; known subtotals include observed entries only",
                   "model_logical_calls": sum(len(row.get("model_calls", [])) for row in rows),
                   "model_physical_attempts": sum(call.get("physical_attempts", 1) for row in rows for call in row.get("model_calls", [])),
                   "tool_ledger_missing_count": len(rows) - sum(tool_complete),
                   "tool_ledger_complete_n": sum(tool_complete),
                   "reserved_tool_slots": sum(row.get("reserved_tool_slots", 0) for row in rows)})
    result["model_retries"] = result["model_physical_attempts"] - result["model_logical_calls"]
    return result


def score_rows(rows):
    rows = list(rows)
    executions = Counter(row.get("execution_status", "missing") for row in rows)
    predictions = Counter(prediction(row) for row in rows)
    return {"classification": score_classification(rows), "evidence": score_evidence(rows),
            "resources": score_resources(rows), "attack_chain": score_attack_chain(rows),
            "coverage": {"planned_n": len(rows), "execution_status": dict(executions),
                         "diagnostic_status": dict(predictions),
                         "answer_coverage": ratio(predictions["attack"] + predictions["benign"], len(rows)),
                         "human_reviewed_n": sum((row.get("human_review") or {}).get("reviewed") is True for row in rows),
                         "strata": dict(Counter(row.get("scenario", "unspecified") for row in rows))}}
