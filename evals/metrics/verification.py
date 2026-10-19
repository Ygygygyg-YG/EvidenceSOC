"""Independent controller-only F8 pairing; no diagnosis scores are rewritten."""
from collections import Counter

from .classification import ratio

CONDITIONS = ("success", "failure", "no_change")
BRANCHES = ("enabled", "disabled")
OUTCOMES = {"success", "failure", "insufficient_evidence", "unverified"}


def score_verification(records, planned_slots):
    slots = {slot["pair_id"]: slot for slot in planned_slots}
    if len(slots) != len(planned_slots):
        raise ValueError("Duplicate planned verification pair")
    if any(slot.get("condition") not in CONDITIONS for slot in slots.values()):
        raise ValueError("Unknown planned verification condition")
    indexed = {}
    for row in records:
        key = (row.get("pair_id"), row.get("branch"))
        if key[0] not in slots or key[1] not in BRANCHES or key in indexed:
            raise ValueError("Unplanned or duplicate verification branch")
        outcome = row.get("outcome")
        if outcome is not None and outcome not in OUTCOMES:
            raise ValueError("Unknown verification outcome")
        if key[1] == "disabled" and outcome in {"success", "failure", "insufficient_evidence"}:
            raise ValueError("Disabled verifier must remain unverified")
        indexed[key] = row

    def executable(row, branch):
        outcomes = {"unverified"} if branch == "disabled" else OUTCOMES - {"unverified"}
        return (row.get("status") == "completed" and row.get("approval_status") == "approved"
                and row.get("outcome") in outcomes)

    conditions = {}
    complete_pairs = 0
    complete_cases = {}
    for condition in CONDITIONS:
        expected = [pair_id for pair_id, slot in slots.items() if slot["condition"] == condition]
        common = [pair_id for pair_id in expected if all(executable(indexed.get((pair_id, branch), {}), branch) for branch in BRANCHES)]
        complete_pairs += len(common)
        for pair_id in common:
            complete_cases.setdefault(slots[pair_id]["case_id"], set()).add(condition)
        branches = {}
        for branch in BRANCHES:
            all_rows = [indexed.get((pair_id, branch), {"status": "missing"}) for pair_id in expected]
            paired_rows = [indexed[(pair_id, branch)] for pair_id in common]
            answered = [row for row in paired_rows if row.get("outcome") in {"success", "failure", "insufficient_evidence"}]
            outcomes = Counter(row.get("outcome", "unanswered") for row in paired_rows)
            branches[branch] = {"answered_n": len(answered), "paired_n": len(common),
                "outcome_counts": dict(outcomes),
                "all_outcome_counts": dict(Counter(row.get("outcome", row.get("status", "missing")) for row in all_rows)),
                "status_counts": dict(Counter(row.get("status", "missing") for row in all_rows)),
                "success_rate": ratio(outcomes["success"], len(answered)),
                "false_success_rate": ratio(outcomes["success"], len(answered)) if condition in {"failure", "no_change"} else None,
                "failure_recognition_rate": ratio(outcomes["failure"], len(answered)) if condition == "failure" else None,
                "no_change_insufficient_rate": ratio(outcomes["insufficient_evidence"], len(answered)) if condition == "no_change" else None,
                "unverified_rate": ratio(outcomes["unverified"], len(common)),
                "answer_coverage": ratio(len(answered), len(expected))}
        conditions[condition] = {"planned_pairs": len(expected), "executable_pairs": len(common),
                                 "branches": branches}
    costs = [row.get("cost") for row in records]
    known = [value for value in costs if isinstance(value, (int, float)) and not isinstance(value, bool)]
    return {"planned_pairs": len(slots), "planned_branches": 2 * len(slots), "observed_branches": len(records),
            "complete_pairs": complete_pairs, "conditions": conditions,
            "cases_complete_all_conditions": sum(len(values) == 3 for values in complete_cases.values()),
            "cost": sum(known) if len(known) == len(records) and len(records) == 2 * len(slots) and records else None,
            "known_cost_subtotal": sum(known) if known else None, "cost_missing_count": 2 * len(slots) - len(known),
            "scope": "independent paired simulation; does not prove real blocking"}
